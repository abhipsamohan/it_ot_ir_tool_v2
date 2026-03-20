"""
app.py - Main Flask Application for IT/OT Incident Response System
REST API endpoints for alert processing, incident management, and response orchestration.
"""

import json
import logging
import os
import uuid
from datetime import datetime

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

from config.settings import get_config
from engine.dependency_engine import DependencyEngine
from engine.rule_engine import RuleEngine
from engine.safe_response_engine import SafeResponseEngine
from models.database import AuditLog, Incident, init_db, get_session

# ------------------------------------------------------------------
# App setup
# ------------------------------------------------------------------

Config = get_config()

logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
CORS(app, origins=Config.CORS_ORIGINS)

# ------------------------------------------------------------------
# Engine initialisation
# ------------------------------------------------------------------

rule_engine = RuleEngine(
    rules_file=Config.RULES_FILE,
    alert_history_limit=Config.ALERT_HISTORY_LIMIT,
    brute_force_threshold=Config.BRUTE_FORCE_THRESHOLD,
    brute_force_window_minutes=Config.BRUTE_FORCE_WINDOW_MINUTES,
)
dependency_engine = DependencyEngine(dependencies_file=Config.DEPENDENCIES_FILE)
response_engine = SafeResponseEngine()

# Database
os.makedirs("data", exist_ok=True)
db_engine = init_db(Config.DATABASE_URL)

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

SEVERITY_MAP = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CRITICALITY_MAP = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _calculate_risk(severity: str, criticality: str, multiplier: float) -> dict:
    sev_score = SEVERITY_MAP.get(severity.lower(), 2)
    crit_score = CRITICALITY_MAP.get(criticality.lower(), 2)
    base_score = (sev_score * 0.6 + crit_score * 0.4) * multiplier

    if base_score >= 3.5:
        level = "CRITICAL"
    elif base_score >= 2.5:
        level = "HIGH"
    elif base_score >= 1.5:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"level": level, "score": round(base_score, 2)}


def _audit(session, incident_id: str, action: str, actor: str, action_type: str, details: dict = None):
    log = AuditLog(
        incident_id=incident_id,
        action=action,
        actor=actor,
        action_type=action_type,
        timestamp=datetime.utcnow(),
        details=json.dumps(details or {}),
    )
    session.add(log)


def _process_single_alert(alert: dict, session) -> dict:
    """
    Full pipeline: rule match → impact analysis → response orchestration → DB store.
    Returns the created incident dict.
    """
    event_type = alert.get("event_type", "UNKNOWN")
    asset_id = alert.get("asset_id", "unknown")
    severity = alert.get("severity", "medium")

    # Asset info from dependency engine
    asset_info = dependency_engine.get_asset_info(asset_id)
    criticality = asset_info.get("criticality", "medium")

    # Enrich alert with criticality for rule matching
    alert["asset_criticality"] = criticality

    # Rule engine
    rule_result = rule_engine.process_alert(alert)
    matched_rules = rule_result["matched_rules"]
    correlations = rule_result["correlations"]
    multiplier = rule_result["severity_multiplier"]

    # Boost severity if correlated
    effective_severity = severity
    if correlations:
        effective_severity = "critical"

    # Risk calculation
    risk = _calculate_risk(effective_severity, criticality, multiplier)

    # First matched rule drives response / explanation
    rule = matched_rules[0] if matched_rules else {}
    rule_name = rule.get("name", "General Alert")
    explanation = rule.get("explanation", f"Suspicious activity: {event_type}")
    do_steps = rule.get("do_steps", [])
    dont_steps = rule.get("dont_steps", [])
    response_actions = rule.get("response_actions", ["alert_team"])

    # Add correlation description to explanation
    if correlations:
        corr_desc = "; ".join(c["description"] for c in correlations)
        explanation = f"{explanation} [CORRELATED: {corr_desc}]"

    # Dependency / blast radius
    impact = dependency_engine.get_impact_summary(asset_id)

    # Build incident ID
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

    # Response orchestration
    context = {"asset_id": asset_id, "event_type": event_type, "details": alert.get("details", {})}
    response_result = response_engine.process_actions(response_actions, incident_id, context)

    # Build response steps list
    response_steps = []
    for ex in response_result["auto_executed"]:
        response_steps.append(f"AUTO: {ex['description']}")
    for pend in response_result["pending_approvals"]:
        response_steps.append(f"PENDING APPROVAL: {pend['description']}")

    # Store in DB
    incident = Incident(
        incident_id=incident_id,
        timestamp=datetime.utcnow(),
        event_type=event_type,
        asset_id=asset_id,
        severity=effective_severity,
        risk_level=risk["level"],
        risk_score=risk["score"],
        rule_matched=rule_name,
        response_action=response_actions[0] if response_actions else "alert_team",
        response_steps=json.dumps(response_steps),
        explanation=explanation,
        do_steps=json.dumps(do_steps),
        dont_steps=json.dumps(dont_steps),
        status="open",
    )
    session.add(incident)

    # Audit log
    _audit(session, incident_id, "incident_created", "system", "auto_executed", {
        "event_type": event_type,
        "asset_id": asset_id,
        "risk_level": risk["level"],
        "rules_matched": [r["id"] for r in matched_rules],
        "correlations": [c["type"] for c in correlations],
    })
    session.commit()

    return {
        **incident.to_dict(),
        "impact": impact,
        "correlations": [c["type"] for c in correlations],
        "pending_approvals": [p["approval_id"] for p in response_result["pending_approvals"]],
    }


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/scan-alerts", methods=["POST"])
def scan_alerts():
    """Scan the alerts directory, process new alerts, create incidents."""
    alerts_dir = Config.ALERTS_DIR
    os.makedirs(alerts_dir, exist_ok=True)

    processed = []
    errors = []
    processed_set: set = getattr(app, "_processed_files", set())
    app._processed_files = processed_set

    session = get_session(db_engine)
    try:
        for filename in sorted(os.listdir(alerts_dir)):
            if not filename.endswith(".json"):
                continue
            filepath = os.path.join(alerts_dir, filename)
            if filepath in processed_set:
                continue
            try:
                with open(filepath) as f:
                    alert = json.load(f)
                incident = _process_single_alert(alert, session)
                processed.append(incident)
                processed_set.add(filepath)
            except Exception as exc:
                logger.error("Error processing %s: %s", filepath, exc)
                errors.append({"file": filename, "error": str(exc)})
    finally:
        session.close()

    return jsonify({"count": len(processed), "incidents": processed, "errors": errors})


@app.route("/api/generate-test-alerts", methods=["POST"])
def generate_test_alerts():
    """Generate test alert files for a chosen scenario."""
    from ingestion.alert_generator import AlertGenerator

    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario", 1)

    generator = AlertGenerator(alerts_dir=Config.ALERTS_DIR)

    if scenario == 1:
        paths = generator.generate_brute_force_scenario()
        scenario_name = "Brute Force"
    elif scenario == 2:
        paths = generator.generate_plc_modification_scenario()
        scenario_name = "PLC Modification"
    elif scenario == 3:
        paths = generator.generate_attack_progression_scenario()
        scenario_name = "Attack Progression"
    else:
        return jsonify({"error": "Invalid scenario. Choose 1, 2, or 3."}), 400

    return jsonify({"scenario": scenario_name, "count": len(paths), "files": paths})


@app.route("/api/incidents", methods=["GET"])
def get_incidents():
    """List all incidents. Supports ?severity=&status= filters."""
    severity_filter = request.args.get("severity", "").lower()
    status_filter = request.args.get("status", "").lower()

    session = get_session(db_engine)
    try:
        from sqlalchemy import select
        from models.database import Incident as IncModel
        query = session.query(IncModel).order_by(IncModel.timestamp.desc())
        if severity_filter:
            query = query.filter(IncModel.severity == severity_filter)
        if status_filter:
            query = query.filter(IncModel.status == status_filter)
        incidents = [i.to_dict() for i in query.all()]
    finally:
        session.close()

    return jsonify(incidents)


@app.route("/api/incident/<incident_id>", methods=["GET"])
def get_incident(incident_id):
    """Get a single incident by ID."""
    session = get_session(db_engine)
    try:
        from models.database import Incident as IncModel
        inc = session.query(IncModel).filter_by(incident_id=incident_id).first()
        if not inc:
            return jsonify({"error": "Incident not found"}), 404
        return jsonify(inc.to_dict())
    finally:
        session.close()


@app.route("/api/dashboard-stats", methods=["GET"])
def dashboard_stats():
    """Return summary statistics for the dashboard."""
    session = get_session(db_engine)
    try:
        from models.database import Incident as IncModel
        total = session.query(IncModel).count()
        open_count = session.query(IncModel).filter_by(status="open").count()
        critical_count = session.query(IncModel).filter_by(risk_level="CRITICAL").count()
    finally:
        session.close()

    pending_approvals = len(response_engine.get_pending_approvals())

    return jsonify({
        "total": total,
        "open": open_count,
        "critical": critical_count,
        "pending_approvals": pending_approvals,
    })


@app.route("/api/pending-approvals", methods=["GET"])
def pending_approvals():
    """Return all pending dangerous action approvals."""
    return jsonify({"approvals": response_engine.get_pending_approvals()})


@app.route("/api/approve-action", methods=["POST"])
def approve_action():
    """Approve or deny a dangerous action."""
    data = request.get_json(silent=True)
    if not data or "approval_id" not in data:
        return jsonify({"error": "approval_id is required"}), 400

    approval_id = data["approval_id"]
    actor = data.get("actor", "operator")
    deny = data.get("deny", False)
    reason = data.get("reason", "")

    if deny:
        result = response_engine.deny_action(approval_id, reason=reason, denier=actor)
    else:
        result = response_engine.approve_action(approval_id, approver=actor)

    if "error" in result:
        return jsonify(result), 404

    # Audit
    incident_id = result.get("incident_id", "unknown")
    session = get_session(db_engine)
    try:
        action_type = "denied" if deny else "approved"
        _audit(session, incident_id, result.get("action", ""), actor, action_type, result)
        session.commit()
    finally:
        session.close()

    return jsonify(result)


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

if __name__ == "__main__":
    logger.info("Starting IT/OT Incident Response System...")
    app.run(debug=Config.DEBUG, host="0.0.0.0", port=5000)
