"""
simulate.py - End-to-End Simulation for IT/OT Incident Response System
Runs 3 realistic attack scenarios to validate system behaviour.
"""

import json
import os
import sys
import time

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import get_config
from engine.dependency_engine import DependencyEngine
from engine.rule_engine import RuleEngine
from engine.safe_response_engine import SafeResponseEngine
from ingestion.alert_generator import AlertGenerator
from models.database import init_db, get_session, Incident, AuditLog
import uuid
from datetime import datetime

Config = get_config()

# ------------------------------------------------------------------
# Setup engines
# ------------------------------------------------------------------

rule_engine = RuleEngine(
    rules_file=Config.RULES_FILE,
    brute_force_threshold=Config.BRUTE_FORCE_THRESHOLD,
    brute_force_window_minutes=Config.BRUTE_FORCE_WINDOW_MINUTES,
)
dependency_engine = DependencyEngine(dependencies_file=Config.DEPENDENCIES_FILE)
response_engine = SafeResponseEngine()

os.makedirs("data", exist_ok=True)
db_engine = init_db(Config.DATABASE_URL)


def _separator(title: str):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def _process_alert(alert: dict) -> dict:
    """Minimal pipeline for simulation (no Flask context)."""
    event_type = alert.get("event_type", "UNKNOWN")
    asset_id = alert.get("asset_id", "unknown")
    severity = alert.get("severity", "medium")

    asset_info = dependency_engine.get_asset_info(asset_id)
    criticality = asset_info.get("criticality", "medium")
    alert["asset_criticality"] = criticality

    rule_result = rule_engine.process_alert(alert)
    matched = rule_result["matched_rules"]
    correlations = rule_result["correlations"]
    multiplier = rule_result["severity_multiplier"]

    rule = matched[0] if matched else {}
    response_actions = rule.get("response_actions", ["alert_team"])

    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    context = {"asset_id": asset_id, "event_type": event_type}
    response_result = response_engine.process_actions(response_actions, incident_id, context)

    impact = dependency_engine.get_impact_summary(asset_id)

    # Store
    session = get_session(db_engine)
    try:
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        crit_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        s = severity_map.get(severity, 2)
        c = crit_map.get(criticality, 2)
        score = (s * 0.6 + c * 0.4) * multiplier
        level = "CRITICAL" if score >= 3.5 else "HIGH" if score >= 2.5 else "MEDIUM" if score >= 1.5 else "LOW"
        if correlations:
            level = "CRITICAL"
            score = 4.0

        inc = Incident(
            incident_id=incident_id,
            timestamp=datetime.utcnow(),
            event_type=event_type,
            asset_id=asset_id,
            severity="critical" if correlations else severity,
            risk_level=level,
            risk_score=round(score, 2),
            rule_matched=rule.get("name", "General"),
            response_action=response_actions[0] if response_actions else "alert_team",
            response_steps=json.dumps([f"AUTO: {e['action']}" for e in response_result["auto_executed"]]),
            explanation=rule.get("explanation", "Suspicious activity detected."),
            do_steps=json.dumps(rule.get("do_steps", [])),
            dont_steps=json.dumps(rule.get("dont_steps", [])),
            status="open",
        )
        session.add(inc)
        session.commit()
    finally:
        session.close()

    return {
        "incident_id": incident_id,
        "event_type": event_type,
        "asset_id": asset_id,
        "risk_level": level,
        "rule_matched": rule.get("name", "None"),
        "correlations": [c["type"] for c in correlations],
        "auto_executed": [e["action"] for e in response_result["auto_executed"]],
        "pending_approvals": [p["action"] for p in response_result["pending_approvals"]],
        "impact_total": impact["total_impacted"],
    }


def _print_incident(inc: dict):
    print(f"  Incident ID  : {inc['incident_id']}")
    print(f"  Event        : {inc['event_type']} on {inc['asset_id']}")
    print(f"  Risk Level   : {inc['risk_level']}")
    print(f"  Rule Matched : {inc['rule_matched']}")
    print(f"  Correlations : {inc['correlations'] or 'None'}")
    print(f"  Auto-Executed: {inc['auto_executed']}")
    print(f"  Need Approval: {inc['pending_approvals']}")
    print(f"  Assets at Risk: {inc['impact_total']}")


# ------------------------------------------------------------------
# Scenario 1: Brute Force Attack
# ------------------------------------------------------------------

def scenario_brute_force():
    _separator("SCENARIO 1: BRUTE FORCE ATTACK")
    print("Sending 5 FAILED_LOGIN alerts on plc_main in rapid succession...")
    rule_engine.clear_history()

    asset_id = "plc_main"
    for i in range(5):
        alert = {
            "event_type": "FAILED_LOGIN",
            "asset_id": asset_id,
            "severity": "medium",
            "timestamp": datetime.now().isoformat(),
            "details": {"source_ip": "192.168.1.50", "attempt": i + 1},
        }
        inc = _process_alert(alert)
        print(f"\n  [Alert {i + 1}/5]")
        _print_incident(inc)
        time.sleep(0.05)

    print("\n  ✅ Brute force scenario complete.")


# ------------------------------------------------------------------
# Scenario 2: Unauthorized PLC Modification
# ------------------------------------------------------------------

def scenario_plc_modification():
    _separator("SCENARIO 2: UNAUTHORIZED PLC MODIFICATION")
    print("Sending a critical PLC_PROGRAM_CHANGE alert...")
    rule_engine.clear_history()

    alert = {
        "event_type": "PLC_PROGRAM_CHANGE",
        "asset_id": "plc_main",
        "severity": "critical",
        "timestamp": datetime.now().isoformat(),
        "details": {"changed_by": "UNKNOWN", "change_type": "ladder_logic"},
    }
    inc = _process_alert(alert)
    _print_incident(inc)
    print("\n  ✅ PLC modification scenario complete.")


# ------------------------------------------------------------------
# Scenario 3: Multi-Stage Attack Progression
# ------------------------------------------------------------------

def scenario_attack_progression():
    _separator("SCENARIO 3: MULTI-STAGE ATTACK PROGRESSION")
    rule_engine.clear_history()

    stages = [
        {
            "stage": "Stage 1: Reconnaissance",
            "alert": {
                "event_type": "NETWORK_SCAN",
                "asset_id": "network_switch_core",
                "severity": "low",
                "timestamp": datetime.now().isoformat(),
                "details": {"source_ip": "192.168.1.99"},
            },
        },
        {
            "stage": "Stage 2: Exploitation - Malware",
            "alert": {
                "event_type": "MALWARE_DETECTED",
                "asset_id": "windows_server",
                "severity": "high",
                "timestamp": datetime.now().isoformat(),
                "details": {"malware": "Industroyer-variant"},
            },
        },
        {
            "stage": "Stage 3: Impact - PLC Modification",
            "alert": {
                "event_type": "PLC_PROGRAM_CHANGE",
                "asset_id": "plc_main",
                "severity": "critical",
                "timestamp": datetime.now().isoformat(),
                "details": {"change_type": "logic_modification"},
            },
        },
    ]

    for stage_info in stages:
        print(f"\n  [{stage_info['stage']}]")
        inc = _process_alert(stage_info["alert"])
        _print_incident(inc)
        time.sleep(0.1)

    print("\n  ✅ Attack progression scenario complete.")


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

if __name__ == "__main__":
    print("\n🛡️  IT/OT Incident Response System - Simulation")
    print("=" * 60)
    print("Validating configuration...")

    # Validate configs
    errors = dependency_engine._validate_config()
    if errors:
        print(f"  ⚠️  Config warnings: {errors}")
    else:
        print("  ✅ Configuration valid.")

    rule_count = len(rule_engine.rules)
    asset_count = len(dependency_engine.assets)
    print(f"  Rules loaded: {rule_count}")
    print(f"  Assets loaded: {asset_count}")

    scenario_brute_force()
    scenario_plc_modification()
    scenario_attack_progression()

    # Summary
    session = get_session(db_engine)
    try:
        total = session.query(Incident).count()
    finally:
        session.close()

    _separator("SIMULATION COMPLETE")
    print(f"  Total incidents stored: {total}")
    print("  All 3 scenarios completed successfully ✅")
    print("\nRun 'python3 app.py' to start the web dashboard.")
