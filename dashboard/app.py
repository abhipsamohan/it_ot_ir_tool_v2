import sys
import os
import json
import threading
import time
import traceback

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, request
from engine.decision_engine import DecisionEngine

app = Flask(__name__)

engine = DecisionEngine()

_ESCALATION_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "config", "escalation.json",
)

# ---------------------------------------------------------------------------
# BACKGROUND AUTO-SCAN THREAD
# Continuously polls the alerts directory every 10 seconds so operators do
# not need to click "Scan Alerts" manually — closing the Gap #3 real-time gap.
# ---------------------------------------------------------------------------

def _background_scan():
    while True:
        try:
            engine.scan_alerts()
        except Exception as e:
            print(f"[auto-scan] error: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        time.sleep(10)

_scan_thread = threading.Thread(target=_background_scan, daemon=True)
_scan_thread.start()


# ---------------------------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


# ---------------------------------------------------------------------------
# ALERT INGESTION — accepts alerts from external sources (IDS, firewall, etc.)
# ---------------------------------------------------------------------------

@app.route("/api/alert", methods=["POST"])
def ingest_alert():
    """
    Accepts a JSON alert payload and processes it immediately through the
    decision engine.  Enables integration with real IDS/SIEM/firewall sources
    without requiring file drops.

    Expected payload:
    {
        "event_type": "FAILED_LOGIN",
        "asset_id": "pump_controller_1",
        "severity": "high",
        "details": { ... }          (optional)
    }
    """
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Invalid or missing JSON body"}), 400

    required = ["event_type", "asset_id", "severity"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {missing}"}), 400

    incident = engine.process_alert_dict(data)

    if incident is None:
        return jsonify({"error": "Failed to process alert"}), 500

    return jsonify(incident), 201


# ---------------------------------------------------------------------------
# SCAN (manual trigger kept for compatibility)
# ---------------------------------------------------------------------------

@app.route("/api/scan")
def scan_alerts():

    incidents = engine.scan_alerts()

    return jsonify({
        "count": len(incidents),
        "incidents": incidents,
    })


# ---------------------------------------------------------------------------
# INCIDENTS
# ---------------------------------------------------------------------------

@app.route("/api/incidents")
def get_incidents():

    incidents = engine.get_incidents()
    return jsonify(incidents)


# ---------------------------------------------------------------------------
# OPERATOR ACKNOWLEDGEMENT
# ---------------------------------------------------------------------------

@app.route("/api/incidents/<incident_id>/acknowledge", methods=["PUT"])
def acknowledge_incident(incident_id):
    """
    Marks an incident as acknowledged by a named operator.
    Body: { "operator": "Jane Smith" }
    """
    data = request.get_json(silent=True) or {}
    operator = (data.get("operator") or "").strip()

    if not operator:
        return jsonify({"error": "operator name is required"}), 400

    updated = engine.db.acknowledge_incident(incident_id, operator)

    if not updated:
        return jsonify({"error": "Incident not found"}), 404

    return jsonify({"status": "acknowledged", "incident_id": incident_id, "operator": operator})


# ---------------------------------------------------------------------------
# SHIFT HANDOVER REPORT
# ---------------------------------------------------------------------------

@app.route("/api/report/shift")
def shift_report():
    """
    Returns a summary of incidents for the last 8 hours (one shift).
    Optional query param: ?since=<ISO timestamp>
    """
    since = request.args.get("since")
    summary = engine.db.get_shift_summary(since_iso=since)
    return jsonify(summary)


# ---------------------------------------------------------------------------
# OT ASSET CONFIG RELOAD
# ---------------------------------------------------------------------------

@app.route("/api/assets/reload", methods=["POST"])
def reload_assets():
    """Reloads OT asset context from ot_assets.json without restarting."""
    assets = engine.reload_assets()
    return jsonify({"reloaded": True, "asset_count": len(assets)})


# ---------------------------------------------------------------------------
# ESCALATION CONFIG
# ---------------------------------------------------------------------------

@app.route("/api/config/escalation")
def get_escalation_config():
    """Returns escalation contacts and thresholds from data/config/escalation.json."""
    if os.path.exists(_ESCALATION_PATH):
        with open(_ESCALATION_PATH) as f:
            return app.response_class(f.read(), mimetype="application/json")
    return jsonify({"contacts": [], "thresholds": {}})


if __name__ == "__main__":
    # Use debug=False in production; set FLASK_DEBUG=1 env var for development.
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode)
