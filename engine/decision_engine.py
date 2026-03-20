import json
import os
import uuid
from datetime import datetime
from typing import Dict, List

from engine.database import IncidentDatabase


class DecisionEngine:

    def __init__(self):

        self.alerts_dir = "data/alerts"
        self.context_file = "data/ot_context/ot_assets.json"

        self.db = IncidentDatabase()
        self.assets = self.load_assets()

        self.processed_files = set()
        self.alert_history = []

    # --------------------------------------------------

    def load_assets(self):

        if not os.path.exists(self.context_file):
            return {}

        with open(self.context_file) as f:
            return json.load(f)

    # --------------------------------------------------

    def calculate_risk(self, alert, asset):

        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        criticality_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        severity = severity_map.get(alert.get("severity", "medium"), 2)
        criticality = criticality_map.get(asset.get("criticality", "medium"), 2)

        score = (severity * 0.6) + (criticality * 0.4)

        if score >= 3.5:
            level = "CRITICAL"
        elif score >= 2.5:
            level = "HIGH"
        elif score >= 1.5:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {"level": level, "score": round(score, 2)}

    # --------------------------------------------------

    def generate_response(self, event_type):

        playbooks = {

            "FAILED_LOGIN": {
                "action": "Investigate Authentication",
                "steps": [
                    "Verify user legitimacy",
                    "Check login source IP",
                    "Review authentication logs",
                    "Coordinate with OT operator"
                ]
            },

            "MALWARE_DETECTED": {
                "action": "Malware Investigation",
                "steps": [
                    "Identify infected host",
                    "Run malware scan",
                    "Check lateral movement",
                    "Avoid immediate shutdown"
                ]
            },

            "NETWORK_SCAN": {
                "action": "Investigate Recon Activity",
                "steps": [
                    "Identify scanning host",
                    "Review firewall logs",
                    "Monitor network activity"
                ]
            },

            "UNAUTHORIZED_CONFIG_CHANGE": {
                "action": "Verify Configuration Change",
                "steps": [
                    "Check change logs",
                    "Verify with OT engineer",
                    "Confirm system stability"
                ]
            },

            "PLC_PROGRAM_CHANGE": {
                "action": "Investigate PLC Logic Change",
                "steps": [
                    "Verify authorization",
                    "Check PLC workstation",
                    "Consult OT engineer"
                ]
            }
        }

        return playbooks.get(event_type, {
            "action": "Investigate Alert",
            "steps": ["Review logs"]
        })

    # --------------------------------------------------
    # EXPLANATION ENGINE
    # --------------------------------------------------

    def explain_event(self, event_type):

        explanations = {
            "FAILED_LOGIN": "Multiple failed login attempts detected. Possible password attack.",
            "NETWORK_SCAN": "System scanning network. Possible reconnaissance.",
            "MALWARE_DETECTED": "Malicious activity detected.",
            "UNAUTHORIZED_CONFIG_CHANGE": "Unexpected configuration change detected.",
            "PLC_PROGRAM_CHANGE": "Industrial control logic modified."
        }

        return explanations.get(event_type, "Suspicious activity detected.")

    # --------------------------------------------------
    # SAFE GUIDANCE
    # --------------------------------------------------

    def generate_safe_guidance(self, asset, correlation):

        do = ["Check logs", "Verify with operator"]
        dont = []

        if asset.get("shutdown_risk") == "high":
            dont.append("Do NOT shut down system immediately")

        if asset.get("criticality") == "critical":
            dont.append("Do NOT act without OT engineer")

        if correlation:
            do.append("Treat as coordinated attack")

        return {"do": do, "dont": dont}

    # --------------------------------------------------
    # CORRELATION ENGINE
    # --------------------------------------------------

    def check_correlation(self, alert):

        self.alert_history.append(alert)

        if len(self.alert_history) > 20:
            self.alert_history.pop(0)

        asset_id = alert.get("asset_id")

        count = sum(
            1 for a in self.alert_history
            if a.get("event_type") == "FAILED_LOGIN"
            and a.get("asset_id") == asset_id
        )

        if count >= 5:
            return {
                "type": "BRUTE_FORCE",
                "description": "Multiple failed logins detected"
            }

        return None

    # --------------------------------------------------

    def process_alert(self, filepath):

        if filepath in self.processed_files:
            return None

        try:
            with open(filepath) as f:
                alert = json.load(f)
        except:
            return None

        correlation = self.check_correlation(alert)

        asset_id = alert.get("asset_id")

        asset = self.assets.get(asset_id, {
            "system": "Unknown Asset",
            "criticality": "medium",
            "shutdown_risk": "unknown"
        })

        risk = self.calculate_risk(alert, asset)

        if correlation:
            risk["level"] = "CRITICAL"
            risk["score"] = 4.0

        response = self.generate_response(alert.get("event_type"))

        explanation = self.explain_event(alert.get("event_type"))
        guidance = self.generate_safe_guidance(asset, correlation)

        # WARNING
        warning = None

        if asset.get("criticality") == "critical":
            warning = "!! Critical OT system - coordinate with engineers"

        if correlation:
            warning = "!! Correlated attack detected"

        # INCIDENT
        incident = {

            "id": f"INC-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.now().isoformat(),

            "event_type": alert.get("event_type"),
            "asset_id": asset_id,
            "asset_name": asset.get("system"),

            "severity": alert.get("severity"),

            "risk": risk,
            "risk_level": risk["level"],
            "risk_score": risk["score"],

            "criticality": asset.get("criticality"),
            "shutdown_risk": asset.get("shutdown_risk"),

            "response_action": response["action"],
            "response_steps": response["steps"],

            "warning": warning,
            "correlation": correlation["description"] if correlation else None,

            "explanation": explanation,
            "do_steps": guidance["do"],
            "dont_steps": guidance["dont"]
        }

        self.db.insert_incident(incident)

        self.processed_files.add(filepath)

        print("Processed:", filepath)

        return incident

    # --------------------------------------------------

    def scan_alerts(self):

        incidents = []

        if not os.path.exists(self.alerts_dir):
            return incidents

        for filename in os.listdir(self.alerts_dir):

            if filename.endswith(".json"):
                filepath = os.path.join(self.alerts_dir, filename)

                inc = self.process_alert(filepath)

                if inc:
                    incidents.append(inc)

        return incidents

    # --------------------------------------------------

    def get_incidents(self):

        return self.db.get_incidents()