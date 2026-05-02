import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from engine.database import IncidentDatabase


# ---------------------------------------------------------------------------
# CORRELATION PATTERNS
# Each pattern defines a multi-event-type attack chain that, when detected
# across the rolling alert history, overrides individual risk scores.
# ---------------------------------------------------------------------------

CORRELATION_PATTERNS = [
    # Evaluated in order — more specific (longer) chains first to avoid
    # shorter patterns shadowing more severe multi-stage detections.
    {
        "name": "COORDINATED_ATTACK",
        "description": "Recon → access → PLC modification chain detected — coordinated multi-stage attack",
        "required_events": ["NETWORK_SCAN", "FAILED_LOGIN", "PLC_PROGRAM_CHANGE"],
        "count_threshold": 1,
        "window_minutes": 60,
        "same_asset": False,
    },
    {
        "name": "RECON_TO_ACCESS",
        "description": "Network scan followed by login attempts — possible targeted intrusion",
        "required_events": ["NETWORK_SCAN", "FAILED_LOGIN"],
        "count_threshold": 1,
        "window_minutes": 30,
        "same_asset": False,
    },
    {
        "name": "BRUTE_FORCE",
        "description": "Multiple failed logins on the same asset — possible brute-force attack",
        "required_events": ["FAILED_LOGIN"],
        "count_threshold": 5,
        "window_minutes": 10,
        "same_asset": True,
    },
    {
        "name": "LATERAL_MOVEMENT",
        "description": "Failed logins across multiple different assets — possible lateral movement",
        "required_events": ["FAILED_LOGIN"],
        "count_threshold": 3,
        "window_minutes": 10,
        "same_asset": False,
        "different_assets": True,
    },
]


class DecisionEngine:

    MAX_ALERT_HISTORY = 200

    def __init__(self):

        self.alerts_dir = "data/alerts"
        self.context_file = "data/ot_context/ot_assets.json"
        self.zones_file = "data/config/network_zones.json"

        self.db = IncidentDatabase()
        self.assets = self.load_assets()
        self.network_segment_mapping = self.load_network_segment_mapping()

        self.processed_files = set()
        # Each entry: {"event_type": str, "asset_id": str, "received_at": datetime}
        self.alert_history: List[Dict] = []

    # --------------------------------------------------

    def load_assets(self) -> Dict:

        if not os.path.exists(self.context_file):
            return {}

        with open(self.context_file) as f:
            return json.load(f)

    def reload_assets(self) -> Dict:
        """Reload OT asset context from disk without restarting the engine."""

        self.assets = self.load_assets()
        self.network_segment_mapping = self.load_network_segment_mapping()
        return self.assets

    def load_network_segment_mapping(self) -> Dict:
        """Load network_segment -> zone/purdue mapping from config."""
        if not os.path.exists(self.zones_file):
            return {}
        try:
            with open(self.zones_file) as f:
                data = json.load(f)
            return data.get("network_segment_mapping", {})
        except Exception:
            return {}

    def _resolve_asset_zone(self, asset: Dict) -> Dict:
        """
        Resolve zone metadata from mapping with asset values as override.
        Prints warning if explicit asset zone values conflict with mapping.
        """
        segment = asset.get("network_segment")
        mapped = self.network_segment_mapping.get(segment, {})

        mapped_zone = mapped.get("zone_id")
        mapped_level = mapped.get("purdue_level")

        asset_zone = asset.get("zone_id")
        asset_level = asset.get("purdue_level")

        if mapped_zone and asset_zone and mapped_zone != asset_zone:
            print(f"[engine] Warning: zone mismatch for segment '{segment}': mapped={mapped_zone} asset={asset_zone}")
        if mapped_level and asset_level and mapped_level != asset_level:
            print(f"[engine] Warning: level mismatch for segment '{segment}': mapped={mapped_level} asset={asset_level}")

        return {
            "zone_id": asset_zone or mapped_zone or "unknown",
            "purdue_level": asset_level or mapped_level or "unknown",
        }

    # --------------------------------------------------
    # RISK SCORING

    def calculate_risk(self, alert: Dict, asset: Dict) -> Dict:

        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        criticality_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        severity_val = severity_map.get(alert.get("severity", "medium"), 2)
        criticality_val = criticality_map.get(asset.get("criticality", "medium"), 2)

        score = round((severity_val * 0.6) + (criticality_val * 0.4), 2)

        if score >= 3.5:
            level = "CRITICAL"
        elif score >= 2.5:
            level = "HIGH"
        elif score >= 1.5:
            level = "MEDIUM"
        else:
            level = "LOW"

        explanation = self._explain_risk_score(
            alert.get("severity", "medium"),
            severity_val,
            asset.get("criticality", "medium"),
            criticality_val,
            score,
            level,
            correlated=False,
        )

        return {"level": level, "score": score, "explanation": explanation}

    def _explain_risk_score(
        self,
        severity_label: str,
        severity_val: int,
        criticality_label: str,
        criticality_val: int,
        score: float,
        level: str,
        correlated: bool,
    ) -> str:

        base = (
            f"Score {score} ({level}): "
            f"Alert severity '{severity_label}' ({severity_val} × 0.6 = {round(severity_val * 0.6, 2)}) "
            f"+ Asset criticality '{criticality_label}' ({criticality_val} × 0.4 = {round(criticality_val * 0.4, 2)})"
        )

        if correlated:
            base += " → upgraded to CRITICAL (correlated attack pattern detected)"

        return base

    # --------------------------------------------------
    # PLAYBOOKS

    def generate_response(self, event_type: str) -> Dict:

        playbooks = {

            "FAILED_LOGIN": {
                "action": "Investigate Authentication",
                "steps": [
                    "Verify user legitimacy",
                    "Check login source IP",
                    "Review authentication logs",
                    "Coordinate with OT operator",
                ]
            },

            "MALWARE_DETECTED": {
                "action": "Malware Investigation",
                "steps": [
                    "Identify infected host",
                    "Run malware scan",
                    "Check lateral movement",
                    "Avoid immediate shutdown",
                ]
            },

            "NETWORK_SCAN": {
                "action": "Investigate Recon Activity",
                "steps": [
                    "Identify scanning host",
                    "Review firewall logs",
                    "Monitor network activity",
                ]
            },

            "UNAUTHORIZED_CONFIG_CHANGE": {
                "action": "Verify Configuration Change",
                "steps": [
                    "Check change logs",
                    "Verify with OT engineer",
                    "Confirm system stability",
                ]
            },

            "PLC_PROGRAM_CHANGE": {
                "action": "Investigate PLC Logic Change",
                "steps": [
                    "Verify authorization",
                    "Check PLC workstation",
                    "Consult OT engineer",
                ]
            },

            "SUSPICIOUS_PROCESS": {
                "action": "Investigate Suspicious Process",
                "steps": [
                    "Identify the process and parent process",
                    "Check if process is authorized",
                    "Review recent software installations",
                    "Do not kill critical control processes without OT approval",
                ]
            },

            "REMOTE_SESSION": {
                "action": "Verify Remote Access",
                "steps": [
                    "Confirm session is authorized",
                    "Check source IP and user account",
                    "Review remote access logs",
                    "Notify OT engineer if session is unscheduled",
                ]
            },

            "FIRMWARE_MODIFICATION": {
                "action": "Investigate Firmware Change",
                "steps": [
                    "Identify which device was modified",
                    "Verify change was authorized by engineering",
                    "Compare firmware hash against known-good version",
                    "Escalate immediately to OT engineer",
                ]
            },
        }

        result = playbooks.get(event_type)
        if result is None:
            self._unknown_event_warning(event_type)
            return {"action": "Investigate Alert", "steps": ["Review system and network logs", "Consult OT operator"]}
        return result

    def _unknown_event_warning(self, event_type: str) -> None:
        """Log a warning when an unrecognized event type is encountered."""
        print(f"[engine] Warning: no playbook for event_type '{event_type}' — using default")

    # --------------------------------------------------
    # EXPLANATION ENGINE

    def explain_event(self, event_type: str) -> str:

        explanations = {
            "FAILED_LOGIN": "Multiple failed login attempts detected. Possible password attack.",
            "NETWORK_SCAN": "A host is scanning the network. Possible reconnaissance before an attack.",
            "MALWARE_DETECTED": "Malicious software activity detected on an OT-connected host.",
            "UNAUTHORIZED_CONFIG_CHANGE": "Unexpected configuration change detected outside a change window.",
            "PLC_PROGRAM_CHANGE": "Industrial control (PLC) logic was modified — verify this was authorized.",
            "SUSPICIOUS_PROCESS": "An unexpected process is running on an OT-connected system.",
            "REMOTE_SESSION": "A remote access session was established to an OT asset.",
            "FIRMWARE_MODIFICATION": "Device firmware was modified — this can alter physical process behaviour.",
        }

        return explanations.get(event_type, "Suspicious activity detected on an OT-connected system.")

    # --------------------------------------------------
    # SAFE GUIDANCE

    def generate_safe_guidance(self, asset: Dict, correlation: Optional[Dict]) -> Dict:

        do = ["Check relevant logs", "Verify with on-site operator before acting"]
        dont = []

        shutdown_risk = asset.get("shutdown_risk", "")
        criticality = asset.get("criticality", "")

        if shutdown_risk == "high":
            dont.append("Do NOT shut down this system without OT engineer approval — high shutdown risk")

        if shutdown_risk == "medium":
            dont.append("Avoid unplanned shutdown — coordinate with operations team first")

        if criticality == "critical":
            dont.append("Do NOT take remediation action alone — OT engineer must be present")

        safety_impact = asset.get("safety_impact")
        if safety_impact:
            dont.append(f"Unsafe action may cause: {safety_impact}")

        if correlation:
            do.append("Treat as a coordinated multi-stage attack — escalate immediately")
            do.append("Preserve all logs and network captures as evidence")

        return {"do": do, "dont": dont}

    # --------------------------------------------------
    # CORRELATION ENGINE (time-windowed, multi-pattern)

    def _trim_history(self, window_minutes: int) -> List[Dict]:
        """Return only history entries within the given time window."""

        cutoff = datetime.now() - timedelta(minutes=window_minutes)
        return [
            a for a in self.alert_history
            if a.get("received_at", datetime.now()) >= cutoff
        ]

    def check_correlation(self, alert: Dict) -> Optional[Dict]:

        self.alert_history.append({
            "event_type": alert.get("event_type"),
            "asset_id": alert.get("asset_id"),
            "received_at": datetime.now(),
        })

        # Keep history bounded
        if len(self.alert_history) > self.MAX_ALERT_HISTORY:
            self.alert_history.pop(0)

        asset_id = alert.get("asset_id")

        for pattern in CORRELATION_PATTERNS:
            window = pattern["window_minutes"]
            recent = self._trim_history(window)

            required = pattern["required_events"]
            same_asset = pattern.get("same_asset", False)
            different_assets = pattern.get("different_assets", False)
            threshold = pattern["count_threshold"]

            if same_asset:
                # All required events must appear on the same asset
                relevant = [
                    a for a in recent
                    if a["event_type"] in required and a["asset_id"] == asset_id
                ]
                # For single-event patterns: count occurrences
                if len(required) == 1:
                    if len(relevant) >= threshold:
                        return {
                            "type": pattern["name"],
                            "description": pattern["description"],
                        }
                else:
                    # Multi-event chain: each required type must appear at least once
                    seen = {a["event_type"] for a in relevant}
                    if all(e in seen for e in required):
                        return {
                            "type": pattern["name"],
                            "description": pattern["description"],
                        }

            elif different_assets:
                # Events of the required type spread across multiple assets
                relevant = [
                    a for a in recent
                    if a["event_type"] in required
                ]
                affected = {a["asset_id"] for a in relevant}
                if len(affected) >= threshold:
                    return {
                        "type": pattern["name"],
                        "description": pattern["description"],
                    }

            else:
                # Events must appear anywhere in the network (any asset)
                seen = {a["event_type"] for a in recent}
                if all(e in seen for e in required):
                    return {
                        "type": pattern["name"],
                        "description": pattern["description"],
                    }

        return None

    # --------------------------------------------------
    # CORE PROCESSING

    def _build_incident(self, alert: Dict) -> Dict:
        """Shared processing logic used by both file-based and API-based ingestion."""

        correlation = self.check_correlation(alert)

        asset_id = alert.get("asset_id", "unknown")

        asset = self.assets.get(asset_id, {
            "system": "Unknown Asset",
            "criticality": "medium",
            "shutdown_risk": "unknown",
            "zone_id": "unknown",
            "purdue_level": "unknown",
        })

        risk = self.calculate_risk(alert, asset)

        if correlation:
            severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            criticality_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            s_val = severity_map.get(alert.get("severity", "medium"), 2)
            c_val = criticality_map.get(asset.get("criticality", "medium"), 2)
            base_score = round((s_val * 0.6) + (c_val * 0.4), 2)

            risk["level"] = "CRITICAL"
            risk["score"] = 4.0
            risk["explanation"] = self._explain_risk_score(
                alert.get("severity", "medium"), s_val,
                asset.get("criticality", "medium"), c_val,
                base_score, "CRITICAL", correlated=True,
            )

        response = self.generate_response(alert.get("event_type", ""))
        explanation = self.explain_event(alert.get("event_type", ""))
        guidance = self.generate_safe_guidance(asset, correlation)

        warning = None
        if asset.get("criticality") == "critical":
            warning = "!! Critical OT system — coordinate with OT engineers before acting"
        if correlation:
            warning = f"!! Correlated attack pattern: {correlation['type']}"

        zone_meta = self._resolve_asset_zone(asset)

        return {
            "id": f"INC-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.now().isoformat(),

            "event_type": alert.get("event_type"),
            "asset_id": asset_id,
            "asset_name": asset.get("system"),

            "severity": alert.get("severity"),

            "risk": risk,
            "risk_level": risk["level"],
            "risk_score": risk["score"],
            "risk_score_explanation": risk["explanation"],

            "criticality": asset.get("criticality"),
            "shutdown_risk": asset.get("shutdown_risk"),
            "zone_id": zone_meta["zone_id"],
            "purdue_level": zone_meta["purdue_level"],

            "response_action": response["action"],
            "response_steps": response["steps"],

            "warning": warning,
            "correlation": correlation["description"] if correlation else None,

            "explanation": explanation,
            "do_steps": guidance["do"],
            "dont_steps": guidance["dont"],

            "status": "open",
        }

    # --------------------------------------------------

    def process_alert(self, filepath: str) -> Optional[Dict]:
        """Process an alert from a JSON file on disk."""

        if filepath in self.processed_files:
            return None

        try:
            with open(filepath) as f:
                alert = json.load(f)
        except Exception:
            return None

        incident = self._build_incident(alert)
        self.db.insert_incident(incident)
        self.processed_files.add(filepath)

        print(f"[engine] Processed: {filepath} → {incident['id']} [{incident['risk_level']}]")

        return incident

    def process_alert_dict(self, alert: Dict) -> Optional[Dict]:
        """Process an alert delivered directly as a dictionary (e.g., from POST /api/alert)."""

        incident = self._build_incident(alert)
        self.db.insert_incident(incident)

        print(f"[engine] Ingested alert → {incident['id']} [{incident['risk_level']}]")

        return incident

    # --------------------------------------------------

    def scan_alerts(self) -> List[Dict]:

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

    def get_incidents(self) -> List[Dict]:

        return self.db.get_incidents()
