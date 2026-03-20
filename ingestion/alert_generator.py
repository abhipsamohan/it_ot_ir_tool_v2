"""
ingestion/alert_generator.py - Test Alert Generator
Generates realistic test alerts for multiple attack scenarios.
"""

import json
import os
import time
from datetime import datetime
from typing import Dict, List


DEFAULT_ALERTS_DIR = "data/alerts"

# Predefined event templates
BRUTE_FORCE_EVENTS = [
    {
        "event_type": "FAILED_LOGIN",
        "asset_id": "plc_main",
        "severity": "medium",
        "details": {"source_ip": "192.168.1.50", "username": "admin"},
    },
    {
        "event_type": "FAILED_LOGIN",
        "asset_id": "plc_main",
        "severity": "medium",
        "details": {"source_ip": "192.168.1.50", "username": "admin"},
    },
    {
        "event_type": "FAILED_LOGIN",
        "asset_id": "plc_main",
        "severity": "medium",
        "details": {"source_ip": "192.168.1.50", "username": "admin"},
    },
    {
        "event_type": "FAILED_LOGIN",
        "asset_id": "plc_main",
        "severity": "medium",
        "details": {"source_ip": "192.168.1.50", "username": "admin"},
    },
    {
        "event_type": "FAILED_LOGIN",
        "asset_id": "plc_main",
        "severity": "high",
        "details": {"source_ip": "192.168.1.50", "username": "admin"},
    },
]

ATTACK_PROGRESSION_EVENTS = [
    {
        "event_type": "NETWORK_SCAN",
        "asset_id": "network_switch_core",
        "severity": "low",
        "details": {"source_ip": "192.168.1.99", "ports_scanned": "1-1024"},
    },
    {
        "event_type": "MALWARE_DETECTED",
        "asset_id": "windows_server",
        "severity": "high",
        "details": {"malware_name": "Industroyer-variant", "process": "svchost.exe"},
    },
    {
        "event_type": "PLC_PROGRAM_CHANGE",
        "asset_id": "plc_main",
        "severity": "critical",
        "details": {"changed_by": "UNKNOWN", "change_type": "logic_modification"},
    },
]

PLC_MODIFICATION_EVENTS = [
    {
        "event_type": "PLC_PROGRAM_CHANGE",
        "asset_id": "plc_main",
        "severity": "critical",
        "details": {"changed_by": "UNKNOWN", "change_type": "ladder_logic"},
    }
]


class AlertGenerator:
    """
    Generates test alert files for various attack scenarios.
    Writes JSON alert files to the configured alerts directory.
    """

    def __init__(self, alerts_dir: str = DEFAULT_ALERTS_DIR):
        self.alerts_dir = alerts_dir
        os.makedirs(alerts_dir, exist_ok=True)

    def _write_alert(self, alert: Dict) -> str:
        """Write a single alert to a JSON file. Returns the file path."""
        if "timestamp" not in alert:
            alert["timestamp"] = datetime.now().isoformat()

        filename = f"alert_{int(time.time() * 1000)}.json"
        filepath = os.path.join(self.alerts_dir, filename)

        with open(filepath, "w") as f:
            json.dump(alert, f, indent=2)

        return filepath

    def _write_alerts(self, events: List[Dict]) -> List[str]:
        """Write multiple alerts, returning list of file paths."""
        paths = []
        for event in events:
            path = self._write_alert(dict(event))
            paths.append(path)
            time.sleep(0.01)  # Ensure unique timestamps
        return paths

    def generate_brute_force_scenario(self) -> List[str]:
        """
        Generate 5 failed login alerts on plc_main to trigger brute force detection.
        Returns list of file paths created.
        """
        print("[AlertGenerator] Generating brute force scenario (5 FAILED_LOGIN alerts)...")
        return self._write_alerts(BRUTE_FORCE_EVENTS)

    def generate_plc_modification_scenario(self) -> List[str]:
        """
        Generate a single critical PLC program change alert.
        Returns list of file paths created.
        """
        print("[AlertGenerator] Generating PLC modification scenario...")
        return self._write_alerts(PLC_MODIFICATION_EVENTS)

    def generate_attack_progression_scenario(self) -> List[str]:
        """
        Generate a 3-stage attack progression:
        1. Network scan (recon)
        2. Malware detection (exploit)
        3. PLC program change (impact)
        Returns list of file paths created.
        """
        print("[AlertGenerator] Generating attack progression scenario (3-stage)...")
        return self._write_alerts(ATTACK_PROGRESSION_EVENTS)

    def generate_custom_alert(
        self,
        event_type: str,
        asset_id: str,
        severity: str = "medium",
        details: Dict = None,
    ) -> str:
        """
        Generate a single custom alert with the given parameters.
        Returns the file path created.
        """
        alert = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "asset_id": asset_id,
            "severity": severity,
            "details": details or {},
        }
        return self._write_alert(alert)

    def clear_alerts(self) -> int:
        """Remove all alert JSON files from the alerts directory. Returns count removed."""
        count = 0
        if not os.path.exists(self.alerts_dir):
            return count
        for filename in os.listdir(self.alerts_dir):
            if filename.endswith(".json"):
                os.remove(os.path.join(self.alerts_dir, filename))
                count += 1
        return count
