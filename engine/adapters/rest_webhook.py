"""
REST/Webhook Format Adapter
Parses webhooks from SOAR platforms and custom integrations:
- Splunk Phantom
- CrowdStrike Falcon
- Microsoft Defender
- Demisto/Cortex XSOAR
- Custom webhook payloads

Expected SOAR webhook format:
{
    "alert": {
        "name": "Failed Login Attempt",
        "severity": "high",
        "source": "Active Directory",
        "asset": "domain_controller"
    },
    "context": { ... }
}
"""

import json
from typing import Dict
from .base_adapter import BaseAdapter


class RESTAdapter(BaseAdapter):
    """
    Parses REST/webhook format alerts from SOAR platforms
    Auto-detects and normalizes various SOAR formats
    """

    @property
    def format_name(self) -> str:
        return "REST/Webhook (SOAR)"

    def can_parse(self, data) -> bool:
        """Check if data is REST/webhook JSON format"""

        if isinstance(data, dict):
            # Check for common SOAR fields
            return any(key in data for key in ["alert", "event", "incident", "data"])

        if isinstance(data, (str, bytes)):
            try:
                parsed = json.loads(data)
                if isinstance(parsed, dict):
                    return any(key in parsed for key in ["alert", "event", "incident", "data"])
            except Exception:
                return False

        return False

    def parse(self, data) -> Dict:
        """Parse REST/webhook alert"""

        if isinstance(data, (str, bytes)):
            data = json.loads(data)

        # Normalize different SOAR formats
        alert_obj = (
            data.get("alert")
            or data.get("event")
            or data.get("incident")
            or data.get("data")
            or data
        )

        # Extract fields with fallback options
        raw_name = alert_obj.get("event_type") or alert_obj.get("name", "")
        event_type = self._normalize_event_type(raw_name) or "UNKNOWN_EVENT"

        asset_id = (
            alert_obj.get("asset")
            or alert_obj.get("source_asset")
            or alert_obj.get("affected_resource")
            or "unknown_asset"
        )

        severity = (
            alert_obj.get("severity") or alert_obj.get("level") or "medium"
        ).lower()

        normalized = {
            "event_type": event_type,
            "asset_id": asset_id,
            "severity": severity,
            "timestamp": alert_obj.get("timestamp", ""),
            "source_format": self.format_name,
            "raw_data": data,
            "extra_fields": {
                "soar_context": data.get("context"),
                "indicators": alert_obj.get("indicators"),
                "source_system": alert_obj.get("source"),
            },
        }

        return normalized

    # ------------------------------------------------------------------

    _EVENT_TYPE_MAP = {
        "FAILED_AUTHENTICATION": "FAILED_LOGIN",
        "FAILED_LOGIN": "FAILED_LOGIN",
        "UNAUTHORIZED_ACCESS": "FAILED_LOGIN",
        "NETWORK_SCAN": "NETWORK_SCAN",
        "PORT_SCAN": "NETWORK_SCAN",
        "MALWARE": "MALWARE_DETECTED",
        "MALWARE_DETECTION": "MALWARE_DETECTED",
        "MALWARE_DETECTED": "MALWARE_DETECTED",
        "CONFIGURATION_CHANGE": "UNAUTHORIZED_CONFIG_CHANGE",
        "FIRMWARE_UPDATE": "FIRMWARE_MODIFICATION",
    }

    def _normalize_event_type(self, name: str) -> str:
        """Map raw alert name to canonical event type used across adapters."""
        key = name.upper().replace(" ", "_")
        return self._EVENT_TYPE_MAP.get(key, key)
