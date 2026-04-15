"""
CEF and Syslog Format Adapter
Parses Common Event Format (CEF) alerts from enterprise security tools:
- Splunk
- Arista
- Palo Alto Networks
- Fortinet FortiGate
- Checkpoint

CEF Format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|cs1=value...
Syslog Format: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE

Example Splunk CEF:
CEF:0|Splunk|IDS|1.0|123456|Failed Authentication|5|src=192.168.1.100 dst=192.168.1.50 msg=Failed login attempt
"""

import re
from datetime import datetime
from typing import Dict
from .base_adapter import BaseAdapter


class CEFAdapter(BaseAdapter):

    @property
    def format_name(self) -> str:
        return "CEF/Syslog (Enterprise)"

    def can_parse(self, data) -> bool:
        """Check if data is CEF or Syslog format"""
        if not isinstance(data, (str, bytes)):
            return False

        data_str = data.decode("utf-8") if isinstance(data, bytes) else data

        # CEF format starts with "CEF:"
        if data_str.strip().startswith("CEF:"):
            return True

        # Syslog format: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
        if re.match(r"<\d+>", data_str.strip()):
            return True

        return False

    def parse(self, data) -> Dict:
        """Parse CEF/Syslog to internal format"""

        data_str = data.decode("utf-8") if isinstance(data, bytes) else data

        if data_str.strip().startswith("CEF:"):
            return self._parse_cef(data_str)
        else:
            return self._parse_syslog(data_str)

    def _parse_cef(self, cef_string: str) -> Dict:
        """Parse CEF format"""

        # Example: CEF:0|Splunk|IDS|1.0|123456|Failed Authentication|5|src=192.168.1.100 dst=192.168.1.50

        parts = cef_string.split("|", 7)  # Split header (7 parts) + extensions

        if len(parts) < 7:
            raise ValueError("Invalid CEF format")

        # CEF header: Version|Vendor|Product|Version|SignatureID|Name|Severity
        cef_severity = int(parts[6]) if parts[6].strip().isdigit() else 3

        # Parse extensions (key=value pairs)
        extensions = {}
        if len(parts) > 7:
            ext_string = parts[7]
            # Simple key=value parser
            for match in re.finditer(r"(\w+)=([^\s]+)", ext_string):
                extensions[match.group(1)] = match.group(2)

        # Map CEF severity (0-10) to IT-OT severity
        severity_map = {
            0: "low", 1: "low", 2: "low", 3: "low", 4: "low",
            5: "medium", 6: "medium", 7: "high", 8: "high",
            9: "critical", 10: "critical",
        }

        # Try to extract asset from source IP
        asset_id = extensions.get("src", "unknown_asset")

        # Extract event type from alert name
        event_name = parts[5].strip().upper().replace(" ", "_")

        # Map common alert names to our event types
        event_type_mapping = {
            "FAILED_AUTHENTICATION": "FAILED_LOGIN",
            "FAILED_LOGIN": "FAILED_LOGIN",
            "UNAUTHORIZED_ACCESS": "FAILED_LOGIN",
            "NETWORK_SCAN": "NETWORK_SCAN",
            "PORT_SCAN": "NETWORK_SCAN",
            "MALWARE": "MALWARE_DETECTED",
            "MALWARE_DETECTED": "MALWARE_DETECTED",
            "CONFIGURATION_CHANGE": "UNAUTHORIZED_CONFIG_CHANGE",
            "FIRMWARE_UPDATE": "FIRMWARE_MODIFICATION",
        }

        event_type = event_type_mapping.get(event_name, event_name)

        normalized = {
            "event_type": event_type,
            "asset_id": asset_id,
            "severity": severity_map.get(cef_severity, "medium"),
            "timestamp": datetime.now().isoformat(),
            "source_format": self.format_name,
            "raw_data": {"cef_extensions": extensions},
            "extra_fields": {
                "vendor": parts[1],
                "product": parts[2],
                "alert_name": parts[5].strip(),
            },
        }

        return normalized

    def _parse_syslog(self, syslog_string: str) -> Dict:
        """Parse Syslog format"""

        # Example: <134>Feb 19 20:15:42 firewall01 %FIREWALL-3-AUTH_FAILED: Failed login from 192.168.1.100
        # BSD syslog timestamp is "MMM DD HH:MM:SS" (three tokens), so we match it explicitly.

        match = re.match(r"<(\d+)>(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+(.+?):\s*(.+)", syslog_string)

        if not match:
            raise ValueError("Invalid Syslog format")

        priority = int(match.group(1))
        hostname = match.group(3)
        tag = match.group(4)
        message = match.group(5)

        # Extract severity from priority
        # Priority = Facility*8 + Severity
        severity_val = priority % 8
        severity_map = {
            0: "critical", 1: "critical", 2: "critical", 3: "high",
            4: "high", 5: "medium", 6: "low", 7: "low",
        }

        normalized = {
            "event_type": self._extract_event_from_syslog(message, tag),
            "asset_id": hostname,
            "severity": severity_map.get(severity_val, "medium"),
            "timestamp": datetime.now().isoformat(),
            "source_format": self.format_name,
            "raw_data": {"syslog_tag": tag, "syslog_message": message},
            "extra_fields": {
                "hostname": hostname,
                "tag": tag,
            },
        }

        return normalized

    def _extract_event_from_syslog(self, message: str, tag: str) -> str:
        """Extract event type from Syslog message"""

        message_upper = message.upper()

        if "AUTH" in message_upper or "LOGIN" in message_upper:
            return "FAILED_LOGIN"
        elif "SCAN" in message_upper or "PROBE" in message_upper:
            return "NETWORK_SCAN"
        elif "MALWARE" in message_upper or "VIRUS" in message_upper:
            return "MALWARE_DETECTED"
        elif "CONFIG" in message_upper or "CHANGE" in message_upper:
            return "UNAUTHORIZED_CONFIG_CHANGE"
        else:
            return "UNKNOWN_EVENT"
