"""
JSON Format Adapter - handles standard JSON alert format
Current format used by alert generator and direct API calls
"""

import json
from typing import Dict
from .base_adapter import BaseAdapter


class JSONAdapter(BaseAdapter):
    """
    Parses standard JSON alert format:
    {
        "event_type": "FAILED_LOGIN",
        "asset_id": "water_treatment_plc",
        "severity": "high",
        "timestamp": "2026-04-15T10:30:00Z",
        "details": { ... }
    }
    """

    @property
    def format_name(self) -> str:
        return "JSON (Standard IT-OT Format)"

    def can_parse(self, data) -> bool:
        """Check if data is JSON and contains required IT-OT fields"""
        if isinstance(data, dict):
            return True

        if isinstance(data, (str, bytes)):
            try:
                parsed = json.loads(data)
                return isinstance(parsed, dict)
            except Exception:
                return False

        return False

    def parse(self, data) -> Dict:
        """Parse JSON alert to internal format"""

        if isinstance(data, (str, bytes)):
            data = json.loads(data)

        normalized = {
            "event_type": data.get("event_type", "UNKNOWN"),
            "asset_id": data.get("asset_id", "unknown_asset"),
            "severity": data.get("severity", "medium").lower(),
            "timestamp": data.get("timestamp", ""),
            "source_format": self.format_name,
            "raw_data": data,
            "extra_fields": {
                "scenario": data.get("scenario"),
                "details": data.get("details"),
            },
        }

        return normalized
