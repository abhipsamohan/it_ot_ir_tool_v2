"""
Base adapter class defining interface for all format converters
Each adapter converts different alert formats to normalized internal format
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional


class BaseAdapter(ABC):
    """
    Abstract base class for alert format adapters

    Responsibilities:
    1. Detect if incoming data matches this format
    2. Parse incoming data into internal normalized format
    3. Validate required fields
    4. Provide human-readable format name
    """

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Return human-readable format name (e.g., 'Splunk JSON', 'CEF')"""
        pass

    @abstractmethod
    def can_parse(self, data) -> bool:
        """
        Determine if this adapter can parse the incoming data

        Args:
            data: Could be string, dict, bytes

        Returns:
            True if this adapter recognizes the format
        """
        pass

    @abstractmethod
    def parse(self, data) -> Dict:
        """
        Parse incoming alert and convert to internal normalized format

        Args:
            data: Raw alert data

        Returns:
            Normalized dict with keys:
            {
                "event_type": str,
                "asset_id": str,
                "severity": str (low/medium/high/critical),
                "timestamp": str (ISO format),
                "source_format": str (which adapter parsed this),
                "raw_data": dict (original for audit trail),
                "extra_fields": dict (additional context)
            }
        """
        pass

    def get_example(self) -> str:
        """Return a short example string for this adapter format."""
        return "See docs/FORMAT_ADAPTERS.md"

    def validate(self, parsed: Dict) -> tuple:
        """
        Validate parsed alert has required fields

        Returns:
            (is_valid: bool, error_message: str or None)
        """
        required = ["event_type", "asset_id", "severity"]
        missing = [f for f in required if not parsed.get(f)]

        if missing:
            return False, f"Missing required fields: {missing}"

        # Validate severity is one of allowed values
        if parsed["severity"] not in ["low", "medium", "high", "critical"]:
            return False, f"Invalid severity: {parsed['severity']}"

        return True, None
