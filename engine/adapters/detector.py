"""
Format Detection Engine
Automatically determines alert format and routes to appropriate adapter
"""

from typing import Dict, List, Tuple
from .base_adapter import BaseAdapter
from .json_adapter import JSONAdapter
from .cef_adapter import CEFAdapter
from .rest_webhook import RESTAdapter


class FormatDetector:
    """
    Detects incoming alert format and routes to appropriate adapter
    Tries adapters in priority order
    """

    def __init__(self):
        # Priority order (most specific first)
        self.adapters: List[BaseAdapter] = [
            CEFAdapter(),    # CEF is most specific (starts with "CEF:")
            RESTAdapter(),   # SOAR webhooks (has alert/event/incident keys)
            JSONAdapter(),   # Generic JSON (most lenient)
        ]

    def detect_and_parse(self, data) -> Tuple[Dict, str]:
        """
        Detect format and parse alert

        Returns:
            (normalized_alert: Dict, adapter_used: str)

        Raises:
            ValueError: If no adapter can parse the data
        """

        for adapter in self.adapters:
            try:
                if adapter.can_parse(data):
                    parsed = adapter.parse(data)

                    # Validate
                    is_valid, error_msg = adapter.validate(parsed)
                    if not is_valid:
                        continue

                    return parsed, adapter.format_name

            except Exception:
                # Try next adapter
                continue

        raise ValueError("No adapter could parse the incoming data")

    def get_adapter_for_format(self, format_name: str) -> BaseAdapter:
        """Get specific adapter by format name"""
        for adapter in self.adapters:
            if adapter.format_name == format_name:
                return adapter
        raise ValueError(f"Unknown format: {format_name}")
