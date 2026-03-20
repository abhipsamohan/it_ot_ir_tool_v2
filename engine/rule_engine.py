"""
engine/rule_engine.py - Detection Engine
Human-readable, rule-based incident detection.
No machine learning - pure logic-based pattern matching.
"""

import json
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Default config paths (overridable for testing)
DEFAULT_RULES_FILE = "config/rules.json"
DEFAULT_ALERT_HISTORY_LIMIT = 1000
DEFAULT_BRUTE_FORCE_THRESHOLD = 5
DEFAULT_BRUTE_FORCE_WINDOW_MINUTES = 5

# Event types that indicate an exploitation or impact stage of an attack
EXPLOITATION_EVENT_TYPES = frozenset({
    "MALWARE_DETECTED",
    "PLC_PROGRAM_CHANGE",
    "FIRMWARE_MODIFICATION",
    "UNAUTHORIZED_CONFIG_CHANGE",
})


class RuleEngine:
    """
    Rule-based detection engine.
    Matches incoming alerts against configured rules and detects correlated attack patterns.
    """

    def __init__(
        self,
        rules_file: str = DEFAULT_RULES_FILE,
        alert_history_limit: int = DEFAULT_ALERT_HISTORY_LIMIT,
        brute_force_threshold: int = DEFAULT_BRUTE_FORCE_THRESHOLD,
        brute_force_window_minutes: int = DEFAULT_BRUTE_FORCE_WINDOW_MINUTES,
    ):
        self.rules_file = rules_file
        self.alert_history_limit = alert_history_limit
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window_minutes = brute_force_window_minutes

        self.rules = self._load_rules()
        self.alert_history: List[Dict] = []

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def _load_rules(self) -> List[Dict]:
        """Load rules from JSON config file."""
        if not os.path.exists(self.rules_file):
            logger.warning("Rules file not found: %s", self.rules_file)
            return []
        try:
            with open(self.rules_file) as f:
                data = json.load(f)
            return data.get("rules", [])
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load rules: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Alert history management
    # ------------------------------------------------------------------

    def add_to_history(self, alert: Dict) -> None:
        """Add alert to history, capped at alert_history_limit."""
        self.alert_history.append(alert)
        if len(self.alert_history) > self.alert_history_limit:
            self.alert_history.pop(0)

    def clear_history(self) -> None:
        """Clear all alert history (used in tests / resets)."""
        self.alert_history = []

    # ------------------------------------------------------------------
    # Rule matching
    # ------------------------------------------------------------------

    def match_rules(self, alert: Dict) -> List[Dict]:
        """
        Return all rules that match the given alert.

        A rule matches when:
        - The alert event_type equals the rule's event_type, AND
        - All rule conditions are satisfied.
        """
        matched = []
        event_type = alert.get("event_type", "")
        asset_criticality = alert.get("asset_criticality", "")

        for rule in self.rules:
            if rule.get("event_type") != event_type:
                continue

            conditions = rule.get("conditions", {})

            # Check asset_criticality condition
            if "asset_criticality" in conditions:
                required = conditions["asset_criticality"]
                if asset_criticality not in required:
                    continue

            # Condition 'any': true means always matches on event_type alone
            matched.append(rule)

        return matched

    # ------------------------------------------------------------------
    # Correlation / pattern detection
    # ------------------------------------------------------------------

    def detect_brute_force(self, alert: Dict) -> Optional[Dict]:
        """
        Detect brute force: N+ FAILED_LOGIN events for the same asset
        within the configured time window.
        """
        if alert.get("event_type") != "FAILED_LOGIN":
            return None

        asset_id = alert.get("asset_id")
        now = datetime.fromisoformat(alert.get("timestamp", datetime.now().isoformat()))
        window_start = now - timedelta(minutes=self.brute_force_window_minutes)

        count = 0
        for hist_alert in self.alert_history:
            if hist_alert.get("event_type") != "FAILED_LOGIN":
                continue
            if hist_alert.get("asset_id") != asset_id:
                continue
            try:
                ts = datetime.fromisoformat(hist_alert.get("timestamp", ""))
                if ts >= window_start:
                    count += 1
            except (ValueError, TypeError):
                continue

        # Include the current alert in the count
        count += 1

        if count >= self.brute_force_threshold:
            return {
                "type": "BRUTE_FORCE",
                "description": (
                    f"Brute force detected: {count} failed logins on {asset_id} "
                    f"within {self.brute_force_window_minutes} minutes"
                ),
                "count": count,
                "asset_id": asset_id,
            }
        return None

    def detect_attack_progression(self, alert: Dict) -> Optional[Dict]:
        """
        Detect multi-stage attack: NETWORK_SCAN followed by MALWARE_DETECTED
        or PLC_PROGRAM_CHANGE on the same or related assets.
        """
        event_type = alert.get("event_type")
        asset_id = alert.get("asset_id")

        # Look for a preceding NETWORK_SCAN that preceded exploitation
        if event_type in EXPLOITATION_EVENT_TYPES:
            recon_found = any(
                h.get("event_type") == "NETWORK_SCAN"
                for h in self.alert_history
            )
            if recon_found:
                return {
                    "type": "ATTACK_PROGRESSION",
                    "description": (
                        f"Multi-stage attack detected: Reconnaissance followed by "
                        f"{event_type} on {asset_id}"
                    ),
                    "stages": ["NETWORK_SCAN", event_type],
                    "asset_id": asset_id,
                }
        return None

    def check_correlations(self, alert: Dict) -> List[Dict]:
        """
        Check all correlation patterns and return a list of detected patterns.
        """
        patterns = []

        brute_force = self.detect_brute_force(alert)
        if brute_force:
            patterns.append(brute_force)

        progression = self.detect_attack_progression(alert)
        if progression:
            patterns.append(progression)

        return patterns

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def process_alert(self, alert: Dict) -> Dict:
        """
        Process a single alert:
        1. Add to history
        2. Match rules
        3. Check correlations
        4. Return enriched result

        Returns a dict with keys: matched_rules, correlations, severity_multiplier
        """
        # Add to history before correlation detection
        self.add_to_history(alert)

        matched_rules = self.match_rules(alert)
        correlations = self.check_correlations(alert)

        # Calculate effective severity multiplier (max of all matched rules)
        severity_multiplier = 1.0
        for rule in matched_rules:
            multiplier = rule.get("severity_multiplier", 1.0)
            if multiplier > severity_multiplier:
                severity_multiplier = multiplier

        # If a correlation was found, apply an additional boost
        if correlations:
            severity_multiplier = max(severity_multiplier, 2.0)

        return {
            "matched_rules": matched_rules,
            "correlations": correlations,
            "severity_multiplier": severity_multiplier,
        }
