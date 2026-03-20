"""
tests/test_rule_engine.py - Unit tests for the RuleEngine.
5 tests covering rule matching, pattern detection, and alert history management.
"""

import pytest
import os
import sys
import json
import tempfile
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.rule_engine import RuleEngine


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def rules_file(tmp_path):
    """Create a temporary rules.json for testing."""
    rules = {
        "rules": [
            {
                "id": "RULE-001",
                "name": "Brute Force Attack",
                "event_type": "FAILED_LOGIN",
                "conditions": {"min_count": 5, "window_minutes": 5},
                "severity_multiplier": 1.5,
                "response_actions": ["block_ip", "alert_team"],
                "explanation": "Multiple failed logins.",
                "do_steps": ["Block IP"],
                "dont_steps": ["Do NOT shut down PLC"],
            },
            {
                "id": "RULE-002",
                "name": "Unauthorized PLC Modification",
                "event_type": "PLC_PROGRAM_CHANGE",
                "conditions": {"asset_criticality": ["critical", "high"]},
                "severity_multiplier": 2.0,
                "response_actions": ["alert_team", "plc_shutdown"],
                "explanation": "Unauthorized PLC change.",
                "do_steps": ["Alert OT engineer"],
                "dont_steps": ["Do NOT revert without assessment"],
            },
            {
                "id": "RULE-003",
                "name": "Malware Detected",
                "event_type": "MALWARE_DETECTED",
                "conditions": {"any": True},
                "severity_multiplier": 1.8,
                "response_actions": ["alert_team", "take_snapshot"],
                "explanation": "Malware detected.",
                "do_steps": ["Take snapshot"],
                "dont_steps": [],
            },
            {
                "id": "RULE-004",
                "name": "Network Scan",
                "event_type": "NETWORK_SCAN",
                "conditions": {"any": True},
                "severity_multiplier": 1.2,
                "response_actions": ["block_ip", "alert_team"],
                "explanation": "Network scan detected.",
                "do_steps": ["Block IP"],
                "dont_steps": [],
            },
        ]
    }
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(rules))
    return str(path)


@pytest.fixture
def engine(rules_file):
    """Create a RuleEngine with test rules and small history limit."""
    return RuleEngine(
        rules_file=rules_file,
        alert_history_limit=100,
        brute_force_threshold=5,
        brute_force_window_minutes=5,
    )


def _make_alert(event_type, asset_id="plc_main", severity="medium", asset_criticality="critical", minutes_ago=0):
    ts = (datetime.now() - timedelta(minutes=minutes_ago)).isoformat()
    return {
        "event_type": event_type,
        "asset_id": asset_id,
        "severity": severity,
        "asset_criticality": asset_criticality,
        "timestamp": ts,
    }


# ------------------------------------------------------------------
# Test 1: Rule matching - FAILED_LOGIN matches brute force rule
# ------------------------------------------------------------------

def test_rule_matching_failed_login(engine):
    alert = _make_alert("FAILED_LOGIN")
    matched = engine.match_rules(alert)
    assert len(matched) == 1
    assert matched[0]["id"] == "RULE-001"
    assert matched[0]["event_type"] == "FAILED_LOGIN"


# ------------------------------------------------------------------
# Test 2: Rule matching - event_type with asset_criticality condition
# ------------------------------------------------------------------

def test_rule_matching_plc_change_critical(engine):
    alert = _make_alert("PLC_PROGRAM_CHANGE", asset_criticality="critical")
    matched = engine.match_rules(alert)
    assert len(matched) == 1
    assert matched[0]["id"] == "RULE-002"


def test_rule_matching_plc_change_low_criticality(engine):
    """PLC_PROGRAM_CHANGE on a low-criticality asset should NOT match RULE-002."""
    alert = _make_alert("PLC_PROGRAM_CHANGE", asset_criticality="low")
    matched = engine.match_rules(alert)
    assert len(matched) == 0


def test_rule_matching_unknown_event(engine):
    """Unknown event_type should match no rules."""
    alert = _make_alert("UNKNOWN_EVENT")
    matched = engine.match_rules(alert)
    assert len(matched) == 0


# ------------------------------------------------------------------
# Test 3: Brute force detection
# ------------------------------------------------------------------

def test_brute_force_detection_triggers(engine):
    """5 FAILED_LOGIN alerts on same asset within window should trigger brute force."""
    asset_id = "pump_controller_1"
    # Add 4 alerts to history
    for i in range(4):
        alert = _make_alert("FAILED_LOGIN", asset_id=asset_id, minutes_ago=i)
        engine.add_to_history(alert)

    # 5th alert (current)
    current_alert = _make_alert("FAILED_LOGIN", asset_id=asset_id)
    result = engine.detect_brute_force(current_alert)

    assert result is not None
    assert result["type"] == "BRUTE_FORCE"
    assert result["asset_id"] == asset_id
    assert result["count"] >= 5


def test_brute_force_not_triggered_below_threshold(engine):
    """Fewer than 5 FAILED_LOGIN alerts should NOT trigger brute force."""
    asset_id = "pump_controller_1"
    # Add 3 alerts to history
    for i in range(3):
        alert = _make_alert("FAILED_LOGIN", asset_id=asset_id, minutes_ago=i)
        engine.add_to_history(alert)

    current_alert = _make_alert("FAILED_LOGIN", asset_id=asset_id)
    result = engine.detect_brute_force(current_alert)
    assert result is None


def test_brute_force_different_assets_not_triggered(engine):
    """FAILED_LOGIN on different assets should not trigger brute force for target asset."""
    # Add 4 failed logins on a different asset
    for i in range(4):
        alert = _make_alert("FAILED_LOGIN", asset_id="other_asset", minutes_ago=i)
        engine.add_to_history(alert)

    # Current alert on a different asset
    current_alert = _make_alert("FAILED_LOGIN", asset_id="plc_main")
    result = engine.detect_brute_force(current_alert)
    assert result is None


# ------------------------------------------------------------------
# Test 4: Attack progression detection
# ------------------------------------------------------------------

def test_attack_progression_detected(engine):
    """NETWORK_SCAN in history + PLC_PROGRAM_CHANGE should trigger progression."""
    recon_alert = _make_alert("NETWORK_SCAN", asset_id="network_switch_core")
    engine.add_to_history(recon_alert)

    exploit_alert = _make_alert("PLC_PROGRAM_CHANGE", asset_id="plc_main")
    result = engine.detect_attack_progression(exploit_alert)

    assert result is not None
    assert result["type"] == "ATTACK_PROGRESSION"
    assert "NETWORK_SCAN" in result["stages"]
    assert "PLC_PROGRAM_CHANGE" in result["stages"]


def test_attack_progression_not_detected_without_recon(engine):
    """PLC_PROGRAM_CHANGE without preceding NETWORK_SCAN should not trigger progression."""
    engine.clear_history()
    alert = _make_alert("PLC_PROGRAM_CHANGE")
    result = engine.detect_attack_progression(alert)
    assert result is None


# ------------------------------------------------------------------
# Test 5: Alert history management
# ------------------------------------------------------------------

def test_alert_history_cap(engine):
    """History should be capped at alert_history_limit."""
    engine.alert_history_limit = 10
    engine.clear_history()

    for i in range(15):
        engine.add_to_history(_make_alert("FAILED_LOGIN", asset_id=f"asset_{i}"))

    assert len(engine.alert_history) == 10


def test_alert_history_clear(engine):
    """clear_history should empty the history list."""
    engine.add_to_history(_make_alert("FAILED_LOGIN"))
    engine.add_to_history(_make_alert("NETWORK_SCAN"))
    engine.clear_history()
    assert len(engine.alert_history) == 0


def test_process_alert_returns_matched_rules(engine):
    """process_alert should return matched rules and correlations in one call."""
    engine.clear_history()
    alert = _make_alert("MALWARE_DETECTED")
    result = engine.process_alert(alert)

    assert "matched_rules" in result
    assert "correlations" in result
    assert "severity_multiplier" in result
    assert len(result["matched_rules"]) == 1
    assert result["matched_rules"][0]["id"] == "RULE-003"
    assert result["severity_multiplier"] == pytest.approx(1.8)


def test_severity_multiplier_boosted_on_correlation(engine):
    """Correlation should boost severity_multiplier to at least 2.0."""
    engine.clear_history()
    # Prime history with recon
    engine.add_to_history(_make_alert("NETWORK_SCAN"))
    # 4 failed logins to set up brute force
    for _ in range(4):
        engine.add_to_history(_make_alert("FAILED_LOGIN", asset_id="plc_main"))

    # 5th failed login triggers brute force correlation
    alert = _make_alert("FAILED_LOGIN", asset_id="plc_main")
    result = engine.process_alert(alert)

    assert result["severity_multiplier"] >= 2.0
    assert len(result["correlations"]) >= 1
