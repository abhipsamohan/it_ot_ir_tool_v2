"""
tests/test_safe_response_engine.py - Unit tests for the SafeResponseEngine.
7 tests covering safe action execution, approval workflow, and categorization.
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.safe_response_engine import SafeResponseEngine, SAFE_ACTIONS, DANGEROUS_ACTIONS


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def engine():
    return SafeResponseEngine()


INCIDENT_ID = "INC-TEST-001"
CONTEXT = {"asset_id": "plc_main", "source_ip": "192.168.1.50"}


# ------------------------------------------------------------------
# Test 1: Action classification
# ------------------------------------------------------------------

def test_classify_safe_actions(engine):
    for action in SAFE_ACTIONS:
        assert engine.classify_action(action) == "safe", f"{action} should be safe"


def test_classify_dangerous_actions(engine):
    for action in DANGEROUS_ACTIONS:
        assert engine.classify_action(action) == "dangerous", f"{action} should be dangerous"


def test_classify_unknown_action(engine):
    assert engine.classify_action("fly_to_moon") == "unknown"


# ------------------------------------------------------------------
# Test 2: Categorize action list
# ------------------------------------------------------------------

def test_categorize_actions_mixed(engine):
    actions = ["block_ip", "alert_team", "plc_shutdown", "isolate_network"]
    safe, dangerous = engine.categorize_actions(actions)
    assert "block_ip" in safe
    assert "alert_team" in safe
    assert "plc_shutdown" in dangerous
    assert "isolate_network" in dangerous


def test_categorize_actions_all_safe(engine):
    actions = list(SAFE_ACTIONS)
    safe, dangerous = engine.categorize_actions(actions)
    assert len(safe) == len(SAFE_ACTIONS)
    assert len(dangerous) == 0


def test_categorize_actions_all_dangerous(engine):
    actions = list(DANGEROUS_ACTIONS)
    safe, dangerous = engine.categorize_actions(actions)
    assert len(safe) == 0
    assert len(dangerous) == len(DANGEROUS_ACTIONS)


# ------------------------------------------------------------------
# Test 3: Safe action execution
# ------------------------------------------------------------------

def test_execute_safe_action_returns_executed_status(engine):
    result = engine.execute_safe_action("block_ip", CONTEXT)
    assert result["action"] == "block_ip"
    assert result["status"] == "executed"
    assert result["requires_approval"] is False
    assert "timestamp" in result


def test_execute_safe_action_alert_team(engine):
    result = engine.execute_safe_action("alert_team", CONTEXT)
    assert result["action"] == "alert_team"
    assert result["status"] == "executed"


# ------------------------------------------------------------------
# Test 4: Dangerous action approval workflow
# ------------------------------------------------------------------

def test_queue_approval_creates_pending_record(engine):
    record = engine.queue_approval("plc_shutdown", CONTEXT, INCIDENT_ID)
    assert record["action"] == "plc_shutdown"
    assert record["status"] == "pending"
    assert record["incident_id"] == INCIDENT_ID
    assert record["requires_approval"] is True
    assert record["approval_id"].startswith("APPR-")


def test_approve_action_updates_status(engine):
    record = engine.queue_approval("isolate_network", CONTEXT, INCIDENT_ID)
    approval_id = record["approval_id"]
    approved = engine.approve_action(approval_id, approver="plant_manager")
    assert approved["status"] == "approved"
    assert approved["approver"] == "plant_manager"
    assert approved["approved_at"] is not None


def test_deny_action_updates_status(engine):
    record = engine.queue_approval("disconnect_power", CONTEXT, INCIDENT_ID)
    approval_id = record["approval_id"]
    denied = engine.deny_action(approval_id, reason="Not necessary", denier="operator")
    assert denied["status"] == "denied"
    assert denied["denial_reason"] == "Not necessary"
    assert denied["denier"] == "operator"


def test_approve_nonexistent_returns_error(engine):
    result = engine.approve_action("APPR-DOES-NOT-EXIST")
    assert "error" in result


def test_deny_nonexistent_returns_error(engine):
    result = engine.deny_action("APPR-DOES-NOT-EXIST")
    assert "error" in result


def test_double_approve_returns_error(engine):
    record = engine.queue_approval("system_restart", CONTEXT, INCIDENT_ID)
    approval_id = record["approval_id"]
    engine.approve_action(approval_id)
    # Second approval attempt should fail
    result = engine.approve_action(approval_id)
    assert "error" in result


# ------------------------------------------------------------------
# Test 5: process_actions orchestrates correctly
# ------------------------------------------------------------------

def test_process_actions_executes_safe_queues_dangerous(engine):
    actions = ["block_ip", "alert_team", "plc_shutdown"]
    result = engine.process_actions(actions, INCIDENT_ID, CONTEXT)

    assert result["safe_count"] == 2
    assert result["approval_count"] == 1
    assert len(result["auto_executed"]) == 2
    assert len(result["pending_approvals"]) == 1

    executed_actions = [r["action"] for r in result["auto_executed"]]
    assert "block_ip" in executed_actions
    assert "alert_team" in executed_actions

    pending_actions = [r["action"] for r in result["pending_approvals"]]
    assert "plc_shutdown" in pending_actions


def test_process_actions_all_safe(engine):
    actions = ["block_ip", "enable_logging"]
    result = engine.process_actions(actions, INCIDENT_ID, CONTEXT)
    assert result["safe_count"] == 2
    assert result["approval_count"] == 0


def test_process_actions_all_dangerous(engine):
    actions = ["plc_shutdown", "isolate_network"]
    result = engine.process_actions(actions, INCIDENT_ID, CONTEXT)
    assert result["safe_count"] == 0
    assert result["approval_count"] == 2


# ------------------------------------------------------------------
# Test 6: Get pending approvals
# ------------------------------------------------------------------

def test_get_pending_approvals(engine):
    engine.queue_approval("plc_shutdown", CONTEXT, "INC-A")
    engine.queue_approval("isolate_network", CONTEXT, "INC-B")
    pending = engine.get_pending_approvals()
    assert len(pending) == 2
    assert all(p["status"] == "pending" for p in pending)


def test_pending_approvals_reduced_after_approve(engine):
    isolated_engine = SafeResponseEngine()
    rec1 = isolated_engine.queue_approval("plc_shutdown", CONTEXT, "INC-X")
    isolated_engine.queue_approval("isolate_network", CONTEXT, "INC-X")
    isolated_engine.approve_action(rec1["approval_id"])
    pending = isolated_engine.get_pending_approvals()
    assert len(pending) == 1


# ------------------------------------------------------------------
# Test 7: Unknown actions are skipped
# ------------------------------------------------------------------

def test_unknown_actions_ignored(engine):
    actions = ["block_ip", "fly_to_mars", "alert_team"]
    safe, dangerous = engine.categorize_actions(actions)
    assert "fly_to_mars" not in safe
    assert "fly_to_mars" not in dangerous
    assert len(safe) == 2
    assert len(dangerous) == 0


def test_process_actions_skips_unknown(engine):
    actions = ["unknown_action", "block_ip"]
    result = engine.process_actions(actions, INCIDENT_ID, CONTEXT)
    assert result["safe_count"] == 1
    assert result["approval_count"] == 0
