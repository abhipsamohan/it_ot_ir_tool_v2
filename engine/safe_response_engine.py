"""
engine/safe_response_engine.py - Response Orchestration Engine
Automatic execution of safe actions + approval workflow for dangerous actions.
"""

import logging
from datetime import datetime
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

# Actions that can be executed automatically (no human approval required)
SAFE_ACTIONS = {
    "block_ip",
    "alert_team",
    "take_snapshot",
    "enable_logging",
    "network_segment_monitor",
}

# Actions that require explicit human approval before execution
DANGEROUS_ACTIONS = {
    "plc_shutdown",
    "disconnect_power",
    "system_restart",
    "isolate_network",
}

# Human-readable descriptions for each action
ACTION_DESCRIPTIONS = {
    "block_ip": "Block source IP address in firewall",
    "alert_team": "Send alert notification to security and OT team",
    "take_snapshot": "Capture system/process snapshot for forensics",
    "enable_logging": "Enable enhanced logging on affected device",
    "network_segment_monitor": "Increase monitoring on affected network segment",
    "plc_shutdown": "Shut down PLC / industrial controller",
    "disconnect_power": "Disconnect power to affected equipment",
    "system_restart": "Restart affected IT/OT system",
    "isolate_network": "Isolate network segment from rest of OT/IT network",
}


class SafeResponseEngine:
    """
    Orchestrates incident response actions.
    - Automatically executes safe actions
    - Routes dangerous actions to approval workflow
    """

    def __init__(self):
        # Pending approvals: dict of approval_id -> pending action info
        self.pending_approvals: Dict[str, Dict] = {}

    # ------------------------------------------------------------------
    # Action classification
    # ------------------------------------------------------------------

    def classify_action(self, action: str) -> str:
        """
        Return 'safe', 'dangerous', or 'unknown' for the given action string.
        """
        if action in SAFE_ACTIONS:
            return "safe"
        if action in DANGEROUS_ACTIONS:
            return "dangerous"
        return "unknown"

    def categorize_actions(self, actions: List[str]) -> Tuple[List[str], List[str]]:
        """
        Split a list of actions into (safe_actions, dangerous_actions).
        Unknown actions are logged and ignored.
        """
        safe = []
        dangerous = []
        for action in actions:
            category = self.classify_action(action)
            if category == "safe":
                safe.append(action)
            elif category == "dangerous":
                dangerous.append(action)
            else:
                logger.warning("Unknown action '%s' - skipping", action)
        return safe, dangerous

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute_safe_action(self, action: str, context: Dict) -> Dict:
        """
        Execute a single safe action immediately.
        In production this would trigger real integrations (firewall API, email, etc.).
        Returns an execution result dict.
        """
        description = ACTION_DESCRIPTIONS.get(action, action)
        logger.info("AUTO-EXECUTING safe action: %s | context: %s", action, context)

        return {
            "action": action,
            "description": description,
            "status": "executed",
            "timestamp": datetime.now().isoformat(),
            "context": context,
            "requires_approval": False,
        }

    def queue_approval(self, action: str, context: Dict, incident_id: str) -> Dict:
        """
        Queue a dangerous action for human approval.
        Returns an approval request dict.
        """
        import uuid
        approval_id = f"APPR-{uuid.uuid4().hex[:8].upper()}"
        description = ACTION_DESCRIPTIONS.get(action, action)

        approval_request = {
            "approval_id": approval_id,
            "incident_id": incident_id,
            "action": action,
            "description": description,
            "status": "pending",
            "requested_at": datetime.now().isoformat(),
            "approved_at": None,
            "denied_at": None,
            "context": context,
            "requires_approval": True,
        }

        self.pending_approvals[approval_id] = approval_request
        logger.info(
            "APPROVAL REQUIRED for action '%s' (approval_id=%s, incident=%s)",
            action, approval_id, incident_id,
        )
        return approval_request

    def approve_action(self, approval_id: str, approver: str = "operator") -> Dict:
        """
        Approve and execute a pending dangerous action.
        Returns the updated approval record.
        """
        if approval_id not in self.pending_approvals:
            return {"error": f"Approval ID not found: {approval_id}"}

        record = self.pending_approvals[approval_id]
        if record["status"] != "pending":
            return {"error": f"Approval {approval_id} is already {record['status']}"}

        action = record["action"]
        logger.info(
            "Executing approved action '%s' (approval_id=%s, approver=%s)",
            action, approval_id, approver,
        )

        record["status"] = "approved"
        record["approved_at"] = datetime.now().isoformat()
        record["approver"] = approver
        return record

    def deny_action(self, approval_id: str, reason: str = "", denier: str = "operator") -> Dict:
        """
        Deny a pending dangerous action.
        Returns the updated approval record.
        """
        if approval_id not in self.pending_approvals:
            return {"error": f"Approval ID not found: {approval_id}"}

        record = self.pending_approvals[approval_id]
        if record["status"] != "pending":
            return {"error": f"Approval {approval_id} is already {record['status']}"}

        record["status"] = "denied"
        record["denied_at"] = datetime.now().isoformat()
        record["denial_reason"] = reason
        record["denier"] = denier
        logger.info(
            "Action '%s' denied (approval_id=%s, reason=%s)",
            record["action"], approval_id, reason,
        )
        return record

    # ------------------------------------------------------------------
    # Main orchestration
    # ------------------------------------------------------------------

    def process_actions(self, actions: List[str], incident_id: str, context: Dict) -> Dict:
        """
        Process all actions for an incident:
        - Execute safe actions immediately
        - Queue dangerous actions for approval

        Returns a response summary dict.
        """
        safe_actions, dangerous_actions = self.categorize_actions(actions)

        executed = []
        approvals_needed = []

        for action in safe_actions:
            result = self.execute_safe_action(action, context)
            executed.append(result)

        for action in dangerous_actions:
            approval = self.queue_approval(action, context, incident_id)
            approvals_needed.append(approval)

        return {
            "incident_id": incident_id,
            "auto_executed": executed,
            "pending_approvals": approvals_needed,
            "safe_count": len(executed),
            "approval_count": len(approvals_needed),
            "timestamp": datetime.now().isoformat(),
        }

    # ------------------------------------------------------------------
    # Pending approvals query
    # ------------------------------------------------------------------

    def get_pending_approvals(self) -> List[Dict]:
        """Return all approvals that are still in 'pending' status."""
        return [
            rec for rec in self.pending_approvals.values()
            if rec["status"] == "pending"
        ]

    def get_all_approvals(self) -> List[Dict]:
        """Return all approval records."""
        return list(self.pending_approvals.values())
