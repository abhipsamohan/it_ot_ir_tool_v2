"""
Comprehensive test suite for IT-OT IR Tool v2.

Covers:
- Unit tests: DecisionEngine risk scoring, playbooks, safe guidance, correlation
- Integration tests: IncidentDatabase CRUD, acknowledgement, shift reports
- API tests: all Flask endpoints via test client
"""

import json
import os
import sys

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.database import IncidentDatabase
from engine.decision_engine import DecisionEngine


# ---------------------------------------------------------------------------
# Shared test-incident factory
# ---------------------------------------------------------------------------

def _make_incident(incident_id: str, **overrides) -> dict:
    """Return a minimal valid incident dict for database tests."""
    base = {
        "id": incident_id,
        "timestamp": "2026-04-15T10:00:00",
        "event_type": "FAILED_LOGIN",
        "asset_id": "test_asset",
        "asset_name": "Test Asset",
        "severity": "high",
        "risk_level": "HIGH",
        "risk_score": 2.8,
        "criticality": "high",
        "shutdown_risk": "medium",
        "zone_id": "ot_control",
        "purdue_level": "L1",
        "warning": None,
        "response_action": "Investigate",
        "response_steps": ["Step 1", "Step 2"],
        "explanation": "Test event",
        "risk_score_explanation": "Score 2.8 (HIGH)",
        "correlation": None,
        "do_steps": ["Check logs"],
        "dont_steps": [],
        "status": "open",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine():
    """Fresh DecisionEngine (uses real asset/zone config from data/)."""
    return DecisionEngine()


@pytest.fixture()
def tmp_db(tmp_path):
    """IncidentDatabase backed by a temporary SQLite file."""
    return IncidentDatabase(db_path=str(tmp_path / "test_incidents.db"))


@pytest.fixture()
def sample_alert():
    return {
        "event_type": "FAILED_LOGIN",
        "asset_id": "water_treatment_plc",
        "severity": "high",
        "timestamp": "2026-04-15T10:30:00Z",
    }


# ---------------------------------------------------------------------------
# Decision Engine — Risk Scoring
# ---------------------------------------------------------------------------

class TestRiskScoring:

    def test_critical_severity_critical_asset_gives_critical_level(self, engine):
        result = engine.calculate_risk({"severity": "critical"}, {"criticality": "critical"})
        assert result["level"] == "CRITICAL"
        assert result["score"] >= 3.5

    def test_low_severity_low_criticality_gives_low_level(self, engine):
        result = engine.calculate_risk({"severity": "low"}, {"criticality": "low"})
        assert result["level"] == "LOW"

    def test_medium_severity_medium_criticality_score(self, engine):
        # (2*0.6) + (2*0.4) = 1.2 + 0.8 = 2.0 → MEDIUM
        result = engine.calculate_risk({"severity": "medium"}, {"criticality": "medium"})
        assert result["score"] == pytest.approx(2.0, rel=1e-2)
        assert result["level"] == "MEDIUM"

    def test_high_severity_medium_criticality_score(self, engine):
        # (3*0.6) + (2*0.4) = 1.8 + 0.8 = 2.6 → HIGH
        result = engine.calculate_risk({"severity": "high"}, {"criticality": "medium"})
        assert result["score"] == pytest.approx(2.6, rel=1e-2)
        assert result["level"] == "HIGH"

    def test_missing_severity_defaults_to_medium(self, engine):
        result = engine.calculate_risk({}, {"criticality": "medium"})
        assert result["score"] == pytest.approx(2.0, rel=1e-2)

    def test_result_contains_required_keys(self, engine):
        result = engine.calculate_risk({"severity": "high"}, {"criticality": "high"})
        assert "level" in result
        assert "score" in result
        assert "explanation" in result

    def test_explanation_mentions_score(self, engine):
        result = engine.calculate_risk({"severity": "high"}, {"criticality": "high"})
        assert str(result["score"]) in result["explanation"] or "Score" in result["explanation"]


# ---------------------------------------------------------------------------
# Decision Engine — Playbooks
# ---------------------------------------------------------------------------

class TestPlaybooks:

    def test_failed_login_playbook_action(self, engine):
        result = engine.generate_response("FAILED_LOGIN")
        assert result["action"] == "Investigate Authentication"
        assert len(result["steps"]) > 0

    def test_malware_playbook_action(self, engine):
        result = engine.generate_response("MALWARE_DETECTED")
        assert "Malware" in result["action"]

    def test_network_scan_playbook_has_steps(self, engine):
        result = engine.generate_response("NETWORK_SCAN")
        assert len(result["steps"]) > 0

    def test_unknown_event_returns_default_playbook(self, engine):
        result = engine.generate_response("COMPLETELY_UNKNOWN_EVENT_XYZ")
        assert result["action"] == "Investigate Alert"
        assert len(result["steps"]) > 0

    @pytest.mark.parametrize("event_type", [
        "FAILED_LOGIN",
        "MALWARE_DETECTED",
        "NETWORK_SCAN",
        "UNAUTHORIZED_CONFIG_CHANGE",
        "PLC_PROGRAM_CHANGE",
        "SUSPICIOUS_PROCESS",
        "REMOTE_SESSION",
        "FIRMWARE_MODIFICATION",
    ])
    def test_all_known_event_types_have_playbooks(self, engine, event_type):
        result = engine.generate_response(event_type)
        assert "action" in result
        assert "steps" in result
        assert len(result["steps"]) >= 1


# ---------------------------------------------------------------------------
# Decision Engine — Event Explanations
# ---------------------------------------------------------------------------

class TestExplanations:

    def test_failed_login_explanation(self, engine):
        result = engine.explain_event("FAILED_LOGIN")
        assert "login" in result.lower() or "failed" in result.lower()

    def test_unknown_event_returns_generic(self, engine):
        result = engine.explain_event("SOMETHING_UNKNOWN_XYZ")
        assert isinstance(result, str)
        assert len(result) > 0


# ---------------------------------------------------------------------------
# Decision Engine — Safe Guidance
# ---------------------------------------------------------------------------

class TestSafeGuidance:

    def test_high_shutdown_risk_adds_dont_guidance(self, engine):
        asset = {"shutdown_risk": "high", "criticality": "low"}
        guidance = engine.generate_safe_guidance(asset, None)
        combined_dont = " ".join(guidance["dont"])
        assert "shutdown" in combined_dont.lower()

    def test_critical_asset_requires_ot_engineer(self, engine):
        asset = {"shutdown_risk": "low", "criticality": "critical"}
        guidance = engine.generate_safe_guidance(asset, None)
        combined_dont = " ".join(guidance["dont"])
        assert "OT engineer" in combined_dont

    def test_correlated_attack_adds_escalate_do_step(self, engine):
        asset = {"shutdown_risk": "low", "criticality": "low"}
        correlation = {"type": "BRUTE_FORCE", "description": "Brute force detected"}
        guidance = engine.generate_safe_guidance(asset, correlation)
        combined_do = " ".join(guidance["do"])
        assert "escalate" in combined_do.lower() or "coordinated" in combined_do.lower()

    def test_no_issues_still_has_base_do_steps(self, engine):
        asset = {"shutdown_risk": "low", "criticality": "low"}
        guidance = engine.generate_safe_guidance(asset, None)
        assert len(guidance["do"]) >= 1

    def test_safety_impact_appears_in_dont(self, engine):
        asset = {
            "shutdown_risk": "low",
            "criticality": "low",
            "safety_impact": "Causes chemical overflow",
        }
        guidance = engine.generate_safe_guidance(asset, None)
        combined_dont = " ".join(guidance["dont"])
        assert "chemical overflow" in combined_dont


# ---------------------------------------------------------------------------
# Decision Engine — Correlation
# ---------------------------------------------------------------------------

class TestCorrelation:

    def test_no_correlation_for_single_novel_alert(self):
        fresh = DecisionEngine()
        result = fresh.check_correlation({"event_type": "REMOTE_SESSION", "asset_id": "x"})
        assert result is None

    def test_brute_force_detected_after_threshold(self):
        fresh = DecisionEngine()
        asset_id = "water_treatment_plc"
        # Send 5 FAILED_LOGIN events on the same asset (threshold = 5 within 10 min)
        for _ in range(5):
            fresh.check_correlation({"event_type": "FAILED_LOGIN", "asset_id": asset_id})
        # The 6th call exceeds the threshold
        result = fresh.check_correlation({"event_type": "FAILED_LOGIN", "asset_id": asset_id})
        assert result is not None
        assert result["type"] == "BRUTE_FORCE"

    def test_recon_to_access_detected(self):
        fresh = DecisionEngine()
        fresh.check_correlation({"event_type": "NETWORK_SCAN", "asset_id": "asset_a"})
        result = fresh.check_correlation({"event_type": "FAILED_LOGIN", "asset_id": "asset_b"})
        # Either RECON_TO_ACCESS or the longer COORDINATED_ATTACK chain
        assert result is not None
        assert result["type"] in ("RECON_TO_ACCESS", "COORDINATED_ATTACK")

    def test_coordinated_attack_detected(self):
        fresh = DecisionEngine()
        fresh.check_correlation({"event_type": "NETWORK_SCAN", "asset_id": "a"})
        fresh.check_correlation({"event_type": "FAILED_LOGIN", "asset_id": "b"})
        result = fresh.check_correlation({"event_type": "PLC_PROGRAM_CHANGE", "asset_id": "c"})
        assert result is not None
        assert result["type"] == "COORDINATED_ATTACK"

    def test_alert_history_bounded_at_max(self):
        fresh = DecisionEngine()
        for i in range(250):
            fresh.check_correlation({"event_type": "REMOTE_SESSION", "asset_id": f"asset_{i}"})
        assert len(fresh.alert_history) <= fresh.MAX_ALERT_HISTORY

    def test_correlation_description_present(self):
        fresh = DecisionEngine()
        asset_id = "plc_controller_1"
        for _ in range(6):
            fresh.check_correlation({"event_type": "FAILED_LOGIN", "asset_id": asset_id})
        result = fresh.check_correlation({"event_type": "FAILED_LOGIN", "asset_id": asset_id})
        assert result is not None
        assert "description" in result
        assert len(result["description"]) > 0


# ---------------------------------------------------------------------------
# Decision Engine — Incident Building
# ---------------------------------------------------------------------------

class TestIncidentBuilding:

    def test_incident_has_all_required_fields(self, engine, sample_alert):
        incident = engine._build_incident(sample_alert)
        required = [
            "id", "timestamp", "event_type", "asset_id", "asset_name",
            "severity", "risk_level", "risk_score", "risk_score_explanation",
            "response_action", "response_steps", "explanation",
            "do_steps", "dont_steps", "status",
        ]
        for field in required:
            assert field in incident, f"Missing field: {field}"

    def test_incident_id_starts_with_inc_prefix(self, engine, sample_alert):
        incident = engine._build_incident(sample_alert)
        assert incident["id"].startswith("INC-")

    def test_known_asset_name_populated(self, engine, sample_alert):
        incident = engine._build_incident(sample_alert)
        assert incident["asset_name"] == "Water Treatment Plant PLC"

    def test_unknown_asset_falls_back_gracefully(self, engine):
        alert = {"event_type": "FAILED_LOGIN", "asset_id": "nonexistent_xyz", "severity": "low"}
        incident = engine._build_incident(alert)
        assert incident["asset_id"] == "nonexistent_xyz"
        assert incident["asset_name"] == "Unknown Asset"

    def test_critical_asset_warning_set(self, engine, sample_alert):
        incident = engine._build_incident(sample_alert)
        assert incident["warning"] is not None
        assert "critical" in incident["warning"].lower() or "Critical" in incident["warning"]

    def test_status_defaults_to_open(self, engine, sample_alert):
        incident = engine._build_incident(sample_alert)
        assert incident["status"] == "open"

    def test_zone_metadata_populated_for_known_asset(self, engine, sample_alert):
        incident = engine._build_incident(sample_alert)
        assert incident["zone_id"] == "ot_control"
        assert incident["purdue_level"] == "L1"

    def test_process_alert_dict_returns_and_stores(self, engine, sample_alert, tmp_path):
        engine.db = IncidentDatabase(db_path=str(tmp_path / "test.db"))
        incident = engine.process_alert_dict(sample_alert)
        assert incident is not None
        assert incident["event_type"] == "FAILED_LOGIN"
        stored = engine.db.get_incidents()
        assert len(stored) == 1
        assert stored[0]["id"] == incident["id"]

    def test_correlated_incident_risk_upgraded_to_critical(self):
        fresh = DecisionEngine()
        # Prime history with NETWORK_SCAN and FAILED_LOGIN to set up RECON_TO_ACCESS
        fresh.check_correlation({"event_type": "NETWORK_SCAN", "asset_id": "a"})
        fresh.check_correlation({"event_type": "FAILED_LOGIN", "asset_id": "b"})
        # Next PLC_PROGRAM_CHANGE should trigger COORDINATED_ATTACK
        alert = {"event_type": "PLC_PROGRAM_CHANGE", "asset_id": "c", "severity": "low"}
        incident = fresh._build_incident(alert)
        assert incident["risk_level"] == "CRITICAL"
        assert incident["risk_score"] == 4.0


# ---------------------------------------------------------------------------
# IncidentDatabase — CRUD
# ---------------------------------------------------------------------------

class TestIncidentDatabase:

    def test_insert_and_retrieve_single(self, tmp_db):
        inc = _make_incident("INC-DB0001")
        tmp_db.insert_incident(inc)
        results = tmp_db.get_incidents()
        assert len(results) == 1
        assert results[0]["id"] == "INC-DB0001"
        assert results[0]["event_type"] == "FAILED_LOGIN"

    def test_response_steps_serialise_round_trip(self, tmp_db):
        inc = _make_incident("INC-DB0002", response_steps=["Alpha", "Beta", "Gamma"])
        tmp_db.insert_incident(inc)
        results = tmp_db.get_incidents()
        assert results[0]["response_steps"] == ["Alpha", "Beta", "Gamma"]

    def test_do_and_dont_steps_round_trip(self, tmp_db):
        inc = _make_incident("INC-DB0003", do_steps=["Do A"], dont_steps=["Dont B"])
        tmp_db.insert_incident(inc)
        result = tmp_db.get_incidents()[0]
        assert result["do_steps"] == ["Do A"]
        assert result["dont_steps"] == ["Dont B"]

    def test_acknowledge_sets_status_and_operator(self, tmp_db):
        tmp_db.insert_incident(_make_incident("INC-ACK0001"))
        updated = tmp_db.acknowledge_incident("INC-ACK0001", "Jane Smith")
        assert updated is True
        result = tmp_db.get_incidents()[0]
        assert result["status"] == "acknowledged"
        assert result["acknowledged_by"] == "Jane Smith"
        assert result["acknowledged_at"] is not None

    def test_acknowledge_nonexistent_returns_false(self, tmp_db):
        assert tmp_db.acknowledge_incident("INC-GHOST", "operator") is False

    def test_shift_summary_empty_database(self, tmp_db):
        summary = tmp_db.get_shift_summary()
        assert summary["total_incidents"] == 0
        assert summary["open"] == 0
        assert summary["acknowledged"] == 0

    def test_shift_summary_counts_open_correctly(self, tmp_db):
        tmp_db.insert_incident(_make_incident("INC-SHIFT001"))
        tmp_db.insert_incident(_make_incident("INC-SHIFT002"))
        # Use a since_iso before the fixed test-incident timestamp so both are included
        summary = tmp_db.get_shift_summary(since_iso="2026-04-15T00:00:00")
        assert summary["total_incidents"] == 2
        assert summary["open"] == 2

    def test_shift_summary_counts_acknowledged(self, tmp_db):
        tmp_db.insert_incident(_make_incident("INC-SHIFT003"))
        tmp_db.acknowledge_incident("INC-SHIFT003", "op")
        summary = tmp_db.get_shift_summary(since_iso="2026-04-15T00:00:00")
        assert summary["acknowledged"] == 1
        assert summary["open"] == 0

    def test_get_incidents_ordered_most_recent_first(self, tmp_db):
        for i in range(3):
            inc = _make_incident(f"INC-ORD{i:04d}", timestamp=f"2026-04-1{i + 1}T10:00:00")
            tmp_db.insert_incident(inc)
        results = tmp_db.get_incidents()
        assert len(results) == 3
        assert results[0]["timestamp"] >= results[1]["timestamp"]

    def test_multiple_incidents_all_retrieved(self, tmp_db):
        for i in range(5):
            tmp_db.insert_incident(_make_incident(f"INC-MULTI{i:04d}"))
        assert len(tmp_db.get_incidents()) == 5


# ---------------------------------------------------------------------------
# Flask API Endpoints
# ---------------------------------------------------------------------------

class TestFlaskAPI:
    """Integration tests for the Flask REST API using the built-in test client."""

    @pytest.fixture(autouse=True)
    def _setup_client(self, tmp_path):
        """Swap the module-level engine database for an isolated temp DB."""
        import dashboard.app as app_module

        test_db = IncidentDatabase(db_path=str(tmp_path / "api_test.db"))
        app_module.engine.db = test_db
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    # -- Dashboard --

    def test_dashboard_root_returns_200(self):
        response = self.client.get("/")
        assert response.status_code == 200

    # -- Incidents listing --

    def test_get_incidents_returns_empty_list_initially(self):
        response = self.client.get("/api/incidents")
        assert response.status_code == 200
        assert json.loads(response.data) == []

    # -- Alert ingestion (JSON) --

    def test_ingest_json_alert_returns_201_with_incident(self):
        alert = {"event_type": "NETWORK_SCAN", "asset_id": "hvac_controller", "severity": "medium"}
        response = self.client.post(
            "/api/alert",
            data=json.dumps(alert),
            content_type="application/json",
        )
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data["event_type"] == "NETWORK_SCAN"
        assert data["id"].startswith("INC-")

    def test_ingest_alert_appears_in_incidents_list(self):
        alert = {"event_type": "MALWARE_DETECTED", "asset_id": "network_gateway", "severity": "critical"}
        self.client.post("/api/alert", data=json.dumps(alert), content_type="application/json")
        incidents = json.loads(self.client.get("/api/incidents").data)
        assert len(incidents) == 1
        assert incidents[0]["event_type"] == "MALWARE_DETECTED"

    # -- Alert ingestion (CEF) --

    def test_ingest_cef_alert_returns_201(self):
        cef = "CEF:0|Splunk|IDS|1.0|123|Failed Authentication|7|src=192.168.1.100 dst=10.0.0.1"
        response = self.client.post("/api/alert", data=cef, content_type="text/plain")
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data["event_type"] == "FAILED_LOGIN"

    # -- Alert ingestion (SOAR webhook) --

    def test_ingest_soar_webhook_returns_201(self):
        webhook = {"alert": {"name": "Malware Detection", "severity": "high", "asset": "hvac_controller"}}
        response = self.client.post(
            "/api/alert",
            data=json.dumps(webhook),
            content_type="application/json",
        )
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data["event_type"] == "MALWARE_DETECTED"

    # -- Malformed alert --

    def test_ingest_unrecognised_format_returns_400(self):
        response = self.client.post(
            "/api/alert",
            data="!!!completely unrecognisable garbage!!!",
            content_type="text/plain",
        )
        assert response.status_code == 400
        error = json.loads(response.data)
        assert "error" in error

    # -- Adapters list --

    def test_list_adapters_returns_three_adapters(self):
        response = self.client.get("/api/adapters")
        assert response.status_code == 200
        adapters = json.loads(response.data)
        assert len(adapters) == 3

    # -- Acknowledgement --

    def test_acknowledge_incident_happy_path(self):
        alert = {"event_type": "FAILED_LOGIN", "asset_id": "water_treatment_plc", "severity": "high"}
        post_resp = self.client.post(
            "/api/alert", data=json.dumps(alert), content_type="application/json"
        )
        incident_id = json.loads(post_resp.data)["id"]

        ack_resp = self.client.put(
            f"/api/incidents/{incident_id}/acknowledge",
            data=json.dumps({"operator": "Jane Smith"}),
            content_type="application/json",
        )
        assert ack_resp.status_code == 200
        body = json.loads(ack_resp.data)
        assert body["status"] == "acknowledged"
        assert body["operator"] == "Jane Smith"

    def test_acknowledge_missing_operator_returns_400(self):
        response = self.client.put(
            "/api/incidents/INC-FAKE0001/acknowledge",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert response.status_code == 400

    def test_acknowledge_nonexistent_incident_returns_404(self):
        response = self.client.put(
            "/api/incidents/INC-DOESNOTEXIST/acknowledge",
            data=json.dumps({"operator": "Test"}),
            content_type="application/json",
        )
        assert response.status_code == 404

    # -- Shift report --

    def test_shift_report_structure(self):
        response = self.client.get("/api/report/shift")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "total_incidents" in data
        assert "open" in data
        assert "acknowledged" in data
        assert "by_risk_level" in data

    # -- Asset reload --

    def test_reload_assets_returns_asset_count(self):
        response = self.client.post("/api/assets/reload")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["reloaded"] is True
        assert data["asset_count"] > 0

    # -- Escalation config --

    def test_escalation_config_endpoint(self):
        response = self.client.get("/api/config/escalation")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "contacts" in data
