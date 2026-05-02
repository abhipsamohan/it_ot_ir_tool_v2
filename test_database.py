from engine.database import IncidentDatabase


def test_database_insert_and_fetch(tmp_path):
    db_path = tmp_path / "incidents.db"
    db = IncidentDatabase(db_path=str(db_path))

    test_incident = {
        "id": "INC-001",
        "timestamp": "2026-01-01T00:00:00",
        "event_type": "TEST_EVENT",
        "asset_id": "test_asset_1",
        "asset_name": "Test Asset",
        "severity": "high",
        "risk_level": "CRITICAL",
        "risk_score": 4.0,
        "response_action": "Test response",
    }

    db.insert_incident(test_incident)
    incidents = db.get_incidents()

    assert len(incidents) == 1
    assert incidents[0]["id"] == "INC-001"
    assert incidents[0]["asset_id"] == "test_asset_1"
