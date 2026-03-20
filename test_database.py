from engine.database import IncidentDatabase

db = IncidentDatabase()

test_incident = {
    "id": "INC-001",
    "timestamp": "2026-01-01",
    "event_type": "TEST_EVENT",
    "asset": "Test Asset",
    "severity": "high",
    "risk": "CRITICAL",
    "response": "Test response"
}

db.insert_incident(test_incident)

print(db.get_incidents())