from engine.decision_engine import DecisionEngine

engine = DecisionEngine()

incident = engine.process_alert("data/alerts/test_alert.json")

print("Generated Incident:")
print(incident)

print("\nAll Incidents in Database:")
print(engine.get_incidents())