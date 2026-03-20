import os

alerts = "data/alerts"

for f in os.listdir(alerts):
    os.remove(os.path.join(alerts, f))

if os.path.exists("data/incidents.db"):
    os.remove("data/incidents.db")

print("Demo environment reset.")