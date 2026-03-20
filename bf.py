import json
import os
from datetime import datetime

os.makedirs("data/alerts", exist_ok=True)

for i in range(5):

    alert = {
        "timestamp": str(datetime.now()),
        "event_type": "FAILED_LOGIN",
        "asset_id": "pump_controller_1",
        "severity": "medium"
    }

    filename = f"data/alerts/brute_test_{i}.json"

    with open(filename, "w") as f:
        json.dump(alert, f)

print("Generated 5 brute force alerts")