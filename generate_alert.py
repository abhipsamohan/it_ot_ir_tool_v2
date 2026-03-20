import json
import os
import random
import time
from datetime import datetime

alerts_dir = "data/alerts"
os.makedirs(alerts_dir, exist_ok=True)

event_types = [
    "FAILED_LOGIN",
    "NETWORK_SCAN",
    "MALWARE_DETECTED",
    "UNAUTHORIZED_CONFIG_CHANGE",
    "PLC_PROGRAM_CHANGE",
    "SUSPICIOUS_PROCESS",
    "REMOTE_SESSION",
    "FIRMWARE_MODIFICATION"
]

assets = [
    "pump_controller_1",
    "hvac_controller_1",
    "valve_controller_1",
    "plc_controller_1"
    #"power_meter_1",
    #"conveyor_controller_1"
]

severities = ["low", "medium", "high", "critical"]

alert = {
    "timestamp": datetime.now().isoformat(),
    "event_type": random.choice(event_types),
    "asset_id": random.choice(assets),
    "severity": random.choice(severities),
    "details": {
        "source_ip": f"192.168.1.{random.randint(1,254)}"
    }
}

filename = f"alert_{int(time.time())}.json"
filepath = os.path.join(alerts_dir, filename)

with open(filepath, "w") as f:
    json.dump(alert, f, indent=2)

print("Generated alert:")
print(json.dumps(alert, indent=2))