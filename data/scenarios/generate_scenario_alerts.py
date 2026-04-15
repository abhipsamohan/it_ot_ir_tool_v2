#!/usr/bin/env python3
"""
Generate scenario-based alert JSON files for IT-OT IR Tool v2.

Each scenario defined in scenario_definitions.py is converted into a series
of timestamped JSON files saved to data/alerts/.  The files are named with
the pattern:

    {scenario_name}_{index:02d}_{event_type}.json

so that the decision engine's background scanner can ingest them in the
correct order and detect the expected correlation patterns.

Usage
-----
    python data/scenarios/generate_scenario_alerts.py

Output
------
    data/alerts/<scenario_name>_<NN>_<EVENT_TYPE>.json  (one file per event)
"""

import json
import os
import sys
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Allow running from the repo root or from inside data/scenarios/
# ---------------------------------------------------------------------------

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _REPO_ROOT)

from data.scenarios.scenario_definitions import SCENARIOS  # noqa: E402

# ---------------------------------------------------------------------------

ALERTS_DIR = os.path.join(_REPO_ROOT, "data", "alerts")


def generate_all() -> None:
    """Generate alert files for every scenario."""

    os.makedirs(ALERTS_DIR, exist_ok=True)

    for scenario in SCENARIOS:
        name = scenario["name"]
        print(f"\n[Scenario] Generating: {name}")

        # Use a fixed reference time so runs are reproducible; in a real
        # integration this would be datetime.now().
        reference_time = datetime(2026, 1, 15, 8, 0, 0)

        for idx, event in enumerate(scenario["events"]):
            timestamp = reference_time + timedelta(minutes=event["offset_minutes"])

            alert = {
                "event_type":  event["event_type"],
                "asset_id":    event["asset_id"],
                "severity":    event["severity"],
                "timestamp":   timestamp.isoformat(),
                # ----------------------------------------------------------
                # Scenario lineage — preserved for audit trails and testing.
                # These fields are ignored by the decision engine but kept in
                # the file so analysts can trace alerts back to their origin.
                # ----------------------------------------------------------
                "scenario": {
                    "name":                 name,
                    "description":          scenario["description"],
                    "expected_correlation": scenario.get("expected_correlation"),
                    "cve_reference":        scenario.get("cve_reference"),
                    "mitre_technique":      scenario.get("mitre_technique"),
                    "event_index":          idx,
                    "total_events":         len(scenario["events"]),
                    "offset_minutes":       event["offset_minutes"],
                },
            }

            filename = f"{name}_{idx:02d}_{event['event_type']}.json"
            filepath = os.path.join(ALERTS_DIR, filename)

            with open(filepath, "w") as fh:
                json.dump(alert, fh, indent=2)

            print(f"  ✓ Created: data/alerts/{filename}")

    print("\n✅ All scenarios generated!")


if __name__ == "__main__":
    generate_all()
