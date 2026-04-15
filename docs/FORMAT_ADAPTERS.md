# Format Adapters - Integration Guide

## Overview

The IT-OT middleware includes a **format abstraction layer** that auto-detects and
normalises incoming alert data regardless of source.  This lets the same decision
engine accept alerts from:

| Source | Format | Adapter |
|--------|--------|---------|
| Direct API / alert generator | JSON | `JSONAdapter` |
| Splunk, Palo Alto, Fortinet | CEF / Syslog | `CEFAdapter` |
| Phantom, Cortex XSOAR, ServiceNow | REST webhook | `RESTAdapter` |

---

## Supported Formats

### 1. JSON (Standard IT-OT Format)

Direct alert injection using the native format.

```bash
curl -X POST http://localhost:5000/api/alert \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "FAILED_LOGIN",
    "asset_id": "water_treatment_plc",
    "severity": "high"
  }'
```

---

### 2. CEF/Syslog (Enterprise Security Tools)

Splunk, Arista, Palo Alto Networks, Fortinet, Checkpoint, etc.

**CEF via HTTP Event Collector:**

```bash
curl -X POST http://localhost:5000/api/alert \
  -H "Content-Type: text/plain" \
  -d 'CEF:0|Splunk|IDS|1.0|123456|Failed Authentication|7|src=192.168.1.100 dst=192.168.1.50'
```

**CEF severity mapping (0–10 → low/medium/high/critical):**

| CEF Severity | IT-OT Severity |
|---|---|
| 0–4 | low |
| 5–6 | medium |
| 7–8 | high |
| 9–10 | critical |

**Syslog (plain-text firewall/IDS):**

```bash
curl -X POST http://localhost:5000/api/alert \
  -H "Content-Type: text/plain" \
  -d '<134>Feb 19 20:15:42 firewall01 %FIREWALL-3-AUTH_FAILED: Failed login from 192.168.1.100'
```

---

### 3. REST/Webhook (SOAR Platforms)

Splunk Phantom, CrowdStrike Falcon, Microsoft Defender, Demisto/Cortex XSOAR,
custom webhooks.

**Splunk Phantom webhook:**

```bash
curl -X POST http://localhost:5000/api/alert \
  -H "Content-Type: application/json" \
  -d '{
    "alert": {
      "name": "Malware Detection",
      "severity": "critical",
      "source": "Phantom",
      "asset": "manufacturing_robot_1"
    },
    "context": {
      "indicators": ["hash1", "hash2"]
    }
  }'
```

Supported wrapper keys: `alert`, `event`, `incident`, `data`.

---

## Auto-Detection Flow

```
POST /api/alert  →  FormatDetector
  ├─ CEFAdapter.can_parse()   → starts with "CEF:" or matches <PRI>
  ├─ RESTAdapter.can_parse()  → dict/JSON with alert/event/incident/data key
  └─ JSONAdapter.can_parse()  → any valid JSON object
        ↓ (all fail)
      400 Bad Request: "No adapter could parse the incoming data"
```

---

## List Supported Formats

```bash
curl http://localhost:5000/api/adapters
```

```json
[
  { "name": "CEF/Syslog (Enterprise)",      "example": "See docs/FORMAT_ADAPTERS.md" },
  { "name": "REST/Webhook (SOAR)",           "example": "See docs/FORMAT_ADAPTERS.md" },
  { "name": "JSON (Standard IT-OT Format)", "example": "See docs/FORMAT_ADAPTERS.md" }
]
```

---

## Normalised Internal Format

Every adapter produces the same internal structure that feeds the decision engine:

```json
{
  "event_type":    "FAILED_LOGIN",
  "asset_id":      "water_treatment_plc",
  "severity":      "high",
  "timestamp":     "2026-04-15T10:30:00",
  "source_format": "CEF/Syslog (Enterprise)",
  "raw_data":      { ... },
  "extra_fields":  { ... }
}
```

---

## Running the Unit Tests

```bash
python -m pytest tests/test_adapters.py -v
```

---

## Adding a New Adapter

1. Create `engine/adapters/my_format.py` that inherits `BaseAdapter`.
2. Implement `format_name`, `can_parse()`, and `parse()`.
3. Register it in `FormatDetector.__init__()` (insert before `JSONAdapter`).
4. Add tests in `tests/test_adapters.py`.

---

## Future Formats

- **STIX/TAXII** — cybersecurity intelligence standard
- **MQTT** — IoT device telemetry
- **Kafka** — streaming data pipelines
- **GraphQL** — custom query integration
