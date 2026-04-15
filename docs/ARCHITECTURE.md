# IT-OT Incident Response Tool v2 — Architecture

## 1. System Overview

This project implements a **middleware layer** for IT-OT (Information Technology – Operational Technology) incident response. It is designed for small-scale Indian industrial facilities that **lack a dedicated Security Operations Centre (SOC)** and cannot afford enterprise SIEM/SOAR platforms.

```
┌──────────────────────────────────────────────────────────────────┐
│                    External Alert Sources                        │
│  (IDS/IPS, Firewalls, Endpoint agents, Manual JSON file drops)  │
└──────────────────────────┬───────────────────────────────────────┘
                           │  JSON alerts (file or HTTP POST)
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                   IT-OT IR Middleware Layer                      │
│                                                                  │
│  ┌────────────────┐   ┌──────────────────┐   ┌───────────────┐  │
│  │ Alert Ingestor │──▶│  Decision Engine │──▶│   SQLite DB   │  │
│  │ (file + HTTP)  │   │  (correlation,   │   │  (incidents)  │  │
│  └────────────────┘   │   risk scoring,  │   └───────────────┘  │
│                       │   playbooks)     │                       │
│                       └──────────────────┘                       │
│                                 │                                │
│                                 ▼                                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Flask REST API + Web Dashboard              │   │
│  │  /api/incidents  /api/alert  /api/report/shift           │   │
│  │  Operator ACK workflow  Escalation config endpoint       │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
                           │
                           ▼
            Non-SOC Operator (shift engineer, plant manager)
```

### Design Philosophy

| Principle | Rationale |
|-----------|-----------|
| No SOC required | Target users are shift operators without security training |
| OT-safe actions | Every recommendation checks `shutdown_risk` before suggesting isolation |
| Explainability | Every risk score shows the formula breakdown in plain language |
| Lightweight | Runs on a Raspberry Pi 4 (Python + SQLite, no external databases) |
| Indian industrial context | Assets, contacts, and regulatory framework localised for India |

---

## 2. File Structure

```
it_ot_ir_tool_v2/
├── data/
│   ├── alerts/                          # Drop-zone for JSON alert files
│   ├── scenarios/
│   │   ├── __init__.py
│   │   ├── scenario_definitions.py      # MITRE ATT&CK ICS attack chains
│   │   └── generate_scenario_alerts.py  # Converts scenarios → JSON alerts
│   ├── config/
│   │   └── escalation.json              # Indian emergency contacts & SLAs
│   └── ot_context/
│       └── ot_assets.json               # Indian industrial asset registry
├── engine/
│   ├── decision_engine.py               # Core correlation + risk scoring
│   └── database.py                      # SQLite persistence layer
├── dashboard/
│   ├── app.py                           # Flask API + background scanner
│   └── templates/
│       └── dashboard.html               # Operator-facing web dashboard
├── docs/
│   └── ARCHITECTURE.md                  # This document
├── requirements.txt
└── README.md
```

---

## 3. Attack Scenario Workflow

### 3.1 Scenario Definitions (`data/scenarios/scenario_definitions.py`)

Each scenario is a Python dictionary describing:

- **name** — machine-readable identifier used as the alert filename prefix
- **description** — human-readable attack summary
- **context** — Indian industrial context explaining why this attack is relevant
- **expected_correlation** — maps to a pattern name in the decision engine
- **cve_reference** — real-world CVE or campaign for academic/training reference
- **mitre_technique** — MITRE ATT&CK for ICS technique identifiers
- **mitigations** — ordered list of recommended countermeasures
- **events** — ordered list of events with `offset_minutes`, `event_type`, `asset_id`, `severity`

### 3.2 Alert Generation (`data/scenarios/generate_scenario_alerts.py`)

```
python data/scenarios/generate_scenario_alerts.py
```

The script:
1. Loads all scenarios from `scenario_definitions.py`
2. Converts each event into a timestamped JSON file
3. Embeds scenario lineage metadata (name, CVE, MITRE technique) for audit trails
4. Saves files to `data/alerts/` using the naming pattern:
   `{scenario_name}_{index:02d}_{event_type}.json`

Timestamps use a fixed reference time (`2026-01-15T08:00:00`) so that repeated
runs produce identical, reproducible alert sequences. In a real deployment, the
timestamp would be `datetime.now()`.

### 3.3 Alert Ingestion

The system accepts alerts via two channels:

| Channel | Description |
|---------|-------------|
| **File drop** | JSON files placed in `data/alerts/` are picked up by a background thread every 10 seconds |
| **HTTP POST** | `POST /api/alert` accepts a JSON body for direct integration with IDS/SIEM |

---

## 4. Decision Engine

### 4.1 Risk Scoring

```
risk_score = (severity_value × 0.6) + (asset_criticality × 0.4)
```

| Label    | Numeric value |
|----------|--------------|
| low      | 1            |
| medium   | 2            |
| high     | 3            |
| critical | 4            |

Score thresholds: `≥3.5 → CRITICAL`, `≥2.5 → HIGH`, `≥1.5 → MEDIUM`, else `LOW`.

When a **correlation pattern** is detected, the risk is automatically elevated to
**CRITICAL** regardless of the individual event score.

### 4.2 Correlation Patterns

Four time-windowed patterns are evaluated in order (most severe first):

| Pattern | Window | Logic |
|---------|--------|-------|
| `COORDINATED_ATTACK` | 60 min | NETWORK_SCAN + FAILED_LOGIN + PLC_PROGRAM_CHANGE anywhere in network |
| `RECON_TO_ACCESS` | 30 min | NETWORK_SCAN + FAILED_LOGIN anywhere in network |
| `BRUTE_FORCE` | 10 min | 5+ FAILED_LOGIN events on the **same** asset |
| `LATERAL_MOVEMENT` | 10 min | FAILED_LOGIN events across **3+ different** assets |

Patterns are checked in this order to prevent a short pattern from masking
a more severe multi-stage detection.

### 4.3 Safe Guidance Generation

For every incident the engine generates:

- **DO** steps — safe investigative actions
- **DON'T** steps — OT-specific constraints (e.g., "Do NOT shut down this system without OT engineer approval — high shutdown risk")

These are derived from the asset's `shutdown_risk` and `criticality` fields in
`ot_assets.json`, ensuring recommendations are always tailored to the physical
consequences of the specific asset.

### 4.4 Explainability

Every incident includes:
- `explanation` — plain-language description of what the event type means
- `risk_score_explanation` — the arithmetic breakdown of the score
- `correlation` — description of the detected attack pattern (if any)
- `warning` — highlighted safety warning for critical/correlated incidents

---

## 5. OT Asset Registry (`data/ot_context/ot_assets.json`)

The asset registry describes each monitored industrial system. Fields:

| Field | Description |
|-------|-------------|
| `system` | Human-readable system name |
| `criticality` | low / medium / high / critical |
| `shutdown_risk` | low / medium / high (consequence of unplanned shutdown) |
| `safety_impact` | Description of physical/safety consequences |
| `protocol` | Industrial protocol (Modbus, DNP3, Profinet, BACnet, OPC-UA) |
| `network_segment` | Logical network zone (CRITICAL, OT_SEGMENT_1, OT_SEGMENT_2, DMZ) |
| `location` | Physical location (Indian city/region) |

Current registry includes 10 Indian industrial assets across water treatment,
textile manufacturing, power distribution, robotics, HVAC, and building management.

---

## 6. Indian Industrial Context

### Regulatory Framework

| Authority | Scope | Reporting Deadline |
|-----------|-------|-------------------|
| CERT-IN | Critical infrastructure incidents, ransomware | 6 hours |
| DSCI | Incidents involving personal data | 72 hours |

### Why Indian Localisation Matters

1. **Asset diversity** — Indian facilities mix legacy Modbus PLCs with modern OPC-UA systems
2. **Vendor ecosystem** — Many facilities use local/Chinese UPS and control system vendors with limited supply-chain transparency
3. **Operator skills** — Shift engineers often lack cybersecurity training; plain-language guidance is essential
4. **Regulatory gaps** — CERT-IN and DSCI obligations are not well-understood by OT operators; the tool surfaces these automatically

---

## 7. Escalation Configuration (`data/config/escalation.json`)

The escalation config defines:

- **Contacts** with Indian phone numbers (+91 format), email, and availability
- **Escalation rules** per risk level (LOW/MEDIUM/HIGH/CRITICAL) with:
  - Response time SLAs
  - Who to notify
  - Ordered action items
- **Reporting obligations** for CERT-IN and DSCI with deadlines and legal basis

The config is surfaced via `GET /api/config/escalation` and displayed on the
dashboard for operator reference during active incidents.

---

## 8. Integration Points (Future Enhancement)

### 8.1 SIEM Integration (Inbound)

Real SIEM/IDS alerts can be forwarded to the middleware via:

```
POST /api/alert
Content-Type: application/json

{
    "event_type": "FAILED_LOGIN",
    "asset_id": "water_treatment_plc",
    "severity": "high",
    "details": { "source_ip": "10.0.1.55", "user": "admin" }
}
```

Planned adapter layer: CEF/Syslog → JSON normaliser (future sprint).

### 8.2 SOAR Integration (Outbound)

Future webhook integration to push correlated incidents to SOAR platforms
(Splunk SOAR, IBM Resilient) for automated playbook execution.

### 8.3 Real Industrial Monitoring

Future integration with:
- **Modbus scanner** — poll PLC register changes and generate `PLC_PROGRAM_CHANGE` alerts
- **DNP3 collector** — monitor SCADA data quality and generate anomaly alerts
- **Passive network sensor** — detect new OT devices and protocol anomalies

### 8.4 Raspberry Pi Deployment

The tool is designed to run on a Raspberry Pi 4 (2 GB RAM):

```bash
pip install -r requirements.txt
python data/scenarios/generate_scenario_alerts.py  # seed test alerts
python dashboard/app.py                             # start middleware
```

No external dependencies beyond Python 3.9+ and SQLite (bundled with Python).

---

## 9. Research Gap Alignment

| Gap | How This Tool Addresses It |
|-----|--------------------------|
| **Gap 1**: Absence of intermediate decision layer | The middleware sits between raw alerts and operator action, providing correlation + risk scoring |
| **Gap 2**: Explainability for non-expert operators | Every incident includes plain-language explanation, formula breakdown, and DO/DON'T guidance |
| **Gap 3**: Real-time processing | Background thread polls alert directory every 10 seconds; HTTP endpoint supports sub-second ingestion |
| **Gap 4**: Non-SOC operator usability | Shift handover report, operator acknowledgement, and escalation contacts designed for non-security staff |

### Novel Contributions

1. **Scenario-Based Testing Framework** — MITRE ATT&CK ICS-aligned attack chains with Indian industrial context, unlike generic SIEM test data
2. **OT-Specific Safe Guidance** — Recommendations gated on `shutdown_risk` to prevent unsafe isolation of critical systems
3. **Indian Industrial Localisation** — Emergency contacts, asset locations, and CERT-IN/DSCI regulatory obligations embedded in the tool
4. **Temporal Correlation Without ML** — Rule-based time-windowed correlation achieves high accuracy with zero training data, suitable for resource-constrained environments
