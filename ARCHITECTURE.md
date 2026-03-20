# System Architecture — IT/OT Incident Response Tool v2

## Overview

This system is a lightweight, rule-based incident detection and response middleware
designed for small industrial facilities. It runs on commodity hardware (Raspberry Pi 4)
with no cloud dependency, no AI/ML, and no external SIEM required.

---

## Core Principles

| Principle | Implementation |
|---|---|
| No AI/ML | Pure rule-based logic — every decision is explainable |
| Safe-by-default | Dangerous actions require human approval before execution |
| Lightweight | SQLite + Flask — runs on 2 GB RAM |
| Interpretable | Plant managers can read and modify all rules in JSON |
| Auditable | Complete trail of every decision and action |

---

## Processing Pipeline

```
Alert Sources (PLCs, Logs, Network devices)
        │  JSON alert files written to data/alerts/
        ▼
Alert Ingestion Layer  (app.py /api/scan-alerts)
        │  Reads and deduplicates alert JSON files
        ▼
Rule Engine  (engine/rule_engine.py)
        │  Matches event_type + conditions against rules.json
        │  Detects brute force (5+ logins / 5 min window)
        │  Detects attack progression (recon → exploit)
        ▼
Dependency Engine  (engine/dependency_engine.py)
        │  Looks up asset in dependencies.json
        │  Calculates blast radius and cascading impact
        │  Identifies safe isolation points
        ▼
Safe Response Engine  (engine/safe_response_engine.py)
        │  Auto-executes safe actions immediately
        │  Queues dangerous actions for human approval
        ▼
Database  (models/database.py — SQLAlchemy + SQLite)
        │  Persists Incident, AuditLog, Alert, Asset records
        ▼
Dashboard  (templates/dashboard.html)
           Real-time display, approval buttons, auto-refresh
```

---

## Component Descriptions

### `engine/rule_engine.py`
- Loads rules from `config/rules.json`
- Matches alerts by `event_type` and optional conditions (`asset_criticality`, `any`)
- Maintains rolling alert history (capped at `ALERT_HISTORY_LIMIT`)
- Detects **brute force**: ≥ N `FAILED_LOGIN` events for same asset within time window
- Detects **attack progression**: `NETWORK_SCAN` in history followed by exploit-stage event
- Returns `matched_rules`, `correlations`, and `severity_multiplier`

### `engine/dependency_engine.py`
- Loads asset graph from `config/dependencies.json`
- Traverses `depended_on_by` edges to compute downstream blast radius
- Reports `directly_impacted` and `cascading_impacted` asset sets
- Identifies `safe_isolation_points` (assets where `shutdown_safe == true`)
- Validates configuration on load

### `engine/safe_response_engine.py`
- Classifies actions as **safe** or **dangerous**
- **Safe actions** (auto-executed): `block_ip`, `alert_team`, `take_snapshot`, `enable_logging`, `network_segment_monitor`
- **Dangerous actions** (approval required): `plc_shutdown`, `disconnect_power`, `system_restart`, `isolate_network`
- Maintains `pending_approvals` dict for approval workflow
- `approve_action()` / `deny_action()` update approval records

### `models/database.py`
- **Alert**: raw incoming alert records
- **Incident**: processed, correlated incidents with risk scores
- **Asset**: OT/IT asset metadata
- **AuditLog**: compliance trail for all automated and manual actions
- **CorrelationPattern**: multi-alert correlation records
- All tables created via SQLAlchemy `Base.metadata.create_all()`

### `app.py`
- Flask REST API with CORS support
- Endpoints: `/api/scan-alerts`, `/api/incidents`, `/api/incident/<id>`, `/api/dashboard-stats`, `/api/pending-approvals`, `/api/approve-action`, `/api/generate-test-alerts`
- Initialises all engines and database on startup

### `config/rules.json`
Each rule defines:
- `event_type`: triggering event
- `conditions`: optional extra match criteria
- `severity_multiplier`: risk score boost
- `response_actions`: ordered list of response actions
- `do_steps` / `dont_steps`: operator guidance

### `config/dependencies.json`
Each asset defines:
- `criticality`: `low | medium | high | critical`
- `shutdown_safe`: whether the asset can be isolated without safety risk
- `depends_on`: assets this asset requires to function
- `depended_on_by`: assets that depend on this asset

---

## Risk Scoring

```
base_score = (severity_score × 0.6 + criticality_score × 0.4) × severity_multiplier

CRITICAL : score ≥ 3.5
HIGH     : score ≥ 2.5
MEDIUM   : score ≥ 1.5
LOW      : score < 1.5
```

Correlated alerts (brute force / attack progression) force `CRITICAL` regardless of base score.

---

## Detection Capabilities

| Threat | Detection Method |
|---|---|
| Brute force | ≥ 5 `FAILED_LOGIN` events on same asset in 5-minute window |
| Unauthorized PLC change | `PLC_PROGRAM_CHANGE` on `critical`/`high` asset |
| Malware | `MALWARE_DETECTED` — any asset |
| Reconnaissance | `NETWORK_SCAN` — any asset |
| Firmware tampering | `FIRMWARE_MODIFICATION` — any asset |
| Multi-stage attack | `NETWORK_SCAN` → exploitation event in alert history |

---

## Deployment

### Local / Development
```bash
./setup.sh
source venv/bin/activate
python3 simulate.py   # Run simulations
python3 app.py        # Start at http://localhost:5000
pytest tests/ -v      # Run all unit tests
```

### Raspberry Pi Production (systemd)
```ini
[Unit]
Description=IT/OT Incident Response System
After=network.target

[Service]
User=pi
WorkingDirectory=/home/pi/it_ot_ir_tool_v2
ExecStart=/home/pi/it_ot_ir_tool_v2/venv/bin/python3 app.py
Restart=always
Environment=FLASK_ENV=production

[Install]
WantedBy=multi-user.target
```

---

## Failure Modes and Mitigation

| Failure | Mitigation |
|---|---|
| Rules file missing | Engine falls back to empty rules list; logs warning |
| Dependencies file missing | Engine returns unknown for all assets; continues |
| Alert file corrupt | Error logged; file skipped; other alerts processed |
| DB write failure | Exception caught; logged; incident returned in API response |
| Unknown action | Logged as warning; skipped; other actions proceed |

---

## Security Considerations

- No hardcoded secrets — all config via environment variables
- SQLAlchemy ORM prevents SQL injection
- Input validation on all API endpoints
- CORS configurable via `CORS_ORIGINS` env variable
- Approval workflow for any action that could disrupt production
- Complete audit trail for compliance

---

## Performance

| Metric | Value |
|---|---|
| Alert processing time | < 100 ms per alert |
| Memory at startup | ~ 150 MB |
| CPU idle | < 5 % |
| CPU while processing | ~ 30 % |
| Compatible hardware | Raspberry Pi 4 (2 GB RAM) |
