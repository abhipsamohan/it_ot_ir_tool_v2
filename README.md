# Portable IT–OT Incident Response Middleware (v2)

A lightweight, **OT-safe incident response decision-support prototype** designed for small/medium industrial environments that **do not have a dedicated SOC**. The system ingests security alerts, enriches them with OT asset context (criticality, shutdown risk, safety impact), performs rule-based correlation, and outputs **explainable, context-aware response guidance** via a web dashboard.

> Goal: help shift engineers / plant operators avoid unsafe “panic actions” (e.g., shutting down critical OT systems) by providing **safety-oriented recommendations** and escalation guidance.

---

## Key Capabilities

### 1) Multi-format alert ingestion (Format Abstraction Layer)
The middleware accepts alerts in **multiple common enterprise formats** and normalizes them into a single internal schema:

- **JSON (standard format)**
- **CEF / Syslog (enterprise SIEM / firewall / IDS)**
- **REST/Webhook (SOAR platforms)**

See: `engine/adapters/` and `docs/FORMAT_ADAPTERS.md`.

### 2) OT-aware risk scoring (severity + asset criticality)
Risk score is calculated as:

- `risk_score = (severity × 0.6) + (criticality × 0.4)`
- Thresholds map to: `LOW / MEDIUM / HIGH / CRITICAL`
- Every incident includes a plain-language **risk score explanation**

OT asset metadata comes from: `data/ot_context/ot_assets.json`.

### 3) Time-windowed correlation (multi-stage pattern detection)
The decision engine detects common multi-stage patterns (evaluated most-severe-first):

- `COORDINATED_ATTACK` (NETWORK_SCAN + FAILED_LOGIN + PLC_PROGRAM_CHANGE)
- `RECON_TO_ACCESS` (NETWORK_SCAN + FAILED_LOGIN)
- `BRUTE_FORCE` (≥5 FAILED_LOGIN on same asset within 10 minutes)
- `LATERAL_MOVEMENT` (FAILED_LOGIN across ≥3 different assets within 10 minutes)

When a correlation pattern is detected, risk is upgraded to **CRITICAL**.

### 4) Safety-aware response guidance (DO / DON’T)
For each incident, the middleware generates:
- **DO steps**: safe investigative actions
- **DON’T steps**: OT-specific safety constraints (e.g., *do not shut down without OT engineer approval* for high shutdown-risk assets)

### 5) Operator workflow + persistence
- Incidents are stored in **SQLite**: `data/incidents.db`
- Operators can **acknowledge** incidents with their name
- A **shift handover report** summarizes incidents for the last 8 hours

### 6) Dashboard UI
A lightweight HTML dashboard shows incidents, risk, warnings, correlation labels, DO/DON’T guidance, and acknowledgement status.

---

## Repository Structure

```
it_ot_ir_tool_v2/
├── dashboard/
│   ├── app.py                      # Flask API + background auto-scan thread
│   └── templates/dashboard.html    # Web dashboard UI
├── engine/
│   ├── decision_engine.py          # Risk scoring + correlation + safe guidance
│   ├── database.py                 # SQLite persistence + migrations
│   └── adapters/                   # Format abstraction layer (CEF/REST/JSON)
├── data/
│   ├── alerts/                     # Drop-zone for alert JSON files (auto-scanned)
│   ├── ot_context/ot_assets.json   # OT asset registry (criticality, shutdown risk, etc.)
│   ├── config/escalation.json      # Contacts, SLAs, CERT-IN/DSCI guidance
│   └── scenarios/                  # MITRE ATT&CK ICS scenario definitions + generator
├── docs/
│   ├── ARCHITECTURE.md
│   └── FORMAT_ADAPTERS.md
├── tests/
│   └── test_adapters.py
└── requirements.txt
```

---

## Quick Start (Local)

### 1) Clone
```bash
git clone https://github.com/abhipsamohan/it_ot_ir_tool_v2.git
cd it_ot_ir_tool_v2
```

### 2) Create virtual environment + install deps
```bash
python -m venv venv
# Windows: venv\Scripts\activate
source venv/bin/activate

pip install -r requirements.txt
```

### 3) (Optional) Generate demo scenario alerts
This creates scenario-based JSON alerts under `data/alerts/`.
```bash
python data/scenarios/generate_scenario_alerts.py
```

### 4) Run the dashboard + API
```bash
# Enable debug logs only if needed:
# export FLASK_DEBUG=1
python dashboard/app.py
```

Open:
- Dashboard: http://127.0.0.1:5000

---

## API Endpoints (Core)

- `POST /api/alert`  
  Ingest a single alert (JSON, CEF/Syslog text, or SOAR webhook JSON). Auto-detected + normalized.

- `GET /api/incidents`  
  List stored incidents (most recent first).

- `PUT /api/incidents/<incident_id>/acknowledge`  
  Mark incident as acknowledged. Body: `{ \"operator\": \"Name\" }`

- `GET /api/report/shift`  
  Shift summary (default: last 8 hours). Optional: `?since=<ISO timestamp>`

- `POST /api/assets/reload`  
  Reload `ot_assets.json` without restart.

- `GET /api/config/escalation`  
  Return escalation contacts/rules (from `data/config/escalation.json`).

- `GET /api/adapters`  
  List supported input formats.

---

## Example: Send Alerts (Multi-format)

### A) Standard JSON
```bash
curl -X POST http://127.0.0.1:5000/api/alert \
  -H \"Content-Type: application/json\" \
  -d '{\"event_type\":\"FAILED_LOGIN\",\"asset_id\":\"water_treatment_plc\",\"severity\":\"high\",\"timestamp\":\"2026-04-15T10:30:00\"}'
```

### B) CEF (text/plain)
```bash
curl -X POST http://127.0.0.1:5000/api/alert \
  -H \"Content-Type: text/plain\" \
  -d 'CEF:0|Splunk|IDS|1.0|123456|Failed Authentication|7|src=192.168.1.100 dst=192.168.1.50 msg=Failed login attempt'
```

### C) SOAR webhook envelope
```bash
curl -X POST http://127.0.0.1:5000/api/alert \
  -H \"Content-Type: application/json\" \
  -d '{\n    \"alert\": {\n      \"name\": \"Malware Detection\",
      \"severity\": \"critical\",
      \"source\": \"Phantom\",
      \"asset\": \"manufacturing_robot_ctrl\"
    },\n    \"context\": { \"indicators\": [\"hash1\", \"hash2\"] }
  }'
```

---

## Demo Checklist (What to show in presentation)

1. Start server: `python dashboard/app.py`
2. Generate scenarios: `python data/scenarios/generate_scenario_alerts.py`
3. Open dashboard and show:
   - Risk score + explanation
   - Correlation labels (e.g., BRUTE_FORCE)
   - OT safety warning / DO-DON’T steps
4. Acknowledge an incident with operator name
5. Show shift report (`/api/report/shift`)
6. Send a CEF/SOAR alert via curl to demonstrate format abstraction

---

## Notes / Limitations (Prototype)
- Rule-based correlation patterns (no ML).
- Requires accurate asset metadata (`ot_assets.json`) for best safety guidance.
- Designed for lightweight local deployment (e.g., laptops / Raspberry Pi-class devices).

---

## Documentation
- Architecture: `docs/ARCHITECTURE.md`
- Format adapters + examples: `docs/FORMAT_ADAPTERS.md`
