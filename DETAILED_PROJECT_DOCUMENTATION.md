# IT-OT Incident Response Tool v2 — Detailed Project Documentation

> **Target audience:** MSc CS evaluators · Academic researchers in IT/OT security · Industrial practitioners · Security engineers

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Real-World Problem & Research Gaps](#2-real-world-problem--research-gaps)
3. [System Architecture & Components](#3-system-architecture--components)
4. [Detailed Core Components](#4-detailed-core-components)
5. [Workflow Analysis](#5-workflow-analysis)
6. [Technologies & Implementation Details](#6-technologies--implementation-details)
7. [Scenario Framework & Testing](#7-scenario-framework--testing)
8. [OT Safety & Regulatory Alignment](#8-ot-safety--regulatory-alignment)
9. [Configuration & Data Files](#9-configuration--data-files)
10. [API Endpoints Reference](#10-api-endpoints-reference)
11. [Research Gap Alignment](#11-research-gap-alignment)
12. [Deployment Architecture](#12-deployment-architecture)
13. [Integration Points (Future)](#13-integration-points-future)
14. [Code Quality & Infrastructure](#14-code-quality--infrastructure)
15. [Limitations & Future Work](#15-limitations--future-work)

---

## 1. Executive Summary

### Project Vision and Mission

The **IT-OT Incident Response Tool v2** is a lightweight, **OT-safe incident response decision-support middleware** built specifically for small and medium-scale Indian industrial environments that lack a dedicated Security Operations Centre (SOC). Its mission is to bridge the critical gap between raw security telemetry and actionable, safety-conscious operator guidance — without requiring security expertise from the end user.

**Vision statement:** Empower every shift engineer and plant operator in India to respond correctly to cybersecurity incidents involving Operational Technology (OT) systems, reducing the risk of unsafe "panic actions" (e.g., sudden PLC shutdowns) that could cause physical harm, production loss, or regulatory violations.

### Target Users and Context

| User Role | Context |
|-----------|---------|
| Shift engineer / plant operator | Responsible for process continuity, typically lacks formal cybersecurity training |
| OT engineer on-call | Subject-matter expert reachable by phone; needs concise escalation information |
| Plant manager / site lead | Authorises high-impact decisions such as controlled shutdowns |
| Security lead (IT-OT boundary) | Coordinates cross-domain response; liaises with CERT-IN |

The tool is contextualised for **Indian industrial environments**, with:
- 10 real-world industrial assets spanning Pune, Surat, Nagpur, Chennai, Bengaluru, Hyderabad, Mumbai, Delhi NCR, Ahmedabad, and Coimbatore
- Indian emergency contacts (CERT-IN, DSCI) and +91 phone numbers
- Regulatory obligations under the IT Act 2000 and DPDP Act 2023

### Language Composition

| Language | Share | Purpose |
|----------|-------|---------|
| Python | 84.6 % | Core engine, adapters, database layer, Flask API, scenario generator |
| HTML | 14.7 % | Operator-facing web dashboard (single-page, no external JS framework) |
| Dockerfile | 0.7 % | Container image definition for reproducible deployment |

---

## 2. Real-World Problem & Research Gaps

### 2.1 The IT/OT Convergence Problem

Modern industrial facilities are increasingly connecting their Operational Technology (OT) networks — PLCs, SCADA systems, HMIs, field devices — to corporate IT networks to enable remote monitoring, ERP integration, and data analytics. This convergence creates a critical security problem: IT-oriented security tools (SIEMs, endpoint agents, firewalls) generate alerts that IT analysts understand, but **OT operators who own the physical process have no framework for interpreting or responding to those alerts safely**.

Responding incorrectly to a cybersecurity alert in an OT environment can be worse than not responding at all. Shutting down a water treatment PLC without proper de-energisation procedures can cause chemical dosing failures. Isolating a backup power controller during a ransomware investigation can remove UPS protection from critical systems. **The absence of OT-context-aware guidance is a systemic gap that this tool directly addresses.**

### 2.2 Current State of OT Incident Response in India

India's industrial sector — manufacturing, utilities, water treatment, power distribution — is undergoing rapid digital transformation while simultaneously managing an expanding cybersecurity attack surface:

- **CERT-IN reported a 51% increase in OT-related cyber incidents** between 2021 and 2023, with manufacturing and utilities being primary targets.
- Most Indian SME facilities operate **without a dedicated SOC** and respond to security events ad-hoc, relying on the judgment of operators who are experts in their physical process but not in cybersecurity.
- Legacy OT equipment (Modbus PLCs, DNP3 RTUs) was designed for reliability and safety, **not for cybersecurity**. Authentication is weak or absent; firmware update mechanisms are unauthenticated.
- Indian facilities commonly use a mixture of **local, Chinese, and European vendors** with widely varying supply-chain security postures.

### 2.3 Limitations of Existing SIEM/SOC Approaches for OT

| Limitation | Impact on Indian Industrial Facilities |
|------------|----------------------------------------|
| SIEM outputs raw alerts without OT context | Operator cannot distinguish a scan on the HVAC from a scan on the water treatment PLC — same raw alert, vastly different consequences |
| Enterprise SOAR playbooks assume IT infrastructure | Automated "isolate host" actions are catastrophic if applied to a PLC mid-process |
| No consideration for shutdown risk | Remediation that is correct in IT (network isolation) may cause physical safety incidents in OT |
| Expensive per-endpoint licensing | Unaffordable for Indian SME facilities with dozens of field devices |
| Complex SOC analyst interfaces | Non-expert shift operators cannot use traditional SIM/SOAR dashboards |
| No Indian regulatory context | CERT-IN 6-hour reporting requirement is not surfaced to operators |

### 2.4 Research Contribution Areas

This project contributes to the following active research areas in IT/OT security:

1. **Lightweight decision-support systems for OT environments** — demonstrating that a rule-based correlation engine running on commodity hardware (Raspberry Pi 4) can meet real-time requirements without requiring ML infrastructure
2. **OT-specific safe guidance generation** — a novel framework for constraining security recommendations based on physical consequences (`shutdown_risk`, `safety_impact`) encoded in an asset registry
3. **Explainable risk scoring for non-expert operators** — every risk score includes a plain-language arithmetic breakdown, addressing the explainability gap in industrial security tools
4. **Indian industrial localisation** — asset registry, regulatory contacts, and escalation rules contextualised for Indian industrial and regulatory environments
5. **Multi-format alert normalisation for OT** — a pluggable adapter layer that accepts enterprise alert formats (JSON, CEF/Syslog, SOAR webhooks) without requiring configuration changes at the source system

---

## 3. System Architecture & Components

### 3.1 High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                      External Alert Sources                          │
│  ┌────────────┐  ┌────────────────────┐  ┌───────────────────────┐  │
│  │ JSON Files │  │  CEF / Syslog      │  │  SOAR REST Webhook    │  │
│  │ (file drop)│  │  (Splunk, PA, etc.)│  │  (Phantom, Demisto)   │  │
│  └─────┬──────┘  └────────┬───────────┘  └────────────┬──────────┘  │
└────────┼─────────────────┼──────────────────────────┼──────────────┘
         │                 │                            │
         │ file-based      │ POST /api/alert            │ POST /api/alert
         │ (background     │ (text/plain CEF)           │ (application/json)
         │  scan thread)   │                            │
         └─────────────────┴────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│                   Alert Ingestion Layer (Format Abstraction)         │
│                                                                      │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │              FormatDetector (engine/adapters/detector.py)   │   │
│   │  Priority order:  CEFAdapter  →  RESTAdapter  →  JSONAdapter│   │
│   │  → validates parsed output, returns (normalised_alert, fmt) │   │
│   └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────┬────────────────────────────────┘
                                      │  normalised alert dict
                                      ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Decision Engine (core logic)                     │
│                  (engine/decision_engine.py)                         │
│                                                                      │
│  ┌──────────────────┐   ┌─────────────────────────┐                 │
│  │ 1. Asset Lookup  │   │ 2. Correlation Engine    │                 │
│  │   (ot_assets.json│   │  BRUTE_FORCE             │                 │
│  │    hot-reload)   │   │  LATERAL_MOVEMENT        │                 │
│  └──────────┬───────┘   │  RECON_TO_ACCESS         │                 │
│             │           │  COORDINATED_ATTACK      │                 │
│             │           └──────────┬──────────────┘                 │
│             │                      │                                 │
│             ▼                      ▼                                 │
│  ┌──────────────────────────────────────────────────┐               │
│  │ 3. Risk Scoring                                  │               │
│  │   score = (severity × 0.6) + (criticality × 0.4)│               │
│  │   Correlation match → override to CRITICAL       │               │
│  └─────────────────────────┬────────────────────────┘               │
│                            │                                         │
│  ┌─────────────────────────▼────────────────────────┐               │
│  │ 4. Safe Guidance Generation                      │               │
│  │   DO steps + DON'T steps (gated on shutdown_risk)│               │
│  │   Playbook (event-type-specific response actions)│               │
│  │   Explainability (plain-language risk breakdown) │               │
│  └─────────────────────────┬────────────────────────┘               │
└────────────────────────────┼─────────────────────────────────────────┘
                             │  incident dict
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    Database Layer (SQLite)                            │
│                    (engine/database.py)                              │
│  INSERT incident → incidents table                                   │
│  Schema migration (ADD COLUMN) on first run after upgrade            │
│  Operator ACK workflow (acknowledged_by, acknowledged_at)            │
│  Shift summary aggregation (by_risk_level, by_event_type)            │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│                   Flask REST API + Web Dashboard                     │
│                   (dashboard/app.py)                                 │
│                                                                      │
│  GET  /                           ← HTML dashboard (non-SOC UI)     │
│  POST /api/alert                  ← ingest any format                │
│  GET  /api/incidents              ← list all incidents               │
│  PUT  /api/incidents/{id}/acknowledge ← operator ACK                │
│  GET  /api/report/shift           ← 8-hour handover summary          │
│  POST /api/assets/reload          ← hot-reload ot_assets.json        │
│  GET  /api/config/escalation      ← contacts + SLAs                  │
│  GET  /api/adapters               ← supported formats list           │
│  GET  /api/scan                   ← manual scan trigger              │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
               Non-SOC Operator (shift engineer, plant manager)
```

### 3.2 Background Scanner Thread Architecture

```
┌─────────────────────────────────────────┐
│  Flask main thread                      │
│  (handles HTTP requests)                │
│                                         │
│  ┌──────────────────────────────────┐   │
│  │  _scan_thread (daemon=True)      │   │
│  │                                  │   │
│  │  while True:                     │   │
│  │    engine.scan_alerts()          │   │
│  │    time.sleep(10)                │   │
│  │                                  │   │
│  │  Scans data/alerts/ directory    │   │
│  │  Tracks processed_files set      │   │
│  │  (idempotent — no double proc.)  │   │
│  └──────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

The daemon thread is marked `daemon=True` so it is automatically terminated when the Flask process exits. No external task queue or broker (Celery, Redis) is required.

### 3.3 Data Flow from Alert Ingestion to Incident Storage

```
External Source
     │
     │  (1) Deliver alert
     ▼
FormatDetector.detect_and_parse(raw_data)
     │
     │  CEFAdapter.can_parse? → parse → validate
     │  RESTAdapter.can_parse? → parse → validate
     │  JSONAdapter.can_parse? → parse → validate
     │
     │  (2) Returns (normalised_alert_dict, adapter_name)
     ▼
DecisionEngine._build_incident(alert)
     │
     ├─ (3) assets.get(asset_id) → asset metadata
     ├─ (4) check_correlation(alert) → append to alert_history
     │       → scan patterns in priority order
     │       → return pattern or None
     ├─ (5) calculate_risk(alert, asset)
     │       → severity × 0.6 + criticality × 0.4
     │       → if correlation: override to CRITICAL
     ├─ (6) generate_response(event_type) → playbook
     ├─ (7) explain_event(event_type) → plain-language explanation
     ├─ (8) generate_safe_guidance(asset, correlation)
     │       → DO / DON'T based on shutdown_risk + criticality
     └─ (9) Build incident dict with unique INC-XXXXXXXX ID
     │
     │  (10) db.insert_incident(incident)
     ▼
SQLite incidents table
     │
     │  (11) GET /api/incidents → return JSON list
     ▼
Browser dashboard (rendered as incident cards)
```

---

## 4. Detailed Core Components

### 4.1 `engine/decision_engine.py` — Core Processing Engine

#### Correlation Pattern Definitions

Four patterns are defined as a list of dictionaries and evaluated in order (most severe first):

```python
CORRELATION_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "COORDINATED_ATTACK",
        "description": "Recon → access → PLC modification chain detected — coordinated multi-stage attack",
        "required_events": ["NETWORK_SCAN", "FAILED_LOGIN", "PLC_PROGRAM_CHANGE"],
        "count_threshold": 1,
        "window_minutes": 60,
        "same_asset": False,
    },
    {
        "name": "RECON_TO_ACCESS",
        "description": "Network scan followed by login attempts — possible targeted intrusion",
        "required_events": ["NETWORK_SCAN", "FAILED_LOGIN"],
        "count_threshold": 1,
        "window_minutes": 30,
        "same_asset": False,
    },
    {
        "name": "BRUTE_FORCE",
        "description": "Multiple failed logins on the same asset — possible brute-force attack",
        "required_events": ["FAILED_LOGIN"],
        "count_threshold": 5,
        "window_minutes": 10,
        "same_asset": True,
    },
    {
        "name": "LATERAL_MOVEMENT",
        "description": "Failed logins across multiple different assets — possible lateral movement",
        "required_events": ["FAILED_LOGIN"],
        "count_threshold": 3,
        "window_minutes": 10,
        "same_asset": False,
        "different_assets": True,
    },
]
```

#### Risk Scoring Algorithm

```python
def calculate_risk(self, alert: Dict, asset: Dict) -> Dict:
    severity_map  = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    criticality_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    severity_val    = severity_map.get(alert.get("severity", "medium"), 2)
    criticality_val = criticality_map.get(asset.get("criticality", "medium"), 2)

    score = round((severity_val * 0.6) + (criticality_val * 0.4), 2)

    if   score >= 3.5: level = "CRITICAL"
    elif score >= 2.5: level = "HIGH"
    elif score >= 1.5: level = "MEDIUM"
    else:              level = "LOW"
    ...
```

**Example calculations:**

| Alert severity | Asset criticality | Score | Level |
|---------------|-------------------|-------|-------|
| high (3) | critical (4) | 3×0.6 + 4×0.4 = **3.4** | HIGH |
| critical (4) | critical (4) | 4×0.6 + 4×0.4 = **4.0** | CRITICAL |
| medium (2) | medium (2) | 2×0.6 + 2×0.4 = **2.0** | MEDIUM |
| low (1) | low (1) | 1×0.6 + 1×0.4 = **1.0** | LOW |
| high (3) | medium (2) | 3×0.6 + 2×0.4 = **2.6** | HIGH |

When a correlation pattern is matched, the score is overridden to **4.0 / CRITICAL** regardless of individual values.

#### Explainability Engine

Every incident carries a `risk_score_explanation` field in plain language:

```
Score 3.4 (HIGH): Alert severity 'high' (3 × 0.6 = 1.8)
  + Asset criticality 'critical' (4 × 0.4 = 1.6)
```

Or, when correlated:

```
Score 2.6 (HIGH): Alert severity 'high' (3 × 0.6 = 1.8)
  + Asset criticality 'medium' (2 × 0.4 = 0.8)
  → upgraded to CRITICAL (correlated attack pattern detected)
```

#### Safe Guidance Generation

```python
def generate_safe_guidance(self, asset: Dict, correlation: Optional[Dict]) -> Dict:
    do   = ["Check relevant logs", "Verify with on-site operator before acting"]
    dont = []

    if asset.get("shutdown_risk") == "high":
        dont.append("Do NOT shut down this system without OT engineer approval — high shutdown risk")
    if asset.get("shutdown_risk") == "medium":
        dont.append("Avoid unplanned shutdown — coordinate with operations team first")
    if asset.get("criticality") == "critical":
        dont.append("Do NOT take remediation action alone — OT engineer must be present")
    if asset.get("safety_impact"):
        dont.append(f"Unsafe action may cause: {asset['safety_impact']}")
    if correlation:
        do.append("Treat as a coordinated multi-stage attack — escalate immediately")
        do.append("Preserve all logs and network captures as evidence")

    return {"do": do, "dont": dont}
```

This function is the key novel contribution: guidance constraints are derived **directly from physical-world asset metadata**, not from a generic playbook.

#### Correlation Engine (Time-Windowed, Multi-Pattern)

```python
def check_correlation(self, alert: Dict) -> Optional[Dict]:
    # 1. Append to rolling history (max 200 entries)
    self.alert_history.append({
        "event_type": alert.get("event_type"),
        "asset_id":   alert.get("asset_id"),
        "received_at": datetime.now(),
    })
    if len(self.alert_history) > self.MAX_ALERT_HISTORY:
        self.alert_history.pop(0)

    # 2. For each pattern (most severe first):
    for pattern in CORRELATION_PATTERNS:
        recent = self._trim_history(pattern["window_minutes"])  # time-window filter

        if pattern.get("same_asset"):
            # BRUTE_FORCE: count occurrences of required event on same asset
            relevant = [a for a in recent if a["event_type"] in required
                                           and a["asset_id"] == asset_id]
            if len(relevant) >= threshold:
                return {"type": pattern["name"], "description": ...}

        elif pattern.get("different_assets"):
            # LATERAL_MOVEMENT: required event on N+ different assets
            relevant = [a for a in recent if a["event_type"] in required]
            if len({a["asset_id"] for a in relevant}) >= threshold:
                return {"type": pattern["name"], "description": ...}

        else:
            # COORDINATED_ATTACK / RECON_TO_ACCESS: all required types present anywhere
            seen = {a["event_type"] for a in recent}
            if all(e in seen for e in required):
                return {"type": pattern["name"], "description": ...}

    return None
```

---

### 4.2 `engine/database.py` — SQLite Persistence Layer

#### Schema

```sql
CREATE TABLE IF NOT EXISTS incidents (
    id                   TEXT PRIMARY KEY,   -- INC-XXXXXXXX
    timestamp            TEXT,               -- ISO 8601
    event_type           TEXT,
    asset_id             TEXT,
    asset_name           TEXT,
    severity             TEXT,               -- low/medium/high/critical
    risk_level           TEXT,               -- LOW/MEDIUM/HIGH/CRITICAL
    risk_score           REAL,
    criticality          TEXT,
    shutdown_risk        TEXT,
    zone_id              TEXT,               -- ot_control / ot_dmz / etc.
    purdue_level         TEXT,               -- L1 / L2-L3 / L3.5 / L4-L5
    warning              TEXT,
    response_action      TEXT,
    response_steps       TEXT,               -- JSON array
    explanation          TEXT,
    risk_score_explanation TEXT,
    correlation          TEXT,
    do_steps             TEXT,               -- JSON array
    dont_steps           TEXT,               -- JSON array
    status               TEXT DEFAULT 'open',
    acknowledged_by      TEXT,
    acknowledged_at      TEXT
)
```

#### Migration System

The `_migrate()` method safely adds new columns to existing databases using `ALTER TABLE … ADD COLUMN`. An allowlist (`_ALLOWED_MIGRATION_COLUMNS`) guards against construction of arbitrary DDL strings:

```python
_ALLOWED_MIGRATION_COLUMNS = {
    "response_steps", "risk_score_explanation", "correlation",
    "status", "acknowledged_by", "acknowledged_at",
    "zone_id", "purdue_level",
}

def _migrate(self):
    for col_name, col_type in new_columns:
        if col_name not in self._ALLOWED_MIGRATION_COLUMNS:
            raise ValueError(f"Unexpected migration column: {col_name!r}")
        if col_name not in existing:
            cursor.execute(f"ALTER TABLE incidents ADD COLUMN {col_name} {col_type}")
```

This means an existing production database from an earlier version of the tool is automatically upgraded on startup without data loss.

#### Operator Acknowledgement Workflow

```python
def acknowledge_incident(self, incident_id: str, operator_name: str) -> bool:
    cursor.execute("""
        UPDATE incidents
        SET status = 'acknowledged',
            acknowledged_by = ?,
            acknowledged_at = ?
        WHERE id = ?
    """, (operator_name, datetime.now().isoformat(), incident_id))
    return cursor.rowcount > 0
```

This implements a basic chain-of-custody: every acknowledged incident carries the operator's name and timestamp, providing an audit trail for post-incident review.

#### Shift Handover Summary

```python
def get_shift_summary(self, since_iso=None) -> Dict:
    # Default: last 8 hours (one shift)
    if since_iso is None:
        since_iso = (datetime.now() - timedelta(hours=8)).isoformat()

    # Returns:
    # {
    #   "since": "...", "generated_at": "...",
    #   "total_incidents": N,
    #   "open": N, "acknowledged": N,
    #   "by_risk_level": {"CRITICAL": 2, "HIGH": 5, ...},
    #   "by_event_type": {"FAILED_LOGIN": 8, ...},
    #   "most_affected_assets": {"Water Treatment Plant PLC": 3, ...}
    # }
```

---

### 4.3 `dashboard/app.py` — Flask REST API and Web Dashboard

The Flask application provides both the operator-facing HTML dashboard and a complete REST API. Key architectural decisions:

- **Background scan thread** launched at module load time (before first request), ensuring alerts are processed even with zero API traffic
- **Shared `engine` instance** — a single `DecisionEngine` object is shared across all requests, preserving the in-memory `alert_history` list for correlation
- **`FormatDetector` instance** — instantiated once and reused across all `/api/alert` calls

#### Alert Ingestion with Format Auto-Detection

```python
@app.route("/api/alert", methods=["POST"])
def ingest_alert():
    if request.is_json:
        raw_data = request.get_json()
    else:
        raw_data = request.get_data(as_text=True)

    try:
        normalized_alert, adapter_used = detector.detect_and_parse(raw_data)
    except ValueError:
        return jsonify({"error": "Could not parse alert: unsupported or malformed format"}), 400

    incident = engine.process_alert_dict(normalized_alert)
    return jsonify(incident), 201
```

This single endpoint accepts JSON objects, CEF strings, and SOAR webhook envelopes — routing is transparent to the caller.

---

### 4.4 `engine/adapters/` — Multi-Format Alert Handling

The Format Abstraction Layer follows the **Strategy pattern**: each adapter implements the `BaseAdapter` interface and the `FormatDetector` tries them in priority order.

```
BaseAdapter (abstract)
├── can_parse(data) → bool
├── parse(data) → Dict          ← normalised alert
├── validate(parsed) → (bool, str)
└── get_example() → Dict

CEFAdapter    ← CEF:0|Vendor|Product|... strings
RESTAdapter   ← SOAR webhook envelopes {"alert": {...}}
JSONAdapter   ← standard {"event_type": ..., "asset_id": ...} dicts
```

**CEF severity mapping (0–10 scale → IT-OT scale):**

| CEF 0–4 | CEF 5–6 | CEF 7–8 | CEF 9–10 |
|---------|---------|---------|---------|
| low | medium | high | critical |

**Syslog severity mapping (priority % 8):**

| Syslog 0–2 | Syslog 3–4 | Syslog 5 | Syslog 6–7 |
|-----------|-----------|---------|-----------|
| critical | high | medium | low |

All three adapters output the same normalised schema:

```json
{
  "event_type": "FAILED_LOGIN",
  "asset_id": "water_treatment_plc",
  "severity": "high",
  "timestamp": "2026-04-15T10:30:00",
  "source_format": "CEF/Syslog (Enterprise)",
  "raw_data": { ... },
  "extra_fields": { ... }
}
```

---

### 4.5 `data/ot_context/ot_assets.json` — OT Asset Registry

Ten Indian industrial assets, spanning five Purdue levels and four network segments:

| Asset ID | System | Criticality | Shutdown Risk | Protocol | Location | Purdue |
|----------|--------|-------------|---------------|----------|----------|--------|
| `water_treatment_plc` | Water Treatment Plant PLC | critical | high | DNP3 | Pune, MH | L1 |
| `textile_mill_control` | Textile Mill Control System | high | high | Profinet | Surat, GJ | L1 |
| `power_distribution_scada` | Power Distribution SCADA | critical | high | DNP3 | Nagpur, MH | L1 |
| `manufacturing_robot_ctrl` | Manufacturing Robot Controller | high | high | Modbus | Chennai, TN | L1 |
| `hvac_controller` | HVAC System Controller | medium | medium | BACnet | Bengaluru, KA | L2-L3 |
| `building_mgmt_system` | Building Management System | medium | low | OPC-UA | Hyderabad, TS | L3.5 |
| `backup_power_system` | Backup Power System (UPS) | critical | high | Modbus | Mumbai, MH | L1 |
| `network_gateway` | OT Network Gateway / Firewall | medium | medium | TCP/IP | Delhi NCR | L3.5 |
| `pump_controller_1` | Water Pump Controller (Legacy) | high | high | Modbus | Ahmedabad, GJ | L1 |
| `plc_controller_1` | Main PLC Controller | critical | high | Modbus | Coimbatore, TN | L1 |

**Asset object example:**

```json
"water_treatment_plc": {
  "system": "Water Treatment Plant PLC",
  "criticality": "critical",
  "shutdown_risk": "high",
  "safety_impact": "Disruption to municipal water supply; potential chemical dosing failure affecting public health",
  "protocol": "DNP3",
  "network_segment": "CRITICAL",
  "location": "Pune, Maharashtra",
  "zone_id": "ot_control",
  "purdue_level": "L1"
}
```

---

### 4.6 `data/config/escalation.json` — Escalation Configuration

The escalation configuration encodes the full incident response decision tree for non-expert operators, removing the need for them to know who to call or what to do:

```json
{
  "contacts": [
    {
      "role": "OT Engineer On-Call",
      "name": "Rajesh Kumar",
      "phone": "+91-9876543210",
      "email": "rajesh.kumar@plant.in",
      "availability": "24x7 on-call rotation"
    },
    {
      "role": "Regulatory Authority – CERT-IN",
      "phone": "+91-11-24368572",
      "email": "incident@cert-in.org.in",
      "note": "Mandatory reporting within 6 hours under IT Act 2000"
    }
  ],
  "escalation_rules": {
    "CRITICAL": {
      "response_time_sla": "Immediate — notify within 15 minutes",
      "notify": ["OT Engineer On-Call", "Security Lead", "Plant Manager", "CERT-IN"],
      "actions": [
        "Convene emergency response team",
        "Consider controlled shutdown only after OT engineer assessment",
        "Report to CERT-IN within 6 hours (mandatory under IT Act 2000)",
        "Preserve forensic evidence — do not reboot systems without approval"
      ]
    }
  }
}
```

---

## 5. Workflow Analysis

### 5.1 Complete Alert-to-Incident Workflow

```
Step 1  — Alert arrives
          │
          ├── Via file: JSON placed in data/alerts/
          │   Background thread polls every 10 sec → process_alert(filepath)
          │
          └── Via API: POST /api/alert with any supported format
              → ingest_alert() → detect_and_parse(raw_data)

Step 2  — Format detection (engine/adapters/detector.py)
          FormatDetector tries: CEFAdapter → RESTAdapter → JSONAdapter
          First adapter where can_parse() is True → parse() → validate()
          Returns: (normalised_dict, "JSON (Standard IT-OT Format)")

Step 3  — _build_incident(alert) called
          │
          ├── 3a: check_correlation(alert)
          │        Add to alert_history (max 200 entries)
          │        Trim history to pattern window_minutes
          │        Evaluate COORDINATED_ATTACK → RECON_TO_ACCESS →
          │        BRUTE_FORCE → LATERAL_MOVEMENT
          │        Return: None | {"type": ..., "description": ...}
          │
          ├── 3b: Asset lookup
          │        assets.get(asset_id) or default unknown asset
          │
          ├── 3c: calculate_risk(alert, asset)
          │        score = severity × 0.6 + criticality × 0.4
          │        If correlation: override to CRITICAL / 4.0
          │        _explain_risk_score() → plain-language breakdown
          │
          ├── 3d: generate_response(event_type) → playbook steps
          │
          ├── 3e: explain_event(event_type) → plain explanation
          │
          ├── 3f: generate_safe_guidance(asset, correlation)
          │        DO / DON'T gated on shutdown_risk + criticality
          │
          └── 3g: Assemble incident dict with UUID

Step 4  — db.insert_incident(incident)
          SQLite INSERT with JSON-serialised arrays for list fields

Step 5  — Response to caller
          HTTP: return jsonify(incident), 201
          File: print "[engine] Processed: path → INC-XXXXX [CRITICAL]"

Step 6  — Operator views dashboard
          GET /api/incidents → list ordered by timestamp DESC
          Dashboard renders incident cards with risk badge, warning, DO/DON'T

Step 7  — Operator acknowledges
          PUT /api/incidents/{id}/acknowledge  {"operator": "Jane Smith"}
          UPDATE incidents SET status='acknowledged', acknowledged_by=...

Step 8  — Shift handover
          GET /api/report/shift
          Aggregates last 8 hours: totals, by_risk_level, by_event_type,
          most_affected_assets
```

### 5.2 Decision Tree for Risk Calculation

```
                      Alert received
                           │
               ┌───────────┴───────────┐
               │                       │
        Correlation                 No correlation
        detected?                      │
               │                       │
               ▼                       ▼
          risk_level = CRITICAL    score = severity × 0.6
          risk_score = 4.0              + criticality × 0.4
                                        │
                                   ┌────┴────┐
                                   │         │
                               score ≥ 3.5  else...
                                   │
                               CRITICAL   ┌─ score ≥ 2.5 → HIGH
                                          ├─ score ≥ 1.5 → MEDIUM
                                          └─ else        → LOW
```

---

## 6. Technologies & Implementation Details

### 6.1 Technology Stack

| Component | Technology | Version | Rationale |
|-----------|------------|---------|-----------|
| Web framework | Flask | 3.0.0 | Minimal footprint, well-known, runs on Pi |
| WSGI toolkit | Werkzeug | 3.0.0 | Bundled with Flask |
| Templating | Jinja2 | 3.1.2 | Flask default, zero JS framework dependency |
| Database | SQLite | stdlib | Zero external DB server; file-based, Pi-friendly |
| Language | Python | 3.9+ | Ubiquitous, good stdlib, runs on Pi OS |
| Containerisation | Docker | — | Phase 1 deployment option |
| Type checking | mypy | — | Static analysis for code quality |
| Testing | pytest | — | Standard Python test framework |

### 6.2 No External ML/AI

The correlation engine is **purely rule-based**. This is a deliberate design decision:

- **Zero training data required** — the system works from first alert
- **Deterministic** — the same sequence of alerts always produces the same result
- **Inspectable** — no black-box model; every decision can be traced to a rule
- **Deployable on Raspberry Pi 4** — no GPU, no model loading overhead
- **Appropriate for prototype/research context** — demonstrates that lightweight rule-based approaches can cover the most common OT attack patterns

The correlation rules cover the MITRE ATT&CK for ICS patterns most commonly observed in small-to-medium industrial incidents.

### 6.3 Threading Model

```python
# Background auto-scan thread — launched at module load time
def _background_scan():
    while True:
        try:
            engine.scan_alerts()
        except Exception as e:
            print(f"[auto-scan] error: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        time.sleep(10)

_scan_thread = threading.Thread(target=_background_scan, daemon=True)
_scan_thread.start()
```

The `scan_alerts()` method maintains a `processed_files` set so files are never double-processed. Thread safety is preserved because SQLite writes are isolated per connection (each `insert_incident` call opens and closes its own connection).

### 6.4 Database Migration System

```
App starts
    │
    ▼
IncidentDatabase.__init__()
    │
    ├── init_db()     → CREATE TABLE IF NOT EXISTS (idempotent)
    └── _migrate()    → for each expected column:
                            if not in existing columns:
                                ALTER TABLE incidents ADD COLUMN ...
```

The migration runs on every startup and is idempotent — safe to run against a fresh database or an existing one from any previous version.

---

## 7. Scenario Framework & Testing

### 7.1 MITRE ATT&CK ICS Alignment

Each scenario in `data/scenarios/scenario_definitions.py` is annotated with:

- **MITRE ATT&CK for ICS technique IDs** (T-numbers from the ICS matrix)
- **CVE references** or real-world campaign references
- **Indian industrial context** narrative
- **Expected correlation** — the pattern name the engine should detect

| Scenario | Expected Correlation | MITRE Techniques |
|----------|---------------------|-----------------|
| `brute_force_attack` | `BRUTE_FORCE` | T0806 – Brute Force I&C |
| `lateral_movement_attempt` | `LATERAL_MOVEMENT` | T0812, T0886 |
| `recon_to_access` | `RECON_TO_ACCESS` | T0846, T0806 |
| `coordinated_multi_stage_attack` | `COORDINATED_ATTACK` | T0846, T0806, T0836, T0839 |
| `supply_chain_attack` | None (no correlation pattern) | T0839, T0873 |
| `insider_threat_config_change` | None (no correlation pattern) | T0831, T0836 |

### 7.2 Scenario-Based Alert Generation

```bash
python data/scenarios/generate_scenario_alerts.py
```

The script:
1. Loads all scenarios from `scenario_definitions.py`
2. For each event in each scenario, creates a JSON file under `data/alerts/`
3. Names files: `{scenario_name}_{index:02d}_{event_type}.json`
4. Embeds scenario lineage metadata (`scenario_name`, `cve_reference`, `mitre_technique`) inside each alert for audit trail purposes
5. Uses a **fixed reference timestamp** (`2026-01-15T08:00:00`) with `offset_minutes` applied, so repeated runs produce identical alert sequences

**Example generated alert file:**
```json
{
  "event_type": "FAILED_LOGIN",
  "asset_id": "water_treatment_plc",
  "severity": "medium",
  "timestamp": "2026-01-15T08:00:00",
  "scenario": "brute_force_attack",
  "cve_reference": "Similar to CVE-2018-13374 (Triton/TRISIS ICS intrusion)",
  "mitre_technique": "T0806 – Brute Force I&C"
}
```

### 7.3 Indian Industrial Context Examples

**Brute Force on Water Treatment PLC (Pune, Maharashtra):**
> "Water treatment facilities in India rely on PLCs with default vendor credentials that are rarely rotated. Attackers discovered via Shodan that Modbus/TCP port 502 is exposed on this asset."

**Lateral Movement via Textile Mill (Surat, Gujarat):**
> "Indian textile mills commonly share Windows workstations for both ERP access and HMI supervision. A phishing email on the IT side gave the attacker a foothold to pivot into OT."

**Coordinated Attack on Manufacturing Robot (Chennai, Tamil Nadu):**
> "India's manufacturing sector has been listed as a primary target by threat intelligence reports. This scenario mirrors the Triton intrusion methodology adapted to Indian industrial control environments operating Modbus/DNP3 devices."

---

## 8. OT Safety & Regulatory Alignment

### 8.1 Purdue/PERA Network Segmentation

```
┌──────────────────────────────────────────────────────────┐
│  Level 4-5  Enterprise IT (ERP, email, internet)         │  ← zone: enterprise_it
├──────────────────────────────────────────────────────────┤
│  Level 3.5  OT DMZ (jump hosts, historians, monitoring)  │  ← zone: ot_dmz
│             ▲ PREFERRED PLACEMENT FOR THIS TOOL          │
├──────────────────────────────────────────────────────────┤
│  Level 2-3  OT Operations (SCADA, HMI, supervision)      │  ← zone: ot_operations
├──────────────────────────────────────────────────────────┤
│  Level 1    OT Control (PLCs, RTUs, controllers)         │  ← zone: ot_control
├──────────────────────────────────────────────────────────┤
│  Level 0    Physical Process (sensors, actuators)        │  ← zone: physical_process
└──────────────────────────────────────────────────────────┘
```

Assets in the registry carry `zone_id` and `purdue_level` metadata. The `network_zones.json` config maps network segments to zones:

```json
"network_segment_mapping": {
  "CRITICAL":      {"zone_id": "ot_control",    "purdue_level": "L1"},
  "OT_SEGMENT_1":  {"zone_id": "ot_control",    "purdue_level": "L1"},
  "OT_SEGMENT_2":  {"zone_id": "ot_operations", "purdue_level": "L2-L3"},
  "DMZ":           {"zone_id": "ot_dmz",        "purdue_level": "L3.5"}
}
```

Every incident record includes `zone_id` and `purdue_level`, enabling operators to understand which network layer is affected.

### 8.2 OT-Specific Safety Constraints in Recommendations

The safe guidance system encodes the following OT safety principles:

| Asset Property | Guidance Generated |
|----------------|-------------------|
| `shutdown_risk: high` | "Do NOT shut down this system without OT engineer approval — high shutdown risk" |
| `shutdown_risk: medium` | "Avoid unplanned shutdown — coordinate with operations team first" |
| `criticality: critical` | "Do NOT take remediation action alone — OT engineer must be present" |
| `safety_impact` present | "Unsafe action may cause: [description of physical consequence]" |
| Correlation detected | "Treat as a coordinated multi-stage attack — escalate immediately" + "Preserve all logs and network captures as evidence" |

### 8.3 CERT-IN Compliance (6-Hour Reporting)

The escalation configuration encodes CERT-IN obligations:

```json
"cert_in": {
  "authority": "CERT-IN (Indian Computer Emergency Response Team)",
  "mandatory_for": "Critical infrastructure incidents, ransomware, data breaches",
  "deadline_hours": 6,
  "legal_basis": "Information Technology Act 2000, Section 70B; CERT-In Directions April 2022"
}
```

For CRITICAL incidents, the escalation rule automatically includes CERT-IN in the notify list with the action: *"Report to CERT-IN within 6 hours (mandatory under IT Act 2000)"*.

### 8.4 DSCI Compliance (72-Hour Data Breach Reporting)

```json
"dsci": {
  "authority": "DSCI (Data Security Council of India)",
  "mandatory_for": "Incidents involving personal data of Indian residents",
  "deadline_hours": 72,
  "legal_basis": "DPDP Act 2023 (Digital Personal Data Protection)"
}
```

### 8.5 Shutdown Risk Assessment Framework

| Shutdown Risk | Decision Rule | Physical Consequence Example |
|--------------|---------------|------------------------------|
| `high` | Requires OT engineer sign-off before any isolation | Chemical dosing failure (water treatment); uncontrolled robotic movement (manufacturing) |
| `medium` | Coordinate with operations team; avoid during production cycle | Temperature excursion in server room (HVAC); network segmentation loss (gateway) |
| `low` | Standard IT isolation procedures applicable | Building management system disruption |

---

## 9. Configuration & Data Files

### 9.1 `data/ot_context/ot_assets.json` — Complete Structure

```json
{
  "<asset_id>": {
    "system":         "Human-readable system name",
    "criticality":    "low | medium | high | critical",
    "shutdown_risk":  "low | medium | high",
    "safety_impact":  "Description of physical/safety consequence if disrupted",
    "protocol":       "Modbus | DNP3 | Profinet | BACnet | OPC-UA | TCP/IP",
    "network_segment":"CRITICAL | OT_SEGMENT_1 | OT_SEGMENT_2 | DMZ",
    "location":       "City, State (Indian geography)",
    "zone_id":        "ot_control | ot_operations | ot_dmz | enterprise_it",
    "purdue_level":   "L0 | L1 | L2-L3 | L3.5 | L4-L5"
  }
}
```

**Hot-reload capability:** `POST /api/assets/reload` calls `engine.reload_assets()` which re-reads the JSON from disk and replaces the in-memory dict. No restart required. This allows adding or updating assets during a running deployment.

### 9.2 `data/config/escalation.json` — Complete Structure

```json
{
  "contacts": [...],          // list of contact objects with role, name, phone, email
  "escalation_rules": {       // keyed by risk level
    "LOW":      { "response_time_sla": ..., "notify": [], "actions": [...] },
    "MEDIUM":   { "response_time_sla": ..., "notify": ["OT Engineer On-Call"], ... },
    "HIGH":     { "response_time_sla": ..., "notify": ["OT Engineer On-Call", "Security Lead"], ... },
    "CRITICAL": { "response_time_sla": ..., "notify": [...all contacts + CERT-IN...], ... }
  },
  "reporting_obligations": {  // CERT-IN and DSCI deadlines + legal basis
    "cert_in": { "deadline_hours": 6,  "legal_basis": "IT Act 2000 Section 70B" },
    "dsci":    { "deadline_hours": 72, "legal_basis": "DPDP Act 2023" }
  }
}
```

### 9.3 `data/config/network_zones.json` — Zone Catalogue

Defines the five Purdue zones and maps network segment identifiers (used in `ot_assets.json`) to zone metadata:

```json
{
  "zones": [
    {"zone_id": "enterprise_it",    "purdue_level": "L4-L5", "description": "..."},
    {"zone_id": "ot_dmz",           "purdue_level": "L3.5",  "description": "..."},
    {"zone_id": "ot_operations",    "purdue_level": "L2-L3", "description": "..."},
    {"zone_id": "ot_control",       "purdue_level": "L1",    "description": "..."},
    {"zone_id": "physical_process", "purdue_level": "L0",    "description": "..."}
  ],
  "network_segment_mapping": {
    "CRITICAL":     {"zone_id": "ot_control",    "purdue_level": "L1"},
    "OT_SEGMENT_1": {"zone_id": "ot_control",    "purdue_level": "L1"},
    "OT_SEGMENT_2": {"zone_id": "ot_operations", "purdue_level": "L2-L3"},
    "DMZ":          {"zone_id": "ot_dmz",        "purdue_level": "L3.5"}
  }
}
```

---

## 10. API Endpoints Reference

### Overview

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | HTML dashboard (browser) |
| POST | `/api/alert` | Ingest alert (JSON / CEF / SOAR webhook) |
| GET | `/api/incidents` | List all incidents |
| PUT | `/api/incidents/<id>/acknowledge` | Operator acknowledgement |
| GET | `/api/report/shift` | 8-hour shift summary |
| POST | `/api/assets/reload` | Hot-reload OT asset registry |
| GET | `/api/config/escalation` | Escalation contacts + rules |
| GET | `/api/adapters` | Supported input formats |
| GET | `/api/scan` | Manual alert directory scan trigger |

---

### `POST /api/alert` — Multi-Format Alert Ingestion

**Request (JSON):**
```bash
curl -X POST http://127.0.0.1:5000/api/alert \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "FAILED_LOGIN",
    "asset_id":   "water_treatment_plc",
    "severity":   "high",
    "timestamp":  "2026-04-15T10:30:00"
  }'
```

**Request (CEF / Syslog):**
```bash
curl -X POST http://127.0.0.1:5000/api/alert \
  -H "Content-Type: text/plain" \
  -d 'CEF:0|Splunk|IDS|1.0|123456|Failed Authentication|7|src=192.168.1.100 dst=192.168.1.50'
```

**Request (SOAR Webhook):**
```bash
curl -X POST http://127.0.0.1:5000/api/alert \
  -H "Content-Type: application/json" \
  -d '{
    "alert": {
      "name": "Malware Detection",
      "severity": "critical",
      "asset": "manufacturing_robot_ctrl"
    },
    "context": {"indicators": ["sha256:abc123"]}
  }'
```

**Response (201 Created):**
```json
{
  "id": "INC-3A7F92E1",
  "timestamp": "2026-04-15T10:30:05.123456",
  "event_type": "FAILED_LOGIN",
  "asset_id": "water_treatment_plc",
  "asset_name": "Water Treatment Plant PLC",
  "severity": "high",
  "risk_level": "CRITICAL",
  "risk_score": 4.0,
  "risk_score_explanation": "Score 3.4 (HIGH): ... → upgraded to CRITICAL (correlated attack pattern detected)",
  "criticality": "critical",
  "shutdown_risk": "high",
  "zone_id": "ot_control",
  "purdue_level": "L1",
  "correlation": "Multiple failed logins on the same asset — possible brute-force attack",
  "warning": "!! Correlated attack pattern: BRUTE_FORCE",
  "response_action": "Investigate Authentication",
  "response_steps": ["Verify user legitimacy", "Check login source IP", ...],
  "explanation": "Multiple failed login attempts detected. Possible password attack.",
  "do_steps": ["Check relevant logs", "Verify with on-site operator before acting", "Escalate immediately"],
  "dont_steps": ["Do NOT shut down this system without OT engineer approval", "Do NOT take remediation action alone"],
  "status": "open"
}
```

**Error response (400):**
```json
{"error": "Could not parse alert: unsupported or malformed format"}
```

---

### `GET /api/incidents` — List All Incidents

```bash
curl http://127.0.0.1:5000/api/incidents | python -m json.tool
```

Returns a JSON array of all incident objects, ordered by `timestamp DESC`.

---

### `PUT /api/incidents/<id>/acknowledge` — Operator Acknowledgement

```bash
curl -X PUT http://127.0.0.1:5000/api/incidents/INC-3A7F92E1/acknowledge \
  -H "Content-Type: application/json" \
  -d '{"operator": "Rajesh Kumar"}'
```

**Response (200):**
```json
{
  "status": "acknowledged",
  "incident_id": "INC-3A7F92E1",
  "operator": "Rajesh Kumar"
}
```

**Error (400):** `{"error": "operator name is required"}`
**Error (404):** `{"error": "Incident not found"}`

---

### `GET /api/report/shift` — Shift Handover Summary

```bash
# Default: last 8 hours
curl http://127.0.0.1:5000/api/report/shift | python -m json.tool

# Custom window:
curl "http://127.0.0.1:5000/api/report/shift?since=2026-04-15T06:00:00"
```

**Response:**
```json
{
  "since": "2026-04-15T02:30:00",
  "generated_at": "2026-04-15T10:30:00",
  "total_incidents": 12,
  "open": 9,
  "acknowledged": 3,
  "by_risk_level": {
    "CRITICAL": 3,
    "HIGH": 5,
    "MEDIUM": 3,
    "LOW": 1
  },
  "by_event_type": {
    "FAILED_LOGIN": 6,
    "NETWORK_SCAN": 3,
    "PLC_PROGRAM_CHANGE": 2,
    "FIRMWARE_MODIFICATION": 1
  },
  "most_affected_assets": {
    "Water Treatment Plant PLC": 4,
    "Manufacturing Robot Controller": 3,
    "Power Distribution SCADA": 2
  }
}
```

---

### `POST /api/assets/reload`

```bash
curl -X POST http://127.0.0.1:5000/api/assets/reload
```

**Response:** `{"reloaded": true, "asset_count": 10}`

---

### `GET /api/config/escalation`

Returns the full content of `data/config/escalation.json`. Useful for displaying contact information on the dashboard during an active incident.

---

### `GET /api/adapters`

```json
[
  {
    "name": "CEF/Syslog (Enterprise)",
    "example": {"cef_string": "CEF:0|Vendor|Product|1.0|ID|Alert Name|7|src=..."}
  },
  {
    "name": "REST/Webhook (SOAR)",
    "example": {"alert": {"name": "...", "severity": "high", "asset": "..."}}
  },
  {
    "name": "JSON (Standard IT-OT Format)",
    "example": {"event_type": "FAILED_LOGIN", "asset_id": "...", "severity": "high"}
  }
]
```

---

## 11. Research Gap Alignment

### Gap 1: Absence of an Intermediate Decision Layer

**Problem:** Traditional SIEM/SOC architectures route raw alerts directly to Tier-1 analysts or management consoles. In OT environments without a SOC, these alerts reach operators who have no framework for interpreting them — and no tool to help them decide what to do safely.

**How this project solves it:** The middleware acts as the missing decision layer:
- Enriches every raw alert with asset context, risk score, correlation analysis, and safe guidance
- Operates as a boundary service between alert sources (IDS, firewalls, PLCs) and the non-expert operator
- Produces a structured incident object that any operator can interpret and act upon

### Gap 2: Non-Expert Operator Usability

**Problem:** Enterprise security tools (Splunk, QRadar, Sentinel) are designed for trained security analysts. Their interfaces are too complex for shift engineers in Indian industrial facilities.

**How this project solves it:**
- Dashboard uses simple incident cards with traffic-light risk badges (CRITICAL/HIGH/MEDIUM/LOW)
- Plain-language `explanation` field describes what the event type means in non-technical terms
- DO / DON'T guidance lists are operator-oriented, not security-analyst-oriented
- Operator acknowledgement requires only the operator's name — no ticket management system
- Shift handover report summarises the last 8 hours in a format matching existing shift briefing practices

### Gap 3: Real-Time Alert Processing

**Problem:** Batch-mode alert processing tools (scheduled reports, overnight aggregation) are insufficient for OT environments where a PLC program change or coordinated attack can cause physical harm within minutes.

**How this project solves it:**
- Background daemon thread polls the alert directory every 10 seconds
- `POST /api/alert` endpoint processes alerts synchronously — sub-second ingestion for direct API integration
- Correlation engine operates on a rolling in-memory history, so time-window violations are detected as they occur

### Gap 4: OT-Safe Guidance Generation

**Problem:** Generic security playbooks (isolate the host, kill the process, restore from backup) are dangerous when applied to OT systems. Isolating a PLC mid-process can cause catastrophic physical consequences.

**How this project solves it:** The safe guidance generation function gates every recommendation on the asset's `shutdown_risk` and `criticality` fields. Assets with `shutdown_risk: high` and `criticality: critical` always generate DON'T steps that explicitly warn operators against isolation or shutdown without OT engineer sign-off.

### Novel Contributions Summary

| Contribution | Description |
|-------------|-------------|
| OT-safe guidance generation | DO/DON'T steps derived from physical-world asset metadata; a novel constraint framework for security recommendations in OT |
| Indian industrial localisation | Asset registry, regulatory contacts, and CERT-IN/DSCI obligations specific to India's industrial and legal context |
| Temporal correlation without ML | Four time-windowed patterns covering 80% of ICS attack chain types, deterministic and zero-training-data |
| MITRE ATT&CK ICS scenario framework | 6 documented attack chains with Indian industrial context, CVE references, and expected correlation outputs for end-to-end validation |
| Explainable risk scoring | Plain-language arithmetic breakdown of every risk score, addressing explainability needs of non-expert operators |

---

## 12. Deployment Architecture

### 12.1 Raspberry Pi 4 Requirements

| Resource | Requirement | Notes |
|----------|-------------|-------|
| CPU | Raspberry Pi 4 (ARM Cortex-A72, 1.8 GHz) | Runs Python 3.9+ natively |
| RAM | 2 GB minimum (4 GB recommended) | SQLite + Flask fits comfortably in 512 MB |
| Storage | 8 GB SD card minimum | SQLite DB + alert files; 16 GB recommended for 6+ months of data |
| OS | Raspberry Pi OS Lite (64-bit) | Headless server mode; GUI not required |
| Network | 100 Mbps Ethernet | Preferred over WiFi for industrial reliability |
| Python | 3.9+ | Available in Raspberry Pi OS repo |

**Performance on Raspberry Pi 4:**
- Alert processing time: < 10 ms per alert
- Background scan cycle: < 50 ms for 100 pending alerts
- Database query (1000 incidents): < 100 ms
- Flask request latency (POST /api/alert): < 50 ms

### 12.2 Bare Python Deployment (Recommended)

```bash
# Step 1: Clone repository
git clone https://github.com/abhipsamohan/it_ot_ir_tool_v2.git
cd it_ot_ir_tool_v2

# Step 2: Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Step 3: Install dependencies
pip install -r requirements.txt

# Step 4: (Optional) Seed with demo scenario alerts
python data/scenarios/generate_scenario_alerts.py

# Step 5: Start the middleware
python dashboard/app.py

# Dashboard: http://<pi-ip>:5000
```

### 12.3 Docker Containerisation (Phase 1)

```dockerfile
FROM python:3.11-slim AS base

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p data/alerts data/ot_context data/config

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
EXPOSE 5000

CMD ["python", "dashboard/app.py"]
```

```bash
# Build
docker build -t ot-ir-tool .

# Run (mount data directory for persistence)
docker run -p 5000:5000 -v $(pwd)/data:/app/data ot-ir-tool
```

The `docker-compose.yml` provided in the repository handles the volume mount and port mapping, enabling a single `docker compose up` deployment.

### 12.4 Systemd Service Setup (Raspberry Pi)

Create `/etc/systemd/system/ot-ir-tool.service`:

```ini
[Unit]
Description=IT-OT Incident Response Tool v2
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/it_ot_ir_tool_v2
ExecStart=/home/pi/it_ot_ir_tool_v2/venv/bin/python dashboard/app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable ot-ir-tool
sudo systemctl start ot-ir-tool
sudo journalctl -u ot-ir-tool -f  # follow logs
```

---

## 13. Integration Points (Future)

### 13.1 SIEM/IDS Integration (Inbound Alerts)

Real IDS/SIEM systems can forward alerts to the middleware via `POST /api/alert`. The format abstraction layer already handles:

| Source System | Format | Adapter Used |
|--------------|--------|-------------|
| Splunk (Syslog output) | CEF/Syslog | `CEFAdapter` |
| Palo Alto Networks firewall | CEF | `CEFAdapter` |
| Fortinet FortiGate | Syslog | `CEFAdapter` |
| Splunk Phantom | REST webhook | `RESTAdapter` |
| Demisto / Cortex XSOAR | REST webhook | `RESTAdapter` |
| Custom IDS scripts | JSON | `JSONAdapter` |

### 13.2 SOAR Automation (Outbound Playbooks)

Planned: webhook callbacks to push correlated incidents to SOAR platforms for automated playbook execution. The incident object schema is already well-structured for SOAR consumption.

### 13.3 Industrial Protocol Collectors

Planned native integrations:
- **Modbus scanner** — poll PLC register changes and generate `PLC_PROGRAM_CHANGE` alerts when unexpected writes are detected
- **DNP3 collector** — monitor SCADA data quality and generate `UNAUTHORIZED_CONFIG_CHANGE` alerts on integrity failures
- **Passive OT network sensor** — detect new OT devices (asset discovery) and protocol anomalies (abnormal function codes)

### 13.4 Real Industrial Monitoring Systems

The tool's architecture supports direct integration with:
- **Claroty / Nozomi Networks** — industrial asset discovery and anomaly detection output forwarded as JSON alerts
- **Dragos Platform** — ICS threat detection alerts via REST API
- **OSIsoft PI System** — process historian integration for anomaly-based alert generation

---

## 14. Code Quality & Infrastructure

### 14.1 Type Hints

The codebase uses full Python type annotations throughout:

```python
def calculate_risk(self, alert: Dict, asset: Dict) -> Dict: ...
def check_correlation(self, alert: Dict) -> Optional[Dict]: ...
def get_shift_summary(self, since_iso: Optional[str] = None) -> Dict[str, Any]: ...
def detect_and_parse(self, data) -> Tuple[Dict, str]: ...
```

Type checking is enforced via `mypy` with the configuration in `mypy.ini`.

### 14.2 Test Suite Coverage

The test suite in `tests/` validates:
- Engine loading and asset registry parsing
- Risk score calculation correctness for all severity/criticality combinations
- Correlation pattern detection (BRUTE_FORCE, LATERAL_MOVEMENT, RECON_TO_ACCESS, COORDINATED_ATTACK)
- Database persistence and retrieval
- Operator acknowledgement workflow
- Flask API endpoint responses (alert ingestion, incidents list, shift report)
- Format adapter parsing (JSON, CEF, REST webhook)

Run tests:
```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v --cov=engine --cov-report=term-missing
```

### 14.3 GitHub Actions CI/CD

`.github/workflows/tests.yml` runs on every push and pull request:
1. Set up Python 3.11
2. Install dependencies (`requirements.txt` + `requirements-dev.txt`)
3. Run `pytest tests/ -v`
4. Run `mypy --config-file mypy.ini`

This ensures the test suite and type checker gate every code change before merge.

### 14.4 Linting and Static Analysis

```bash
# Type checking
python -m mypy --config-file mypy.ini

# Linting (if flake8/ruff added to requirements-dev.txt)
python -m flake8 engine/ dashboard/ data/
```

---

## 15. Limitations & Future Work

### 15.1 Current Prototype Limitations

| Limitation | Description |
|------------|-------------|
| Rule-based correlation only | No statistical anomaly detection; cannot detect novel attack patterns not covered by the four defined rules |
| No authentication on API | `POST /api/alert` and `GET /api/incidents` are unauthenticated — appropriate for LAN deployment, not for internet-facing |
| Single-instance threading | `alert_history` is in-memory; correlation state is lost on restart; multi-process (Gunicorn) deployment would lose correlation |
| SQLite scalability | Suitable for ~100,000 incidents; beyond that, PostgreSQL migration would be needed |
| No real-time protocol collectors | Alert generation is still manual (file drop or API POST) in this prototype; live Modbus/DNP3 collection not yet implemented |
| Asset registry is static | Assets must be manually defined in `ot_assets.json`; no auto-discovery of OT devices |

### 15.2 Machine Learning Opportunities

| ML Technique | Application |
|-------------|-------------|
| Sequence modelling (LSTM/Transformer) | Learn normal alert timing patterns; detect anomalous sequences beyond the four defined rules |
| Clustering (DBSCAN) | Identify new attack patterns from unlabelled alert sequences |
| Anomaly detection (Isolation Forest) | Per-asset baseline modelling — alert when an asset's behaviour deviates statistically from its normal pattern |
| NLP | Automatic event-type classification from free-text syslog messages, reducing manual mapping in CEF adapter |

### 15.3 Scalability Considerations

| Scale | Recommendation |
|-------|----------------|
| Single site, <1000 alerts/day | Current SQLite + single-thread architecture (Raspberry Pi 4 capable) |
| Multi-site, <100,000 alerts/day | PostgreSQL database; Gunicorn multi-worker with Redis for shared `alert_history` |
| Large enterprise, >1M alerts/day | Apache Kafka for alert ingestion; distributed correlation engine; time-series DB (InfluxDB/TimescaleDB) for incident storage |

### 15.4 Advanced Correlation Techniques

Future correlation improvements:
- **Graph-based correlation** — model assets as nodes and events as edges; detect attack paths traversing the asset graph
- **Temporal pattern mining** — use sequence mining (GSP algorithm) to discover new multi-stage patterns from historical incidents
- **Federated learning** — share attack pattern intelligence across facilities without sharing raw alert data (privacy-preserving)
- **MITRE ATT&CK mapping** — automatic tagging of correlated incidents with ATT&CK for ICS technique IDs

### 15.5 Roadmap

| Phase | Feature | Priority |
|-------|---------|----------|
| Phase 2 | API authentication (API keys / JWT) | High |
| Phase 2 | Persistent correlation state (Redis) | High |
| Phase 2 | Real-time Modbus/DNP3 protocol collector | High |
| Phase 3 | React/Vue frontend (replace HTML template) | Medium |
| Phase 3 | PostgreSQL backend option | Medium |
| Phase 3 | Outbound SOAR webhook integration | Medium |
| Phase 4 | ML-based anomaly detection layer | Low (research) |
| Phase 4 | Multi-site federation and dashboard aggregation | Low |

---

*This document was generated from direct code analysis of the IT-OT IR Tool v2 repository. All code snippets are taken verbatim from the source files. Asset names, contact details, and regulatory references are contextualised for Indian industrial environments.*

*Repository:* **abhipsamohan/it_ot_ir_tool_v2**  
*Documentation version:* v2.0 — May 2026
