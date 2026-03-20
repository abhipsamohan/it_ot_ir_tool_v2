# IT/OT Incident Response Tool v2

A production-ready, rule-based IT/OT incident response middleware for small industrial facilities.
Runs on Raspberry Pi 4. No AI/ML — just simple, interpretable rules that plant managers can read and modify.

## Features

- **Rule-based detection** — human-readable JSON rules, no neural networks
- **Brute force detection** — 5+ failed logins in 5 minutes on same OT asset
- **Multi-stage attack detection** — reconnaissance → exploitation chain
- **Blast radius calculation** — cascading dependency impact analysis
- **Safe-by-default response** — auto-executes safe actions, queues dangerous ones for approval
- **Web dashboard** — real-time incidents, approval buttons, auto-refresh
- **Full audit trail** — every decision logged for compliance

## Quick Start

```bash
./setup.sh                    # Install deps, init DB
source venv/bin/activate
python3 simulate.py           # Run 3 attack scenarios
python3 app.py                # Start dashboard at http://localhost:5000
pytest tests/ -v              # Run all 47 unit tests
```

## Project Structure

```
it_ot_ir_tool_v2/
├── app.py                        # Flask REST API + dashboard
├── simulate.py                   # End-to-end simulation (3 scenarios)
├── config/
│   ├── settings.py               # Environment-based config
│   ├── rules.json                # Detection rules (editable)
│   └── dependencies.json         # Asset dependency map (editable)
├── engine/
│   ├── rule_engine.py            # Pattern matching + correlation
│   ├── dependency_engine.py      # Blast radius calculation
│   └── safe_response_engine.py   # Response orchestration
├── ingestion/
│   └── alert_generator.py        # Test alert generator
├── models/
│   └── database.py               # SQLAlchemy ORM models
├── templates/
│   └── dashboard.html            # Web dashboard
├── tests/
│   ├── test_rule_engine.py
│   ├── test_dependency_engine.py
│   └── test_safe_response_engine.py
├── requirements.txt
├── setup.sh
├── .env.example
└── ARCHITECTURE.md
```

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/scan-alerts` | Scan alerts dir, create incidents |
| POST | `/api/generate-test-alerts` | Generate test scenario alerts |
| GET | `/api/incidents` | List incidents (`?severity=&status=`) |
| GET | `/api/incident/<id>` | Get incident details |
| GET | `/api/dashboard-stats` | Dashboard statistics |
| GET | `/api/pending-approvals` | Dangerous actions awaiting approval |
| POST | `/api/approve-action` | Approve or deny a dangerous action |

## Configuration

Copy `.env.example` to `.env` and edit as needed. Key settings:

| Variable | Default | Description |
|---|---|---|
| `FLASK_ENV` | `development` | `development` / `production` / `testing` |
| `DATABASE_URL` | `sqlite:///data/incidents.db` | SQLAlchemy DB URL |
| `ALERTS_DIR` | `data/alerts` | Directory polled for alert JSON files |
| `BRUTE_FORCE_THRESHOLD` | `5` | Failed logins to trigger brute force |
| `BRUTE_FORCE_WINDOW_MINUTES` | `5` | Time window for brute force detection |

## Testing

```bash
pytest tests/ -v          # All 47 unit tests
python3 simulate.py       # 3 integration scenarios
```

## Deployment on Raspberry Pi

See `ARCHITECTURE.md` for the systemd service unit file and production configuration guide.

## Architecture

See `ARCHITECTURE.md` for full system design, data flows, risk scoring formula, and failure modes.