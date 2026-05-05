# engine/database.py

import sqlite3
import os
from typing import Any, Dict, List, Optional
import json
from datetime import datetime, timedelta


class IncidentDatabase:

    def __init__(self, db_path="data/incidents.db"):

        self.db_path = db_path

        os.makedirs("data", exist_ok=True)

        self.init_db()
        self._migrate()

    # --------------------------------------------------

    def init_db(self):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            timestamp TEXT,
            event_type TEXT,
            asset_id TEXT,
            asset_name TEXT,
            severity TEXT,
            risk_level TEXT,
            risk_score REAL,
            criticality TEXT,
            shutdown_risk TEXT,
            zone_id TEXT,
            purdue_level TEXT,
            warning TEXT,
            response_action TEXT,
            response_steps TEXT,
            explanation TEXT,
            risk_score_explanation TEXT,
            correlation TEXT,
            do_steps TEXT,
            dont_steps TEXT,
            status TEXT DEFAULT 'open',
            acknowledged_by TEXT,
            acknowledged_at TEXT
        )
        """)

        conn.commit()
        conn.close()

    # --------------------------------------------------
    # MIGRATION — safely add new columns to existing databases
    #
    # Column names and types come from a hardcoded internal list, not external
    # input.  We use an allowlist check as a defence-in-depth measure so that
    # the f-string construction can never be reached with arbitrary strings.

    _ALLOWED_MIGRATION_COLUMNS = {
        "response_steps", "risk_score_explanation", "correlation",
        "status", "acknowledged_by", "acknowledged_at",
        "zone_id", "purdue_level",
    }

    def _migrate(self):

        new_columns = [
            ("response_steps", "TEXT"),
            ("risk_score_explanation", "TEXT"),
            ("correlation", "TEXT"),
            ("status", "TEXT DEFAULT 'open'"),
            ("acknowledged_by", "TEXT"),
            ("acknowledged_at", "TEXT"),
            ("zone_id", "TEXT"),
            ("purdue_level", "TEXT"),
        ]

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(incidents)")
        existing = {row[1] for row in cursor.fetchall()}

        for col_name, col_type in new_columns:
            if col_name not in self._ALLOWED_MIGRATION_COLUMNS:
                raise ValueError(f"Unexpected migration column: {col_name!r}")
            if col_name not in existing:
                # col_name and col_type are validated against the allowlist above;
                # SQLite does not support parameterised DDL statements.
                cursor.execute(f"ALTER TABLE incidents ADD COLUMN {col_name} {col_type}")  # noqa: S608

        conn.commit()
        conn.close()

    # --------------------------------------------------

    def insert_incident(self, incident: Dict):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO incidents (
            id,
            timestamp,
            event_type,
            asset_id,
            asset_name,
            severity,
            risk_level,
            risk_score,
            criticality,
            shutdown_risk,
            zone_id,
            purdue_level,
            warning,
            response_action,
            response_steps,
            explanation,
            risk_score_explanation,
            correlation,
            do_steps,
            dont_steps,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident["id"],
            incident["timestamp"],
            incident.get("event_type"),
            incident.get("asset_id", "unknown"),
            incident.get("asset_name", "Unknown Asset"),
            incident.get("severity", "medium"),
            incident.get("risk_level", "MEDIUM"),
            incident.get("risk_score", 0.0),
            incident.get("criticality"),
            incident.get("shutdown_risk"),
            incident.get("zone_id"),
            incident.get("purdue_level"),
            incident.get("warning"),
            incident.get("response_action"),
            json.dumps(incident.get("response_steps", [])),
            incident.get("explanation"),
            incident.get("risk_score_explanation"),
            incident.get("correlation"),
            json.dumps(incident.get("do_steps", [])),
            json.dumps(incident.get("dont_steps", [])),
            "open",
        ))

        conn.commit()
        conn.close()

    # --------------------------------------------------

    def get_incidents(self) -> List[Dict]:

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
        SELECT
            id,
            timestamp,
            event_type,
            asset_id,
            asset_name,
            severity,
            risk_level,
            risk_score,
            criticality,
            shutdown_risk,
            zone_id,
            purdue_level,
            warning,
            response_action,
            response_steps,
            explanation,
            risk_score_explanation,
            correlation,
            do_steps,
            dont_steps,
            status,
            acknowledged_by,
            acknowledged_at
        FROM incidents
        ORDER BY timestamp DESC
        """)

        rows = cursor.fetchall()
        conn.close()

        incidents = []

        for r in rows:
            incidents.append({
                "id": r[0],
                "timestamp": r[1],
                "event_type": r[2],
                "asset_id": r[3],
                "asset_name": r[4],
                "severity": r[5],
                "risk_level": r[6],
                "risk_score": r[7],
                "criticality": r[8],
                "shutdown_risk": r[9],
                "zone_id": r[10],
                "purdue_level": r[11],
                "warning": r[12],
                "response_action": r[13],
                "response_steps": json.loads(r[14]) if r[14] else [],
                "explanation": r[15],
                "risk_score_explanation": r[16],
                "correlation": r[17],
                "do_steps": json.loads(r[18]) if r[18] else [],
                "dont_steps": json.loads(r[19]) if r[19] else [],
                "status": r[20] or "open",
                "acknowledged_by": r[21],
                "acknowledged_at": r[22],
            })

        return incidents

    # --------------------------------------------------
    # OPERATOR ACKNOWLEDGEMENT

    def acknowledge_incident(self, incident_id: str, operator_name: str) -> bool:

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
        UPDATE incidents
        SET status = 'acknowledged',
            acknowledged_by = ?,
            acknowledged_at = ?
        WHERE id = ?
        """, (operator_name, datetime.now().isoformat(), incident_id))

        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()

        return updated

    # --------------------------------------------------
    # SHIFT HANDOVER SUMMARY

    def get_shift_summary(self, since_iso: Optional[str] = None) -> Dict[str, Any]:

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if since_iso is None:
            since_iso = (datetime.now() - timedelta(hours=8)).isoformat()

        cursor.execute("""
        SELECT
            risk_level,
            event_type,
            asset_name,
            status,
            id,
            timestamp
        FROM incidents
        WHERE timestamp >= ?
        ORDER BY timestamp DESC
        """, (since_iso,))

        rows = cursor.fetchall()
        conn.close()

        total = len(rows)
        by_risk: Dict[str, int] = {}
        by_event: Dict[str, int] = {}
        by_asset: Dict[str, int] = {}
        open_count = 0
        acknowledged_count = 0

        for r in rows:
            risk_level = r[0] or "UNKNOWN"
            event_type = r[1] or "UNKNOWN"
            asset_name = r[2] or "Unknown"
            status = r[3] or "open"

            by_risk[risk_level] = by_risk.get(risk_level, 0) + 1
            by_event[event_type] = by_event.get(event_type, 0) + 1
            by_asset[asset_name] = by_asset.get(asset_name, 0) + 1

            if status == "acknowledged":
                acknowledged_count += 1
            else:
                open_count += 1

        return {
            "since": since_iso,
            "generated_at": datetime.now().isoformat(),
            "total_incidents": total,
            "open": open_count,
            "acknowledged": acknowledged_count,
            "by_risk_level": by_risk,
            "by_event_type": by_event,
            "most_affected_assets": dict(
                sorted(by_asset.items(), key=lambda x: x[1], reverse=True)
            ),
        }
