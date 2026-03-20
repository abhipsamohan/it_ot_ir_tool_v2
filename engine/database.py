# engine/database.py

import sqlite3
import os
from typing import Dict, List
import json


class IncidentDatabase:

    def __init__(self, db_path="data/incidents.db"):

        self.db_path = db_path

        os.makedirs("data", exist_ok=True)

        self.init_db()

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
            warning TEXT,
            response_action TEXT,
            explanation TEXT,
            do_steps TEXT,
            dont_steps TEXT
                       
        )
        """)

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
            warning,
            response_action,
            explanation,
            do_steps,
            dont_steps
            
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (

            incident["id"],
            incident["timestamp"],
            incident["event_type"],
            incident["asset_id"],
            incident["asset_name"],
            incident["severity"],
            incident["risk_level"],
            incident["risk_score"],
            incident.get("criticality"),
            incident.get("shutdown_risk"),
            incident.get("warning"),
            incident.get("response_action"),
            incident.get("explanation"),
            json.dumps(incident.get("do_steps", [])),
            json.dumps(incident.get("dont_steps", []))


            


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
            warning,
            response_action,
            explanation,
            do_steps,
            dont_steps               
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
                "warning": r[10],
                "response_action": r[11],
                "explanation": r[12],
                "do_steps": json.loads(r[13]) if r[13] else [],
                "dont_steps": json.loads(r[14]) if r[14] else []
                
                

            })

        return incidents