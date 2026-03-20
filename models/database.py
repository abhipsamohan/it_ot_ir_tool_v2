"""
models/database.py - SQLAlchemy ORM models for IT/OT Incident Response System.
5 tables: Alert, Incident, Asset, AuditLog, CorrelationPattern
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, Float, Boolean, DateTime, Text, Integer, Index,
    create_engine, event,
)
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


def _generate_uuid():
    return str(uuid.uuid4())


def _now():
    return datetime.utcnow()


# ------------------------------------------------------------------
# Models
# ------------------------------------------------------------------

class Alert(Base):
    """Raw incoming alerts from OT/IT sources."""
    __tablename__ = "alerts"

    alert_id = Column(String(36), primary_key=True, default=_generate_uuid)
    timestamp = Column(DateTime, default=_now, nullable=False)
    event_type = Column(String(64), nullable=False, index=True)
    asset_id = Column(String(64), nullable=False, index=True)
    source = Column(String(128))
    severity = Column(String(16), nullable=False, default="medium")
    details = Column(Text)     # JSON blob
    processed = Column(Boolean, default=False)

    __table_args__ = (
        Index("ix_alerts_timestamp", "timestamp"),
    )

    def to_dict(self):
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "asset_id": self.asset_id,
            "source": self.source,
            "severity": self.severity,
            "details": self.details,
            "processed": self.processed,
        }


class Incident(Base):
    """Processed incidents created from one or more correlated alerts."""
    __tablename__ = "incidents"

    incident_id = Column(String(36), primary_key=True, default=_generate_uuid)
    timestamp = Column(DateTime, default=_now, nullable=False)
    event_type = Column(String(64), nullable=False, index=True)
    asset_id = Column(String(64), nullable=False, index=True)
    severity = Column(String(16), nullable=False, default="medium", index=True)
    risk_level = Column(String(16))
    risk_score = Column(Float)
    rule_matched = Column(String(128))
    response_action = Column(String(256))
    response_steps = Column(Text)    # JSON list
    explanation = Column(Text)
    do_steps = Column(Text)          # JSON list
    dont_steps = Column(Text)        # JSON list
    status = Column(String(16), default="open", index=True)

    __table_args__ = (
        Index("ix_incidents_timestamp", "timestamp"),
    )

    def to_dict(self):
        import json
        return {
            "incident_id": self.incident_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "asset_id": self.asset_id,
            "severity": self.severity,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "rule_matched": self.rule_matched,
            "response_action": self.response_action,
            "response_steps": json.loads(self.response_steps) if self.response_steps else [],
            "explanation": self.explanation,
            "do_steps": json.loads(self.do_steps) if self.do_steps else [],
            "dont_steps": json.loads(self.dont_steps) if self.dont_steps else [],
            "status": self.status,
        }


class Asset(Base):
    """OT/IT asset metadata."""
    __tablename__ = "assets"

    asset_id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    asset_type = Column(String(32))
    criticality = Column(String(16), default="medium")
    shutdown_safe = Column(Boolean, default=False)
    location = Column(String(128))
    notes = Column(Text)
    last_seen = Column(DateTime)

    def to_dict(self):
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "asset_type": self.asset_type,
            "criticality": self.criticality,
            "shutdown_safe": self.shutdown_safe,
            "location": self.location,
            "notes": self.notes,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class AuditLog(Base):
    """Compliance audit trail for all system decisions and actions."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(36), nullable=False, index=True)
    action = Column(String(128), nullable=False)
    actor = Column(String(64), default="system")
    action_type = Column(String(32))    # auto_executed / approval_requested / approved / denied
    timestamp = Column(DateTime, default=_now, nullable=False)
    details = Column(Text)              # JSON blob

    __table_args__ = (
        Index("ix_audit_log_timestamp", "timestamp"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "action": self.action,
            "actor": self.actor,
            "action_type": self.action_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "details": self.details,
        }


class CorrelationPattern(Base):
    """Detected multi-alert correlation patterns."""
    __tablename__ = "correlation_patterns"

    pattern_id = Column(String(36), primary_key=True, default=_generate_uuid)
    incident_id = Column(String(36), nullable=False, index=True)
    pattern_type = Column(String(64))    # e.g. BRUTE_FORCE, ATTACK_PROGRESSION
    description = Column(Text)
    asset_id = Column(String(64))
    timestamp = Column(DateTime, default=_now, nullable=False)
    details = Column(Text)               # JSON blob

    def to_dict(self):
        return {
            "pattern_id": self.pattern_id,
            "incident_id": self.incident_id,
            "pattern_type": self.pattern_type,
            "description": self.description,
            "asset_id": self.asset_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "details": self.details,
        }


# ------------------------------------------------------------------
# Database factory
# ------------------------------------------------------------------

def create_db_engine(db_url: str = "sqlite:///data/incidents.db"):
    """Create and return a SQLAlchemy engine."""
    import os
    # Ensure data directory exists for SQLite
    if db_url.startswith("sqlite:///") and not db_url.startswith("sqlite:///:"):
        path = db_url[len("sqlite:///"):]
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    engine = create_engine(db_url, connect_args={"check_same_thread": False} if "sqlite" in db_url else {})
    # Enable WAL mode for SQLite
    if "sqlite" in db_url:
        @event.listens_for(engine, "connect")
        def set_wal(dbapi_conn, _):
            dbapi_conn.execute("PRAGMA journal_mode=WAL")
    return engine


def init_db(db_url: str = "sqlite:///data/incidents.db"):
    """Initialize the database, creating all tables."""
    engine = create_db_engine(db_url)
    Base.metadata.create_all(engine)
    return engine


def get_session(engine):
    """Return a new SQLAlchemy session."""
    Session = sessionmaker(bind=engine)
    return Session()
