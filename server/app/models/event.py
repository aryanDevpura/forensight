from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text
from server.app.database.base import Base


class InvestigationEvent(Base):
    """
    Audit log / event timeline for system events, collector check-ins, and investigative operations.
    """
    __tablename__ = "investigation_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    event_type = Column(String(64), nullable=False)  # SYSTEM_START, COLLECTOR_HEARTBEAT, INGEST_EVENT
    source = Column(String(128), nullable=False)     # SERVER, COLLECTOR, EXAMINER
    severity = Column(String(32), default="INFO", nullable=False)  # INFO, WARNING, ERROR
    message = Column(Text, nullable=False)
    metadata_json = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
