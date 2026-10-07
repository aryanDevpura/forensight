from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text
from server.app.database.base import Base


class Finding(Base):
    """
    Forensic analysis finding / security alert identified from examined artifacts.
    Analysis detection engines (PCAP, beaconing, etc.) will be connected in future milestones.
    """
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    finding_id = Column(String(64), unique=True, index=True, nullable=False)
    evidence_id = Column(String(64), index=True, nullable=False)
    category = Column(String(64), nullable=False)  # NETWORK_SCAN, BEACONING, SUSPICIOUS_USB, ANOMALY
    severity = Column(String(32), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    title = Column(String(256), nullable=False)
    details = Column(Text, nullable=True)
    detected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
