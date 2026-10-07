from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text
from server.app.database.base import Base


class ChainOfCustody(Base):
    """
    Chain of Custody record tracking evidence handling, transfers, and access events.
    Cryptographic verification and HMAC signatures will be added in future milestones.
    """
    __tablename__ = "chain_of_custody"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    evidence_id = Column(String(64), index=True, nullable=False)
    action = Column(String(64), nullable=False)  # ACQUIRED, TRANSFERRED, ACCESSED, EXAMINED
    actor = Column(String(128), nullable=False)   # Collector ID or Examiner name
    location = Column(String(256), nullable=True) # Storage location or host
    notes = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
