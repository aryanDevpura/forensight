from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, Integer, String, BigInteger, DateTime, Text
from server.app.database.base import Base


class Evidence(Base):
    """
    Core Evidence entity tracking acquired forensic artifacts.
    Stores cryptographic SHA-256 acquisition hash and physical storage path.
    """
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    evidence_id = Column(String(64), unique=True, index=True, nullable=False)
    file_name = Column(String(256), nullable=False)
    evidence_type = Column(String(64), nullable=False)  # PCAP, LOG, IMAGE, VIDEO, AUDIO, DOCUMENT, ARCHIVE
    source_device = Column(String(128), nullable=False)
    collector_id = Column(String(128), nullable=True)
    file_path = Column(String(512), nullable=False)
    file_size_bytes = Column(BigInteger, default=0, nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(32), default="ACQUIRED", nullable=False)  # Initial state: ACQUIRED
    # True when the on-disk artifact has been AES-256-GCM encrypted at rest.
    # sha256_hash always stores the PLAINTEXT hash regardless of this flag.
    is_encrypted = Column(Boolean, default=False, nullable=False, server_default="0")
    collected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
