from datetime import datetime, timezone
from sqlalchemy import BigInteger, Column, DateTime, Integer, String, Text
from server.app.database.base import Base


class InvestigationReport(Base):
    """
    Forensic investigation report metadata and persistent history record.
    Tracks both evidence-specific dossiers and comprehensive case reports.
    """
    __tablename__ = "investigation_reports"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    report_id = Column(String(64), unique=True, index=True, nullable=False)
    title = Column(String(256), nullable=False)
    report_scope = Column(String(32), nullable=False)  # "EVIDENCE" or "CASE_SUMMARY"
    evidence_id = Column(String(64), index=True, nullable=True)  # Nullable for CASE_SUMMARY
    generated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    generated_by = Column(String(128), default="ForenSight Forensic Examiner", nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size_bytes = Column(BigInteger, default=0, nullable=False)
    notes = Column(Text, nullable=True)
    summary_json = Column(Text, nullable=True)  # JSON-serialized report data for UI preview

