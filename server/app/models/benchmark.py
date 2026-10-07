from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from server.app.database.base import Base


class BenchmarkResult(Base):
    """
    Performance benchmarking records measuring ingestion speed, hashing throughput,
    and analysis execution latency.
    """
    __tablename__ = "benchmark_results"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    benchmark_name = Column(String(128), nullable=False)
    sample_size_bytes = Column(Integer, nullable=False)
    duration_ms = Column(Float, nullable=False)
    throughput_mbps = Column(Float, nullable=True)
    system_info = Column(Text, nullable=True)
    recorded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
