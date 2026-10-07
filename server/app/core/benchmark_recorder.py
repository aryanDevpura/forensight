"""
ForenSight Performance Measurement & Benchmark Recorder
========================================================
Provides high-resolution monotonic timer utilities for recording real
runtime benchmarks across evidence hashing, HMAC signing/verification,
ingestion I/O, and PCAP analysis without fabricating synthetic data.
"""

import time
import platform
import json
from typing import Optional
from sqlalchemy.orm import Session

from server.app.models.benchmark import BenchmarkResult


def record_benchmark(
    db: Session,
    benchmark_name: str,
    duration_sec: float,
    sample_size_bytes: int,
    evidence_id: Optional[str] = None,
    system_info: Optional[str] = None,
) -> BenchmarkResult:
    """
    Persists a genuine benchmark record to the database.

    Args:
        db: SQLAlchemy database session.
        benchmark_name: Identifier for operation (e.g. 'SHA256_HASHING', 'HMAC_VERIFICATION', 'EVIDENCE_INGESTION', 'PCAP_ANALYSIS').
        duration_sec: Elapsed monotonic time in seconds (float).
        sample_size_bytes: Size of sample processed in bytes (int).
        evidence_id: Optional associated evidence identifier.
        system_info: Optional environment or diagnostic metadata.
    """
    duration_ms = round(max(0.0001, duration_sec * 1000.0), 4)

    # Compute throughput in MB/sec where duration > 0 and sample_size_bytes > 0
    throughput_mbps: Optional[float] = None
    if duration_sec > 0 and sample_size_bytes > 0:
        # (bytes / (1024 * 1024)) / duration_sec
        mb = sample_size_bytes / (1024.0 * 1024.0)
        throughput_mbps = round(mb / duration_sec, 4)

    sys_meta = system_info or f"{platform.system()} {platform.machine()} Python/{platform.python_version()}"

    record = BenchmarkResult(
        benchmark_name=benchmark_name,
        evidence_id=evidence_id,
        sample_size_bytes=sample_size_bytes,
        duration_ms=duration_ms,
        throughput_mbps=throughput_mbps,
        system_info=sys_meta,
    )
    db.add(record)
    try:
        db.commit()
        db.refresh(record)
    except Exception:
        db.rollback()

    return record
