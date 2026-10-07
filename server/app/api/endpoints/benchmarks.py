"""
Performance Benchmarking API Endpoints
=======================================
Provides retrieval of genuine runtime performance and latency metrics
recorded across evidence acquisition, hashing, HMAC verification, and
PCAP deep packet analysis.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from server.app.database.session import get_db
from server.app.models.evidence import Evidence
from server.app.models.benchmark import BenchmarkResult
from server.app.api.endpoints.schemas import BenchmarkResultRead

router = APIRouter(prefix="/benchmarks", tags=["Performance Benchmarks"])


@router.get(
    "",
    response_model=List[BenchmarkResultRead],
    summary="List all benchmark results",
    description=(
        "Returns all recorded runtime benchmarks, ordered from most recent. "
        "Can be filtered by benchmark_name or evidence_id."
    ),
)
def list_benchmarks(
    benchmark_name: Optional[str] = None,
    evidence_id: Optional[str] = None,
    db: Session = Depends(get_db),
) -> List[BenchmarkResultRead]:
    """
    Retrieve benchmark results with optional filtering.
    """
    query = db.query(BenchmarkResult)
    if benchmark_name:
        query = query.filter(BenchmarkResult.benchmark_name == benchmark_name)
    if evidence_id:
        query = query.filter(BenchmarkResult.evidence_id == evidence_id)

    return query.order_by(BenchmarkResult.recorded_at.desc(), BenchmarkResult.id.desc()).all()


@router.get(
    "/evidence/{evidence_id}",
    response_model=List[BenchmarkResultRead],
    summary="Get benchmarks for a specific evidence item",
    description="Returns all recorded benchmarks associated with a specific evidence artifact.",
)
def get_benchmarks_for_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
) -> List[BenchmarkResultRead]:
    """
    Validates that evidence exists, then returns its benchmark records.
    """
    evidence = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found.",
        )

    return (
        db.query(BenchmarkResult)
        .filter(BenchmarkResult.evidence_id == evidence_id)
        .order_by(BenchmarkResult.recorded_at.asc(), BenchmarkResult.id.asc())
        .all()
    )


@router.get(
    "/summary",
    summary="Get aggregate performance summary",
    description=(
        "Returns aggregated performance metrics including average duration (ms), "
        "average throughput (MB/s), and count per benchmark category."
    ),
)
def get_benchmarks_summary(
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Calculates genuine summary statistics grouped by benchmark operation.
    """
    results = (
        db.query(
            BenchmarkResult.benchmark_name,
            func.count(BenchmarkResult.id).label("count"),
            func.avg(BenchmarkResult.duration_ms).label("avg_duration_ms"),
            func.min(BenchmarkResult.duration_ms).label("min_duration_ms"),
            func.max(BenchmarkResult.duration_ms).label("max_duration_ms"),
            func.avg(BenchmarkResult.throughput_mbps).label("avg_throughput_mbps"),
            func.sum(BenchmarkResult.sample_size_bytes).label("total_bytes_processed"),
        )
        .group_by(BenchmarkResult.benchmark_name)
        .all()
    )

    summary_data = {}
    for r in results:
        summary_data[r.benchmark_name] = {
            "count": r.count,
            "avg_duration_ms": round(float(r.avg_duration_ms or 0.0), 4),
            "min_duration_ms": round(float(r.min_duration_ms or 0.0), 4),
            "max_duration_ms": round(float(r.max_duration_ms or 0.0), 4),
            "avg_throughput_mbps": round(float(r.avg_throughput_mbps or 0.0), 4) if r.avg_throughput_mbps is not None else None,
            "total_bytes_processed": int(r.total_bytes_processed or 0),
        }

    return {
        "operations": summary_data,
        "total_records": db.query(BenchmarkResult).count(),
    }
