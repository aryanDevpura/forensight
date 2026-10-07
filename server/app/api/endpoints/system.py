from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from server.app.database.session import get_db
from server.app.models.evidence import Evidence
from server.app.models.finding import Finding
from server.app.models.event import InvestigationEvent
from server.app.models.custody import ChainOfCustody
from server.app.models.benchmark import BenchmarkResult
from server.app.core.config import settings
from server.app.api.endpoints.schemas import SystemStatsResponse

router = APIRouter()


@router.get("/system/stats", response_model=SystemStatsResponse, tags=["System"])
def get_system_stats(db: Session = Depends(get_db)) -> SystemStatsResponse:
    """
    Returns actual counts and state from the database.
    Zero mock/synthetic values are generated.
    """
    evidence_count = db.query(Evidence).count()
    findings_count = db.query(Finding).count()
    events_count = db.query(InvestigationEvent).count()
    custody_count = db.query(ChainOfCustody).count()
    benchmark_count = db.query(BenchmarkResult).count()

    return SystemStatsResponse(
        evidence_count=evidence_count,
        findings_count=findings_count,
        events_count=events_count,
        custody_records_count=custody_count,
        benchmark_runs_count=benchmark_count,
        database_file=settings.DATABASE_URL,
        collector_status="Configured (Standby for telemetry)",
    )
