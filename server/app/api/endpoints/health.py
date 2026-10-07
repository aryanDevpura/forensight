from datetime import datetime, timezone
from fastapi import APIRouter
from server.app.core.config import settings
from server.app.database.session import check_db_connection
from server.app.api.endpoints.schemas import HealthResponse, StorageStatus

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["Health"])
def get_health() -> HealthResponse:
    """
    System Health Check Endpoint.
    Returns status of the ForenSight Investigation Server, SQLite database,
    and filesystem evidence storage directories.
    """
    db_connected = check_db_connection()
    evidence_dir = settings.resolved_evidence_dir
    reports_dir = settings.resolved_reports_dir

    return HealthResponse(
        status="ok",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.FORENSIGHT_ENV,
        database="connected" if db_connected else "disconnected",
        timestamp=datetime.now(timezone.utc),
        storage=StorageStatus(
            evidence_dir="available" if evidence_dir.exists() else "missing",
            evidence_path=str(evidence_dir),
            reports_dir="available" if reports_dir.exists() else "missing",
            reports_path=str(reports_dir),
        ),
    )
