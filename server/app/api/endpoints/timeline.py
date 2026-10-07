"""
Forensic Timeline & Event Correlation API Endpoints
===================================================
Provides retrieval of chronological investigation and forensic events
associated with specific evidence items.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from server.app.database.session import get_db
from server.app.models.evidence import Evidence
from server.app.models.event import InvestigationEvent
from server.app.api.endpoints.schemas import InvestigationEventRead

router = APIRouter(prefix="/timeline", tags=["Timeline & Events"])


@router.get(
    "/{evidence_id}",
    response_model=List[InvestigationEventRead],
    summary="Get chronological timeline events for an evidence item",
    description=(
        "Returns all forensic timeline events associated with the specified "
        "evidence artifact, ordered chronologically (oldest first)."
    ),
)
def get_evidence_timeline(
    evidence_id: str,
    db: Session = Depends(get_db),
) -> List[InvestigationEventRead]:
    """
    Retrieve forensic events for a specific evidence item ordered chronologically.
    Returns 404 if the evidence_id does not exist.
    """
    evidence = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found.",
        )

    events = (
        db.query(InvestigationEvent)
        .filter(InvestigationEvent.evidence_id == evidence_id)
        .order_by(InvestigationEvent.timestamp.asc(), InvestigationEvent.id.asc())
        .all()
    )
    return events


@router.get(
    "",
    response_model=List[InvestigationEventRead],
    summary="List all timeline events",
    description="Retrieve all forensic events across all artifacts, ordered chronologically.",
)
def list_timeline_events(
    evidence_id: Optional[str] = None,
    db: Session = Depends(get_db),
) -> List[InvestigationEventRead]:
    """
    Retrieve timeline events, optionally filtered by evidence_id.
    """
    query = db.query(InvestigationEvent)
    if evidence_id:
        query = query.filter(InvestigationEvent.evidence_id == evidence_id)

    return query.order_by(InvestigationEvent.timestamp.asc(), InvestigationEvent.id.asc()).all()
