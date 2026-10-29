"""
Forensic Timeline & Event Correlation API Endpoints
===================================================
Provides retrieval of chronological investigation and forensic events
associated with specific evidence items.

Timeline scope: Only PCAP and PCAPNG evidence produces forensic network-flow
and security-finding events. All other evidence types return an empty timeline.
Non-evidence audit events (e.g. SIGNATURE_VERIFICATION_FAILURE) are excluded
from timeline responses; they are available via the audit log.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from server.app.database.session import get_db
from server.app.models.evidence import Evidence
from server.app.models.event import InvestigationEvent
from server.app.api.endpoints.schemas import InvestigationEventRead

router = APIRouter(prefix="/timeline", tags=["Timeline & Events"])

# Evidence types that produce forensic network timelines.
PCAP_TYPES = ("PCAP", "PCAPNG")


@router.get(
    "/{evidence_id}",
    response_model=List[InvestigationEventRead],
    summary="Get chronological timeline events for an evidence item",
    description=(
        "Returns forensic timeline events for a PCAP/PCAPNG evidence artifact, "
        "ordered chronologically (oldest first). "
        "Returns an empty list for evidence types that do not produce timeline events "
        "(e.g. LOG, IMAGE). Returns 404 if the evidence_id does not exist."
    ),
)
def get_evidence_timeline(
    evidence_id: str,
    db: Session = Depends(get_db),
) -> List[InvestigationEventRead]:
    """
    Retrieve forensic events for a specific evidence item ordered chronologically.
    Returns 404 if the evidence_id does not exist.
    Returns [] for evidence types other than PCAP/PCAPNG (evidence still exists,
    it simply does not have a forensic network timeline).
    """
    evidence = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found.",
        )

    # Only PCAP/PCAPNG evidence produces timeline events.
    if (evidence.evidence_type or "").upper() not in PCAP_TYPES:
        return []

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
    description=(
        "Retrieve forensic timeline events across PCAP/PCAPNG artifacts only, "
        "ordered chronologically. Non-PCAP evidence and audit-only events "
        "(e.g. SIGNATURE_VERIFICATION_FAILURE) are excluded."
    ),
)
def list_timeline_events(
    evidence_id: Optional[str] = None,
    db: Session = Depends(get_db),
) -> List[InvestigationEventRead]:
    """
    Retrieve timeline events for PCAP/PCAPNG evidence only.
    Joins InvestigationEvent with Evidence and filters to PCAP_TYPES so that
    audit events with evidence_id=None and events for non-PCAP evidence are excluded.
    Optionally filtered by evidence_id.
    """
    query = (
        db.query(InvestigationEvent)
        .join(Evidence, InvestigationEvent.evidence_id == Evidence.evidence_id)
        .filter(Evidence.evidence_type.in_(PCAP_TYPES))
    )
    if evidence_id:
        query = query.filter(InvestigationEvent.evidence_id == evidence_id)

    return query.order_by(InvestigationEvent.timestamp.asc(), InvestigationEvent.id.asc()).all()
