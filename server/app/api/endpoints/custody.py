"""
Chain of Custody API Endpoints
==============================
Provides retrieval of tamper-evident custody history for forensic
evidence items. Custody records are created automatically during
evidence ingestion and can be appended by authorized actions.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from server.app.database.session import get_db
from server.app.models.evidence import Evidence
from server.app.models.custody import ChainOfCustody
from server.app.api.endpoints.schemas import ChainOfCustodyRead

router = APIRouter(prefix="/custody", tags=["Chain of Custody"])


@router.get(
    "/{evidence_id}",
    response_model=List[ChainOfCustodyRead],
    summary="Get chain of custody for an evidence item",
    description=(
        "Returns the complete tamper-evident custody history for the "
        "specified evidence item, ordered chronologically (oldest first)."
    ),
)
def get_custody_chain(
    evidence_id: str,
    db: Session = Depends(get_db),
) -> List[ChainOfCustodyRead]:
    """
    Retrieve all chain-of-custody records for a specific evidence item.

    Returns 404 if the evidence_id does not correspond to any registered
    evidence artifact. Returns an empty list if the evidence exists but
    has no custody records (should not happen — acquisition creates one).
    """
    # Verify the evidence item actually exists
    evidence = db.query(Evidence).filter(
        Evidence.evidence_id == evidence_id
    ).first()

    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No evidence registered with ID '{evidence_id}'.",
        )

    records = (
        db.query(ChainOfCustody)
        .filter(ChainOfCustody.evidence_id == evidence_id)
        .order_by(ChainOfCustody.timestamp.asc(), ChainOfCustody.id.asc())
        .all()
    )

    return records
