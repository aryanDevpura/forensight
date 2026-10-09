"""
Forensic Analysis API Endpoints
==============================
Provides endpoints for executing forensic analysis on acquired evidence
artifacts and querying detected forensic findings.
"""

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from server.app.database.session import get_db
from server.app.models.evidence import Evidence
from server.app.models.finding import Finding
from server.app.api.endpoints.schemas import (
    AnalysisTriggerResponse,
    FindingRead,
)
from server.app.services.pcap_analyzer import analyze_pcap_evidence
from server.app.services.pcap_parser import backend_info

router = APIRouter(prefix="/analysis", tags=["Forensic Analysis"])


@router.get(
    "/backend",
    summary="PCAP parser backend information",
    description=(
        "Returns the active PCAP parsing backend (PyShark/tshark or pure-Python fallback) "
        "and its capabilities. The backend is selected automatically based on tshark availability."
    ),
)
def get_parser_backend() -> Dict[str, Any]:
    """Returns which PCAP parser backend is active on the server."""
    return backend_info()



@router.post(
    "/{evidence_id}",
    response_model=AnalysisTriggerResponse,
    summary="Trigger forensic analysis on an evidence artifact",
    description=(
        "Executes non-destructive forensic inspection on the specified evidence. "
        "For PCAP evidence, extracts packet counts, protocols, network endpoints, "
        "and generates structured findings linked to the evidence ID. "
        "Preserves original disk artifacts and SHA-256 acquisition hashes."
    ),
)
def run_evidence_analysis(
    evidence_id: str,
    db: Session = Depends(get_db),
) -> AnalysisTriggerResponse:
    """
    Triggers analysis for an evidence item.
    """
    evidence = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found.",
        )

    # ------------------------------------------------------------------ #
    # Integrity pre-check: file existence + SHA-256 verification           #
    # Runs BEFORE the evidence-type check so that a missing or tampered    #
    # file is reported accurately regardless of the evidence type.         #
    # ------------------------------------------------------------------ #
    evidence_path = Path(evidence.file_path)
    if not evidence_path.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Evidence file not found on disk: {evidence.file_path}",
        )

    pre_hasher = hashlib.sha256()
    with open(evidence_path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            pre_hasher.update(chunk)
    pre_hash = pre_hasher.hexdigest()
    if pre_hash.lower() != evidence.sha256_hash.lower():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Pre-analysis integrity check FAILED for '{evidence.evidence_id}'. "
                f"Stored acquisition hash: {evidence.sha256_hash}. "
                f"Current on-disk hash: {pre_hash}. "
                "Analysis aborted — the artifact appears to have been modified after acquisition."
            ),
        )

    if evidence.evidence_type not in ("PCAP", "PCAPNG"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Automated deep inspection is currently supported for PCAP/PCAPNG evidence. Type was '{evidence.evidence_type}'.",
        )

    try:
        result = analyze_pcap_evidence(evidence=evidence, db=db, record_custody_event=True)
        return AnalysisTriggerResponse(**result)
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
    except ValueError as exc:
        # Raised by the pre-analysis integrity guard when the on-disk hash
        # does not match the stored acquisition hash.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis pipeline error: {str(exc)}",
        )


@router.get(
    "/findings",
    response_model=List[FindingRead],
    summary="List all forensic findings",
    description="Retrieve all forensic findings across all evidence items.",
)
def list_findings(
    evidence_id: Optional[str] = None,
    db: Session = Depends(get_db),
) -> List[FindingRead]:
    """
    Returns findings, optionally filtered by evidence_id.
    """
    query = db.query(Finding)
    if evidence_id:
        query = query.filter(Finding.evidence_id == evidence_id)
    return query.order_by(Finding.detected_at.desc(), Finding.id.desc()).all()


@router.get(
    "/findings/{evidence_id}",
    response_model=List[FindingRead],
    summary="Get findings for a specific evidence item",
    description="Retrieve all structured findings associated with an evidence artifact.",
)
def get_findings_for_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
) -> List[FindingRead]:
    """
    Validates evidence exists, then returns its findings.
    """
    evidence = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found.",
        )

    return (
        db.query(Finding)
        .filter(Finding.evidence_id == evidence_id)
        .order_by(Finding.detected_at.desc(), Finding.id.desc())
        .all()
    )
