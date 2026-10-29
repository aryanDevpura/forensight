"""
Forensic Report Generation & History API Endpoints
==================================================
Provides generation, retrieval, and PDF download for evidence-specific
forensic dossiers.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from server.app.database.session import get_db
from server.app.core.config import settings
from server.app.models.evidence import Evidence
from server.app.models.report import InvestigationReport
from server.app.api.endpoints.schemas import (
    ReportGenerateRequest,
    InvestigationReportRead,
    InvestigationReportDetail,
)
from server.app.services.report_generator import (
    build_evidence_report_data,
    generate_pdf_report,
)

router = APIRouter(prefix="/reports", tags=["Forensic Reports"])


@router.get(
    "",
    response_model=List[InvestigationReportRead],
    summary="List all generated forensic reports",
    description="Returns chronological history of all generated evidence reports.",
)
def list_reports(
    evidence_id: Optional[str] = None,
    db: Session = Depends(get_db),
) -> List[InvestigationReportRead]:
    """Retrieve report history with optional evidence_id filtering."""
    query = db.query(InvestigationReport)
    if evidence_id:
        query = query.filter(InvestigationReport.evidence_id == evidence_id)

    return query.order_by(InvestigationReport.generated_at.desc(), InvestigationReport.id.desc()).all()


@router.post(
    "",
    response_model=InvestigationReportDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a forensic evidence investigation report",
    description=(
        "Generates a formal forensic evidence report for the specified evidence artifact. "
        "Compiles real database records, creates a verified PDF dossier in storage/reports, "
        "and persists the report metadata for preview and download."
    ),
)
def generate_report(
    req: ReportGenerateRequest,
    db: Session = Depends(get_db),
) -> InvestigationReportDetail:
    """Generate an authentic forensic evidence report and PDF export."""
    if not req.evidence_id or not req.evidence_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="evidence_id is required to generate a forensic evidence report.",
        )

    evidence_obj = db.query(Evidence).filter(Evidence.evidence_id == req.evidence_id.strip()).first()
    if not evidence_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{req.evidence_id}' not found.",
        )

    target_evidence_id = evidence_obj.evidence_id
    scope = "EVIDENCE"

    # De-duplication check: avoid duplicate reports from rapid double-clicks within 5s
    now_utc = datetime.now(timezone.utc)
    recent_report = (
        db.query(InvestigationReport)
        .filter(
            InvestigationReport.evidence_id == target_evidence_id,
        )
        .order_by(InvestigationReport.generated_at.desc())
        .first()
    )
    if recent_report:
        age_seconds = (now_utc - recent_report.generated_at.replace(tzinfo=timezone.utc)).total_seconds()
        if age_seconds < 5.0 and Path(recent_report.file_path).exists():
            summary_dict = None
            if recent_report.summary_json:
                try:
                    summary_dict = json.loads(recent_report.summary_json)
                except Exception:
                    pass
            return InvestigationReportDetail(
                id=recent_report.id,
                report_id=recent_report.report_id,
                title=recent_report.title,
                report_scope=recent_report.report_scope,
                evidence_id=recent_report.evidence_id,
                generated_at=recent_report.generated_at,
                generated_by=recent_report.generated_by,
                file_size_bytes=recent_report.file_size_bytes,
                file_path=recent_report.file_path,
                notes=recent_report.notes,
                download_url=f"/api/reports/{recent_report.report_id}/download",
                summary_data=summary_dict,
            )

    # Generate unique report identifier
    unique_suffix = uuid.uuid4().hex[:6].upper()
    ts_str = now_utc.strftime("%Y%m%d%H%M%S")
    report_id = f"RPT-{ts_str}-{unique_suffix}"

    # Compile data from database
    examiner_name = req.examiner_name or "ForenSight Forensic Examiner"
    report_data = build_evidence_report_data(
        evidence=evidence_obj,
        db=db,
        examiner_name=examiner_name,
        notes=req.notes,
    )
    default_title = f"Forensic Evidence Dossier — {evidence_obj.evidence_id}"

    final_title = req.title.strip() if req.title and req.title.strip() else default_title
    report_data["report_id"] = report_id
    report_data["title"] = final_title

    # Render PDF file to resolved reports storage
    reports_dir = settings.resolved_reports_dir
    pdf_filename = f"{report_id}.pdf"
    pdf_path = reports_dir / pdf_filename

    try:
        generate_pdf_report(report_data=report_data, output_path=str(pdf_path))
        file_size = pdf_path.stat().st_size
    except Exception as exc:
        if pdf_path.exists():
            pdf_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to render forensic report PDF: {str(exc)}",
        )

    # Persist report history record
    report_record = InvestigationReport(
        report_id=report_id,
        title=final_title,
        report_scope=scope,
        evidence_id=target_evidence_id,
        generated_at=now_utc,
        generated_by=examiner_name,
        file_path=str(pdf_path),
        file_size_bytes=file_size,
        notes=req.notes,
        summary_json=json.dumps(report_data),
    )
    db.add(report_record)
    db.commit()
    db.refresh(report_record)

    return InvestigationReportDetail(
        id=report_record.id,
        report_id=report_record.report_id,
        title=report_record.title,
        report_scope=report_record.report_scope,
        evidence_id=report_record.evidence_id,
        generated_at=report_record.generated_at,
        generated_by=report_record.generated_by,
        file_size_bytes=report_record.file_size_bytes,
        file_path=report_record.file_path,
        notes=report_record.notes,
        download_url=f"/api/reports/{report_id}/download",
        summary_data=report_data,
    )


@router.get(
    "/{report_id}",
    response_model=InvestigationReportDetail,
    summary="Get report details and preview data",
    description="Retrieves report metadata and structured summary payload for UI preview.",
)
def get_report(
    report_id: str,
    db: Session = Depends(get_db),
) -> InvestigationReportDetail:
    """Retrieve metadata and preview for a previously generated report."""
    report = db.query(InvestigationReport).filter(InvestigationReport.report_id == report_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found.",
        )

    summary_dict = None
    if report.summary_json:
        try:
            summary_dict = json.loads(report.summary_json)
        except Exception:
            pass

    return InvestigationReportDetail(
        id=report.id,
        report_id=report.report_id,
        title=report.title,
        report_scope=report.report_scope,
        evidence_id=report.evidence_id,
        generated_at=report.generated_at,
        generated_by=report.generated_by,
        file_size_bytes=report.file_size_bytes,
        file_path=report.file_path,
        notes=report.notes,
        download_url=f"/api/reports/{report.report_id}/download",
        summary_data=summary_dict,
    )


@router.get(
    "/{report_id}/download",
    summary="Download forensic report PDF",
    description="Returns the court-admissible forensic PDF document.",
)
def download_report_pdf(
    report_id: str,
    db: Session = Depends(get_db),
):
    """Download the generated report PDF file."""
    report = db.query(InvestigationReport).filter(InvestigationReport.report_id == report_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found.",
        )

    reports_dir = settings.resolved_reports_dir
    pdf_candidates = [
        Path(report.file_path),
        reports_dir / f"{report.report_id}.pdf",
        reports_dir / Path(report.file_path).name,
    ]
    pdf_file = None
    for candidate in pdf_candidates:
        try:
            if candidate.exists() and candidate.is_file():
                pdf_file = candidate
                break
        except Exception:
            continue

    # If the physical file was deleted or moved, attempt to re-render it from summary_json
    if pdf_file is None:
        if report.summary_json:
            try:
                summary_data = json.loads(report.summary_json)
                target_path = reports_dir / f"{report.report_id}.pdf"
                generate_pdf_report(summary_data, str(target_path))
                pdf_file = target_path
                report.file_path = str(target_path)
                report.file_size_bytes = target_path.stat().st_size
                db.commit()
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Report PDF file '{report.report_id}.pdf' not found on server disk.",
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report PDF file '{report.report_id}.pdf' not found on server disk.",
            )

    return FileResponse(
        path=str(pdf_file),
        filename=f"{report.report_id}.pdf",
        media_type="application/pdf",
    )

