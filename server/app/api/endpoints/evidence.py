import os
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from server.app.core.config import settings
from server.app.database.session import get_db
from server.app.models.evidence import Evidence
from server.app.api.endpoints.schemas import EvidenceRead

router = APIRouter(prefix="/evidence", tags=["Evidence"])

# Supported file extensions for ForenSight artifacts
SUPPORTED_EXTENSIONS = {
    # Packet captures
    ".pcap": "PCAP",
    ".pcapng": "PCAPNG",
    ".cap": "PCAP",
    # Text / log files
    ".log": "LOG",
    ".txt": "TEXT",
    ".json": "JSON",
    ".csv": "CSV",
    ".xml": "XML",
    ".evtx": "EVENT_LOG",
    # Images
    ".png": "IMAGE",
    ".jpg": "IMAGE",
    ".jpeg": "IMAGE",
    ".gif": "IMAGE",
    ".bmp": "IMAGE",
    ".tiff": "IMAGE",
    ".webp": "IMAGE",
    # Audio
    ".wav": "AUDIO",
    ".mp3": "AUDIO",
    ".ogg": "AUDIO",
    ".flac": "AUDIO",
    ".m4a": "AUDIO",
    # Video
    ".mp4": "VIDEO",
    ".avi": "VIDEO",
    ".mkv": "VIDEO",
    ".mov": "VIDEO",
    ".wmv": "VIDEO",
    # Documents
    ".pdf": "DOCUMENT",
    ".doc": "DOCUMENT",
    ".docx": "DOCUMENT",
    ".rtf": "DOCUMENT",
    ".odt": "DOCUMENT",
    # Common archives
    ".zip": "ARCHIVE",
    ".tar": "ARCHIVE",
    ".gz": "ARCHIVE",
    ".tgz": "ARCHIVE",
    ".7z": "ARCHIVE",
    ".rar": "ARCHIVE",
    ".bz2": "ARCHIVE",
}


def get_file_extension(filename: str) -> str:
    """Extract lowercase file extension from filename."""
    return Path(filename).suffix.lower()


def generate_evidence_id() -> str:
    """Generate a unique forensic evidence identifier."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    unique_suffix = uuid.uuid4().hex[:6].upper()
    return f"EVD-{timestamp}-{unique_suffix}"


@router.post("", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    file: UploadFile = File(...),
    source_device: str = Form(default="local-workstation"),
    collector_id: Optional[str] = Form(default=None),
    description: Optional[str] = Form(default=None),
    db: Session = Depends(get_db),
) -> EvidenceRead:
    """
    Ingest forensic evidence artifact with streaming SHA-256 calculation.
    Enforces safe filesystem path generation, file type verification,
    and sets status to ACQUIRED.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File submission must include a valid filename.",
        )

    # Sanitize original filename to strip directory traversal sequences
    original_filename = Path(file.filename).name
    ext = get_file_extension(original_filename)

    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported file type '{ext}'. ForenSight accepts: "
                "PCAP/PCAPNG, text/log files, images, audio, video, "
                "documents (PDF/DOC/DOCX), and archives."
            ),
        )

    evidence_type = SUPPORTED_EXTENSIONS[ext]
    evidence_id = generate_evidence_id()

    # Prevent path traversal: Generate secure unique filename for disk storage
    safe_storage_filename = f"{evidence_id}_{uuid.uuid4().hex[:8]}{ext}"
    evidence_dir = settings.resolved_evidence_dir
    destination_path = (evidence_dir / safe_storage_filename).resolve()

    # Verify destination is strictly inside the evidence storage directory
    if not str(destination_path).startswith(str(evidence_dir.resolve())):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Illegal file storage path detected.",
        )

    # Compute SHA-256 hash using streaming chunks (64 KB)
    hasher = hashlib.sha256()
    file_size_bytes = 0
    chunk_size = 65536

    try:
        with open(destination_path, "wb") as dest_file:
            while chunk := await file.read(chunk_size):
                hasher.update(chunk)
                dest_file.write(chunk)
                file_size_bytes += len(chunk)
    except Exception as exc:
        # Clean up partial file on failure
        if destination_path.exists():
            destination_path.unlink()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to write evidence artifact: {str(exc)}",
        )

    sha256_digest = hasher.hexdigest()
    now_utc = datetime.now(timezone.utc)

    # Store record in SQLite database
    evidence_record = Evidence(
        evidence_id=evidence_id,
        file_name=original_filename,
        evidence_type=evidence_type,
        source_device=source_device.strip() or "local-workstation",
        collector_id=collector_id.strip() if collector_id else "collector-node-01",
        file_path=str(destination_path),
        file_size_bytes=file_size_bytes,
        sha256_hash=sha256_digest,
        description=description.strip() if description else None,
        status="ACQUIRED",  # Initial status: ACQUIRED, NOT VERIFIED
        collected_at=now_utc,
        created_at=now_utc,
    )

    try:
        db.add(evidence_record)
        db.commit()
        db.refresh(evidence_record)
    except Exception as exc:
        if destination_path.exists():
            destination_path.unlink()
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record evidence in database: {str(exc)}",
        )

    return evidence_record


@router.get("", response_model=List[EvidenceRead])
def list_evidence(
    db: Session = Depends(get_db),
) -> List[EvidenceRead]:
    """
    Retrieve real database records of all registered evidence artifacts.
    """
    records = db.query(Evidence).order_by(Evidence.created_at.desc()).all()
    return records
