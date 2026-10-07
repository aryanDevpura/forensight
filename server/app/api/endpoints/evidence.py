import os
import uuid
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from server.app.core.config import settings
from server.app.core.hmac_auth import verify_hmac_signature
from server.app.core.benchmark_recorder import record_benchmark
from server.app.database.session import get_db
from server.app.models.evidence import Evidence
from server.app.models.custody import ChainOfCustody
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


async def _ingest_evidence(
    file: UploadFile,
    source_device: str,
    collector_id: Optional[str],
    description: Optional[str],
    db: Session,
    signed_payload_hash: Optional[str] = None,
    encryption_header: Optional[str] = None,
) -> Tuple[Evidence, Optional[float]]:
    """
    Core evidence ingestion logic shared by both upload routes.

    When ``encryption_header`` indicates encrypted transfer (e.g. 'AES-GCM-256'),
    the streamed transfer payload is decrypted using the pre-shared AES key,
    and genuine decryption latency is measured.
    When ``signed_payload_hash`` is provided (authenticated collector path),
    the SHA-256 computed from the recovered original bytes is cross-checked against it.
    A mismatch or decryption failure rejects the upload with HTTP 422.
    Only recovered original evidence bytes are persisted on disk as the forensic artifact.
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

    # Measure total ingestion time with monotonic timers
    t_ingest_start = time.perf_counter()

    # Read uploaded file content
    raw_incoming_bytes = await file.read()
    decryption_duration_sec: Optional[float] = None

    if encryption_header and encryption_header.strip().upper() == "AES-GCM-256":
        if not settings.FORENSIGHT_ENCRYPTION_KEY:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "Evidence transfer encryption is enabled by collector, but server has no "
                    "FORENSIGHT_ENCRYPTION_KEY configured."
                ),
            )
        from server.app.core.crypto import decrypt_payload
        try:
            # Bind signed_payload_hash as AAD if available
            aad = signed_payload_hash.encode("utf-8") if signed_payload_hash else None
            decrypted_bytes, decryption_duration_sec = decrypt_payload(
                encrypted_data=raw_incoming_bytes,
                key=settings.FORENSIGHT_ENCRYPTION_KEY,
                associated_data=aad,
            )
            final_bytes = decrypted_bytes
        except ValueError as err:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Decryption verification failed: {str(err)}",
            )
    else:
        final_bytes = raw_incoming_bytes

    # Compute SHA-256 on recovered plaintext evidence
    t_hash_start = time.perf_counter()
    hasher = hashlib.sha256()
    hasher.update(final_bytes)
    sha256_digest = hasher.hexdigest()
    hashing_duration_sec = time.perf_counter() - t_hash_start
    file_size_bytes = len(final_bytes)

    # Authenticated path: cross-check recovered plaintext hash against signed claim
    if signed_payload_hash is not None:
        if sha256_digest.lower() != signed_payload_hash.lower():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "Payload integrity check failed: the SHA-256 of the received "
                    "file does not match the hash included in the HMAC signature. "
                    "The artifact may have been modified in transit."
                ),
            )

    # Persist the recovered plaintext evidence on disk
    try:
        with open(destination_path, "wb") as dest_file:
            dest_file.write(final_bytes)
    except Exception as exc:
        if destination_path.exists():
            destination_path.unlink()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to write evidence artifact: {str(exc)}",
        )

    now_utc = datetime.now(timezone.utc)

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
        status="ACQUIRED",
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

    # Create the initial chain-of-custody record for the ACQUIRED event
    is_encrypted_transfer = bool(encryption_header and encryption_header.strip().upper() == "AES-GCM-256")
    custody_notes = (
        f"Evidence artifact '{original_filename}' acquired via "
        f"{'authenticated collector (AES-GCM encrypted transfer)' if is_encrypted_transfer else ('authenticated collector' if signed_payload_hash else 'browser UI')} upload. "
        f"SHA-256: {sha256_digest}. Size: {file_size_bytes} bytes."
    )
    custody_record = ChainOfCustody(
        evidence_id=evidence_record.evidence_id,
        action="ACQUIRED",
        actor=evidence_record.collector_id or "unknown",
        location=str(destination_path),
        notes=custody_notes,
        timestamp=now_utc,
    )
    try:
        db.add(custody_record)
        db.commit()
    except Exception:
        db.rollback()

    total_ingestion_sec = time.perf_counter() - t_ingest_start

    # Persist genuine benchmark measurements
    record_benchmark(
        db=db,
        benchmark_name="SHA256_HASHING",
        duration_sec=hashing_duration_sec,
        sample_size_bytes=file_size_bytes,
        evidence_id=evidence_record.evidence_id,
        system_info="SHA-256 integrity verification",
    )
    record_benchmark(
        db=db,
        benchmark_name="EVIDENCE_INGESTION",
        duration_sec=total_ingestion_sec,
        sample_size_bytes=file_size_bytes,
        evidence_id=evidence_record.evidence_id,
        system_info=f"Storage: {destination_path.name}",
    )
    if decryption_duration_sec is not None:
        record_benchmark(
            db=db,
            benchmark_name="AES_DECRYPTION",
            duration_sec=decryption_duration_sec,
            sample_size_bytes=file_size_bytes,
            evidence_id=evidence_record.evidence_id,
            system_info="AES-256-GCM transfer payload authenticated decryption",
        )

    return evidence_record, decryption_duration_sec


# ---------------------------------------------------------------------------
# Route 1: Browser / UI upload (no HMAC required)
#   Used by the React frontend on the same workstation.
# ---------------------------------------------------------------------------

@router.post("", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    file: UploadFile = File(...),
    source_device: str = Form(default="local-workstation"),
    collector_id: Optional[str] = Form(default=None),
    description: Optional[str] = Form(default=None),
    db: Session = Depends(get_db),
) -> EvidenceRead:
    """
    Ingest a forensic evidence artifact from the local browser UI.
    Streaming SHA-256 is computed and stored. No HMAC required on this
    route — it is intended for same-machine workstation uploads.
    """
    record, _ = await _ingest_evidence(
        file=file,
        source_device=source_device,
        collector_id=collector_id,
        description=description,
        db=db,
        signed_payload_hash=None,
        encryption_header=None,
    )
    return record


# ---------------------------------------------------------------------------
# Route 2: Collector upload (HMAC-SHA256 required)
#   Used by collector nodes. Validates signature and payload integrity.
# ---------------------------------------------------------------------------

@router.post(
    "/authenticated",
    response_model=EvidenceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Authenticated evidence upload (collector nodes only)",
    description=(
        "Accepts forensic artifacts from authenticated collector nodes. "
        "Requires HMAC-SHA256 signed headers: X-ForenSight-Timestamp, "
        "X-ForenSight-Evidence-ID, X-ForenSight-Payload-Hash, "
        "X-ForenSight-Signature. Supports AES-256-GCM transfer encryption."
    ),
)
async def upload_evidence_authenticated(
    file: UploadFile = File(...),
    source_device: str = Form(default="local-workstation"),
    collector_id: Optional[str] = Form(default=None),
    description: Optional[str] = Form(default=None),
    x_forensight_encryption: Optional[str] = Header(
        None,
        alias="X-ForenSight-Encryption",
        description="Optional transfer encryption algorithm (e.g. AES-GCM-256).",
    ),
    db: Session = Depends(get_db),
    auth_claims: dict = Depends(verify_hmac_signature),
) -> EvidenceRead:
    """
    Authenticated evidence upload for collector nodes.

    HMAC verification is enforced via the ``verify_hmac_signature``
    dependency before any payload decryption or file storage occurs.
    If transfer encryption is enabled, the server decrypts the ciphertext
    using the pre-shared AES key, measures decryption duration, cross-checks
    the recovered plaintext SHA-256 against the HMAC-signed payload hash,
    and stores only the recovered original evidence artifact.
    """
    record, _ = await _ingest_evidence(
        file=file,
        source_device=source_device,
        collector_id=collector_id,
        description=description,
        db=db,
        signed_payload_hash=auth_claims["payload_hash"],
        encryption_header=x_forensight_encryption,
    )

    # Record HMAC verification benchmark if measured in verify_hmac_signature
    if "verification_time_sec" in auth_claims:
        record_benchmark(
            db=db,
            benchmark_name="HMAC_VERIFICATION",
            duration_sec=auth_claims["verification_time_sec"],
            sample_size_bytes=record.file_size_bytes,
            evidence_id=record.evidence_id,
            system_info="HMAC-SHA256 pre-shared secret verification",
        )

    return record



# ---------------------------------------------------------------------------
# Route 3: List all evidence (no auth required — read-only)
# ---------------------------------------------------------------------------

@router.get("", response_model=List[EvidenceRead])
def list_evidence(
    db: Session = Depends(get_db),
) -> List[EvidenceRead]:
    """
    Retrieve real database records of all registered evidence artifacts.
    """
    records = db.query(Evidence).order_by(Evidence.created_at.desc()).all()
    return records
