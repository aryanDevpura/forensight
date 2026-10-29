import os
import uuid
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Response, UploadFile, status
from sqlalchemy.orm import Session

from server.app.core.config import settings
from server.app.core.benchmark_recorder import record_benchmark
from server.app.core.crypto import (
    GCM_NONCE_LENGTH,
    GCM_TAG_LENGTH,
    decrypt_evidence_artifact,
    recover_evidence_aes_key,
)
from server.app.core.rsa_crypto import (
    build_canonical_signing_data,
    get_trusted_signer_public_key,
    rsa_pss_verify,
    rsa_oaep_decrypt,
    DEFAULT_SIGNER_ID,
)
from Crypto.Cipher import AES
from server.app.database.session import get_db
from server.app.models.evidence import Evidence
from server.app.models.custody import ChainOfCustody
from server.app.models.event import InvestigationEvent
from server.app.api.endpoints.schemas import EvidenceRead, EvidenceIntegrityResult


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


# ---------------------------------------------------------------------------
# Route 1: Unified Secure Evidence Upload (Sole Supported Ingestion Path)
#   Enforces RSA-PSS digital signature verification, RSA-OAEP AES key recovery,
#   AES-256-GCM authenticated decryption, and original SHA-256 verification.
# ---------------------------------------------------------------------------

@router.post("", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    file: UploadFile = File(...),
    source_device: str = Form(default="local-workstation"),
    collector_id: Optional[str] = Form(default=None),
    description: Optional[str] = Form(default=None),
    # Cryptographic parameters passed in form or headers:
    original_sha256: Optional[str] = Form(default=None),
    encrypted_aes_key: Optional[str] = Form(default=None),
    rsa_signature: Optional[str] = Form(default=None),
    signer_key_id: Optional[str] = Form(default=None),
    nonce: Optional[str] = Form(default=None),
    tag: Optional[str] = Form(default=None),
    timestamp: Optional[int] = Form(default=None),
    upload_id: Optional[str] = Form(default=None),
    # Header fallbacks:
    x_forensight_original_sha256: Optional[str] = Header(None, alias="X-ForenSight-Original-SHA256"),
    x_forensight_encrypted_key: Optional[str] = Header(None, alias="X-ForenSight-Encrypted-Key"),
    x_forensight_signature: Optional[str] = Header(None, alias="X-ForenSight-Signature"),
    x_forensight_signer_id: Optional[str] = Header(None, alias="X-ForenSight-Signer-ID"),
    x_forensight_nonce: Optional[str] = Header(None, alias="X-ForenSight-Nonce"),
    x_forensight_tag: Optional[str] = Header(None, alias="X-ForenSight-Tag"),
    x_forensight_timestamp: Optional[str] = Header(None, alias="X-ForenSight-Timestamp"),
    x_forensight_upload_id: Optional[str] = Header(None, alias="X-ForenSight-Upload-ID"),
    db: Session = Depends(get_db),
) -> EvidenceRead:
    """
    Unified secure evidence ingestion endpoint.

    Step 1: Validate request format & file size.
    Step 2: Validate required metadata & cryptographic parameters.
    Step 3: Verify RSA-PSS signature against trusted public key.
    Step 4: Validate encrypted payload digest in canonical claim.
    Step 5: Recover AES key via RSA-OAEP decryption.
    Step 6: Decrypt and authenticate AES-256-GCM ciphertext.
    Step 7: Recalculate SHA-256 of recovered original bytes.
    Step 8: Compare SHA-256 against signed expected digest.
    Step 9: Store encrypted evidence at rest and create Evidence record.
    Step 10: Create initial ACQUIRED chain-of-custody event.
    Step 11: Return evidence record and record genuine benchmarks.
    """
    t_ingest_start = time.perf_counter()

    # Step 1: Validate request format & file size
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File submission must include a valid filename.",
        )

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

    # Step 2: Validate required metadata and cryptographic parameters
    orig_sha256 = (original_sha256 or x_forensight_original_sha256 or "").strip()
    enc_aes_key = (encrypted_aes_key or x_forensight_encrypted_key or "").strip()
    sig_str = (rsa_signature or x_forensight_signature or "").strip()
    target_signer_id = (signer_key_id or x_forensight_signer_id or DEFAULT_SIGNER_ID).strip()
    n_hex = (nonce or x_forensight_nonce or "").strip()
    t_hex = (tag or x_forensight_tag or "").strip()
    u_id = (upload_id or x_forensight_upload_id or f"UPLOAD-{uuid.uuid4().hex[:12].upper()}").strip()

    # Timestamp & replay check
    if timestamp is not None:
        req_ts = timestamp
    elif x_forensight_timestamp:
        try:
            req_ts = int(x_forensight_timestamp)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="X-ForenSight-Timestamp must be an integer Unix timestamp.",
            )
    else:
        req_ts = int(time.time())

    now_ts = int(time.time())
    age_seconds = abs(now_ts - req_ts)
    if age_seconds > settings.HMAC_REPLAY_WINDOW_SECONDS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                f"Request timestamp is {age_seconds}s outside the allowed "
                f"{settings.HMAC_REPLAY_WINDOW_SECONDS}s replay window."
            ),
        )

    if not orig_sha256 or not enc_aes_key or not sig_str:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Unified secure upload requires client-side AES-256-GCM encryption and RSA-PSS signature. "
                "Missing required parameters: original_sha256, encrypted_aes_key, and rsa_signature."
            ),
        )

    # Step 3: Verify RSA signature against trusted public key before trusting signed metadata
    trusted_pub_key = get_trusted_signer_public_key(target_signer_id)
    if trusted_pub_key is None:
        # Audit failure event
        db.add(InvestigationEvent(
            event_id=f"EVT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}",
            event_type="UNTRUSTED_KEY_REJECTED",
            source="evidence-ingestion",
            severity="WARNING",
            message=f"Upload rejected for '{original_filename}': untrusted signer key '{target_signer_id}'.",
            timestamp=datetime.now(timezone.utc),
        ))
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Untrusted or unregistered signing key '{target_signer_id}'. Upload rejected.",
        )

    raw_incoming_bytes = await file.read()
    if len(raw_incoming_bytes) < GCM_NONCE_LENGTH + GCM_TAG_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Encrypted evidence payload is too short (must contain nonce, tag, and ciphertext).",
        )

    payload_nonce = raw_incoming_bytes[:GCM_NONCE_LENGTH]
    payload_tag = raw_incoming_bytes[GCM_NONCE_LENGTH : GCM_NONCE_LENGTH + GCM_TAG_LENGTH]
    ciphertext = raw_incoming_bytes[GCM_NONCE_LENGTH + GCM_TAG_LENGTH :]

    if n_hex and n_hex.lower() != payload_nonce.hex().lower():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Nonce mismatch between upload parameters and payload container.",
        )
    if t_hex and t_hex.lower() != payload_tag.hex().lower():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Tag mismatch between upload parameters and payload container.",
        )

    encrypted_payload_sha256 = hashlib.sha256(raw_incoming_bytes).hexdigest()

    canonical_bytes = build_canonical_signing_data(
        upload_id=u_id,
        original_sha256=orig_sha256,
        filename=original_filename,
        source_device=source_device,
        collector_id=collector_id or "collector-node-01",
        timestamp=req_ts,
        encryption_algorithm="AES-256-GCM",
        nonce_hex=payload_nonce.hex(),
        tag_hex=payload_tag.hex(),
        encrypted_payload_sha256=encrypted_payload_sha256,
    )

    try:
        sig_bytes = bytes.fromhex(sig_str)
    except ValueError:
        import base64
        try:
            sig_bytes = base64.b64decode(sig_str)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid RSA signature encoding. Expected hex or base64.",
            )

    sig_valid, rsa_verify_duration_sec = rsa_pss_verify(
        canonical_data=canonical_bytes,
        signature=sig_bytes,
        public_key=trusted_pub_key,
    )

    if not sig_valid:
        db.add(InvestigationEvent(
            event_id=f"EVT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}",
            event_type="SIGNATURE_VERIFICATION_FAILURE",
            source="evidence-ingestion",
            severity="WARNING",
            message=f"RSA-PSS signature verification failed for upload '{original_filename}'.",
            timestamp=datetime.now(timezone.utc),
        ))
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="RSA digital signature verification failed. Signature does not match trusted public key or canonical payload.",
        )

    # Step 5: Recover the AES key securely via RSA-OAEP
    try:
        wrapped_aes_bytes = bytes.fromhex(enc_aes_key)
    except ValueError:
        import base64
        try:
            wrapped_aes_bytes = base64.b64decode(enc_aes_key)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid encrypted_aes_key encoding. Expected hex or base64.",
            )

    try:
        aes_key, rsa_decrypt_duration_sec = rsa_oaep_decrypt(wrapped_aes_bytes)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"AES key unwrapping failed: {str(err)}",
        )

    # Step 6: Decrypt and authenticate AES-GCM ciphertext
    t0_aes = time.perf_counter()
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=payload_nonce)
    try:
        recovered_plaintext = cipher.decrypt_and_verify(ciphertext, payload_tag)
    except (ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Decryption or authentication failed: AES-GCM authentication tag mismatch (ciphertext tampered or corrupted).",
        )
    aes_decryption_duration_sec = time.perf_counter() - t0_aes

    # Step 7 & 8: Recalculate original SHA-256 and compare with signed expected digest
    t0_hash = time.perf_counter()
    hasher = hashlib.sha256()
    hasher.update(recovered_plaintext)
    computed_original_sha256 = hasher.hexdigest()
    hashing_duration_sec = time.perf_counter() - t0_hash

    if computed_original_sha256.lower() != orig_sha256.lower():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Integrity verification failed: recovered plaintext SHA-256 ({computed_original_sha256}) "
                f"does not match signed expected digest ({orig_sha256})."
            ),
        )

    # Step 9: Store encrypted evidence and metadata
    evidence_id = generate_evidence_id()
    safe_storage_filename = f"{evidence_id}_{uuid.uuid4().hex[:8]}{ext}"
    evidence_dir = settings.resolved_evidence_dir
    destination_path = (evidence_dir / safe_storage_filename).resolve()

    if not str(destination_path).startswith(str(evidence_dir.resolve())):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Illegal file storage path detected.",
        )

    try:
        with open(destination_path, "wb") as dest_file:
            dest_file.write(raw_incoming_bytes)
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
        file_size_bytes=len(recovered_plaintext),
        sha256_hash=computed_original_sha256,
        description=description.strip() if description else None,
        status="ACQUIRED",
        is_encrypted=True,
        encrypted_aes_key=wrapped_aes_bytes.hex(),
        rsa_signature=sig_bytes.hex(),
        signer_key_id=target_signer_id,
        encryption_algorithm="AES-256-GCM",
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

    # Step 10: Create initial chain-of-custody event
    custody_notes = (
        f"Evidence artifact '{original_filename}' acquired via secure dashboard upload. "
        f"RSA-PSS signature verified ({target_signer_id}). "
        f"AES-256-GCM encrypted at rest. "
        f"SHA-256 (plaintext): {computed_original_sha256}. Size: {len(recovered_plaintext)} bytes."
    )
    custody_record = ChainOfCustody(
        evidence_id=evidence_record.evidence_id,
        action="ACQUIRED",
        actor=evidence_record.collector_id or "local-workstation",
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

    # Step 11: Return evidence record and record genuine benchmarks
    record_benchmark(
        db=db,
        benchmark_name="SHA256_HASHING",
        duration_sec=hashing_duration_sec,
        sample_size_bytes=len(recovered_plaintext),
        evidence_id=evidence_record.evidence_id,
        system_info="SHA-256 integrity verification",
    )
    record_benchmark(
        db=db,
        benchmark_name="AES_DECRYPTION",
        duration_sec=aes_decryption_duration_sec,
        sample_size_bytes=len(recovered_plaintext),
        evidence_id=evidence_record.evidence_id,
        system_info="AES-256-GCM authenticated decryption",
    )
    record_benchmark(
        db=db,
        benchmark_name="RSA_VERIFICATION",
        duration_sec=rsa_verify_duration_sec,
        sample_size_bytes=len(canonical_bytes),
        evidence_id=evidence_record.evidence_id,
        system_info=f"RSA-PSS signature verification ({target_signer_id})",
    )
    record_benchmark(
        db=db,
        benchmark_name="EVIDENCE_INGESTION",
        duration_sec=total_ingestion_sec,
        sample_size_bytes=len(raw_incoming_bytes),
        evidence_id=evidence_record.evidence_id,
        system_info=f"Storage: {destination_path.name}",
    )

    return evidence_record


# ---------------------------------------------------------------------------
# Route 2: Post-acquisition integrity verification
#   Recalculates SHA-256 from disk and compares against stored acquisition hash.
#   Never modifies the stored hash. Always writes a custody event.
# ---------------------------------------------------------------------------

@router.post(
    "/{evidence_id}/verify",
    response_model=EvidenceIntegrityResult,
    summary="Verify evidence artifact integrity",
    description=(
        "Recalculates the SHA-256 hash of the on-disk evidence file and compares it "
        "against the original acquisition hash stored in the database. "
        "Returns an intact/tampered/missing status and records every attempt in "
        "the chain-of-custody ledger. The original acquisition hash is never modified."
    ),
)
def verify_evidence_integrity(
    evidence_id: str,
    db: Session = Depends(get_db),
) -> EvidenceIntegrityResult:
    """
    Post-acquisition integrity check for a stored evidence artifact.

    Three possible outcomes:
      - INTACT      : on-disk hash matches the stored acquisition hash.
      - TAMPERED    : on-disk hash does NOT match the stored acquisition hash.
      - FILE_MISSING: the evidence file no longer exists at the stored path.

    A chain-of-custody record is written for every verification attempt,
    including the result, so the audit trail captures both clean checks and
    detected integrity failures.
    """
    now_utc = datetime.now(timezone.utc)

    evidence = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found in the database.",
        )

    evidence_dir = settings.resolved_evidence_dir.resolve()
    target_path = Path(evidence.file_path).resolve()
    try:
        target_path.relative_to(evidence_dir)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Access denied: evidence file path is outside the authorized storage directory.",
        )

    # ------------------------------------------------------------------ #
    # Case 1: File is missing from disk                                    #
    # ------------------------------------------------------------------ #
    if not target_path.exists():
        custody_record = ChainOfCustody(
            evidence_id=evidence.evidence_id,
            action="INTEGRITY_CHECK",
            actor="forensight-integrity-verifier",
            location=str(target_path),
            notes=(
                f"Integrity check FAILED — FILE MISSING. "
                f"Expected at: {target_path}. "
                f"Stored acquisition hash: {evidence.sha256_hash}."
            ),
            timestamp=now_utc,
        )
        db.add(custody_record)
        db.commit()
        return EvidenceIntegrityResult(
            evidence_id=evidence_id,
            is_intact=False,
            stored_hash=evidence.sha256_hash,
            current_hash=None,
            status="FILE_MISSING",
            message=(
                f"Evidence file is missing from disk at '{target_path}'. "
                "The original acquisition hash has been preserved in the database."
            ),
        )

    # ------------------------------------------------------------------ #
    # Case 2: File exists — read and (if encrypted at rest) decrypt first  #
    # The stored sha256_hash is always the PLAINTEXT hash.                #
    # For encrypted artifacts, we must decrypt before comparing hashes.   #
    # ------------------------------------------------------------------ #
    try:
        with open(target_path, "rb") as fh:
            raw_disk_bytes = fh.read()
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not read evidence file for integrity check: {exc}",
        )

    if evidence.is_encrypted:
        try:
            bytes_to_hash, _ = decrypt_evidence_artifact(evidence, raw_disk_bytes)
        except ValueError:
            # GCM tag mismatch — ciphertext was tampered
            current_hash = None
            is_intact = False
            integrity_status = "TAMPERED"
            custody_notes = (
                f"Integrity check FAILED — AES-GCM decryption rejected (authentication tag mismatch). "
                f"Stored acquisition hash: {evidence.sha256_hash}. "
                f"The artifact's encrypted container has been corrupted or tampered with."
            )
            message = (
                "INTEGRITY VIOLATION: AES-GCM authentication tag mismatch — the encrypted artifact "
                "has been corrupted or tampered with after acquisition."
            )
            custody_record = ChainOfCustody(
                evidence_id=evidence.evidence_id,
                action="INTEGRITY_CHECK",
                actor="forensight-integrity-verifier",
                location=str(target_path),
                notes=custody_notes,
                timestamp=now_utc,
            )
            db.add(custody_record)
            db.commit()
            return EvidenceIntegrityResult(
                evidence_id=evidence_id,
                is_intact=False,
                stored_hash=evidence.sha256_hash,
                current_hash=None,
                status=integrity_status,
                message=message,
            )
    else:
        bytes_to_hash = raw_disk_bytes

    hasher = hashlib.sha256(bytes_to_hash)
    current_hash = hasher.hexdigest()
    is_intact = current_hash.lower() == evidence.sha256_hash.lower()

    if is_intact:
        integrity_status = "INTACT"
        custody_notes = (
            f"Integrity check PASSED — SHA-256 verified. "
            f"Stored hash: {evidence.sha256_hash}. "
            f"Computed hash: {current_hash}."
        )
        message = "Evidence artifact is intact. On-disk SHA-256 matches the original acquisition hash."
    else:
        integrity_status = "TAMPERED"
        custody_notes = (
            f"Integrity check FAILED — SHA-256 MISMATCH DETECTED. "
            f"Stored acquisition hash: {evidence.sha256_hash}. "
            f"Current on-disk hash: {current_hash}. "
            f"The artifact may have been modified, corrupted, or replaced after acquisition."
        )
        message = (
            f"INTEGRITY VIOLATION: on-disk SHA-256 ({current_hash[:16]}…) does NOT match "
            f"stored acquisition hash ({evidence.sha256_hash[:16]}…). "
            "The artifact may have been tampered with after acquisition."
        )

    # Record the verification attempt in the chain-of-custody ledger.
    # The original acquisition hash in the Evidence row is NEVER updated here.
    custody_record = ChainOfCustody(
        evidence_id=evidence.evidence_id,
        action="INTEGRITY_CHECK",
        actor="forensight-integrity-verifier",
        location=str(target_path),
        notes=custody_notes,
        timestamp=now_utc,
    )
    db.add(custody_record)
    db.commit()

    return EvidenceIntegrityResult(
        evidence_id=evidence_id,
        is_intact=is_intact,
        stored_hash=evidence.sha256_hash,
        current_hash=current_hash,
        status=integrity_status,
        message=message,
    )


# ---------------------------------------------------------------------------
# Route 5: List all evidence (no auth required — read-only)
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


@router.get("/{evidence_id}", response_model=EvidenceRead, summary="Get evidence artifact metadata")
def get_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
) -> EvidenceRead:
    """Retrieve metadata for a single evidence artifact."""
    evidence = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found in database.",
        )
    return evidence


@router.get(
    "/{evidence_id}/download",
    summary="Download evidence artifact (decrypted if encrypted at rest)",
    description=(
        "Retrieves and returns the original plaintext evidence artifact. "
        "If the artifact was encrypted at rest with AES-256-GCM, it is safely "
        "decrypted on the fly, verifying authentication tag before transmission. "
        "Records an ACCESS chain-of-custody audit event."
    ),
)
def download_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
) -> Response:
    evidence = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found.",
        )
    evidence_dir = settings.resolved_evidence_dir.resolve()
    target_path = Path(evidence.file_path).resolve()
    try:
        target_path.relative_to(evidence_dir)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Access denied: evidence file path is outside the authorized storage directory.",
        )
    if not target_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence file not found on disk at '{target_path}'.",
        )
    raw_bytes = target_path.read_bytes()
    if evidence.is_encrypted:
        try:
            content_bytes, _ = decrypt_evidence_artifact(evidence, raw_bytes)
        except ValueError as exc:
            now_utc = datetime.now(timezone.utc)
            custody_record = ChainOfCustody(
                evidence_id=evidence.evidence_id,
                action="DOWNLOAD_FAILED",
                actor="forensight-investigator",
                location=str(target_path),
                notes=f"Download rejected: AES-GCM decryption failed (tampered ciphertext or tag mismatch: {exc}).",
                timestamp=now_utc,
            )
            db.add(custody_record)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Decryption failed: integrity authentication tag mismatch ({exc}).",
            )

        # Download integrity verification: verify recovered plaintext SHA-256 matches stored acquisition hash
        download_hash = hashlib.sha256(content_bytes).hexdigest()
        if download_hash.lower() != evidence.sha256_hash.lower():
            now_utc = datetime.now(timezone.utc)
            custody_record = ChainOfCustody(
                evidence_id=evidence.evidence_id,
                action="DOWNLOAD_FAILED",
                actor="forensight-investigator",
                location=str(target_path),
                notes=f"Download rejected: recovered bytes SHA-256 ({download_hash}) does not match stored acquisition hash ({evidence.sha256_hash}).",
                timestamp=now_utc,
            )
            db.add(custody_record)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Download integrity verification failed: decrypted evidence digest does not match original acquisition hash.",
            )
    else:
        content_bytes = raw_bytes

    # Record chain-of-custody audit record for artifact download
    now_utc = datetime.now(timezone.utc)
    custody_record = ChainOfCustody(
        evidence_id=evidence.evidence_id,
        action="DOWNLOAD",
        actor="forensight-investigator",
        location=str(target_path),
        notes=(
            f"Evidence artifact '{evidence.file_name}' downloaded/decrypted. "
            f"Plaintext SHA-256: {evidence.sha256_hash}."
        ),
        timestamp=now_utc,
    )
    db.add(custody_record)
    db.commit()

    return Response(
        content=content_bytes,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{evidence.file_name}"',
            "X-ForenSight-SHA256": evidence.sha256_hash,
        },
    )

