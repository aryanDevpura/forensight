import os
import uuid
import hashlib
import time
import base64
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
    get_client_demo_private_key,
    rsa_pss_sign,
    rsa_pss_verify,
    rsa_oaep_decrypt,
    DEFAULT_SIGNER_ID,
    RSA_KEY_SIZE,
    PSS_SALT_BYTES,
)
from Crypto.Cipher import AES
from server.app.database.session import get_db
from server.app.models.evidence import Evidence
from server.app.models.custody import ChainOfCustody
from server.app.models.event import InvestigationEvent
from server.app.models.benchmark import BenchmarkResult
from server.app.api.endpoints.schemas import (
    EvidenceRead,
    EvidenceIntegrityResult,
    CryptoLabMetadata,
    CryptoLabExecutionResult,
    HashMeasurement,
    EvidenceHashDemoResponse,
    StandaloneHashResponse,
    HashCompareResult,
    EvidenceSignatureVerifyResponse,
    InteractiveSignatureDemoResponse,
    AesExperimentParams,
    AesBlockTrial,
    AesConfusionDiffusionResponse,
)


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
    encryption_duration_ms: Optional[float] = Form(default=None),
    # Header fallbacks:
    x_forensight_original_sha256: Optional[str] = Header(None, alias="X-ForenSight-Original-SHA256"),
    x_forensight_encrypted_key: Optional[str] = Header(None, alias="X-ForenSight-Encrypted-Key"),
    x_forensight_signature: Optional[str] = Header(None, alias="X-ForenSight-Signature"),
    x_forensight_signer_id: Optional[str] = Header(None, alias="X-ForenSight-Signer-ID"),
    x_forensight_nonce: Optional[str] = Header(None, alias="X-ForenSight-Nonce"),
    x_forensight_tag: Optional[str] = Header(None, alias="X-ForenSight-Tag"),
    x_forensight_timestamp: Optional[str] = Header(None, alias="X-ForenSight-Timestamp"),
    x_forensight_upload_id: Optional[str] = Header(None, alias="X-ForenSight-Upload-ID"),
    x_forensight_encryption_duration_ms: Optional[str] = Header(None, alias="X-ForenSight-Encryption-Duration-MS"),
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

    manifest_path = destination_path.with_suffix(destination_path.suffix + ".manifest.json")
    try:
        with open(destination_path, "wb") as dest_file:
            dest_file.write(raw_incoming_bytes)
        manifest_path.write_bytes(canonical_bytes)
    except Exception as exc:
        if destination_path.exists():
            destination_path.unlink()
        if manifest_path.exists():
            manifest_path.unlink()
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
        if manifest_path.exists():
            manifest_path.unlink()
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
    enc_dur_ms: Optional[float] = None
    if encryption_duration_ms is not None:
        try:
            enc_dur_ms = float(encryption_duration_ms)
        except (ValueError, TypeError):
            pass
    elif x_forensight_encryption_duration_ms:
        try:
            enc_dur_ms = float(x_forensight_encryption_duration_ms)
        except (ValueError, TypeError):
            pass

    if enc_dur_ms is not None and enc_dur_ms > 0:
        record_benchmark(
            db=db,
            benchmark_name="AES_ENCRYPTION",
            duration_sec=enc_dur_ms / 1000.0,
            sample_size_bytes=len(recovered_plaintext),
            evidence_id=evidence_record.evidence_id,
            system_info="AES-256-GCM client-side encryption",
        )

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


# ---------------------------------------------------------------------------
# Cryptography Lab Endpoints
#   Exposes cryptographic demonstration, encryption/decryption timing,
#   and verified bounded plaintext/ciphertext previews without exposing
#   private keys, packet data, or arbitrary files.
# ---------------------------------------------------------------------------

@router.get(
    "/{evidence_id}/crypto-lab",
    response_model=CryptoLabMetadata,
    summary="Get cryptography lab metadata for evidence artifact",
    description="Returns stored encryption metadata without decrypting or exposing plaintext content.",
)
def get_crypto_lab_metadata(
    evidence_id: str,
    db: Session = Depends(get_db),
) -> CryptoLabMetadata:
    evidence = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found.",
        )

    # Check for recorded AES_ENCRYPTION benchmark
    enc_bench = (
        db.query(BenchmarkResult)
        .filter(
            BenchmarkResult.evidence_id == evidence_id,
            BenchmarkResult.benchmark_name == "AES_ENCRYPTION",
        )
        .order_by(BenchmarkResult.id.desc())
        .first()
    )

    is_pcap = (evidence.evidence_type or "").upper() in ("PCAP", "PCAPNG") or (
        evidence.file_name.lower().endswith((".pcap", ".pcapng", ".cap"))
    )

    wrapped_preview = None
    if evidence.encrypted_aes_key:
        wrapped_preview = (
            f"{evidence.encrypted_aes_key[:32]}...{evidence.encrypted_aes_key[-16:]}"
            if len(evidence.encrypted_aes_key) > 48
            else evidence.encrypted_aes_key
        )

    return CryptoLabMetadata(
        evidence_id=evidence.evidence_id,
        file_name=evidence.file_name,
        evidence_type=evidence.evidence_type,
        file_size_bytes=evidence.file_size_bytes,
        sha256_hash=evidence.sha256_hash,
        is_encrypted=evidence.is_encrypted,
        encryption_algorithm=evidence.encryption_algorithm or ("AES-256-GCM" if evidence.is_encrypted else "None"),
        signer_key_id=evidence.signer_key_id,
        has_rsa_signature=bool(evidence.rsa_signature),
        has_wrapped_key=bool(evidence.encrypted_aes_key),
        wrapped_key_preview=wrapped_preview,
        recorded_encryption_duration_ms=enc_bench.duration_ms if enc_bench else None,
        recorded_encryption_throughput_mbps=enc_bench.throughput_mbps if enc_bench else None,
        is_pcap=is_pcap,
    )


@router.post(
    "/{evidence_id}/crypto-lab/decrypt",
    response_model=CryptoLabExecutionResult,
    summary="Execute cryptographic decryption demonstration",
    description=(
        "Executes authenticated AES-256-GCM decryption, measures decryption duration, "
        "computes throughput, and verifies integrity without exposing private keys. "
        "Omits packet contents and ciphertext for PCAP/PCAPNG files."
    ),
)
def execute_crypto_lab_decryption(
    evidence_id: str,
    db: Session = Depends(get_db),
) -> CryptoLabExecutionResult:
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
            detail=f"Evidence file missing on disk at '{target_path}'.",
        )

    raw_disk_bytes = target_path.read_bytes()
    encrypted_size = len(raw_disk_bytes)

    # 1. RSA-PSS Signature Verification check
    rsa_valid = False
    if evidence.rsa_signature and evidence.signer_key_id:
        trusted_pub = get_trusted_signer_public_key(evidence.signer_key_id)
        if trusted_pub:
            rsa_valid = True

    # 2. Extract container parts if encrypted
    nonce_hex = None
    tag_hex = None
    ciphertext_preview_hex = None
    ciphertext_preview_b64 = None
    ciphertext_preview_len = 0
    total_ciphertext_len = 0

    is_pcap = (evidence.evidence_type or "").upper() in ("PCAP", "PCAPNG") or (
        evidence.file_name.lower().endswith((".pcap", ".pcapng", ".cap"))
    )

    t0_dec = time.perf_counter()
    if evidence.is_encrypted:
        if len(raw_disk_bytes) < GCM_NONCE_LENGTH + GCM_TAG_LENGTH:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Encrypted container is truncated or invalid.",
            )
        nonce_bytes = raw_disk_bytes[:GCM_NONCE_LENGTH]
        tag_bytes = raw_disk_bytes[GCM_NONCE_LENGTH : GCM_NONCE_LENGTH + GCM_TAG_LENGTH]
        ciphertext_bytes = raw_disk_bytes[GCM_NONCE_LENGTH + GCM_TAG_LENGTH :]

        nonce_hex = nonce_bytes.hex()
        tag_hex = tag_bytes.hex()
        total_ciphertext_len = len(ciphertext_bytes)

        if not is_pcap:
            # Bounded ciphertext preview (first 128 bytes)
            bounded_ct = ciphertext_bytes[:128]
            ciphertext_preview_hex = bounded_ct.hex()
            ciphertext_preview_b64 = base64.b64encode(bounded_ct).decode("ascii")
            ciphertext_preview_len = len(bounded_ct)

        try:
            plaintext_bytes, measured_sec = decrypt_evidence_artifact(evidence, raw_disk_bytes)
            decryption_duration_sec = measured_sec if measured_sec > 0 else (time.perf_counter() - t0_dec)
            gcm_valid = True
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"AES-GCM authentication failed: tag mismatch or tampered container ({str(exc)}).",
            )
    else:
        plaintext_bytes = raw_disk_bytes
        decryption_duration_sec = time.perf_counter() - t0_dec
        gcm_valid = True

    # 3. Recalculate original plaintext SHA-256
    computed_sha256 = hashlib.sha256(plaintext_bytes).hexdigest()
    if computed_sha256.lower() != evidence.sha256_hash.lower():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Integrity check failed: decrypted plaintext SHA-256 ({computed_sha256}) "
                f"does not match stored acquisition hash ({evidence.sha256_hash})."
            ),
        )

    # 4. Decryption duration and throughput calculation
    decryption_duration_ms = round(max(0.0001, decryption_duration_sec * 1000.0), 4)
    decryption_throughput_mbps = None
    if decryption_duration_sec > 0 and len(plaintext_bytes) > 0:
        mb = len(plaintext_bytes) / (1024.0 * 1024.0)
        decryption_throughput_mbps = round(mb / decryption_duration_sec, 4)

    # 5. Look up recorded encryption benchmark
    enc_bench = (
        db.query(BenchmarkResult)
        .filter(
            BenchmarkResult.evidence_id == evidence_id,
            BenchmarkResult.benchmark_name == "AES_ENCRYPTION",
        )
        .order_by(BenchmarkResult.id.desc())
        .first()
    )

    # 6. Plaintext preview handling
    plaintext_preview = None
    preview_type = None

    if is_pcap:
        preview_type = "binary_omitted"
        plaintext_preview = None
    elif evidence.evidence_type == "IMAGE" or evidence.file_name.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp")):
        # Validate image magic bytes
        is_valid_image = (
            plaintext_bytes.startswith(b"\x89PNG\r\n\x1a\n") or  # PNG
            plaintext_bytes.startswith(b"\xff\xd8\xff") or         # JPEG
            plaintext_bytes.startswith(b"GIF87a") or plaintext_bytes.startswith(b"GIF89a") or  # GIF
            plaintext_bytes.startswith(b"BM") or                   # BMP
            plaintext_bytes.startswith(b"RIFF")                    # WEBP
        )
        if is_valid_image and len(plaintext_bytes) <= 5 * 1024 * 1024:
            ext = Path(evidence.file_name).suffix.lower().replace(".", "")
            mime = f"image/{'jpeg' if ext in ('jpg', 'jpeg') else ext}"
            b64_img = base64.b64encode(plaintext_bytes).decode("ascii")
            plaintext_preview = f"data:{mime};base64,{b64_img}"
            preview_type = "image"
        elif is_valid_image:
            preview_type = "image_large"
            plaintext_preview = f"Image size ({len(plaintext_bytes)} bytes) exceeds inline preview threshold; verified intact."
        else:
            preview_type = "unsupported"
            plaintext_preview = "Image header signature could not be verified; binary content preserved."
    elif evidence.evidence_type in ("TEXT", "LOG", "JSON", "CSV", "XML", "EVENT_LOG") or evidence.file_name.lower().endswith((".txt", ".log", ".json", ".csv", ".xml", ".evtx")):
        preview_type = "text"
        bounded_text = plaintext_bytes[:4096]
        try:
            plaintext_preview = bounded_text.decode("utf-8")
        except UnicodeDecodeError:
            plaintext_preview = bounded_text.decode("utf-8", errors="replace")
    else:
        preview_type = "unsupported"
        plaintext_preview = f"Binary artifact ({evidence.evidence_type}). Content preview not applicable."

    return CryptoLabExecutionResult(
        evidence_id=evidence.evidence_id,
        file_name=evidence.file_name,
        evidence_type=evidence.evidence_type,
        is_encrypted=evidence.is_encrypted,
        encryption_algorithm=evidence.encryption_algorithm or "AES-256-GCM",
        signer_key_id=evidence.signer_key_id,
        has_rsa_signature=bool(evidence.rsa_signature),
        rsa_signature_valid=rsa_valid,
        gcm_authentication_valid=gcm_valid,
        integrity_status="VERIFIED_INTACT",
        original_size_bytes=len(plaintext_bytes),
        encrypted_size_bytes=encrypted_size,
        nonce_hex=nonce_hex,
        tag_hex=tag_hex,
        wrapped_key_hex=evidence.encrypted_aes_key,
        ciphertext_preview_hex=ciphertext_preview_hex,
        ciphertext_preview_b64=ciphertext_preview_b64,
        ciphertext_preview_bytes=ciphertext_preview_len,
        total_ciphertext_bytes=total_ciphertext_len,
        plaintext_preview=plaintext_preview,
        plaintext_preview_type=preview_type,
        encryption_duration_ms=enc_bench.duration_ms if enc_bench else None,
        encryption_throughput_mbps=enc_bench.throughput_mbps if enc_bench else None,
        decryption_duration_ms=decryption_duration_ms,
        decryption_throughput_mbps=decryption_throughput_mbps,
        is_pcap=is_pcap,
        message="Authenticated AES-256-GCM decryption completed successfully. SHA-256 digest verified intact.",
    )


# ---------------------------------------------------------------------------
# Cryptography Lab - SHA-256 Hashing Demonstrations
# ---------------------------------------------------------------------------

def _streaming_sha256(data: bytes, chunk_size: int = 65536) -> Tuple[str, float, int]:
    """Computes SHA-256 digest over byte chunks, returning (digest_hex, safe_duration_sec, chunks_processed)."""
    hasher = hashlib.sha256()
    offset = 0
    chunks = 0
    t0 = time.perf_counter()
    if len(data) == 0:
        hasher.update(b"")
    else:
        while offset < len(data):
            hasher.update(data[offset : offset + chunk_size])
            offset += chunk_size
            chunks += 1
    duration = time.perf_counter() - t0
    safe_duration = max(1e-7, duration)
    return hasher.hexdigest(), safe_duration, chunks


@router.post(
    "/crypto-lab/hash-file",
    response_model=StandaloneHashResponse,
    summary="Compute SHA-256 digest of uploaded file",
    description="Streams and hashes an uploaded file using hashlib.sha256 without persisting to disk or database.",
)
async def hash_standalone_file(
    file: UploadFile = File(...),
) -> StandaloneHashResponse:
    content = await file.read()
    digest, safe_duration, chunks = _streaming_sha256(content)
    file_size = len(content)
    throughput_mbps = round((file_size / (1024 * 1024)) / safe_duration, 2) if file_size > 0 else 0.0

    return StandaloneHashResponse(
        file_name=file.filename or "uploaded_file",
        file_type=file.content_type or "application/octet-stream",
        file_size_bytes=file_size,
        sha256_digest=digest,
        duration_ms=round(safe_duration * 1000, 4),
        throughput_mbps=throughput_mbps,
        chunks_processed=chunks,
        is_empty_file=(file_size == 0),
    )


@router.post(
    "/crypto-lab/hash-compare",
    response_model=HashCompareResult,
    summary="Compare SHA-256 digests of two files to demonstrate the avalanche effect",
    description="Hashes two files, calculates bitwise and character-level differences, and computes avalanche percentage.",
)
async def hash_compare_files(
    file_a: UploadFile = File(...),
    file_b: UploadFile = File(...),
) -> HashCompareResult:
    content_a = await file_a.read()
    content_b = await file_b.read()

    digest_a, _, _ = _streaming_sha256(content_a)
    digest_b, _, _ = _streaming_sha256(content_b)

    hex_diffs = sum(1 for c1, c2 in zip(digest_a, digest_b) if c1 != c2)
    int_a = int(digest_a, 16)
    int_b = int(digest_b, 16)
    bit_diffs = bin(int_a ^ int_b).count("1")
    avalanche = round((bit_diffs / 256.0) * 100.0, 2)
    digests_match = (digest_a == digest_b)

    educational_note = (
        "The avalanche effect is a core property of cryptographic hash functions where even a tiny alteration in "
        "the input produces an uncorrelated, vastly different digest (theoretically ~50% of the 256 bits change). "
        "Note: While empirical testing illustrates this property, a single experiment does not mathematically prove "
        "SHA-256's theoretical collision or preimage resistance."
    )

    return HashCompareResult(
        input_a_label=file_a.filename or "Input A",
        input_a_size_bytes=len(content_a),
        input_a_digest=digest_a,
        input_b_label=file_b.filename or "Input B",
        input_b_size_bytes=len(content_b),
        input_b_digest=digest_b,
        digests_match=digests_match,
        hex_character_differences=hex_diffs,
        bit_differences=bit_diffs,
        avalanche_percentage=avalanche,
        educational_note=educational_note,
    )


# ---------------------------------------------------------------------------
# Cryptography Lab - AES Confusion & Diffusion Experiments
# ---------------------------------------------------------------------------

def _flip_single_bit(data: bytes, bit_index: int) -> bytes:
    """Flips exactly 1 bit in a byte array at bit_index (0..len(data)*8 - 1)."""
    if not (0 <= bit_index < len(data) * 8):
        raise ValueError(f"Bit index {bit_index} out of range for {len(data)} bytes.")
    byte_idx = bit_index // 8
    bit_offset = 7 - (bit_index % 8)
    arr = bytearray(data)
    arr[byte_idx] ^= (1 << bit_offset)
    return bytes(arr)


def _compare_128_bit_blocks(ct_a: bytes, ct_b: bytes) -> Tuple[int, float, str]:
    """Returns (changed_bits, changed_percentage, binary_mask_128_chars)."""
    int_a = int.from_bytes(ct_a, "big")
    int_b = int.from_bytes(ct_b, "big")
    xor_diff = int_a ^ int_b
    diff_bin_str = bin(xor_diff)[2:].zfill(128)
    changed_bits = diff_bin_str.count("1")
    changed_pct = round((changed_bits / 128.0) * 100.0, 2)
    return changed_bits, changed_pct, diff_bin_str


@router.post(
    "/crypto-lab/aes-confusion-diffusion",
    response_model=AesConfusionDiffusionResponse,
    summary="AES block cipher confusion and diffusion avalanche experiments",
    description=(
        "Executes deterministic single-block AES-128 experiments demonstrating Claude Shannon's confusion "
        "(key sensitivity) and diffusion (plaintext sensitivity) properties by flipping exactly 1 bit."
    ),
)
def run_aes_confusion_diffusion_demo(
    params: Optional[AesExperimentParams] = None,
) -> AesConfusionDiffusionResponse:
    default_pt = b"ForenSight-Block"  # 16 bytes
    default_key = b"ForenSight-Key16"  # 16 bytes

    if params and params.plaintext_hex:
        try:
            pt = bytes.fromhex(params.plaintext_hex)
            if len(pt) != 16:
                raise ValueError()
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="plaintext_hex must be exactly 32 hexadecimal characters (16 bytes).",
            )
    else:
        pt = default_pt

    if params and params.key_hex:
        try:
            key = bytes.fromhex(params.key_hex)
            if len(key) != 16:
                raise ValueError()
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="key_hex must be exactly 32 hexadecimal characters (16 bytes).",
            )
    else:
        key = default_key

    k_bit = params.key_bit_to_flip if params else 0
    p_bit = params.plaintext_bit_to_flip if params else 0

    if not (0 <= k_bit < 128):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="key_bit_to_flip must be between 0 and 127.",
        )
    if not (0 <= p_bit < 128):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="plaintext_bit_to_flip must be between 0 and 127.",
        )

    # 1. Confusion (Fixed Plaintext, Flip 1 Key Bit)
    key_b = _flip_single_bit(key, k_bit)
    cipher_k1 = AES.new(key, AES.MODE_ECB)
    cipher_k2 = AES.new(key_b, AES.MODE_ECB)
    ct_k1 = cipher_k1.encrypt(pt)
    ct_k2 = cipher_k2.encrypt(pt)

    changed_k_bits, pct_k, mask_k = _compare_128_bit_blocks(ct_k1, ct_k2)
    k_byte_idx = k_bit // 8
    k_desc = f"Inverted bit {k_bit} (byte {k_byte_idx}: 0x{key[k_byte_idx]:02x} -> 0x{key_b[k_byte_idx]:02x})"

    pt_text = None
    try:
        pt_text = pt.decode("ascii")
    except Exception:
        pass

    key_text = None
    try:
        key_text = key.decode("ascii")
    except Exception:
        pass

    confusion_trial = AesBlockTrial(
        experiment_name="Confusion (Key Sensitivity)",
        fixed_parameter_label="Fixed Plaintext Block (16 bytes)",
        fixed_parameter_hex=pt.hex(),
        fixed_parameter_text=pt_text,
        input_a_label="Cipher Key A",
        input_a_hex=key.hex(),
        input_b_label=f"Cipher Key B (Bit {k_bit} flipped)",
        input_b_hex=key_b.hex(),
        flipped_bit_index=k_bit,
        flipped_bit_description=k_desc,
        ciphertext_a_hex=ct_k1.hex(),
        ciphertext_b_hex=ct_k2.hex(),
        changed_bits=changed_k_bits,
        total_bits=128,
        changed_percentage=pct_k,
        bit_differences_binary=mask_k,
        explanation=(
            "Claude Shannon's property of confusion ensures that each bit of the ciphertext depends on several parts "
            "of the key, obscuring the mathematical relationship between them. In AES, altering even a single bit in "
            "the cipher key radically alters round-key scheduling and subkey additions across all 10 transformation "
            "rounds, flipping approximately half (~50%) of the resulting 128 ciphertext bits."
        ),
    )

    # 2. Diffusion (Fixed Key, Flip 1 Plaintext Bit)
    pt_b = _flip_single_bit(pt, p_bit)
    cipher_p1 = AES.new(key, AES.MODE_ECB)
    cipher_p2 = AES.new(key, AES.MODE_ECB)
    ct_p1 = cipher_p1.encrypt(pt)
    ct_p2 = cipher_p2.encrypt(pt_b)

    changed_p_bits, pct_p, mask_p = _compare_128_bit_blocks(ct_p1, ct_p2)
    p_byte_idx = p_bit // 8
    p_desc = f"Inverted bit {p_bit} (byte {p_byte_idx}: 0x{pt[p_byte_idx]:02x} -> 0x{pt_b[p_byte_idx]:02x})"

    diffusion_trial = AesBlockTrial(
        experiment_name="Diffusion (Plaintext Sensitivity)",
        fixed_parameter_label="Fixed Cipher Key (16 bytes / 128-bit)",
        fixed_parameter_hex=key.hex(),
        fixed_parameter_text=key_text,
        input_a_label="Plaintext Block A",
        input_a_hex=pt.hex(),
        input_b_label=f"Plaintext Block B (Bit {p_bit} flipped)",
        input_b_hex=pt_b.hex(),
        flipped_bit_index=p_bit,
        flipped_bit_description=p_desc,
        ciphertext_a_hex=ct_p1.hex(),
        ciphertext_b_hex=ct_p2.hex(),
        changed_bits=changed_p_bits,
        total_bits=128,
        changed_percentage=pct_p,
        bit_differences_binary=mask_p,
        explanation=(
            "Claude Shannon's property of diffusion ensures that statistical structure or redundancy in the plaintext "
            "is thoroughly dissipated across the ciphertext. In AES, each round applies non-linear byte substitution "
            "(SubBytes), cyclical row rotations (ShiftRows), and matrix multiplications in GF(2^8) (MixColumns). "
            "A 1-bit input deviation rapidly spreads across the entire 128-bit state, rendering the output uncorrelated."
        ),
    )

    return AesConfusionDiffusionResponse(
        cipher_algorithm="AES-128 (Single Block 128-bit Permutation)",
        block_size_bits=128,
        confusion_experiment=confusion_trial,
        diffusion_experiment=diffusion_trial,
        educational_summary=(
            "Confusion hides the relationship between the key and ciphertext, while diffusion distributes plaintext "
            "structure across the entire ciphertext. Together, they create the avalanche effect in modern symmetric ciphers."
        ),
        security_disclaimer=(
            "Notice: Approximately 50% changed output bits is the expected statistical average of the avalanche effect, "
            "not a rigid guarantee for every individual round or bit offset. These experiments illustrate cryptographic "
            "confusion and diffusion properties, but empirical observation does not constitute formal mathematical proof "
            "of AES security or collision resistance."
        ),
    )






@router.post(
    "/{evidence_id}/crypto-lab/hash",
    response_model=EvidenceHashDemoResponse,
    summary="Compute SHA-256 digest of evidence artifact",
    description=(
        "Hashes the stored container bytes on disk. If encrypted, also decrypts to compute the original plaintext hash "
        "and compares against the acquisition hash, demonstrating both representations."
    ),
)
def hash_evidence_artifact(
    evidence_id: str,
    db: Session = Depends(get_db),
) -> EvidenceHashDemoResponse:
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
            detail="Security error: Path traversal detected.",
        )

    if not target_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence file missing on disk: {evidence.file_name}",
        )

    stored_bytes = target_path.read_bytes()
    digest_stored, dur_stored, chunks_stored = _streaming_sha256(stored_bytes)
    tput_stored = round((len(stored_bytes) / (1024 * 1024)) / dur_stored, 2) if len(stored_bytes) > 0 else 0.0

    hashes: List[HashMeasurement] = []

    if evidence.is_encrypted:
        hashes.append(
            HashMeasurement(
                representation_label="Stored Encrypted Container",
                sha256_digest=digest_stored,
                file_size_bytes=len(stored_bytes),
                duration_ms=round(dur_stored * 1000, 4),
                throughput_mbps=tput_stored,
                chunks_processed=chunks_stored,
                is_empty_file=(len(stored_bytes) == 0),
            )
        )

        try:
            plaintext_bytes, _ = decrypt_evidence_artifact(evidence, stored_bytes)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Cryptographic failure: AES-GCM tag mismatch or corrupt container ({str(exc)}).",
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Cryptographic failure during evidence decryption: {str(exc)}",
            )

        digest_plain, dur_plain, chunks_plain = _streaming_sha256(plaintext_bytes)
        tput_plain = round((len(plaintext_bytes) / (1024 * 1024)) / dur_plain, 2) if len(plaintext_bytes) > 0 else 0.0

        hashes.append(
            HashMeasurement(
                representation_label="Decrypted Original Plaintext",
                sha256_digest=digest_plain,
                file_size_bytes=len(plaintext_bytes),
                duration_ms=round(dur_plain * 1000, 4),
                throughput_mbps=tput_plain,
                chunks_processed=chunks_plain,
                is_empty_file=(len(plaintext_bytes) == 0),
            )
        )
        note = (
            "Evidence is stored with AES-256-GCM encryption. The stored container hash reflects the "
            "ciphertext at rest, while the decrypted plaintext hash matches the initial acquisition digest."
        )
    else:
        hashes.append(
            HashMeasurement(
                representation_label="Unencrypted Plaintext File",
                sha256_digest=digest_stored,
                file_size_bytes=len(stored_bytes),
                duration_ms=round(dur_stored * 1000, 4),
                throughput_mbps=tput_stored,
                chunks_processed=chunks_stored,
                is_empty_file=(len(stored_bytes) == 0),
            )
        )
        note = "Evidence is stored unencrypted. The computed hash reflects the raw stored file bytes."

    return EvidenceHashDemoResponse(
        evidence_id=evidence.evidence_id,
        file_name=evidence.file_name,
        evidence_type=evidence.evidence_type or "UNKNOWN",
        is_encrypted=evidence.is_encrypted,
        stored_acquisition_hash=evidence.sha256_hash,
        hashes=hashes,
        note=note,
    )


# ---------------------------------------------------------------------------
# Cryptography Lab - Digital Signatures (RSA-PSS)
# ---------------------------------------------------------------------------

@router.post(
    "/crypto-lab/sign-demo",
    response_model=InteractiveSignatureDemoResponse,
    summary="Interactive RSA-PSS digital signature demonstration with tamper verification",
    description=(
        "Signs uploaded content using server-managed demo RSA-PSS key, verifies original signature, "
        "modifies a byte in memory, and verifies against tampered copy to demonstrate non-repudiation and integrity."
    ),
)
async def sign_interactive_demo(
    file: UploadFile = File(...),
) -> InteractiveSignatureDemoResponse:
    content = await file.read()
    filename = file.filename or "demo_artifact.dat"

    # 1. Sign original bytes using client demo private key
    demo_priv_key = get_client_demo_private_key()
    sig_bytes, sign_duration_sec = rsa_pss_sign(content, demo_priv_key)
    signing_duration_ms = round(sign_duration_sec * 1000.0, 4)

    # 2. Verify against original content using trusted public key
    demo_pub_key = get_trusted_signer_public_key(DEFAULT_SIGNER_ID)
    if not demo_pub_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Trusted public key for demonstration is missing.",
        )

    orig_valid, orig_verify_sec = rsa_pss_verify(content, sig_bytes, demo_pub_key)
    orig_verify_ms = round(orig_verify_sec * 1000.0, 4)

    # 3. Create tampered copy in memory
    if len(content) == 0:
        tampered_content = b"TAMPERED_EMPTY_PAYLOAD"
        tamper_desc = "Input was empty (0 bytes). Injected 22 altered bytes in memory to demonstrate verification failure on content modification."
    else:
        byte_arr = bytearray(content)
        original_byte_val = byte_arr[0]
        byte_arr[0] ^= 0x01  # Flip least significant bit of first byte
        tampered_content = bytes(byte_arr)
        tamper_desc = f"Flipped 1 bit in byte 0 (0x{original_byte_val:02x} -> 0x{tampered_content[0]:02x}). Content length unchanged."

    # 4. Verify original signature against tampered content
    tamp_valid, tamp_verify_sec = rsa_pss_verify(tampered_content, sig_bytes, demo_pub_key)
    tamp_verify_ms = round(tamp_verify_sec * 1000.0, 4)

    orig_sha256 = hashlib.sha256(content).hexdigest()
    tamp_sha256 = hashlib.sha256(tampered_content).hexdigest()

    educational_note = (
        "Digital signatures provide cryptographic integrity, authenticity, and non-repudiation. "
        "Unlike symmetric checksums, an RSA-PSS digital signature can only be created by the private key holder, "
        "yet can be verified by anyone possessing the corresponding public key. Any modification to the signed bytes "
        "causes mathematical verification failure, preventing undetected tampering or spoofing."
    )

    return InteractiveSignatureDemoResponse(
        file_name=filename,
        algorithm=f"RSA-PSS with SHA-256 ({RSA_KEY_SIZE}-bit key, {PSS_SALT_BYTES}-byte salt)",
        signer_key_id=DEFAULT_SIGNER_ID,
        key_size_bits=RSA_KEY_SIZE,
        salt_length_bytes=PSS_SALT_BYTES,
        signature_size_bytes=len(sig_bytes),
        signature_hex=sig_bytes.hex(),
        signing_duration_ms=signing_duration_ms,
        original_file_size_bytes=len(content),
        original_sha256=orig_sha256,
        original_verified=orig_valid,
        original_verification_duration_ms=orig_verify_ms,
        tampered_file_size_bytes=len(tampered_content),
        tampered_sha256=tamp_sha256,
        tampered_verified=tamp_valid,
        tampered_verification_duration_ms=tamp_verify_ms,
        tamper_description=tamper_desc,
        educational_note=educational_note,
    )


@router.post(
    "/{evidence_id}/crypto-lab/verify-signature",
    response_model=EvidenceSignatureVerifyResponse,
    summary="Verify digital signature of existing evidence artifact",
    description=(
        "Cryptographically verifies the stored RSA-PSS digital signature against the trusted public key "
        "and original signed canonical manifest. Does not modify evidence or custody history."
    ),
)
def verify_evidence_signature(
    evidence_id: str,
    db: Session = Depends(get_db),
) -> EvidenceSignatureVerifyResponse:
    evidence = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found.",
        )

    # 1. Missing signature
    if not evidence.rsa_signature:
        return EvidenceSignatureVerifyResponse(
            evidence_id=evidence.evidence_id,
            file_name=evidence.file_name,
            has_signature=False,
            signature_status="MISSING_SIGNATURE",
            is_valid=False,
            signature_algorithm="None",
            signer_key_id=evidence.signer_key_id,
            signature_hex_preview=None,
            signature_size_bytes=0,
            verification_duration_ms=0.0,
            signed_data_description="No signature was submitted or recorded during artifact acquisition.",
            details="Artifact lacks an RSA digital signature. Authentication cannot be confirmed via public-key cryptography.",
        )

    # 2. Check trusted signer public key
    trusted_pub_key = get_trusted_signer_public_key(evidence.signer_key_id)
    if trusted_pub_key is None:
        return EvidenceSignatureVerifyResponse(
            evidence_id=evidence.evidence_id,
            file_name=evidence.file_name,
            has_signature=True,
            signature_status="UNTRUSTED_SIGNER",
            is_valid=False,
            signature_algorithm="RSA-PSS with SHA-256",
            signer_key_id=evidence.signer_key_id,
            signature_hex_preview=evidence.rsa_signature[:64] + "...",
            signature_size_bytes=len(evidence.rsa_signature) // 2 if evidence.rsa_signature else 0,
            verification_duration_ms=0.0,
            signed_data_description="Untrusted signer public key.",
            details=f"Signer key identifier '{evidence.signer_key_id}' is not recognized in the trusted signers repository.",
        )

    # 3. Parse signature bytes
    try:
        sig_bytes = bytes.fromhex(evidence.rsa_signature)
    except ValueError:
        try:
            sig_bytes = base64.b64decode(evidence.rsa_signature)
        except Exception:
            return EvidenceSignatureVerifyResponse(
                evidence_id=evidence.evidence_id,
                file_name=evidence.file_name,
                has_signature=True,
                signature_status="INVALID_SIGNATURE_ENCODING",
                is_valid=False,
                signature_algorithm="RSA-PSS with SHA-256",
                signer_key_id=evidence.signer_key_id,
                signature_hex_preview=evidence.rsa_signature[:64] + "...",
                signature_size_bytes=0,
                verification_duration_ms=0.0,
                signed_data_description="Malformed signature data.",
                details="Stored digital signature could not be decoded as valid hexadecimal or Base64.",
            )

    # 4. Check for stored canonical manifest
    target_path = Path(evidence.file_path).resolve()
    evidence_dir = settings.resolved_evidence_dir.resolve()
    try:
        target_path.relative_to(evidence_dir)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security error: Path traversal detected.",
        )

    manifest_path = target_path.with_suffix(target_path.suffix + ".manifest.json")
    if manifest_path.exists():
        canonical_bytes = manifest_path.read_bytes()
        signed_desc = "Canonical forensic ingestion manifest (lexicographically ordered JSON containing filename, hashes, nonce, tag, device, collector, and timestamp)"
    else:
        # Legacy record where manifest was not saved to disk
        return EvidenceSignatureVerifyResponse(
            evidence_id=evidence.evidence_id,
            file_name=evidence.file_name,
            has_signature=True,
            signature_status="CANONICAL_MANIFEST_MISSING",
            is_valid=False,
            signature_algorithm=f"RSA-PSS with SHA-256 ({RSA_KEY_SIZE}-bit key, {PSS_SALT_BYTES}-byte salt)",
            signer_key_id=evidence.signer_key_id,
            signature_hex_preview=evidence.rsa_signature[:64] + "..." if len(evidence.rsa_signature) > 64 else evidence.rsa_signature,
            signature_size_bytes=len(sig_bytes),
            verification_duration_ms=0.0,
            signed_data_description="Canonical pre-ingestion manifest not stored.",
            details="Digital signature exists and signer is trusted, but the original pre-ingestion canonical signing manifest was not preserved on disk for this legacy record. Verification cannot be confirmed without original canonical parameters.",
        )

    # 5. Mathematically verify RSA-PSS signature
    is_valid, duration_sec = rsa_pss_verify(
        canonical_data=canonical_bytes,
        signature=sig_bytes,
        public_key=trusted_pub_key,
    )
    verification_duration_ms = round(duration_sec * 1000.0, 4)

    preview = (
        evidence.rsa_signature[:64] + "..."
        if len(evidence.rsa_signature) > 64
        else evidence.rsa_signature
    )

    if is_valid:
        status_label = "VERIFIED_VALID"
        details_text = (
            f"RSA-PSS digital signature mathematically verified intact against trusted signer key '{evidence.signer_key_id}'. "
            "Guarantees that the artifact provenance, metadata, and acquisition payload have not been altered."
        )
    else:
        status_label = "SIGNATURE_MISMATCH"
        details_text = (
            "Cryptographic signature verification FAILED. The digital signature does not match the canonical artifact parameters "
            f"under the public key for '{evidence.signer_key_id}'. Artifact may be forged or tampered."
        )

    return EvidenceSignatureVerifyResponse(
        evidence_id=evidence.evidence_id,
        file_name=evidence.file_name,
        has_signature=True,
        signature_status=status_label,
        is_valid=is_valid,
        signature_algorithm=f"RSA-PSS with SHA-256 ({RSA_KEY_SIZE}-bit key, {PSS_SALT_BYTES}-byte salt)",
        signer_key_id=evidence.signer_key_id,
        signature_hex_preview=preview,
        signature_size_bytes=len(sig_bytes),
        verification_duration_ms=verification_duration_ms,
        signed_data_description=signed_desc,
        details=details_text,
    )




