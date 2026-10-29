"""
Test utilities for ForenSight unified secure evidence upload testing.
"""

import io
import time
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from Crypto.Random import get_random_bytes

from server.app.core.crypto import encrypt_payload, GCM_NONCE_LENGTH, GCM_TAG_LENGTH
from server.app.core.rsa_crypto import (
    get_server_public_key,
    get_client_demo_private_key,
    rsa_oaep_encrypt,
    rsa_pss_sign,
    build_canonical_signing_data,
    DEFAULT_SIGNER_ID,
)


def create_signed_encrypted_payload(
    content: bytes,
    filename: str = "test.pcap",
    source_device: str = "test-workstation",
    collector_id: str = "collector-node-01",
    description: Optional[str] = None,
    signer_key_id: str = DEFAULT_SIGNER_ID,
    client_private_key=None,
    server_public_key=None,
    timestamp: Optional[int] = None,
    upload_id: Optional[str] = None,
    corrupt_ciphertext: bool = False,
    corrupt_tag: bool = False,
    corrupt_signature: bool = False,
    corrupt_digest: bool = False,
    aes_key: Optional[bytes] = None,
    signing_duration_ms: Optional[float] = None,
) -> Tuple[bytes, Dict[str, Any]]:
    """
    Helper creating encrypted evidence payload and signed form parameters
    matching the unified dashboard upload protocol.
    """
    original_sha256 = hashlib.sha256(content).hexdigest()
    if corrupt_digest:
        original_sha256 = "0" * 64

    # 1. AES key & encryption
    key = aes_key or get_random_bytes(32)
    packaged, duration_sec = encrypt_payload(content, key)

    nonce = packaged[:GCM_NONCE_LENGTH]
    tag = packaged[GCM_NONCE_LENGTH : GCM_NONCE_LENGTH + GCM_TAG_LENGTH]
    ciphertext = packaged[GCM_NONCE_LENGTH + GCM_TAG_LENGTH :]

    if corrupt_ciphertext and len(ciphertext) > 0:
        ciphertext = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
        packaged = nonce + tag + ciphertext

    if corrupt_tag:
        tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        packaged = nonce + tag + ciphertext

    payload_sha256 = hashlib.sha256(packaged).hexdigest()

    # 2. RSA-OAEP Key Wrapping
    server_pub = server_public_key or get_server_public_key()
    wrapped_aes, _ = rsa_oaep_encrypt(key, server_pub)

    # 3. Canonical metadata & RSA-PSS signing
    ts = timestamp if timestamp is not None else int(time.time())
    u_id = upload_id or f"UPLOAD-{int(time.time())}-{hashlib.md5(content[:16]).hexdigest()[:6]}"
    clean_filename = Path(filename).name

    canonical_bytes = build_canonical_signing_data(
        upload_id=u_id,
        original_sha256=original_sha256,
        filename=clean_filename,
        source_device=source_device,
        collector_id=collector_id,
        timestamp=ts,
        encryption_algorithm="AES-256-GCM",
        nonce_hex=nonce.hex(),
        tag_hex=tag.hex(),
        encrypted_payload_sha256=payload_sha256,
    )

    client_priv = client_private_key or get_client_demo_private_key()
    sig_bytes, sign_duration_sec = rsa_pss_sign(canonical_bytes, client_priv)

    if corrupt_signature:
        sig_bytes = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]

    form_data = {
        "source_device": source_device,
        "collector_id": collector_id,
        "original_sha256": original_sha256,
        "encrypted_aes_key": wrapped_aes.hex(),
        "rsa_signature": sig_bytes.hex(),
        "signer_key_id": signer_key_id,
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "timestamp": ts,
        "upload_id": u_id,
        "encryption_duration_ms": round(duration_sec * 1000.0, 4),
    }
    if signing_duration_ms is not None:
        form_data["signing_duration_ms"] = float(signing_duration_ms)
    elif sign_duration_sec is not None:
        form_data["signing_duration_ms"] = round(sign_duration_sec * 1000.0, 4)

    if description:
        form_data["description"] = description

    return packaged, form_data


def upload_secure_evidence(
    client,
    content: bytes,
    filename: str = "test.pcap",
    source_device: str = "test-workstation",
    collector_id: str = "collector-node-01",
    description: Optional[str] = None,
    **kwargs,
):
    """Convenience helper to upload secure evidence to POST /api/evidence."""
    packaged, form_data = create_signed_encrypted_payload(
        content=content,
        filename=filename,
        source_device=source_device,
        collector_id=collector_id,
        description=description,
        **kwargs,
    )
    return client.post(
        "/api/evidence",
        files={"file": (filename, io.BytesIO(packaged), "application/octet-stream")},
        data=form_data,
    )
