"""
ForenSight RSA Cryptography & Digital Signature Subsystem
=========================================================
Implements:
  1. RSA-PSS with SHA-256 for uploader digital signatures and verification.
  2. RSA-OAEP with SHA-256 for envelope encryption / AES key wrapping.
  3. Canonical representation construction for unambiguous signing.
  4. Modular key management separating signing keys from key-encryption keys.
"""

import json
import os
import time
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

# Base directory for server keys
KEYS_DIR = Path(__file__).resolve().parent.parent.parent / "keys"
SERVER_PRIV_KEY_FILE = KEYS_DIR / "server_private_key.pem"
SERVER_PUB_KEY_FILE = KEYS_DIR / "server_public_key.pem"
TRUSTED_SIGNERS_DIR = KEYS_DIR / "trusted_signers"
CLIENT_DEMO_PRIV_KEY_FILE = KEYS_DIR / "client_signing_key.pem"
CLIENT_DEMO_PUB_KEY_FILE = KEYS_DIR / "client_signing_key.pub.pem"

DEFAULT_SIGNER_ID = "client-demo-01"
RSA_KEY_SIZE = 2048
PSS_SALT_BYTES = 32


def init_rsa_keys(force_recreate: bool = False) -> None:
    """
    Initialize cryptographic key pairs for ForenSight if they do not exist.
    Creates:
      - Server RSA key pair (used exclusively for RSA-OAEP AES key wrapping)
      - Trusted signers directory and default client demo key pair (used exclusively for RSA-PSS signing)
    """
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    TRUSTED_SIGNERS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Server RSA Key Pair (Key-Encryption Key / KEK for RSA-OAEP)
    if force_recreate or not SERVER_PRIV_KEY_FILE.exists() or not SERVER_PUB_KEY_FILE.exists():
        server_key = RSA.generate(RSA_KEY_SIZE)
        SERVER_PRIV_KEY_FILE.write_bytes(server_key.export_key(format="PEM", pkcs=8))
        SERVER_PUB_KEY_FILE.write_bytes(server_key.public_key().export_key(format="PEM"))

    # 2. Client Demo Key Pair (Uploader Signing Key for RSA-PSS)
    demo_trusted_dest = TRUSTED_SIGNERS_DIR / f"{DEFAULT_SIGNER_ID}.pub.pem"
    if force_recreate or not CLIENT_DEMO_PRIV_KEY_FILE.exists() or not demo_trusted_dest.exists():
        client_key = RSA.generate(RSA_KEY_SIZE)
        CLIENT_DEMO_PRIV_KEY_FILE.write_bytes(client_key.export_key(format="PEM", pkcs=8))
        pub_pem = client_key.public_key().export_key(format="PEM")
        CLIENT_DEMO_PUB_KEY_FILE.write_bytes(pub_pem)
        demo_trusted_dest.write_bytes(pub_pem)


def get_server_private_key() -> RSA.RsaKey:
    """Load the server's RSA private key for RSA-OAEP decryption."""
    if not SERVER_PRIV_KEY_FILE.exists():
        init_rsa_keys()
    try:
        return RSA.import_key(SERVER_PRIV_KEY_FILE.read_bytes())
    except Exception as exc:
        raise ValueError(f"Failed to load server RSA private key from {SERVER_PRIV_KEY_FILE}: {exc}") from exc


def get_server_public_key() -> RSA.RsaKey:
    """Load the server's RSA public key for RSA-OAEP encryption."""
    if not SERVER_PUB_KEY_FILE.exists():
        init_rsa_keys()
    try:
        return RSA.import_key(SERVER_PUB_KEY_FILE.read_bytes())
    except Exception as exc:
        raise ValueError(f"Failed to load server RSA public key from {SERVER_PUB_KEY_FILE}: {exc}") from exc


def get_server_public_key_pem() -> str:
    """Return the server's RSA public key in PEM format."""
    return get_server_public_key().export_key(format="PEM").decode("ascii")


def get_client_demo_private_key() -> RSA.RsaKey:
    """Load the demo client's RSA private key (for tests and local signing)."""
    if not CLIENT_DEMO_PRIV_KEY_FILE.exists():
        init_rsa_keys()
    return RSA.import_key(CLIENT_DEMO_PRIV_KEY_FILE.read_bytes())


def get_client_demo_private_key_pem() -> str:
    """Return the client demo RSA private key in PEM format (PKCS#8)."""
    return get_client_demo_private_key().export_key(format="PEM", pkcs=8).decode("ascii")


def get_trusted_signer_public_key(signer_key_id: Optional[str] = None) -> Optional[RSA.RsaKey]:
    """
    Look up a trusted signer's public key by key ID.
    Rejects any key that is not registered in the server's trusted signers repository.
    """
    if not TRUSTED_SIGNERS_DIR.exists():
        init_rsa_keys()

    target_id = (signer_key_id or DEFAULT_SIGNER_ID).strip()

    # Disallow path traversal characters in signer_key_id
    if ".." in target_id or "/" in target_id or "\\" in target_id:
        return None

    # Check for direct file match e.g. <target_id>.pub.pem or <target_id>.pem
    candidate_files = [
        TRUSTED_SIGNERS_DIR / f"{target_id}.pub.pem",
        TRUSTED_SIGNERS_DIR / f"{target_id}.pem",
        TRUSTED_SIGNERS_DIR / f"{target_id}",
    ]

    for candidate in candidate_files:
        if candidate.exists() and candidate.is_file():
            try:
                return RSA.import_key(candidate.read_bytes())
            except Exception:
                return None

    return None


def register_trusted_signer(signer_key_id: str, public_key_pem: str | bytes) -> bool:
    """Register a new trusted signer public key in the trusted repository."""
    TRUSTED_SIGNERS_DIR.mkdir(parents=True, exist_ok=True)
    target_id = signer_key_id.strip()
    if not target_id or ".." in target_id or "/" in target_id or "\\" in target_id:
        raise ValueError("Invalid signer_key_id")

    try:
        rsa_key = RSA.import_key(public_key_pem)
        if not rsa_key.has_private():
            out_file = TRUSTED_SIGNERS_DIR / f"{target_id}.pub.pem"
            out_file.write_bytes(rsa_key.export_key(format="PEM"))
            return True
        else:
            raise ValueError("Provided key is a private key, expected public key.")
    except Exception as exc:
        raise ValueError(f"Failed to import/register public key: {exc}") from exc


def build_canonical_signing_data(
    upload_id: str,
    original_sha256: str,
    filename: str,
    source_device: str,
    collector_id: str,
    timestamp: int,
    encryption_algorithm: str,
    nonce_hex: str,
    tag_hex: str,
    encrypted_payload_sha256: str,
) -> bytes:
    """
    Construct the canonical, deterministic byte representation covering all
    evidence upload parameters for unambiguous RSA-PSS digital signing.

    Keys are lexicographically sorted and formatted with strict JSON separators
    to guarantee byte-for-byte reproducibility across Python and JavaScript runtimes.
    """
    canonical_dict = {
        "collector_id": (collector_id or "").strip(),
        "encryption_algorithm": (encryption_algorithm or "AES-256-GCM").strip(),
        "encrypted_payload_sha256": (encrypted_payload_sha256 or "").strip().lower(),
        "filename": (filename or "").strip(),
        "nonce": (nonce_hex or "").strip().lower(),
        "original_sha256": (original_sha256 or "").strip().lower(),
        "source_device": (source_device or "").strip(),
        "tag": (tag_hex or "").strip().lower(),
        "timestamp": int(timestamp),
        "upload_id": (upload_id or "").strip(),
    }
    return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")


def rsa_oaep_encrypt(
    aes_key: bytes,
    public_key: Optional[RSA.RsaKey] = None,
) -> Tuple[bytes, float]:
    """
    Wrap a 256-bit symmetric AES key using RSA-OAEP with SHA-256.

    Args:
        aes_key: 32 raw key bytes.
        public_key: RSA public key (defaults to server public key).

    Returns:
        Tuple of (wrapped_aes_key_bytes, duration_seconds: float).
    """
    if len(aes_key) != 32:
        raise ValueError(f"AES key must be exactly 32 bytes (got {len(aes_key)}).")
    key = public_key or get_server_public_key()

    t0 = time.perf_counter()
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    wrapped = cipher.encrypt(aes_key)
    duration_sec = time.perf_counter() - t0
    return wrapped, duration_sec


def rsa_oaep_decrypt(
    wrapped_key: bytes,
    private_key: Optional[RSA.RsaKey] = None,
) -> Tuple[bytes, float]:
    """
    Unwrap an RSA-OAEP wrapped AES key using the server's RSA private key.

    Args:
        wrapped_key: Ciphertext bytes of the wrapped AES key.
        private_key: RSA private key (defaults to server private key).

    Returns:
        Tuple of (recovered_32_byte_aes_key, duration_seconds: float).

    Raises:
        ValueError: If decryption fails or recovered key length is not 32 bytes.
    """
    key = private_key or get_server_private_key()

    t0 = time.perf_counter()
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    try:
        raw_key = cipher.decrypt(wrapped_key)
    except (ValueError, KeyError) as exc:
        raise ValueError("RSA-OAEP decryption failed: key unwrapping rejected.") from exc

    duration_sec = time.perf_counter() - t0
    if len(raw_key) != 32:
        raise ValueError(f"Unwrapped key length mismatch: expected 32 bytes, got {len(raw_key)}.")

    return raw_key, duration_sec


def rsa_pss_sign(
    canonical_data: bytes,
    private_key: RSA.RsaKey,
) -> Tuple[bytes, float]:
    """
    Sign canonical data using RSA-PSS with SHA-256 and a 32-byte salt.

    Args:
        canonical_data: Serialized canonical bytes.
        private_key: Signer's RSA private key.

    Returns:
        Tuple of (signature_bytes, duration_seconds: float).
    """
    t0 = time.perf_counter()
    h = SHA256.new(canonical_data)
    signer = pss.new(private_key, salt_bytes=PSS_SALT_BYTES)
    signature = signer.sign(h)
    duration_sec = time.perf_counter() - t0
    return signature, duration_sec


def rsa_pss_verify(
    canonical_data: bytes,
    signature: bytes,
    public_key: RSA.RsaKey,
) -> Tuple[bool, float]:
    """
    Verify an RSA-PSS digital signature over canonical data with SHA-256.

    Args:
        canonical_data: Serialized canonical bytes that were signed.
        signature: RSA-PSS signature bytes.
        public_key: Trusted signer's RSA public key.

    Returns:
        Tuple of (is_valid: bool, duration_seconds: float).
    """
    t0 = time.perf_counter()
    h = SHA256.new(canonical_data)
    verifier = pss.new(public_key, salt_bytes=PSS_SALT_BYTES)
    try:
        verifier.verify(h, signature)
        is_valid = True
    except (ValueError, TypeError):
        is_valid = False
    duration_sec = time.perf_counter() - t0
    return is_valid, duration_sec

