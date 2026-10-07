"""
ForenSight AES-256-GCM Transfer Cryptography
============================================
Provides authenticated symmetric encryption for evidence artifacts during
Collector -> Server transmission.

Security Design:
  - Cipher: AES-256 in Galois/Counter Mode (GCM).
  - Key: 256-bit pre-shared symmetric key (parsed from 64-char hex or 32-byte string).
  - IV/Nonce: 12 bytes (96 bits) cryptographically random per operation.
  - Tag: 16 bytes (128 bits) authentication tag verifying integrity and authenticity.
  - Wire Format: nonce (12 bytes) || tag (16 bytes) || ciphertext (N bytes).
  - Additional Authenticated Data (AAD): Optional binding context (e.g. evidence_id).
"""

import time
from typing import Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

GCM_NONCE_LENGTH = 12
GCM_TAG_LENGTH = 16


def parse_encryption_key(key_input: str | bytes) -> bytes:
    """
    Parse and validate a 256-bit (32 bytes) AES key.

    Accepts:
      - 32 raw bytes
      - 64-character hexadecimal string
      - 32-character UTF-8 string

    Raises ValueError if key cannot be resolved to exactly 32 bytes.
    """
    if not key_input:
        raise ValueError("Encryption key cannot be empty.")

    if isinstance(key_input, bytes):
        if len(key_input) == 32:
            return key_input
        if len(key_input) == 64:
            try:
                decoded = bytes.fromhex(key_input.decode("ascii", errors="ignore"))
                if len(decoded) == 32:
                    return decoded
            except ValueError:
                pass
        raise ValueError(f"Raw key bytes must be exactly 32 bytes (got {len(key_input)} bytes).")

    # String input
    stripped = key_input.strip()
    if len(stripped) == 64:
        try:
            decoded = bytes.fromhex(stripped)
            if len(decoded) == 32:
                return decoded
        except ValueError:
            pass

    key_bytes = stripped.encode("utf-8")
    if len(key_bytes) == 32:
        return key_bytes

    raise ValueError(
        f"Encryption key must be either a 64-character hex string or 32-byte UTF-8 string. Got {len(key_bytes)} bytes."
    )


def encrypt_payload(
    plaintext: bytes,
    key: str | bytes,
    associated_data: Optional[bytes] = None,
) -> Tuple[bytes, float]:
    """
    Encrypt plaintext bytes using AES-256-GCM with a unique 12-byte nonce.

    Args:
        plaintext: Raw unencrypted bytes.
        key: 32-byte key (raw, hex, or str).
        associated_data: Optional AAD bound to the authentication tag.

    Returns:
        Tuple of (packaged_bytes: nonce + tag + ciphertext, elapsed_duration_seconds: float).
    """
    validated_key = parse_encryption_key(key)
    nonce = get_random_bytes(GCM_NONCE_LENGTH)

    t0 = time.perf_counter()
    cipher = AES.new(validated_key, AES.MODE_GCM, nonce=nonce)
    if associated_data:
        cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    duration_sec = time.perf_counter() - t0

    # Package as nonce (12) + tag (16) + ciphertext
    packaged = nonce + tag + ciphertext
    return packaged, duration_sec


def decrypt_payload(
    encrypted_data: bytes,
    key: str | bytes,
    associated_data: Optional[bytes] = None,
) -> Tuple[bytes, float]:
    """
    Decrypt and verify AES-256-GCM packaged data (nonce + tag + ciphertext).

    Args:
        encrypted_data: Packaged bytes containing nonce (12) + tag (16) + ciphertext.
        key: 32-byte key (raw, hex, or str).
        associated_data: Optional AAD that was bound during encryption.

    Returns:
        Tuple of (recovered_plaintext_bytes, elapsed_duration_seconds: float).

    Raises:
        ValueError: If payload is too short or ciphertext/tag fails verification.
    """
    min_len = GCM_NONCE_LENGTH + GCM_TAG_LENGTH
    if len(encrypted_data) < min_len:
        raise ValueError(
            f"Encrypted payload is too short ({len(encrypted_data)} bytes). "
            f"Minimum required is {min_len} bytes (nonce + tag)."
        )

    validated_key = parse_encryption_key(key)
    nonce = encrypted_data[:GCM_NONCE_LENGTH]
    tag = encrypted_data[GCM_NONCE_LENGTH:min_len]
    ciphertext = encrypted_data[min_len:]

    t0 = time.perf_counter()
    cipher = AES.new(validated_key, AES.MODE_GCM, nonce=nonce)
    if associated_data:
        cipher.update(associated_data)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except (ValueError, KeyError) as exc:
        raise ValueError("Decryption failed: invalid key or corrupted/tampered ciphertext.") from exc

    duration_sec = time.perf_counter() - t0
    return plaintext, duration_sec
