"""
ForenSight Collector HMAC-SHA256 Request Signer
================================================
Produces the four authentication headers that the ForenSight
Investigation Server expects on POST /api/evidence/authenticated.

canonical_message = f"{timestamp}:{evidence_id}:{payload_hash}"
where:
  timestamp    = int(time.time())   -- Unix UTC seconds
  evidence_id  = caller-supplied identifier (included in signed message)
  payload_hash = SHA-256(raw file bytes, hex-encoded)

Headers produced:
  X-ForenSight-Timestamp   : str(timestamp)
  X-ForenSight-Evidence-ID : evidence_id
  X-ForenSight-Payload-Hash: payload_hash
  X-ForenSight-Signature   : hex(HMAC-SHA256(secret, canonical_message))
"""

import hashlib
import hmac
import time


def compute_payload_hash(file_bytes: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of raw file bytes."""
    return hashlib.sha256(file_bytes).hexdigest()


def sign_request(
    secret: str,
    evidence_id: str,
    payload_hash: str,
    timestamp: int | None = None,
) -> dict[str, str]:
    """
    Build the four HMAC authentication headers for a collector upload.

    Args:
        secret:       Pre-shared secret loaded from environment.
        evidence_id:  The evidence identifier string to include in signing.
        payload_hash: SHA-256 hex digest of the raw file bytes.
        timestamp:    Unix UTC int (default: current time).

    Returns:
        Dict mapping header name -> header value.
    """
    ts = timestamp if timestamp is not None else int(time.time())
    canonical = f"{ts}:{evidence_id}:{payload_hash}"
    signature = hmac.new(
        key=secret.encode("utf-8"),
        msg=canonical.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()

    return {
        "X-ForenSight-Timestamp": str(ts),
        "X-ForenSight-Evidence-ID": evidence_id,
        "X-ForenSight-Payload-Hash": payload_hash,
        "X-ForenSight-Signature": signature,
    }


def sign_request_with_metrics(
    secret: str,
    evidence_id: str,
    payload_hash: str,
    timestamp: int | None = None,
) -> tuple[dict[str, str], float]:
    """
    Sign collector upload request and measure execution time using high-resolution monotonic timer.

    Returns:
        tuple of (headers dict, elapsed_duration_seconds float)
    """
    t0 = time.perf_counter()
    headers = sign_request(secret, evidence_id, payload_hash, timestamp)
    elapsed_sec = time.perf_counter() - t0
    return headers, elapsed_sec

