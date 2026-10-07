"""
ForenSight HMAC-SHA256 Request Authentication
=============================================
Provides server-side verification of collector requests signed with a
pre-shared secret. Protects POST /api/evidence against unauthenticated
and replayed requests.

Signature covers: timestamp (Unix UTC int) + evidence_id + payload_hash
  where payload_hash = SHA-256(raw file bytes, hex-encoded)

Headers consumed:
  X-ForenSight-Timestamp   : Unix UTC integer (seconds)
  X-ForenSight-Evidence-ID : The evidence identifier string included in signing
  X-ForenSight-Payload-Hash: SHA-256 hex digest of the raw file bytes
  X-ForenSight-Signature   : hex(HMAC-SHA256(secret, canonical_message))

canonical_message = f"{timestamp}:{evidence_id}:{payload_hash}"
"""

import hashlib
import hmac
import time
from fastapi import Header, HTTPException, Request, status

from server.app.core.config import settings

# Allowed clock skew in seconds. Requests outside this window are rejected
# as expired or potentially replayed.
REPLAY_WINDOW_SECONDS: int = 300  # 5 minutes


def _canonical_message(timestamp: int, evidence_id: str, payload_hash: str) -> str:
    """Construct the canonical string used for HMAC computation."""
    return f"{timestamp}:{evidence_id}:{payload_hash}"


def compute_hmac(
    secret: str,
    timestamp: int,
    evidence_id: str,
    payload_hash: str,
) -> str:
    """
    Compute HMAC-SHA256 over the canonical message.

    Args:
        secret:       Pre-shared secret (UTF-8 string from environment).
        timestamp:    Unix UTC timestamp (integer seconds).
        evidence_id:  Evidence identifier included in the message.
        payload_hash: SHA-256 hex digest of the raw file bytes.

    Returns:
        Lowercase hex-encoded HMAC-SHA256 digest.
    """
    message = _canonical_message(timestamp, evidence_id, payload_hash)
    return hmac.new(
        key=secret.encode("utf-8"),
        msg=message.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def verify_hmac_signature(
    request: Request,
    x_forensight_timestamp: str = Header(
        ...,
        alias="X-ForenSight-Timestamp",
        description="Unix UTC timestamp (integer seconds) at time of signing.",
    ),
    x_forensight_evidence_id: str = Header(
        ...,
        alias="X-ForenSight-Evidence-ID",
        description="Evidence identifier string included in the HMAC.",
    ),
    x_forensight_payload_hash: str = Header(
        ...,
        alias="X-ForenSight-Payload-Hash",
        description="SHA-256 hex digest of the raw file bytes.",
    ),
    x_forensight_signature: str = Header(
        ...,
        alias="X-ForenSight-Signature",
        description="HMAC-SHA256 hex digest for request authentication.",
    ),
) -> dict:
    """
    FastAPI dependency that verifies HMAC-SHA256 request authentication.

    Raises HTTP 401 if the secret is not configured.
    Raises HTTP 400 if the timestamp header cannot be parsed.
    Raises HTTP 401 if the timestamp is outside the replay window.
    Raises HTTP 403 if the HMAC signature does not match.

    Returns a dict of extracted auth claims for use by the endpoint.
    """
    secret = settings.FORENSIGHT_HMAC_SECRET

    # If no secret is configured the server cannot authenticate -- fail safe.
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "HMAC authentication is not configured on this server. "
                "Set FORENSIGHT_HMAC_SECRET in environment."
            ),
            headers={"WWW-Authenticate": "HMAC-SHA256"},
        )

    # Parse and validate timestamp
    try:
        request_ts = int(x_forensight_timestamp)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-ForenSight-Timestamp must be an integer Unix timestamp.",
        )

    now_ts = int(time.time())
    age_seconds = abs(now_ts - request_ts)

    if age_seconds > REPLAY_WINDOW_SECONDS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                f"Request timestamp is {age_seconds}s outside the allowed "
                f"{REPLAY_WINDOW_SECONDS}s replay window. "
                "Ensure system clocks are synchronised."
            ),
            headers={"WWW-Authenticate": "HMAC-SHA256"},
        )

    # Measure HMAC verification computation time using high-resolution monotonic timer
    t0 = time.perf_counter()

    # Compute expected signature
    expected_sig = compute_hmac(
        secret=secret,
        timestamp=request_ts,
        evidence_id=x_forensight_evidence_id,
        payload_hash=x_forensight_payload_hash,
    )

    # Constant-time comparison to prevent timing attacks
    sig_valid = hmac.compare_digest(
        expected_sig.lower(),
        x_forensight_signature.lower(),
    )
    verification_time_sec = time.perf_counter() - t0

    # Attach metric to request state for downstream recording
    request.state.hmac_verification_time_sec = verification_time_sec

    if not sig_valid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "HMAC signature verification failed. "
                "The request has been rejected."
            ),
        )

    return {
        "timestamp": request_ts,
        "evidence_id": x_forensight_evidence_id,
        "payload_hash": x_forensight_payload_hash,
        "verification_time_sec": verification_time_sec,
    }

