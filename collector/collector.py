import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Any, Tuple

from collector.config import CollectorConfig
from collector.auth import compute_payload_hash, sign_request, sign_request_with_metrics



class EvidenceCollector:
    """
    Evidence Collector client responsible for edge device monitoring,
    artifact acquisition, and secure communication with the ForenSight
    Investigation Server.
    """

    def __init__(self, config: CollectorConfig | None = None):
        self.config = config or CollectorConfig()

    def check_server_connection(self, timeout_sec: float = 3.0) -> Tuple[bool, Dict[str, Any]]:
        """
        Pings the ForenSight Investigation Server health endpoint.
        Returns a tuple of (is_connected, details).
        """
        url = self.config.health_check_url
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": f"ForenSight-Collector/{self.config.collector_id}"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=timeout_sec) as response:
                status_code = response.getcode()
                body = json.loads(response.read().decode("utf-8"))
                return (status_code == 200, {
                    "http_status": status_code,
                    "server_response": body,
                })
        except urllib.error.URLError as err:
            return (False, {
                "error": f"Failed to connect to server at {url}: {err.reason}",
            })
        except Exception as ex:
            return (False, {
                "error": f"Unexpected error probing server: {str(ex)}",
            })

    def get_status(self) -> Dict[str, Any]:
        """Returns collector runtime configuration and status."""
        return {
            "collector_id": self.config.collector_id,
            "target_server": self.config.server_base_url,
            "hmac_configured": bool(self.config.hmac_secret),
            "status": "READY_STANDBY",
        }

    def upload_evidence_authenticated(
        self,
        file_path: str | Path,
        source_device: str = "",
        description: str = "",
        evidence_id_override: str = "",
        timeout_sec: float = 30.0,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Upload a forensic artifact to the authenticated collector endpoint.

        Reads the file, computes SHA-256 payload hash, signs the request with
        HMAC-SHA256, and submits to POST /api/evidence/authenticated.

        Args:
            file_path:           Absolute or relative path to the artifact file.
            source_device:       Label identifying the originating device.
            description:         Optional free-text case note.
            evidence_id_override: Optional evidence ID to include in signing.
                                 A placeholder value is used if omitted.
            timeout_sec:         HTTP request timeout in seconds.

        Returns:
            Tuple of (success: bool, detail: dict).
        """
        if not self.config.hmac_secret:
            return (False, {
                "error": "HMAC secret is not configured. Set FORENSIGHT_HMAC_SECRET in environment.",
            })

        artifact = Path(file_path)
        if not artifact.exists():
            return (False, {"error": f"File not found: {artifact}"})

        # Read file bytes for hashing (kept in memory for signing; streamed on upload)
        file_bytes = artifact.read_bytes()
        t_hash = time.perf_counter()
        payload_hash = compute_payload_hash(file_bytes)
        payload_hashing_sec = time.perf_counter() - t_hash

        # Use a deterministic placeholder; the server generates the real ID on ingest.
        evidence_id_for_signing = evidence_id_override or f"PENDING-{artifact.name}"

        auth_headers, signing_duration_sec = sign_request_with_metrics(
            secret=self.config.hmac_secret,
            evidence_id=evidence_id_for_signing,
            payload_hash=payload_hash,
        )

        # Build multipart form-data manually using urllib (no external deps)
        boundary = "ForenSightBoundary1234567890"
        crlf = b"\r\n"

        def field_part(name: str, value: str) -> bytes:
            return (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n"
            ).encode("utf-8")

        def file_part(name: str, filename: str, data: bytes) -> bytes:
            return (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode("utf-8") + data + crlf

        body = (
            field_part("source_device", source_device or self.config.collector_id)
            + field_part("collector_id", self.config.collector_id)
            + (field_part("description", description) if description else b"")
            + file_part("file", artifact.name, file_bytes)
            + f"--{boundary}--\r\n".encode("utf-8")
        )

        url = self.config.authenticated_upload_url
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": f"ForenSight-Collector/{self.config.collector_id}",
            **auth_headers,
        }

        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout_sec) as response:
                status_code = response.getcode()
                body_json = json.loads(response.read().decode("utf-8"))
                return (True, {
                    "http_status": status_code,
                    "evidence": body_json,
                    "metrics": {
                        "payload_hashing_ms": round(payload_hashing_sec * 1000.0, 4),
                        "hmac_signing_ms": round(signing_duration_sec * 1000.0, 4),
                        "file_size_bytes": len(file_bytes),
                    },
                })
        except urllib.error.HTTPError as err:
            try:
                err_body = json.loads(err.read().decode("utf-8"))
            except Exception:
                err_body = {}
            return (False, {
                "http_status": err.code,
                "error": err_body.get("detail", str(err)),
            })
        except urllib.error.URLError as err:
            return (False, {"error": f"Connection error: {err.reason}"})
        except Exception as ex:
            return (False, {"error": f"Unexpected error: {str(ex)}"})
