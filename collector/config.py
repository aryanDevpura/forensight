import os
from pathlib import Path
from dataclasses import dataclass, field
from dotenv import load_dotenv

# Try loading .env from parent directory or current directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


@dataclass
class CollectorConfig:
    """
    Configuration for the ForenSight Evidence Collector node.
    Enables remote server communication across separate devices or VMs.
    """
    collector_id: str = field(
        default_factory=lambda: os.getenv("COLLECTOR_ID", "collector-node-01")
    )
    server_host: str = field(
        default_factory=lambda: os.getenv("COLLECTOR_SERVER_HOST", "127.0.0.1")
    )
    server_port: int = field(
        default_factory=lambda: int(os.getenv("COLLECTOR_SERVER_PORT", "8000"))
    )
    poll_interval_seconds: int = field(
        default_factory=lambda: int(os.getenv("COLLECTOR_POLL_INTERVAL_SEC", "30"))
    )
    # Pre-shared HMAC secret — loaded from environment only, never hardcoded.
    hmac_secret: str = field(
        default_factory=lambda: os.getenv("FORENSIGHT_HMAC_SECRET", "")
    )
    # Pre-shared AES-256-GCM encryption key — loaded from environment only.
    encryption_key: str = field(
        default_factory=lambda: os.getenv("FORENSIGHT_ENCRYPTION_KEY", "")
    )

    @property
    def server_base_url(self) -> str:
        return f"http://{self.server_host}:{self.server_port}"

    @property
    def health_check_url(self) -> str:
        return f"{self.server_base_url}/api/health"

    @property
    def evidence_upload_url(self) -> str:
        """Unauthenticated evidence upload endpoint (browser/UI)."""
        return f"{self.server_base_url}/api/evidence"

    @property
    def authenticated_upload_url(self) -> str:
        """HMAC-authenticated evidence upload endpoint (collector nodes)."""
        return f"{self.server_base_url}/api/evidence/authenticated"

    def summary(self) -> dict:
        return {
            "collector_id": self.collector_id,
            "target_server_host": self.server_host,
            "target_server_port": self.server_port,
            "target_server_url": self.server_base_url,
            "poll_interval_seconds": self.poll_interval_seconds,
            "hmac_configured": bool(self.hmac_secret),
            "encryption_configured": bool(self.encryption_key),
        }
