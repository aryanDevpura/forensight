import os
from pathlib import Path
from dataclasses import dataclass
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
    collector_id: str = os.getenv("COLLECTOR_ID", "collector-node-01")
    server_host: str = os.getenv("COLLECTOR_SERVER_HOST", "127.0.0.1")
    server_port: int = int(os.getenv("COLLECTOR_SERVER_PORT", "8000"))
    poll_interval_seconds: int = int(os.getenv("COLLECTOR_POLL_INTERVAL_SEC", "30"))

    @property
    def server_base_url(self) -> str:
        return f"http://{self.server_host}:{self.server_port}"

    @property
    def health_check_url(self) -> str:
        return f"{self.server_base_url}/api/health"

    def summary(self) -> dict:
        return {
            "collector_id": self.collector_id,
            "target_server_host": self.server_host,
            "target_server_port": self.server_port,
            "target_server_url": self.server_base_url,
            "poll_interval_seconds": self.poll_interval_seconds,
        }
