import json
import urllib.request
import urllib.error
from typing import Dict, Any, Tuple
from collector.config import CollectorConfig


class EvidenceCollector:
    """
    Evidence Collector client responsible for edge device monitoring,
    artifact acquisition, and secure communication with the ForenSight Investigation Server.
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
            "status": "READY_STANDBY",
        }
