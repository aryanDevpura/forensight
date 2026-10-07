import sys
from collector.config import CollectorConfig
from collector.collector import EvidenceCollector


def main():
    config = CollectorConfig()
    print("=" * 60)
    print(" ForenSight — Digital Evidence Collector")
    print("=" * 60)
    print(f" Collector ID        : {config.collector_id}")
    print(f" Target Server Host  : {config.server_host}")
    print(f" Target Server Port  : {config.server_port}")
    print(f" Health Check URL    : {config.health_check_url}")
    print("-" * 60)
    print("Checking connection to ForenSight Investigation Server...")

    collector = EvidenceCollector(config)
    connected, details = collector.check_server_connection()

    if connected:
        print("[SUCCESS] Connected to ForenSight Server!")
        print(f"Server response: {details.get('server_response')}")
        sys.exit(0)
    else:
        print("[WARNING] Could not reach ForenSight Server.")
        print(f"Details: {details.get('error')}")
        print("Note: The ForenSight server might not be running yet.")
        sys.exit(1)


if __name__ == "__main__":
    main()
