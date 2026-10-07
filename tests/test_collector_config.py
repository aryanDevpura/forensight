from collector.config import CollectorConfig


def test_collector_config_defaults():
    config = CollectorConfig(
        collector_id="test-collector",
        server_host="192.168.1.50",
        server_port=8080,
    )
    assert config.collector_id == "test-collector"
    assert config.server_host == "192.168.1.50"
    assert config.server_port == 8080
    assert config.server_base_url == "http://192.168.1.50:8080"
    assert config.health_check_url == "http://192.168.1.50:8080/api/health"
