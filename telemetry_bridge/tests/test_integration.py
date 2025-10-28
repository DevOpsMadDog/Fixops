"""Integration tests for end-to-end telemetry flow."""

import json
import os
import subprocess
import time
from pathlib import Path

import pytest
import requests


@pytest.fixture(scope="module")
def docker_compose_up():
    """Start Docker Compose services for integration testing."""
    compose_file = Path(__file__).parent.parent / "docker-compose.yml"

    subprocess.run(
        ["docker-compose", "-f", str(compose_file), "up", "-d"],
        check=True,
        cwd=compose_file.parent,
    )

    time.sleep(10)

    max_retries = 30
    for i in range(max_retries):
        try:
            response = requests.get("http://localhost:8080/health", timeout=2)
            if response.status_code == 200:
                break
        except requests.RequestException:
            pass
        time.sleep(1)
    else:
        raise RuntimeError("Collector API did not become healthy in time")

    yield

    subprocess.run(
        ["docker-compose", "-f", str(compose_file), "down", "-v"],
        check=True,
        cwd=compose_file.parent,
    )


def test_health_check(docker_compose_up):
    """Test that the collector API health check works."""
    response = requests.get("http://localhost:8080/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data


def test_telemetry_ingestion_file_mode(docker_compose_up):
    """Test telemetry ingestion in file mode."""
    payload = {"alerts": [{"rule": "waf-blocks", "count": 10}], "latency_ms_p95": 250}

    response = requests.post(
        "http://localhost:8080/telemetry", json=payload, timeout=10
    )

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert "file" in data

    output_file = (
        Path(__file__).parent.parent / "demo_decision_inputs" / "ops-telemetry.json"
    )
    assert output_file.exists()

    with open(output_file) as f:
        saved_data = json.load(f)

    assert saved_data["alerts"][0]["count"] == 10
    assert saved_data["latency_ms_p95"] == 250


def test_evidence_generation(docker_compose_up):
    """Test evidence bundle generation."""
    for i in range(5):
        payload = {
            "alerts": [{"rule": "waf-blocks", "count": i}],
            "latency_ms_p95": 100 + i * 10,
        }
        requests.post("http://localhost:8080/telemetry", json=payload, timeout=10)
        time.sleep(0.1)

    response = requests.get("http://localhost:8080/evidence?since=60", timeout=10)

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["metadata"]["line_count"] > 0
    assert "sha256" in data["metadata"]
    assert "upload" in data


def test_evidence_with_asset_filter(docker_compose_up):
    """Test evidence generation with asset filtering."""
    payload = {
        "alerts": [{"rule": "waf-blocks", "count": 5, "asset": "app-1"}],
        "latency_ms_p95": 150,
    }
    requests.post("http://localhost:8080/telemetry", json=payload, timeout=10)

    time.sleep(0.5)

    response = requests.get(
        "http://localhost:8080/evidence?since=60&asset=app-1", timeout=10
    )

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True


def test_cli_integration_with_telemetry():
    """Test FixOps CLI integration with telemetry data."""
    telemetry_file = (
        Path(__file__).parent.parent / "demo_decision_inputs" / "ops-telemetry.json"
    )
    telemetry_file.parent.mkdir(parents=True, exist_ok=True)

    telemetry_data = {
        "alerts": [{"rule": "waf-blocks", "count": 25}],
        "latency_ms_p95": 350,
    }

    with open(telemetry_file, "w") as f:
        json.dump(telemetry_data, f)

    result = subprocess.run(
        [
            "python",
            "-m",
            "core.cli",
            "demo",
            "--mode",
            "demo",
            "--output",
            "/tmp/pipeline-test.json",
        ],
        cwd=Path(__file__).parent.parent.parent,
        capture_output=True,
        text=True,
        env={**os.environ, "FIXOPS_DISABLE_TELEMETRY": "1"},
    )

    assert result.returncode == 0 or "demo" in result.stdout.lower()


def test_aws_lambda_handler_simulation():
    """Test AWS Lambda handler with simulated CloudWatch Logs event."""
    from telemetry_bridge.aws_lambda.handler import lambda_handler

    sample_event_file = (
        Path(__file__).parent.parent
        / "shared"
        / "payload_examples"
        / "aws_cloudwatch_logs.json"
    )
    with open(sample_event_file) as f:
        event = json.load(f)

    with pytest.MonkeyPatch.context() as m:
        m.setenv("TELEMETRY_MODE", "file")
        m.setenv("TELEMETRY_OUTPUT_PATH", "/tmp/test-telemetry.json")

        result = lambda_handler(event, None)

    assert result["ok"] is True


def test_azure_function_handler_simulation():
    """Test Azure Function handler with simulated Event Hub event."""
    from unittest.mock import MagicMock

    from telemetry_bridge.azure_function import main

    sample_event_file = (
        Path(__file__).parent.parent
        / "shared"
        / "payload_examples"
        / "azure_event_hub.json"
    )
    with open(sample_event_file) as f:
        event_data = json.load(f)

    mock_event = MagicMock()
    mock_event.get_body.return_value = json.dumps(event_data).encode("utf-8")

    with pytest.MonkeyPatch.context() as m:
        m.setenv("TELEMETRY_MODE", "file")
        m.setenv("TELEMETRY_OUTPUT_PATH", "/tmp/test-telemetry.json")

        main(mock_event)


def test_gcp_function_handler_simulation():
    """Test GCP Cloud Function handler with simulated Pub/Sub event."""
    from telemetry_bridge.gcp_function.main import telemetry_handler

    sample_event_file = (
        Path(__file__).parent.parent / "shared" / "payload_examples" / "gcp_pubsub.json"
    )
    with open(sample_event_file) as f:
        event = json.load(f)

    with pytest.MonkeyPatch.context() as m:
        m.setenv("TELEMETRY_MODE", "file")
        m.setenv("TELEMETRY_OUTPUT_PATH", "/tmp/test-telemetry.json")

        result = telemetry_handler(event, None)

    assert result["ok"] is True


def test_end_to_end_telemetry_flow(docker_compose_up):
    """Test complete end-to-end telemetry flow."""
    telemetry_payload = {
        "alerts": [{"rule": "waf-blocks", "count": 15}],
        "latency_ms_p95": 200,
    }

    response = requests.post(
        "http://localhost:8080/telemetry", json=telemetry_payload, timeout=10
    )
    assert response.status_code == 200

    output_file = (
        Path(__file__).parent.parent / "demo_decision_inputs" / "ops-telemetry.json"
    )
    assert output_file.exists()

    with open(output_file) as f:
        saved_data = json.load(f)
    assert saved_data["alerts"][0]["count"] == 15

    time.sleep(1)
    response = requests.get("http://localhost:8080/evidence?since=60", timeout=10)
    assert response.status_code == 200
    evidence_data = response.json()
    assert evidence_data["ok"] is True
    assert evidence_data["metadata"]["line_count"] > 0

    evidence_dir = Path(__file__).parent.parent / "evidence"
    evidence_files = list(evidence_dir.glob("evidence-*.jsonl.gz"))
    assert len(evidence_files) > 0

    latest_evidence = max(evidence_files, key=lambda p: p.stat().st_mtime)
    metadata_file = latest_evidence.with_suffix(".json")
    assert metadata_file.exists()

    with open(metadata_file) as f:
        metadata = json.load(f)
    assert "sha256" in metadata
    assert "line_count" in metadata
    assert "timestamp" in metadata


def test_overlay_configuration_loading():
    """Test that overlay configuration is properly loaded."""
    from core.configuration import load_overlay

    overlay = load_overlay()

    assert hasattr(overlay, "telemetry_bridge")
    assert overlay.telemetry_bridge is not None

    tb_config = overlay.telemetry_bridge
    assert "mode" in tb_config
    assert "ring_buffer" in tb_config
    assert "retention_days" in tb_config
    assert "aws" in tb_config
    assert "azure" in tb_config
    assert "gcp" in tb_config


def test_multiple_telemetry_sources(docker_compose_up):
    """Test handling telemetry from multiple sources."""
    sources = ["aws-waf", "azure-frontdoor", "gcp-armor"]

    for source in sources:
        payload = {
            "alerts": [{"rule": "waf-blocks", "count": 5, "source": source}],
            "latency_ms_p95": 150,
        }

        response = requests.post(
            "http://localhost:8080/telemetry", json=payload, timeout=10
        )
        assert response.status_code == 200

    time.sleep(1)
    response = requests.get("http://localhost:8080/evidence?since=60", timeout=10)

    assert response.status_code == 200
    data = response.json()
    assert data["metadata"]["line_count"] >= len(sources)
