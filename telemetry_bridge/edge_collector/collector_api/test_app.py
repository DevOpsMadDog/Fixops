"""Unit tests for Edge Collector API."""

import gzip
import json
import os
from unittest.mock import MagicMock, patch

import pytest
from app import RingBuffer, app, load_overlay_config
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def overlay_config():
    """Sample overlay configuration."""
    return {
        "mode": "http",
        "fixops_url": "https://fixops.example/api/v1/telemetry",
        "api_key_secret_ref": "FIXOPS_API_KEY",
        "ring_buffer": {"max_lines": 1000, "max_seconds": 3600},
    }


def test_health_check(client):
    """Test health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data


@patch("app.requests.post")
@patch(
    "app.config",
    {
        "mode": "http",
        "fixops_url": "https://fixops.example/api/v1/telemetry",
        "api_key_secret_ref": "FIXOPS_API_KEY",
    },
)
def test_ingest_telemetry_http(mock_post, client):
    """Test telemetry ingestion in HTTP mode."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_post.return_value = mock_response

    payload = {"alerts": [{"rule": "waf-blocks", "count": 5}], "latency_ms_p95": 125}

    with patch.dict(os.environ, {"FIXOPS_API_KEY": "test-key"}):
        response = client.post("/telemetry", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["status_code"] == 200

    mock_post.assert_called_once()


@patch("app.config", {"mode": "file"})
def test_ingest_telemetry_file(client, tmp_path):
    """Test telemetry ingestion in file mode."""
    output_file = tmp_path / "ops-telemetry.json"

    payload = {"alerts": [{"rule": "waf-blocks", "count": 5}], "latency_ms_p95": 125}

    with patch.dict(os.environ, {"TELEMETRY_OUTPUT_PATH": str(output_file)}):
        response = client.post("/telemetry", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert output_file.exists()

    with open(output_file) as f:
        saved_data = json.load(f)
    assert saved_data == payload


def test_ring_buffer():
    """Test ring buffer functionality."""
    buffer = RingBuffer(max_lines=3, max_seconds=3600)

    buffer.append("line1")
    buffer.append("line2")
    buffer.append("line3")
    buffer.append("line4")  # Should evict line1

    lines = buffer.get_lines()
    assert len(lines) == 3
    assert "line1" not in lines
    assert "line2" in lines
    assert "line3" in lines
    assert "line4" in lines


def test_ring_buffer_time_filter():
    """Test ring buffer time filtering."""
    import time

    buffer = RingBuffer(max_lines=100, max_seconds=3600)

    buffer.append("old_line")
    time.sleep(0.1)
    buffer.append("new_line")

    lines = buffer.get_lines(since_seconds=0.05)
    assert len(lines) == 1
    assert "new_line" in lines
    assert "old_line" not in lines


def test_ring_buffer_asset_filter():
    """Test ring buffer asset filtering."""
    buffer = RingBuffer(max_lines=100, max_seconds=3600)

    buffer.append('{"asset": "app-1", "data": "test1"}')
    buffer.append('{"asset": "app-2", "data": "test2"}')
    buffer.append('{"asset": "app-1", "data": "test3"}')

    lines = buffer.get_lines(asset="app-1")
    assert len(lines) == 2
    assert all("app-1" in line for line in lines)


@patch("app.upload_evidence_bundle")
@patch("app.ring_buffer")
def test_generate_evidence(mock_ring_buffer, mock_upload, client):
    """Test evidence generation endpoint."""
    mock_ring_buffer.get_lines.return_value = [
        '{"alert": "test1"}',
        '{"alert": "test2"}',
    ]

    mock_upload.return_value = {
        "provider": "local",
        "path": "/app/evidence/test.jsonl.gz",
    }

    response = client.get("/evidence?since=3600&asset=app-1")

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["metadata"]["line_count"] == 2
    assert "sha256" in data["metadata"]
    assert "upload" in data


@patch("app.ring_buffer")
def test_generate_evidence_no_logs(mock_ring_buffer, client):
    """Test evidence generation with no logs."""
    mock_ring_buffer.get_lines.return_value = []

    response = client.get("/evidence")

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["line_count"] == 0


def test_evidence_bundle_compression():
    """Test evidence bundle compression and hashing."""
    lines = ['{"test": "data1"}', '{"test": "data2"}']
    jsonl_content = "\n".join(lines)

    compressed = gzip.compress(jsonl_content.encode("utf-8"))

    assert len(compressed) < len(jsonl_content)

    decompressed = gzip.decompress(compressed).decode("utf-8")
    assert decompressed == jsonl_content


def test_load_overlay_config_from_env():
    """Test loading config from environment variables."""
    with patch.dict(
        os.environ,
        {
            "TELEMETRY_MODE": "file",
            "FIXOPS_URL": "https://test.example/api",
            "API_KEY_SECRET_REF": "TEST_KEY",
            "RING_BUFFER_MAX_LINES": "50000",
            "RING_BUFFER_MAX_SECONDS": "7200",
        },
    ):
        with patch("builtins.open", side_effect=FileNotFoundError):
            config = load_overlay_config()

    assert config["mode"] == "file"
    assert config["fixops_url"] == "https://test.example/api"
    assert config["ring_buffer"]["max_lines"] == 50000
    assert config["ring_buffer"]["max_seconds"] == 7200
