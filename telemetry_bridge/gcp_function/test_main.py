"""Unit tests for GCP Cloud Function telemetry handler."""

import base64
import json
import os
from unittest.mock import MagicMock, patch

import pytest
from main import (
    aggregate_telemetry,
    load_overlay_config,
    parse_pubsub_message,
    send_to_fixops,
    telemetry_handler,
)


@pytest.fixture
def sample_pubsub_event():
    """Sample Pub/Sub event from GCP Log Router."""
    log_entry = {
        "insertId": "1234567890",
        "jsonPayload": {
            "enforcedSecurityPolicy": {"name": "prod-waf-policy", "outcome": "DENY"},
            "httpRequest": {
                "remoteIp": "203.0.113.1",
                "requestMethod": "GET",
                "requestUrl": "https://example.com/api/v1/users",
            },
            "latency_ms": 156,
        },
        "logName": "projects/my-fixops-project/logs/cloudarmor.googleapis.com%2Frequests",
        "severity": "WARNING",
        "timestamp": "2024-01-15T12:00:00.000Z",
    }

    encoded = base64.b64encode(json.dumps(log_entry).encode("utf-8")).decode("utf-8")

    return {"data": encoded}


@pytest.fixture
def overlay_config():
    """Sample overlay configuration."""
    return {
        "mode": "http",
        "fixops_url": "https://fixops.example/api/v1/telemetry",
        "api_key_secret_ref": "FIXOPS_API_KEY",
    }


def test_parse_pubsub_message(sample_pubsub_event):
    """Test parsing Pub/Sub message."""
    log_entries = parse_pubsub_message(sample_pubsub_event)

    assert len(log_entries) == 1
    assert log_entries[0]["jsonPayload"]["enforcedSecurityPolicy"]["outcome"] == "DENY"


def test_parse_pubsub_message_with_message_wrapper():
    """Test parsing Pub/Sub message with message wrapper."""
    log_entry = {
        "jsonPayload": {
            "enforcedSecurityPolicy": {"outcome": "DENY"},
            "latency_ms": 100,
        }
    }

    encoded = base64.b64encode(json.dumps(log_entry).encode("utf-8")).decode("utf-8")

    event = {"message": {"data": encoded}}

    log_entries = parse_pubsub_message(event)

    assert len(log_entries) == 1
    assert log_entries[0]["jsonPayload"]["enforcedSecurityPolicy"]["outcome"] == "DENY"


def test_aggregate_telemetry():
    """Test aggregation of log entries into standard format."""
    log_entries = [
        {
            "jsonPayload": {
                "enforcedSecurityPolicy": {"outcome": "DENY"},
                "latency_ms": 156,
            }
        },
        {
            "jsonPayload": {
                "enforcedSecurityPolicy": {"outcome": "DENY"},
                "latency_ms": 98,
            }
        },
        {
            "jsonPayload": {
                "enforcedSecurityPolicy": {"outcome": "ALLOW"},
                "latency_ms": 25,
            }
        },
        {
            "jsonPayload": {
                "enforcedSecurityPolicy": {"outcome": "deny"},
                "latency_ms": 200,
            }
        },
    ]

    telemetry = aggregate_telemetry(log_entries)

    assert "alerts" in telemetry
    assert "latency_ms_p95" in telemetry

    assert len(telemetry["alerts"]) == 1
    assert telemetry["alerts"][0]["rule"] == "waf-blocks"
    assert telemetry["alerts"][0]["count"] == 3

    assert telemetry["latency_ms_p95"] == 200


def test_aggregate_telemetry_no_blocks():
    """Test aggregation with no DENY actions."""
    log_entries = [
        {
            "jsonPayload": {
                "enforcedSecurityPolicy": {"outcome": "ALLOW"},
                "latency_ms": 25,
            }
        }
    ]

    telemetry = aggregate_telemetry(log_entries)

    assert telemetry["alerts"][0]["count"] == 0
    assert telemetry["latency_ms_p95"] == 25


def test_aggregate_telemetry_no_latency():
    """Test aggregation with no latency data."""
    log_entries = [{"jsonPayload": {"enforcedSecurityPolicy": {"outcome": "DENY"}}}]

    telemetry = aggregate_telemetry(log_entries)

    assert telemetry["alerts"][0]["count"] == 1
    assert telemetry["latency_ms_p95"] is None


@patch("main.requests.post")
def test_send_to_fixops_http(mock_post, overlay_config):
    """Test sending telemetry via HTTP."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_post.return_value = mock_response

    telemetry = {"alerts": [{"rule": "waf-blocks", "count": 5}], "latency_ms_p95": 125}

    with patch.dict(os.environ, {"FIXOPS_API_KEY": "test-key"}):
        result = send_to_fixops(telemetry, overlay_config)

    assert result["ok"] is True
    assert result["status_code"] == 200

    mock_post.assert_called_once()
    call_args = mock_post.call_args
    assert call_args[1]["json"] == telemetry
    assert call_args[1]["headers"]["X-API-Key"] == "test-key"


def test_send_to_fixops_file(overlay_config, tmp_path):
    """Test sending telemetry via file mode."""
    config = overlay_config.copy()
    config["mode"] = "file"

    output_file = tmp_path / "ops-telemetry.json"

    telemetry = {"alerts": [{"rule": "waf-blocks", "count": 5}], "latency_ms_p95": 125}

    with patch.dict(os.environ, {"TELEMETRY_OUTPUT_PATH": str(output_file)}):
        result = send_to_fixops(telemetry, config)

    assert result["ok"] is True
    assert output_file.exists()

    with open(output_file) as f:
        saved_data = json.load(f)
    assert saved_data == telemetry


@patch("main.send_to_fixops")
@patch("main.load_overlay_config")
def test_telemetry_handler_success(
    mock_load_config, mock_send, sample_pubsub_event, overlay_config
):
    """Test successful handler execution."""
    mock_load_config.return_value = overlay_config
    mock_send.return_value = {"ok": True, "status_code": 200}

    result = telemetry_handler(sample_pubsub_event, None)

    assert result["ok"] is True

    call_args = mock_send.call_args[0]
    telemetry = call_args[0]
    assert telemetry["alerts"][0]["rule"] == "waf-blocks"
    assert telemetry["alerts"][0]["count"] == 1  # One DENY action in sample


@patch("main.parse_pubsub_message")
def test_telemetry_handler_error(mock_parse, sample_pubsub_event):
    """Test handler error handling."""
    mock_parse.side_effect = Exception("Parse error")

    result = telemetry_handler(sample_pubsub_event, None)

    assert result["ok"] is False
    assert "error" in result
    assert "Parse error" in result["error"]


def test_load_overlay_config_from_env():
    """Test loading config from environment variables."""
    with patch.dict(
        os.environ,
        {
            "TELEMETRY_MODE": "file",
            "FIXOPS_URL": "https://test.example/api",
            "API_KEY_SECRET_REF": "TEST_KEY",
        },
    ):
        with patch("builtins.open", side_effect=FileNotFoundError):
            config = load_overlay_config()

    assert config["mode"] == "file"
    assert config["fixops_url"] == "https://test.example/api"
    assert config["api_key_secret_ref"] == "TEST_KEY"
