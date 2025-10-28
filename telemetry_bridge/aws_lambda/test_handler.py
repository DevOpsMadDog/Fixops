"""Unit tests for AWS Lambda telemetry handler."""

import base64
import gzip
import json
import os
from unittest.mock import MagicMock, patch

import pytest
from handler import (
    aggregate_telemetry,
    lambda_handler,
    load_overlay_config,
    parse_cloudwatch_logs,
    send_to_fixops,
)


@pytest.fixture
def sample_cloudwatch_event():
    """Sample CloudWatch Logs subscription event."""
    log_data = {
        "messageType": "DATA_MESSAGE",
        "owner": "123456789012",
        "logGroup": "/aws/waf/prod",
        "logStream": "2024-01-15",
        "subscriptionFilters": ["fixops-telemetry"],
        "logEvents": [
            {
                "id": "1",
                "timestamp": 1705334400000,
                "message": json.dumps(
                    {
                        "action": "BLOCK",
                        "terminatingRuleId": "rate-limit",
                        "latency_ms": 125,
                    }
                ),
            },
            {
                "id": "2",
                "timestamp": 1705334401000,
                "message": json.dumps(
                    {
                        "action": "BLOCK",
                        "terminatingRuleId": "sql-injection",
                        "latency_ms": 89,
                    }
                ),
            },
            {
                "id": "3",
                "timestamp": 1705334402000,
                "message": json.dumps(
                    {
                        "action": "ALLOW",
                        "terminatingRuleId": "default",
                        "latency_ms": 15,
                    }
                ),
            },
        ],
    }

    compressed = gzip.compress(json.dumps(log_data).encode("utf-8"))
    encoded = base64.b64encode(compressed).decode("utf-8")

    return {"awslogs": {"data": encoded}}


@pytest.fixture
def overlay_config():
    """Sample overlay configuration."""
    return {
        "mode": "http",
        "fixops_url": "https://fixops.example/api/v1/telemetry",
        "api_key_secret_ref": "FIXOPS_API_KEY",
    }


def test_parse_cloudwatch_logs(sample_cloudwatch_event):
    """Test parsing CloudWatch Logs event."""
    log_events = parse_cloudwatch_logs(sample_cloudwatch_event)

    assert len(log_events) == 3
    assert log_events[0]["id"] == "1"
    assert "message" in log_events[0]


def test_aggregate_telemetry():
    """Test aggregation of log events into standard format."""
    log_events = [
        {"message": json.dumps({"action": "BLOCK", "latency_ms": 125})},
        {"message": json.dumps({"action": "BLOCK", "latency_ms": 89})},
        {"message": json.dumps({"action": "ALLOW", "latency_ms": 15})},
        {"message": json.dumps({"action": "BLOCK", "latency_ms": 200})},
    ]

    telemetry = aggregate_telemetry(log_events)

    assert "alerts" in telemetry
    assert "latency_ms_p95" in telemetry

    assert len(telemetry["alerts"]) == 1
    assert telemetry["alerts"][0]["rule"] == "waf-blocks"
    assert telemetry["alerts"][0]["count"] == 3

    assert telemetry["latency_ms_p95"] == 200


def test_aggregate_telemetry_no_blocks():
    """Test aggregation with no BLOCK actions."""
    log_events = [{"message": json.dumps({"action": "ALLOW", "latency_ms": 15})}]

    telemetry = aggregate_telemetry(log_events)

    assert telemetry["alerts"][0]["count"] == 0
    assert telemetry["latency_ms_p95"] == 15


def test_aggregate_telemetry_no_latency():
    """Test aggregation with no latency data."""
    log_events = [{"message": json.dumps({"action": "BLOCK"})}]

    telemetry = aggregate_telemetry(log_events)

    assert telemetry["alerts"][0]["count"] == 1
    assert telemetry["latency_ms_p95"] is None


@patch("handler.requests.post")
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


@patch("handler.send_to_fixops")
@patch("handler.load_overlay_config")
def test_lambda_handler_success(
    mock_load_config, mock_send, sample_cloudwatch_event, overlay_config
):
    """Test successful Lambda handler execution."""
    mock_load_config.return_value = overlay_config
    mock_send.return_value = {"ok": True, "status_code": 200}

    result = lambda_handler(sample_cloudwatch_event, None)

    assert result["ok"] is True

    call_args = mock_send.call_args[0]
    telemetry = call_args[0]
    assert telemetry["alerts"][0]["rule"] == "waf-blocks"
    assert telemetry["alerts"][0]["count"] == 2  # Two BLOCK actions in sample


@patch("handler.parse_cloudwatch_logs")
def test_lambda_handler_error(mock_parse, sample_cloudwatch_event):
    """Test Lambda handler error handling."""
    mock_parse.side_effect = Exception("Parse error")

    result = lambda_handler(sample_cloudwatch_event, None)

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
