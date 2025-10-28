"""Unit tests for Azure Function telemetry handler."""

import json
import os
from unittest.mock import MagicMock, patch

import azure.functions as func
import pytest
from __init__ import (
    aggregate_telemetry,
    load_overlay_config,
    main,
    parse_event_hub_message,
    send_to_fixops,
)


@pytest.fixture
def sample_event_hub_event():
    """Sample Event Hub event from Azure Diagnostic Settings."""
    records = {
        "records": [
            {
                "time": "2024-01-15T12:00:00.000Z",
                "resourceId": "/subscriptions/12345/resourceGroups/prod-rg/providers/Microsoft.Network/applicationGateways/prod-waf",
                "operationName": "ApplicationGatewayFirewall",
                "category": "ApplicationGatewayFirewallLog",
                "properties": {
                    "instanceId": "appgw_0",
                    "clientIp": "203.0.113.1",
                    "action": "Blocked",
                    "latency_ms": 142,
                },
            },
            {
                "time": "2024-01-15T12:00:01.000Z",
                "resourceId": "/subscriptions/12345/resourceGroups/prod-rg/providers/Microsoft.Network/applicationGateways/prod-waf",
                "operationName": "ApplicationGatewayFirewall",
                "category": "ApplicationGatewayFirewallLog",
                "properties": {
                    "instanceId": "appgw_0",
                    "clientIp": "198.51.100.42",
                    "action": "Blocked",
                    "latency_ms": 98,
                },
            },
            {
                "time": "2024-01-15T12:00:02.000Z",
                "resourceId": "/subscriptions/12345/resourceGroups/prod-rg/providers/Microsoft.Network/applicationGateways/prod-waf",
                "operationName": "ApplicationGatewayFirewall",
                "category": "ApplicationGatewayFirewallLog",
                "properties": {
                    "instanceId": "appgw_0",
                    "clientIp": "192.0.2.100",
                    "action": "Allowed",
                    "latency_ms": 25,
                },
            },
        ]
    }

    event = MagicMock(spec=func.EventHubEvent)
    event.get_body.return_value = json.dumps(records).encode("utf-8")

    return event


@pytest.fixture
def overlay_config():
    """Sample overlay configuration."""
    return {
        "mode": "http",
        "fixops_url": "https://fixops.example/api/v1/telemetry",
        "api_key_secret_ref": "FIXOPS_API_KEY",
    }


def test_parse_event_hub_message(sample_event_hub_event):
    """Test parsing Event Hub message."""
    records = parse_event_hub_message(sample_event_hub_event)

    assert len(records) == 3
    assert records[0]["properties"]["action"] == "Blocked"
    assert records[1]["properties"]["action"] == "Blocked"
    assert records[2]["properties"]["action"] == "Allowed"


def test_aggregate_telemetry():
    """Test aggregation of log records into standard format."""
    records = [
        {"properties": {"action": "Blocked", "latency_ms": 142}},
        {"properties": {"action": "Blocked", "latency_ms": 98}},
        {"properties": {"action": "Allowed", "latency_ms": 25}},
        {"properties": {"action": "Block", "latency_ms": 200}},
    ]

    telemetry = aggregate_telemetry(records)

    assert "alerts" in telemetry
    assert "latency_ms_p95" in telemetry

    assert len(telemetry["alerts"]) == 1
    assert telemetry["alerts"][0]["rule"] == "waf-blocks"
    assert telemetry["alerts"][0]["count"] == 3

    assert telemetry["latency_ms_p95"] == 200


def test_aggregate_telemetry_no_blocks():
    """Test aggregation with no BLOCK actions."""
    records = [{"properties": {"action": "Allowed", "latency_ms": 25}}]

    telemetry = aggregate_telemetry(records)

    assert telemetry["alerts"][0]["count"] == 0
    assert telemetry["latency_ms_p95"] == 25


def test_aggregate_telemetry_no_latency():
    """Test aggregation with no latency data."""
    records = [{"properties": {"action": "Blocked"}}]

    telemetry = aggregate_telemetry(records)

    assert telemetry["alerts"][0]["count"] == 1
    assert telemetry["latency_ms_p95"] is None


@patch("__init__.requests.post")
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


@patch("__init__.send_to_fixops")
@patch("__init__.load_overlay_config")
def test_main_success(
    mock_load_config, mock_send, sample_event_hub_event, overlay_config
):
    """Test successful Function execution."""
    mock_load_config.return_value = overlay_config
    mock_send.return_value = {"ok": True, "status_code": 200}

    main(sample_event_hub_event)

    call_args = mock_send.call_args[0]
    telemetry = call_args[0]
    assert telemetry["alerts"][0]["rule"] == "waf-blocks"
    assert telemetry["alerts"][0]["count"] == 2  # Two Blocked actions in sample


@patch("__init__.parse_event_hub_message")
def test_main_error(mock_parse, sample_event_hub_event):
    """Test Function error handling."""
    mock_parse.side_effect = Exception("Parse error")

    with pytest.raises(Exception, match="Parse error"):
        main(sample_event_hub_event)


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
