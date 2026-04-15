"""Tests for N8nAPIClient — all HTTP calls mocked via unittest.mock."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from connectors.n8n_connector import N8nAPIClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(payload: dict | list, status: int = 200):
    """Return a context-manager mock that yields a response with .read() and .status."""
    body = json.dumps(payload).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.status = status
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _http_error(code: int, body: dict = None):
    body_bytes = json.dumps(body or {}).encode()
    return urllib.error.HTTPError(
        url="http://localhost:5678/api/v1/test",
        code=code,
        msg="Error",
        hdrs=None,
        fp=BytesIO(body_bytes),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    return N8nAPIClient(base_url="http://localhost:5678", api_key="test-key")


@pytest.fixture
def client_no_key():
    return N8nAPIClient(base_url="http://localhost:5678", api_key="")


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def test_init_defaults_from_env(monkeypatch):
    monkeypatch.setenv("N8N_BASE_URL", "http://n8n.example.com")
    monkeypatch.setenv("N8N_API_KEY", "env-key-123")
    c = N8nAPIClient()
    assert c._base == "http://n8n.example.com"
    assert c._key == "env-key-123"
    assert c._api == "http://n8n.example.com/api/v1"


def test_init_explicit_params():
    c = N8nAPIClient(base_url="http://myhost:5678/", api_key="mykey")
    assert c._base == "http://myhost:5678"  # trailing slash stripped
    assert c._key == "mykey"


def test_headers_include_api_key(client):
    h = client._headers()
    assert h["X-N8N-API-KEY"] == "test-key"
    assert h["Content-Type"] == "application/json"


def test_headers_no_api_key_when_empty(client_no_key):
    h = client_no_key._headers()
    assert "X-N8N-API-KEY" not in h


# ---------------------------------------------------------------------------
# create_workflow
# ---------------------------------------------------------------------------

def test_create_workflow_returns_dict_with_id(client):
    payload = {"id": "wf-123", "name": "My Workflow", "active": False}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.create_workflow(
            name="My Workflow",
            nodes=[],
            connections={},
        )
    assert result["id"] == "wf-123"
    assert result["name"] == "My Workflow"


def test_create_workflow_passes_settings(client):
    payload = {"id": "wf-456", "name": "W", "active": False}
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["body"] = json.loads(req.data.decode())
        return _mock_response(payload)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        client.create_workflow("W", [], {}, settings={"executionOrder": "v1"})

    assert captured["body"]["settings"] == {"executionOrder": "v1"}


# ---------------------------------------------------------------------------
# activate / deactivate
# ---------------------------------------------------------------------------

def test_activate_workflow_returns_active_true(client):
    payload = {"id": "wf-1", "active": True}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.activate_workflow("wf-1")
    assert result["active"] is True


def test_deactivate_workflow_returns_active_false(client):
    payload = {"id": "wf-1", "active": False}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.deactivate_workflow("wf-1")
    assert result["active"] is False


# ---------------------------------------------------------------------------
# list_workflows
# ---------------------------------------------------------------------------

def test_list_workflows_returns_list(client):
    payload = [{"id": "wf-1"}, {"id": "wf-2"}]
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.list_workflows()
    assert isinstance(result, list)
    assert len(result) == 2


def test_list_workflows_unwraps_data_key(client):
    payload = {"data": [{"id": "wf-99"}], "nextCursor": None}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.list_workflows()
    assert result == [{"id": "wf-99"}]


# ---------------------------------------------------------------------------
# get_workflow
# ---------------------------------------------------------------------------

def test_get_workflow_returns_dict(client):
    payload = {"id": "wf-42", "name": "Test", "active": True}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.get_workflow("wf-42")
    assert result["id"] == "wf-42"


# ---------------------------------------------------------------------------
# delete_workflow
# ---------------------------------------------------------------------------

def test_delete_workflow_returns_true_on_success(client):
    payload = {"id": "wf-1"}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        assert client.delete_workflow("wf-1") is True


def test_delete_workflow_returns_false_on_http_error(client):
    with patch("urllib.request.urlopen", side_effect=_http_error(404, {"message": "Not found"})):
        assert client.delete_workflow("wf-missing") is False


# ---------------------------------------------------------------------------
# list_executions
# ---------------------------------------------------------------------------

def test_list_executions_returns_list(client):
    payload = {"data": [{"id": "exec-1"}, {"id": "exec-2"}]}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.list_executions()
    assert isinstance(result, list)
    assert result[0]["id"] == "exec-1"


def test_list_executions_filtered_by_workflow_id(client):
    payload = {"data": [{"id": "exec-5", "workflowId": "wf-99"}]}
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        return _mock_response(payload)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        client.list_executions(workflow_id="wf-99")

    assert "workflowId=wf-99" in captured["url"]


# ---------------------------------------------------------------------------
# get_execution
# ---------------------------------------------------------------------------

def test_get_execution_returns_dict(client):
    payload = {"id": "exec-7", "status": "success"}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.get_execution("exec-7")
    assert result["id"] == "exec-7"


# ---------------------------------------------------------------------------
# get_webhook_url
# ---------------------------------------------------------------------------

def test_get_webhook_url_correct_format(client):
    url = client.get_webhook_url("aldeci-finding")
    assert url == "http://localhost:5678/webhook/aldeci-finding"


def test_get_webhook_url_no_double_slash(client):
    c = N8nAPIClient(base_url="http://localhost:5678/")
    url = c.get_webhook_url("test-path")
    assert url == "http://localhost:5678/webhook/test-path"


# ---------------------------------------------------------------------------
# provision_security_workflow
# ---------------------------------------------------------------------------

def test_provision_security_workflow_returns_expected_keys(client):
    create_payload = {"id": "wf-prov-1", "name": "ALDECI finding → slack", "active": False}
    activate_payload = {"id": "wf-prov-1", "active": True}
    responses = iter([create_payload, activate_payload])

    def fake_urlopen(req, timeout=None):
        return _mock_response(next(responses))

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        result = client.provision_security_workflow("finding", ["slack"])

    assert result["workflow_id"] == "wf-prov-1"
    assert result["webhook_url"] == "http://localhost:5678/webhook/aldeci-finding"
    assert result["active"] is True


def test_provision_security_workflow_multiple_integrations(client):
    create_payload = {"id": "wf-multi", "active": False}
    activate_payload = {"id": "wf-multi", "active": True}
    responses = iter([create_payload, activate_payload])

    def fake_urlopen(req, timeout=None):
        return _mock_response(next(responses))

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        result = client.provision_security_workflow("incident", ["slack", "jira", "pagerduty"])

    assert result["workflow_id"] == "wf-multi"
    assert "aldeci-incident" in result["webhook_url"]


# ---------------------------------------------------------------------------
# Graceful fallback when n8n is unreachable
# ---------------------------------------------------------------------------

def test_create_workflow_graceful_when_n8n_down(client):
    with patch("urllib.request.urlopen", side_effect=ConnectionRefusedError("Connection refused")):
        result = client.create_workflow("W", [], {})
    assert "error" in result
    assert result["error"] == "n8n unavailable"


def test_list_workflows_graceful_when_n8n_down(client):
    with patch("urllib.request.urlopen", side_effect=OSError("unreachable")):
        result = client.list_workflows()
    # Returns error dict, does not raise
    assert isinstance(result, dict)
    assert "error" in result


def test_provision_graceful_when_n8n_down(client):
    with patch("urllib.request.urlopen", side_effect=ConnectionRefusedError("down")):
        result = client.provision_security_workflow("alert", ["slack"])
    assert "error" in result
    assert result["error"] == "n8n unavailable"


def test_activate_graceful_on_http_error(client):
    with patch("urllib.request.urlopen", side_effect=_http_error(500, {"message": "server error"})):
        result = client.activate_workflow("wf-bad")
    assert "error" in result
    assert "HTTP 500" in result["error"]


# ---------------------------------------------------------------------------
# API key in request headers
# ---------------------------------------------------------------------------

def test_api_key_header_sent_in_requests(client):
    payload = {"id": "wf-hdr"}
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["headers"] = dict(req.headers)
        return _mock_response(payload)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        client.create_workflow("H", [], {})

    # urllib capitalises header names: "X-n8n-api-key"
    key = captured["headers"].get("X-n8n-api-key") or captured["headers"].get("X-N8N-API-KEY")
    assert key == "test-key"


def test_no_api_key_header_when_not_configured(client_no_key):
    payload = [{"id": "wf-1"}]
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["headers"] = dict(req.headers)
        return _mock_response(payload)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        client_no_key.list_workflows()

    key = captured["headers"].get("X-n8n-api-key") or captured["headers"].get("X-N8N-API-KEY")
    assert key is None
