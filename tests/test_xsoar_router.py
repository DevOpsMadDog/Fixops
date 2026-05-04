"""Tests for xsoar_router — ALDECI.

Mounts a minimal FastAPI app with the XSOAR router. Each test gets an
isolated httpx stub client and resets the engine singleton so state
doesn't bleed between tests.

NO MOCKS rule:
  * Capability summary reports ``status="unavailable"`` when creds missing.
  * All live endpoints return HTTP 503 when XSOAR_BASE_URL / XSOAR_API_KEY unset.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the Authorization header + JSON parsing code paths.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# httpx stubs
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        if text:
            self.text = text
        else:
            try:
                self.text = json.dumps(payload)
            except Exception:
                self.text = str(payload)

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no body")
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL suffix."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _resolve(self, url: str) -> _StubResponse:
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.calls.append(
            {"method": "GET", "url": url, "headers": dict(headers or {})}
        )
        return self._resolve(url)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[bytes] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": dict(headers or {}),
                "content": content,
            }
        )
        return self._resolve(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_OK_CREDS = {
    "base_url": "https://xsoar.example.com",
    "api_key": "xsoar-test-api-key-value",
}

_OK_CREDS_V8 = {
    "base_url": "https://xsoar.example.com",
    "api_key": "xsoar-test-api-key-value",
    "api_key_id": "42",
}


def _build_app(
    *,
    creds: Optional[Dict[str, str]],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine."""
    from core import xsoar_engine as engine_mod

    engine_mod.reset_xsoar_engine()

    stub_client = _StubClient(stub_responses)
    if creds is None:
        engine_mod.get_xsoar_engine(client=stub_client)
    else:
        engine_mod.get_xsoar_engine(
            base_url=creds.get("base_url"),
            api_key=creds.get("api_key"),
            api_key_id=creds.get("api_key_id"),
            client=stub_client,
        )

    from apps.api.xsoar_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import xsoar_engine as engine_mod

    engine_mod.reset_xsoar_engine()


@pytest.fixture(autouse=True)
def _wipe_env(monkeypatch):
    """Ensure env-var creds don't leak in from the host."""
    for var in ("XSOAR_BASE_URL", "XSOAR_API_KEY", "XSOAR_API_KEY_ID"):
        monkeypatch.delenv(var, raising=False)
    _reset()
    yield
    _reset()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/xsoar/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Palo Alto Cortex XSOAR"
    assert body["endpoints"] == [
        "/incidents/search",
        "/incidents/{id}",
        "/incidents/{id}/run",
        "/playbooks/search",
        "/settings/integration/search",
    ]
    assert body["xsoar_base_url_present"] is False
    assert body["xsoar_api_key_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_creds_present():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/xsoar/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["xsoar_base_url_present"] is True
    assert body["xsoar_api_key_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 paths when creds missing
# ---------------------------------------------------------------------------


def test_incidents_search_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/xsoar/incidents/search",
        json={"filter": {"query": "type:Phishing", "page": 0, "size": 10}},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "XSOAR" in r.json()["detail"]


def test_incident_get_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/xsoar/incidents/100", headers=HEADERS)
    assert r.status_code == 503, r.text


def test_run_playbook_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/xsoar/incidents/100/run",
        json={"playbookId": "auto-isolate-host"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


def test_playbooks_search_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/xsoar/playbooks/search",
        json={"query": "phish", "page": 0, "size": 10},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


def test_integrations_search_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/xsoar/settings/integration/search",
        json={"page": 0, "size": 10},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


# ---------------------------------------------------------------------------
# 422 validation
# ---------------------------------------------------------------------------


def test_incidents_search_422_on_bad_status():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post(
        "/api/v1/xsoar/incidents/search",
        json={"filter": {"page": 0, "size": 10, "status": [99]}},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_incidents_search_422_on_bad_severity():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post(
        "/api/v1/xsoar/incidents/search",
        json={"filter": {"page": 0, "size": 10, "severity": [9]}},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_add_entry_422_on_bad_format():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post(
        "/api/v1/xsoar/entry",
        json={"investigationId": "100", "data": "note", "format": "binary"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_run_playbook_422_on_empty_playbook_id():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post(
        "/api/v1/xsoar/incidents/100/run",
        json={"playbookId": ""},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_incidents_search_happy_path_normalizes_and_signs():
    raw = {
        "total": 1,
        "data": [
            {
                "id": "100",
                "version": 7,
                "name": "Phishing email — exec spoof",
                "type": "Phishing",
                "severity": 3,
                "status": 1,
                "category": "phishing",
                "occurred": "2026-04-30T12:00:00Z",
                "modified": "2026-05-01T08:00:00Z",
                "created": "2026-04-30T12:00:00Z",
                "sourceBrand": "EWS v2",
                "sourceInstance": "ews-instance-1",
                "hasRole": True,
                "owner": "alice",
                "sla": 30,
                "dueDate": "2026-05-02T12:00:00Z",
                "closeReason": "",
                "closeNotes": "",
                "runStatus": "active",
                "openDuration": 86400,
                "closingUserId": "",
                "lastOpen": "2026-04-30T12:05:00Z",
                "autime": 1714478400,
                "account": "",
                "CustomFields": {"phishingurl": "http://bad.example.com"},
                "labels": [{"type": "Email/from", "value": "ceo@spoof.example"}],
            }
        ],
    }
    app, stub = _build_app(
        creds=_OK_CREDS_V8,
        stub_responses={"/incidents/search": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/xsoar/incidents/search",
        json={
            "filter": {
                "query": "type:Phishing",
                "page": 0,
                "size": 25,
                "status": [0, 1],
                "severity": [3, 4],
            },
            "ascending": False,
            "sort": [{"field": "created", "asc": False}],
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 1
    assert len(body["data"]) == 1
    inc = body["data"][0]
    assert inc["id"] == "100"
    assert inc["severity"] == 3
    assert inc["status"] == 1
    assert inc["sourceBrand"] == "EWS v2"
    assert inc["customFields"] == {"phishingurl": "http://bad.example.com"}
    assert inc["labels"] == [{"type": "Email/from", "value": "ceo@spoof.example"}]

    # Auth headers were set on the upstream call.
    assert len(stub.calls) == 1
    call = stub.calls[0]
    assert call["headers"].get("Authorization") == _OK_CREDS_V8["api_key"]
    assert call["headers"].get("x-xdr-auth-id") == _OK_CREDS_V8["api_key_id"]
    assert call["headers"].get("Content-Type") == "application/json"
    body_sent = json.loads(call["content"])
    assert body_sent["filter"]["query"] == "type:Phishing"
    assert body_sent["filter"]["status"] == [0, 1]
    assert body_sent["sort"] == [{"field": "created", "asc": False}]


def test_incident_get_happy_path():
    raw = {
        "id": "100",
        "version": 7,
        "name": "Phishing — exec spoof",
        "type": "Phishing",
        "severity": 3,
        "status": 1,
        "category": "phishing",
        "occurred": "2026-04-30T12:00:00Z",
        "modified": "2026-05-01T08:00:00Z",
        "created": "2026-04-30T12:00:00Z",
        "sourceBrand": "EWS v2",
        "sourceInstance": "ews-1",
        "hasRole": True,
        "owner": "alice",
        "sla": 30,
        "dueDate": "2026-05-02T12:00:00Z",
        "closeReason": "",
        "closeNotes": "",
        "runStatus": "active",
        "openDuration": 86400,
        "closingUserId": "",
        "lastOpen": "2026-04-30T12:05:00Z",
        "autime": 1714478400,
        "account": "",
        "CustomFields": {"phishingurl": "http://bad.example.com"},
        "labels": [],
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/incident/load/100": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/xsoar/incidents/100", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "100"
    assert body["status"] == 1
    assert body["customFields"] == {"phishingurl": "http://bad.example.com"}


def test_run_playbook_happy_path_returns_204():
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/incident/playbook/100/run": _StubResponse(204, {}, text="")},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/xsoar/incidents/100/run",
        json={"playbookId": "auto-isolate-host"},
        headers=HEADERS,
    )
    assert r.status_code == 204, r.text
    assert r.content == b""

    assert len(stub.calls) == 1
    body_sent = json.loads(stub.calls[0]["content"])
    assert body_sent == {"playbookId": "auto-isolate-host"}


def test_add_entry_happy_path():
    raw = {
        "id": "entry-1",
        "investigationId": "100",
        "type": 1,
        "format": "markdown",
        "contents": "# triage notes",
        "created": "2026-05-01T10:00:00Z",
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/entry": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/xsoar/entry",
        json={
            "investigationId": "100",
            "data": "# triage notes",
            "format": "markdown",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "entry-1"
    assert body["format"] == "markdown"
    assert body["investigationId"] == "100"

    body_sent = json.loads(stub.calls[0]["content"])
    assert body_sent["investigationId"] == "100"
    assert body_sent["data"] == "# triage notes"
    assert body_sent["format"] == "markdown"


def test_playbooks_search_happy_path_normalizes():
    raw = {
        "total": 1,
        "playbooks": [
            {
                "id": "auto-isolate-host",
                "version": 4,
                "name": "Auto Isolate Host",
                "description": "Isolates infected host via EDR.",
                "missingScripts": [],
                "tasks": {"0": {"id": "0", "type": "start"}},
                "taskIds": ["0", "1"],
                "inputs": [
                    {"key": "Hostname", "value": "${incident.hostname}", "required": True, "description": "Target host"}
                ],
                "outputs": [
                    {"contextPath": "Isolation.Result", "description": "Isolation outcome", "type": "string"}
                ],
                "commands": ["edr-isolate-host"],
                "tags": ["EDR", "Containment"],
            }
        ],
        "savedFilters": [],
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/playbook/search": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/xsoar/playbooks/search",
        json={"query": "isolate", "page": 0, "size": 10},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 1
    pb = body["playbooks"][0]
    assert pb["id"] == "auto-isolate-host"
    assert pb["inputs"][0]["required"] is True
    assert pb["outputs"][0]["contextPath"] == "Isolation.Result"
    assert pb["commands"] == ["edr-isolate-host"]
    assert body["savedFilters"] == []


def test_integrations_search_happy_path():
    raw = {
        "total": 1,
        "instances": [
            {
                "name": "VirusTotal-prod",
                "brand": "VirusTotal",
                "category": "Threat Intelligence",
                "data": [{"name": "apikey", "hasvalue": True}],
                "canSample": False,
                "isLongRunning": False,
                "defaultMapperIn": "",
                "defaultMapperOut": "",
                "longRunningEnabled": False,
                "mappingId": "",
                "hidden": False,
                "version": 3,
            }
        ],
        "configurations": {"VirusTotal": {"display": "VirusTotal"}},
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/settings/integration/search": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/xsoar/settings/integration/search",
        json={"query": "virus", "page": 0, "size": 10},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 1
    inst = body["instances"][0]
    assert inst["name"] == "VirusTotal-prod"
    assert inst["brand"] == "VirusTotal"
    assert inst["configurations"] == [{"name": "apikey", "hasvalue": True}]
    assert body["configurations"] == {"VirusTotal": {"display": "VirusTotal"}}


def test_integration_test_happy_path_success():
    raw = {"success": True, "message": "ok"}
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/settings/integration/test": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/xsoar/settings/integration/test",
        json={
            "name": "VirusTotal-prod",
            "brand": "VirusTotal",
            "configuration": [{"name": "apikey", "value": "REDACTED"}],
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True
    assert body["message"] == "ok"

    body_sent = json.loads(stub.calls[0]["content"])
    assert body_sent["name"] == "VirusTotal-prod"
    assert body_sent["brand"] == "VirusTotal"
    assert body_sent["data"] == [{"name": "apikey", "value": "REDACTED"}]


def test_integration_test_happy_path_failure():
    raw = {"success": False, "message": "Invalid API key"}
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/settings/integration/test": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/xsoar/settings/integration/test",
        json={
            "name": "VirusTotal-prod",
            "brand": "VirusTotal",
            "configuration": [{"name": "apikey", "value": "BAD"}],
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is False
    assert "Invalid" in body["message"]


# ---------------------------------------------------------------------------
# Upstream error handling
# ---------------------------------------------------------------------------


def test_incidents_search_503_on_upstream_401():
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/incidents/search": _StubResponse(401, {"error": "bad token"})
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/xsoar/incidents/search",
        json={"filter": {"page": 0, "size": 10}},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "401" in r.json()["detail"]


def test_playbooks_search_503_on_upstream_429():
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/playbook/search": _StubResponse(429, {"error": "rate limit"})
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/xsoar/playbooks/search",
        json={"page": 0, "size": 10},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "429" in r.json()["detail"] or "rate-limit" in r.json()["detail"]
