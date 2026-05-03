"""Tests for elastic_security_router — ALDECI.

Spins up a minimal FastAPI app with the Elastic Security router mounted.
Each test resets the engine singleton so state doesn't bleed between tests.

NO MOCKS rule:
  * When ELASTIC_URL or ELASTIC_API_KEY is unset the capability summary
    reports ``status="unavailable"`` and every lookup endpoint returns 503.
  * The happy-path tests inject a stub httpx.Client (not a fake response
    payload baked into the engine) so we still exercise the real
    networking + parsing code paths.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from tests.conftest import API_TOKEN

from fastapi import FastAPI
from fastapi.testclient import TestClient

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _StubResponse:
    """Minimal stand-in for httpx.Response with .json() + .status_code."""

    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per (method, url-suffix)."""

    def __init__(self, responses: Dict[tuple, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        json: Optional[Any] = None,  # noqa: A002 — matches httpx signature
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.calls.append({
            "method": method,
            "url": url,
            "json": json,
            "params": params or {},
            "headers": headers or {},
        })
        for (m, suffix), resp in self._responses.items():
            if method.upper() == m.upper() and url.endswith(suffix):
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def close(self) -> None:
        pass


def _build_app(
    *,
    base_url: Optional[str],
    api_key: Optional[str],
    stub_responses: Dict[tuple, Any],
):
    from core import elastic_security_engine as engine_mod

    engine_mod.reset_elastic_security_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_elastic_security_engine(
        base_url=base_url,
        api_key=api_key,
        client=stub_client,
    )

    from apps.api.elastic_security_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_env(monkeypatch):
    monkeypatch.delenv("ELASTIC_URL", raising=False)
    monkeypatch.delenv("ELASTIC_API_KEY", raising=False)
    app, _ = _build_app(base_url=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/elastic-security/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Elastic Security"
    assert set(body["endpoints"]) == {
        "/api/detection_engine/rules",
        "/api/detection_engine/signals/search",
        "/api/cases",
        "/api/exception_lists",
    }
    assert body["elastic_url_present"] is False
    assert body["elastic_api_key_present"] is False
    assert body["status"] == "unavailable"

    from core import elastic_security_engine as engine_mod
    engine_mod.reset_elastic_security_engine()


def test_capability_summary_ok_when_env_present(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://elastic.local:9200")
    monkeypatch.setenv("ELASTIC_API_KEY", "test-api-key")
    app, _ = _build_app(
        base_url="https://elastic.local:9200",
        api_key="test-api-key",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/elastic-security/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["elastic_url_present"] is True
    assert body["elastic_api_key_present"] is True
    assert body["status"] == "ok"

    from core import elastic_security_engine as engine_mod
    engine_mod.reset_elastic_security_engine()


def test_capability_summary_unavailable_when_only_url_present(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://elastic.local:9200")
    monkeypatch.delenv("ELASTIC_API_KEY", raising=False)
    app, _ = _build_app(
        base_url="https://elastic.local:9200",
        api_key=None,
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/elastic-security/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["elastic_url_present"] is True
    assert body["elastic_api_key_present"] is False
    assert body["status"] == "unavailable"

    from core import elastic_security_engine as engine_mod
    engine_mod.reset_elastic_security_engine()


# ---------------------------------------------------------------------------
# 503 paths (NO MOCKS)
# ---------------------------------------------------------------------------


def test_list_rules_returns_503_when_no_env(monkeypatch):
    monkeypatch.delenv("ELASTIC_URL", raising=False)
    monkeypatch.delenv("ELASTIC_API_KEY", raising=False)
    app, _ = _build_app(base_url=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get(
        "/api/v1/elastic-security/api/detection_engine/rules",
        headers=HEADERS,
    )
    assert r.status_code == 503
    assert "detail" in r.json()

    from core import elastic_security_engine as engine_mod
    engine_mod.reset_elastic_security_engine()


def test_search_signals_returns_503_when_no_env(monkeypatch):
    monkeypatch.delenv("ELASTIC_URL", raising=False)
    monkeypatch.delenv("ELASTIC_API_KEY", raising=False)
    app, _ = _build_app(base_url=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post(
        "/api/v1/elastic-security/api/detection_engine/signals/search",
        json={"query": {"match_all": {}}},
        headers=HEADERS,
    )
    assert r.status_code == 503

    from core import elastic_security_engine as engine_mod
    engine_mod.reset_elastic_security_engine()


def test_list_cases_returns_503_when_no_env(monkeypatch):
    monkeypatch.delenv("ELASTIC_URL", raising=False)
    monkeypatch.delenv("ELASTIC_API_KEY", raising=False)
    app, _ = _build_app(base_url=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/elastic-security/api/cases", headers=HEADERS)
    assert r.status_code == 503

    from core import elastic_security_engine as engine_mod
    engine_mod.reset_elastic_security_engine()


def test_list_exception_lists_returns_503_when_no_env(monkeypatch):
    monkeypatch.delenv("ELASTIC_URL", raising=False)
    monkeypatch.delenv("ELASTIC_API_KEY", raising=False)
    app, _ = _build_app(base_url=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get(
        "/api/v1/elastic-security/api/exception_lists", headers=HEADERS
    )
    assert r.status_code == 503

    from core import elastic_security_engine as engine_mod
    engine_mod.reset_elastic_security_engine()


# ---------------------------------------------------------------------------
# Happy paths via stub httpx client
# ---------------------------------------------------------------------------


def test_list_rules_happy_path(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://elastic.local:9200")
    monkeypatch.setenv("ELASTIC_API_KEY", "test-api-key")
    payload = {
        "page": 1,
        "perPage": 25,
        "total": 2,
        "data": [
            {
                "id": "rule-uuid-1",
                "name": "Suspicious PowerShell",
                "description": "Detects encoded PowerShell launches",
                "severity": "high",
                "risk_score": 75,
                "type": "query",
                "language": "kuery",
                "query": "process.name : \"powershell.exe\"",
                "enabled": True,
                "tags": ["Windows", "Endpoint"],
            },
            {
                "id": "rule-uuid-2",
                "name": "Unusual Network Connection",
                "description": "Outbound connection to rare host",
                "severity": "medium",
                "risk_score": 47,
                "type": "eql",
                "language": "eql",
                "query": "network where destination.port == 4444",
                "enabled": False,
                "tags": ["Network"],
            },
        ],
    }
    app, stub = _build_app(
        base_url="https://elastic.local:9200",
        api_key="test-api-key",
        stub_responses={
            ("GET", "/api/detection_engine/rules/_find"): _StubResponse(
                200, payload
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get(
        "/api/v1/elastic-security/api/detection_engine/rules"
        "?per_page=25&page=1",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 2
    assert body["perPage"] == 25
    assert body["page"] == 1
    assert len(body["data"]) == 2
    assert body["data"][0]["id"] == "rule-uuid-1"
    assert body["data"][0]["severity"] == "high"
    assert body["data"][0]["enabled"] is True
    assert body["data"][1]["language"] == "eql"

    # Verify outbound headers carried ApiKey + kbn-xsrf.
    assert len(stub.calls) == 1
    headers = stub.calls[0]["headers"]
    assert headers["Authorization"] == "ApiKey test-api-key"
    assert headers["kbn-xsrf"] == "true"

    from core import elastic_security_engine as engine_mod
    engine_mod.reset_elastic_security_engine()


def test_search_signals_happy_path(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://elastic.local:9200")
    monkeypatch.setenv("ELASTIC_API_KEY", "test-api-key")
    payload = {
        "took": 12,
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [
                {
                    "_id": "alert-1",
                    "_source": {
                        "kibana.alert.rule.uuid": "rule-uuid-1",
                        "kibana.alert.rule.name": "Suspicious PowerShell",
                        "kibana.alert.workflow_status": "open",
                        "kibana.alert.severity": "high",
                        "host": {"name": "win-prod-01"},
                        "user": {"name": "alice"},
                        "source": {"ip": "10.0.0.42"},
                    },
                }
            ],
        },
    }
    app, stub = _build_app(
        base_url="https://elastic.local:9200",
        api_key="test-api-key",
        stub_responses={
            ("POST", "/api/detection_engine/signals/search"): _StubResponse(
                200, payload
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post(
        "/api/v1/elastic-security/api/detection_engine/signals/search",
        json={"query": {"match_all": {}}, "size": 10},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["took"] == 12
    assert body["hits"]["total"] == 1
    hit = body["hits"]["hits"][0]
    assert hit["_id"] == "alert-1"
    src = hit["_source"]
    assert src["rule_id"] == "rule-uuid-1"
    assert src["rule_name"] == "Suspicious PowerShell"
    assert src["signal_status"] == "open"
    assert src["kibana_alert_severity"] == "high"
    assert src["source_ip"] == "10.0.0.42"

    # Outbound payload preserves user query.
    assert stub.calls[0]["json"] == {"query": {"match_all": {}}, "size": 10}

    from core import elastic_security_engine as engine_mod
    engine_mod.reset_elastic_security_engine()


def test_search_signals_validates_query_field(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://elastic.local:9200")
    monkeypatch.setenv("ELASTIC_API_KEY", "test-api-key")
    app, _ = _build_app(
        base_url="https://elastic.local:9200",
        api_key="test-api-key",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post(
        "/api/v1/elastic-security/api/detection_engine/signals/search",
        json={"size": 10},  # missing 'query'
        headers=HEADERS,
    )
    assert r.status_code == 422

    from core import elastic_security_engine as engine_mod
    engine_mod.reset_elastic_security_engine()


def test_list_cases_happy_path(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://elastic.local:9200")
    monkeypatch.setenv("ELASTIC_API_KEY", "test-api-key")
    payload = {
        "page": 1,
        "perPage": 20,
        "total": 1,
        "cases": [
            {
                "id": "case-1",
                "title": "Investigation: PowerShell anomaly",
                "description": "Triage encoded PowerShell on win-prod-01",
                "status": "open",
                "severity": "high",
                "owner": "securitySolution",
                "tags": ["pwsh", "endpoint"],
                "totalAlerts": 3,
                "totalComments": 2,
            }
        ],
    }
    app, stub = _build_app(
        base_url="https://elastic.local:9200",
        api_key="test-api-key",
        stub_responses={
            ("GET", "/api/cases/_find"): _StubResponse(200, payload),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get(
        "/api/v1/elastic-security/api/cases?perPage=20&status=open",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 1
    case = body["cases"][0]
    assert case["id"] == "case-1"
    assert case["status"] == "open"
    assert case["totalAlerts"] == 3

    # Status filter forwarded as a param.
    assert stub.calls[0]["params"].get("status") == "open"

    from core import elastic_security_engine as engine_mod
    engine_mod.reset_elastic_security_engine()


def test_list_cases_rejects_bad_status(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://elastic.local:9200")
    monkeypatch.setenv("ELASTIC_API_KEY", "test-api-key")
    app, _ = _build_app(
        base_url="https://elastic.local:9200",
        api_key="test-api-key",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get(
        "/api/v1/elastic-security/api/cases?status=bogus",
        headers=HEADERS,
    )
    assert r.status_code == 422

    from core import elastic_security_engine as engine_mod
    engine_mod.reset_elastic_security_engine()


def test_list_exception_lists_happy_path(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://elastic.local:9200")
    monkeypatch.setenv("ELASTIC_API_KEY", "test-api-key")
    payload = {
        "page": 1,
        "perPage": 20,
        "total": 1,
        "data": [
            {
                "id": "exception-list-1",
                "list_id": "endpoint_trusted_apps",
                "name": "Endpoint Trusted Applications",
                "description": "Apps allowed to bypass detection rules",
                "type": "endpoint",
                "namespace_type": "agnostic",
                "tags": [],
                "version": 3,
            }
        ],
    }
    app, _ = _build_app(
        base_url="https://elastic.local:9200",
        api_key="test-api-key",
        stub_responses={
            ("GET", "/api/exception_lists/_find"): _StubResponse(200, payload),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get(
        "/api/v1/elastic-security/api/exception_lists",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 1
    assert body["data"][0]["list_id"] == "endpoint_trusted_apps"
    assert body["data"][0]["type"] == "endpoint"

    from core import elastic_security_engine as engine_mod
    engine_mod.reset_elastic_security_engine()


def test_upstream_401_translates_to_503(monkeypatch):
    """Elastic returning 401/403 should surface as 503 — NO MOCKS rule."""
    monkeypatch.setenv("ELASTIC_URL", "https://elastic.local:9200")
    monkeypatch.setenv("ELASTIC_API_KEY", "wrong-key")
    app, _ = _build_app(
        base_url="https://elastic.local:9200",
        api_key="wrong-key",
        stub_responses={
            ("GET", "/api/detection_engine/rules/_find"): _StubResponse(
                401, {"message": "unauthorized"}, text="unauthorized"
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get(
        "/api/v1/elastic-security/api/detection_engine/rules",
        headers=HEADERS,
    )
    assert r.status_code == 503

    from core import elastic_security_engine as engine_mod
    engine_mod.reset_elastic_security_engine()
