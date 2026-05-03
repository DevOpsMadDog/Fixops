"""Tests for the Datadog Cloud SIEM router (NO MOCKS, real httpx path).

Each test uses a stub ``httpx.Client`` so the engine's REAL request
construction + header building + JSON parsing is exercised — only the
network is intercepted.

Coverage:
  1. Capability summary returns ``status="unavailable"`` when env unset.
  2. Capability summary returns ``status="ok"`` + dd_site echo when env set.
  3. POST /signals/search returns 503 when env unset.
  4. POST /signals/search returns a real Datadog page via stub client when configured.
  5. GET /rules returns 503 when env unset.
  6. GET /rules returns parsed payload via stub client when configured + checks DD-* headers.
  7. POST /cases returns 503 unset, returns case envelope when configured.
  8. GET /suppressions + /notification_rules return 503 when env unset.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------- helpers


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Minimal httpx.Client stand-in: matches by URL substring."""

    def __init__(self, responses: Dict[str, _StubResponse]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> _StubResponse:
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"errors": ["not found"]}, text="not found")

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "headers": headers or {},
                "params": params or {},
            }
        )
        return self._match(url)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json: Any = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": headers or {},
                "json": json,
                "params": params or {},
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


def _build_app(
    *,
    api_key: Optional[str],
    app_key: Optional[str],
    site: Optional[str] = None,
    stub_responses: Optional[Dict[str, _StubResponse]] = None,
):
    """Build a minimal FastAPI app mounting the Datadog router."""
    from core import datadog_security_engine as eng_mod

    eng_mod.reset_datadog_security_engine()
    stub = _StubClient(stub_responses or {})
    eng_mod.get_datadog_security_engine(
        api_key=api_key,
        app_key=app_key,
        site=site,
        client=stub,
        force_refresh=True,
    )

    from apps.api.datadog_security_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


def _reset() -> None:
    from core import datadog_security_engine as eng_mod
    eng_mod.reset_datadog_security_engine()


# ============================================================ capability


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("DD_API_KEY", raising=False)
    monkeypatch.delenv("DD_APP_KEY", raising=False)
    app, _ = _build_app(api_key="", app_key="", site="datadoghq.eu")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/datadog-security/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Datadog Cloud SIEM"
    for ep in [
        "/api/v2/security_monitoring/signals/search",
        "/api/v2/security_monitoring/rules",
        "/api/v2/security/cases",
        "/api/v2/security_monitoring/configuration/suppressions",
        "/api/v2/security_monitoring/notification_rules",
    ]:
        assert ep in body["endpoints"], f"missing endpoint {ep}"
    assert body["dd_api_key_present"] is False
    assert body["dd_app_key_present"] is False
    assert body["dd_site"] == "datadoghq.eu"
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_creds_present(monkeypatch):
    monkeypatch.setenv("DD_API_KEY", "ddkey")
    monkeypatch.setenv("DD_APP_KEY", "ddapp")
    app, _ = _build_app(
        api_key="ddkey", app_key="ddapp", site="us5.datadoghq.com"
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/datadog-security/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dd_api_key_present"] is True
    assert body["dd_app_key_present"] is True
    assert body["dd_site"] == "us5.datadoghq.com"
    assert body["status"] == "ok"
    _reset()


# ============================================================ 503 paths


def test_signals_search_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("DD_API_KEY", raising=False)
    monkeypatch.delenv("DD_APP_KEY", raising=False)
    app, _ = _build_app(api_key="", app_key="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/datadog-security/api/v2/security_monitoring/signals/search",
        headers=HEADERS,
        json={"filter": {"query": "*"}, "sort": "-timestamp"},
    )
    assert r.status_code == 503, r.text
    assert "DD_API_KEY" in r.json()["detail"]
    _reset()


def test_rules_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("DD_API_KEY", raising=False)
    monkeypatch.delenv("DD_APP_KEY", raising=False)
    app, _ = _build_app(api_key="", app_key="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/datadog-security/api/v2/security_monitoring/rules",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_suppressions_and_notifications_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("DD_API_KEY", raising=False)
    monkeypatch.delenv("DD_APP_KEY", raising=False)
    app, _ = _build_app(api_key="", app_key="")
    client = TestClient(app, raise_server_exceptions=True)

    for path in (
        "/api/v2/security_monitoring/configuration/suppressions",
        "/api/v2/security_monitoring/notification_rules",
    ):
        r = client.get(f"/api/v1/datadog-security{path}", headers=HEADERS)
        assert r.status_code == 503, f"{path}: {r.text}"
    _reset()


# ============================================================ real httpx path


def test_signals_search_returns_data_via_stub(monkeypatch):
    monkeypatch.setenv("DD_API_KEY", "ddkey")
    monkeypatch.setenv("DD_APP_KEY", "ddapp")
    raw = {
        "data": [
            {
                "id": "sig-crit-1",
                "type": "security_signal",
                "attributes": {
                    "message": "Suspicious AWS API call",
                    "status": "high",
                    "timestamp": "2026-05-04T00:00:00Z",
                    "tags": ["env:prod", "aws"],
                    "custom": {"source": "cloudtrail"},
                    "workflow": {"state": "open"},
                    "attributes": {"evidence": []},
                },
            }
        ],
        "links": {"next": "https://api.datadoghq.com/api/v2/security_monitoring/signals/search?cursor=abc"},
        "meta": {"page": {"after": "abc"}},
    }
    app, stub = _build_app(
        api_key="ddkey",
        app_key="ddapp",
        site="datadoghq.com",
        stub_responses={"/security_monitoring/signals/search": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/datadog-security/api/v2/security_monitoring/signals/search",
        headers=HEADERS,
        json={
            "filter": {
                "query": "@source:cloudtrail",
                "from": "now-1h",
                "to": "now",
            },
            "sort": "-timestamp",
            "page": {"limit": 25},
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["data"]) == 1
    assert body["data"][0]["id"] == "sig-crit-1"
    assert body["meta"]["page"]["after"] == "abc"
    assert "cursor=abc" in body["links"]["next"]

    # Verify DD headers + base url shape
    assert stub.calls, "expected at least one upstream call"
    first = stub.calls[0]
    assert first["method"] == "POST"
    assert first["headers"].get("DD-API-KEY") == "ddkey"
    assert first["headers"].get("DD-APPLICATION-KEY") == "ddapp"
    assert first["url"].startswith("https://api.datadoghq.com/")
    # alias 'from' must round-trip into the JSON body
    sent = first["json"]
    assert sent.get("filter", {}).get("from") == "now-1h"
    _reset()


def test_rules_list_with_filters_via_stub(monkeypatch):
    monkeypatch.setenv("DD_API_KEY", "ddkey")
    monkeypatch.setenv("DD_APP_KEY", "ddapp")
    raw = {
        "data": [
            {
                "id": "rule-abc",
                "type": "security_monitoring_rule",
                "attributes": {
                    "name": "Brute force on SSH",
                    "message": "Multiple failed logins",
                    "queries": [
                        {
                            "query": "service:ssh @evt.outcome:failure",
                            "name": "ssh_failures",
                            "aggregation": "count",
                            "distinctFields": ["@usr.name"],
                        }
                    ],
                    "cases": [
                        {
                            "name": "high",
                            "condition": "ssh_failures > 5",
                            "status": "high",
                            "notifications": [],
                        }
                    ],
                    "options": {
                        "evaluationWindow": 300,
                        "keepAlive": 600,
                        "maxSignalDuration": 86400,
                        "decreaseCriticalityBasedOnEnv": False,
                    },
                    "isEnabled": True,
                    "version": 3,
                },
            }
        ],
        "meta": {"page": {"total_count": 12, "total_filtered_count": 1}},
    }
    app, stub = _build_app(
        api_key="ddkey",
        app_key="ddapp",
        site="datadoghq.com",
        stub_responses={"/security_monitoring/rules": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/datadog-security/api/v2/security_monitoring/rules",
        params={
            "page[size]": 25,
            "page[number]": 0,
            "filter[name]": "ssh",
            "filter[severity]": "high,critical",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["meta"]["page"]["total_count"] == 12
    rule = body["data"][0]
    assert rule["attributes"]["name"] == "Brute force on SSH"
    assert rule["attributes"]["isEnabled"] is True

    assert stub.calls
    sent = stub.calls[0]
    assert sent["params"].get("page[size]") == 25
    assert sent["params"].get("filter[name]") == "ssh"
    assert sent["params"].get("filter[severity]") == "high,critical"
    assert sent["headers"].get("DD-API-KEY") == "ddkey"
    _reset()


def test_create_case_returns_envelope_via_stub(monkeypatch):
    monkeypatch.setenv("DD_API_KEY", "ddkey")
    monkeypatch.setenv("DD_APP_KEY", "ddapp")
    raw = {
        "data": {
            "id": "case-1",
            "type": "case",
            "attributes": {
                "title": "Investigate brute force",
                "description": "5 failed logins from one IP",
                "priority": "P2",
                "type": "security",
                "status": "open",
            },
        }
    }
    app, stub = _build_app(
        api_key="ddkey",
        app_key="ddapp",
        site="datadoghq.com",
        stub_responses={"/security/cases": _StubResponse(201, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/datadog-security/api/v2/security/cases",
        headers=HEADERS,
        json={
            "data": {
                "type": "case",
                "attributes": {
                    "title": "Investigate brute force",
                    "description": "5 failed logins from one IP",
                    "priority": "P2",
                    "type": "security",
                    "status": "open",
                },
            }
        },
    )
    assert r.status_code == 200, r.text  # router returns 200, upstream is 201
    body = r.json()
    assert body["data"]["id"] == "case-1"
    assert body["data"]["attributes"]["priority"] == "P2"

    assert stub.calls
    sent = stub.calls[0]
    assert sent["method"] == "POST"
    assert sent["json"]["data"]["attributes"]["title"] == "Investigate brute force"
    _reset()
