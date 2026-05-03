"""Tests for the New Relic APM router (NO MOCKS, real httpx path).

Each test uses a stub ``httpx.Client`` so the engine's REAL request
construction + header building + JSON parsing is exercised — only the
network is intercepted.
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
    account_id: Optional[str] = None,
    region: Optional[str] = None,
    stub_responses: Optional[Dict[str, _StubResponse]] = None,
):
    """Build a minimal FastAPI app mounting the New Relic router."""
    from core import newrelic_apm_engine as eng_mod

    eng_mod.reset_newrelic_apm_engine()
    stub = _StubClient(stub_responses or {})
    eng_mod.get_newrelic_apm_engine(
        api_key=api_key,
        account_id=account_id,
        region=region,
        client=stub,
        force_refresh=True,
    )

    from apps.api.newrelic_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


def _reset() -> None:
    from core import newrelic_apm_engine as eng_mod
    eng_mod.reset_newrelic_apm_engine()


# ============================================================ capability


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("NEWRELIC_API_KEY", raising=False)
    monkeypatch.delenv("NEWRELIC_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("NEWRELIC_REGION", raising=False)
    app, _ = _build_app(api_key="", account_id="", region="US")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/newrelic/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "New Relic"
    for ep in [
        "/v2/applications.json",
        "/v2/applications/{id}.json",
        "/v2/alerts_incidents.json",
        "/v2/alerts_violations.json",
        "/graphql",
    ]:
        assert ep in body["endpoints"], f"missing endpoint {ep}"
    assert body["api_key_present"] is False
    assert body["account_id_present"] is False
    assert body["region"] == "US"
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_creds_present(monkeypatch):
    monkeypatch.setenv("NEWRELIC_API_KEY", "nrk")
    monkeypatch.setenv("NEWRELIC_ACCOUNT_ID", "1234567")
    monkeypatch.setenv("NEWRELIC_REGION", "EU")
    app, _ = _build_app(api_key="nrk", account_id="1234567", region="EU")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/newrelic/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["api_key_present"] is True
    assert body["account_id_present"] is True
    assert body["region"] == "EU"
    assert body["status"] == "ok"
    _reset()


# ============================================================ 503 paths


def test_applications_list_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("NEWRELIC_API_KEY", raising=False)
    app, _ = _build_app(api_key="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/newrelic/v2/applications.json", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "NEWRELIC_API_KEY" in r.json()["detail"]
    _reset()


def test_application_detail_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("NEWRELIC_API_KEY", raising=False)
    app, _ = _build_app(api_key="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/newrelic/v2/applications/9999.json", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_alerts_incidents_and_violations_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("NEWRELIC_API_KEY", raising=False)
    app, _ = _build_app(api_key="")
    client = TestClient(app, raise_server_exceptions=True)

    for path in (
        "/v2/alerts_incidents.json",
        "/v2/alerts_violations.json",
    ):
        r = client.get(f"/api/v1/newrelic{path}", headers=HEADERS)
        assert r.status_code == 503, f"{path}: {r.text}"
    _reset()


def test_graphql_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("NEWRELIC_API_KEY", raising=False)
    app, _ = _build_app(api_key="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/newrelic/graphql",
        headers=HEADERS,
        json={"query": "{ actor { user { email } } }"},
    )
    assert r.status_code == 503, r.text
    _reset()


# ============================================================ real httpx path


def test_applications_list_returns_data_via_stub(monkeypatch):
    monkeypatch.setenv("NEWRELIC_API_KEY", "nrk")
    monkeypatch.setenv("NEWRELIC_ACCOUNT_ID", "1234567")
    raw = {
        "applications": [
            {
                "id": 7777,
                "name": "checkout-svc",
                "language": "python",
                "health_status": "green",
                "reporting": True,
                "last_reported_at": "2026-05-04T00:00:00Z",
                "application_summary": {
                    "response_time": 123.4,
                    "throughput": 9876.5,
                    "error_rate": 0.01,
                    "apdex_target": 0.5,
                    "apdex_score": 0.97,
                    "host_count": 4,
                    "instance_count": 12,
                },
                "end_user_summary": {
                    "response_time": 0,
                    "throughput": 0,
                    "apdex_target": 7.0,
                    "apdex_score": 0.94,
                },
                "settings": {
                    "app_apdex_threshold": 0.5,
                    "end_user_apdex_threshold": 7.0,
                    "enable_real_user_monitoring": True,
                    "use_server_side_config": True,
                },
                "links": {
                    "application_instances": [],
                    "application_hosts": [],
                    "servers": [],
                    "alert_policy": 42,
                },
            }
        ],
        "links": {"application.alert_policy": "/v2/alerts_policies/{alert_policy_id}"},
    }
    app, stub = _build_app(
        api_key="nrk",
        account_id="1234567",
        region="US",
        stub_responses={"/v2/applications.json": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/newrelic/v2/applications.json",
        params={
            "filter[name]": "checkout",
            "filter[language]": "python",
            "page": 1,
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["applications"]) == 1
    app_obj = body["applications"][0]
    assert app_obj["id"] == 7777
    assert app_obj["language"] == "python"
    assert app_obj["health_status"] == "green"
    assert app_obj["application_summary"]["apdex_score"] == 0.97

    # Verify X-Api-Key + base url shape
    assert stub.calls, "expected at least one upstream call"
    first = stub.calls[0]
    assert first["method"] == "GET"
    assert first["headers"].get("X-Api-Key") == "nrk"
    assert first["url"].startswith("https://api.newrelic.com/")
    assert first["params"].get("filter[name]") == "checkout"
    assert first["params"].get("filter[language]") == "python"
    assert first["params"].get("page") == 1
    _reset()


def test_application_detail_returns_payload_via_stub(monkeypatch):
    monkeypatch.setenv("NEWRELIC_API_KEY", "nrk")
    raw = {
        "application": {
            "id": 7777,
            "name": "checkout-svc",
            "language": "python",
            "health_status": "orange",
            "reporting": True,
        }
    }
    app, stub = _build_app(
        api_key="nrk",
        region="US",
        stub_responses={"/v2/applications/7777.json": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/newrelic/v2/applications/7777.json", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["application"]["id"] == 7777
    assert body["application"]["health_status"] == "orange"
    assert stub.calls and stub.calls[0]["url"].endswith("/v2/applications/7777.json")
    _reset()


def test_alerts_incidents_returns_payload_via_stub(monkeypatch):
    monkeypatch.setenv("NEWRELIC_API_KEY", "nrk")
    raw = {
        "incidents": [
            {
                "id": 100,
                "opened_at": 1745000000000,
                "closed_at": None,
                "incident_preference": "PER_POLICY",
                "links": {"violations": [201, 202], "policy_id": 33},
            }
        ]
    }
    app, stub = _build_app(
        api_key="nrk",
        region="EU",
        stub_responses={"/v2/alerts_incidents.json": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/newrelic/v2/alerts_incidents.json",
        params={"only_open": "true", "exclude_violations": "false"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["incidents"][0]["id"] == 100
    assert body["incidents"][0]["incident_preference"] == "PER_POLICY"

    # EU region
    assert stub.calls
    sent = stub.calls[0]
    assert sent["url"].startswith("https://api.eu.newrelic.com/")
    assert sent["headers"].get("X-Api-Key") == "nrk"
    assert sent["params"].get("only_open") == "true"
    assert sent["params"].get("exclude_violations") == "false"
    _reset()


def test_alerts_violations_returns_payload_via_stub(monkeypatch):
    monkeypatch.setenv("NEWRELIC_API_KEY", "nrk")
    raw = {
        "violations": [
            {
                "id": 555,
                "label": "Apdex < 0.7",
                "duration": 600,
                "policy_name": "Prod Web",
                "condition_name": "Slow apdex",
                "priority": "Critical",
                "opened_at": 1745001000000,
                "entity": {
                    "product": "APM",
                    "type": "Application",
                    "group_id": 1,
                    "id": 7777,
                    "name": "checkout-svc",
                },
                "links": {"policy_id": 33, "condition_id": 22, "incident_id": 100},
            }
        ]
    }
    app, stub = _build_app(
        api_key="nrk",
        region="US",
        stub_responses={"/v2/alerts_violations.json": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/newrelic/v2/alerts_violations.json",
        params={
            "start_date": "2026-05-01T00:00:00Z",
            "end_date": "2026-05-04T00:00:00Z",
            "only_open": "true",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["violations"][0]["priority"] == "Critical"
    assert body["violations"][0]["entity"]["id"] == 7777

    sent = stub.calls[0]
    assert sent["params"].get("start_date") == "2026-05-01T00:00:00Z"
    assert sent["params"].get("end_date") == "2026-05-04T00:00:00Z"
    assert sent["params"].get("only_open") == "true"
    _reset()


def test_nerdgraph_returns_data_via_stub(monkeypatch):
    monkeypatch.setenv("NEWRELIC_API_KEY", "nrk")
    raw = {
        "data": {
            "actor": {
                "account": {
                    "nrql": {
                        "results": [{"count": 42, "facet": "checkout-svc"}]
                    }
                }
            }
        }
    }
    app, stub = _build_app(
        api_key="nrk",
        region="US",
        stub_responses={"/graphql": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    query = (
        "{ actor { account(id: 1234567) { nrql(query: "
        "\"SELECT count(*) FROM Transaction\") { results } } } }"
    )
    r = client.post(
        "/api/v1/newrelic/graphql",
        headers=HEADERS,
        json={"query": query, "variables": {"x": 1}},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["actor"]["account"]["nrql"]["results"][0]["count"] == 42

    # NerdGraph uses Api-Key (NOT X-Api-Key)
    assert stub.calls
    sent = stub.calls[0]
    assert sent["method"] == "POST"
    assert sent["headers"].get("Api-Key") == "nrk"
    assert sent["url"] == "https://api.newrelic.com/graphql"
    assert sent["json"]["query"] == query
    assert sent["json"]["variables"] == {"x": 1}
    _reset()


def test_graphql_rejects_empty_query(monkeypatch):
    monkeypatch.setenv("NEWRELIC_API_KEY", "nrk")
    app, _ = _build_app(api_key="nrk")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/newrelic/graphql",
        headers=HEADERS,
        json={"query": ""},
    )
    # FastAPI / pydantic should reject min_length=1
    assert r.status_code == 422, r.text
    _reset()


def test_invalid_region_falls_back_to_us(monkeypatch):
    monkeypatch.setenv("NEWRELIC_API_KEY", "nrk")
    app, _ = _build_app(api_key="nrk", region="MARS")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/newrelic/", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["region"] == "US"
    _reset()
