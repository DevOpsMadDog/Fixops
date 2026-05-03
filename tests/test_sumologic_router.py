"""Tests for sumologic_router (Sumo Logic Cloud SIEM REST proxy).

Covers:
- GET /                                                   capability summary (unavailable + ok)
- POST /api/v1/search/jobs                                create job
- GET /api/v1/search/jobs/{id}                            state
- GET /api/v1/search/jobs/{id}/messages                   messages page
- GET /api/v1/search/jobs/{id}/records                    records page
- DELETE /api/v1/search/jobs/{id}                         cancel
- GET /api/v1/dashboards                                  list (paginated)
- GET /api/v1/collectors                                  list
- GET /api/v1/collectors/{cid}/sources                    nested
- GET /api/sec/v1/insights                                Cloud SIEM
- GET /api/v1/health-events                               health
- 503 on lookup endpoints when env unset (NO MOCKS rule)
- 422 validation on bad payloads

Usage:
    pytest tests/test_sumologic_router.py -x --tb=short -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite-core and suite-api on path
for _p in ("suite-core", "suite-api"):
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sumo_env(monkeypatch):
    """Configure SUMO_ACCESS_ID + SUMO_ACCESS_KEY (+ explicit endpoint)."""
    monkeypatch.setenv("SUMO_ACCESS_ID", "su-id-abc")
    monkeypatch.setenv("SUMO_ACCESS_KEY", "su-key-xyz")
    monkeypatch.setenv("SUMO_ENDPOINT", "https://api.us2.sumologic.com")
    from core.sumologic_siem_engine import reset_sumologic_siem_engine
    reset_sumologic_siem_engine()
    yield
    reset_sumologic_siem_engine()


@pytest.fixture()
def no_sumo_env(monkeypatch):
    """Ensure env is unset (NO MOCKS — must surface 503)."""
    monkeypatch.delenv("SUMO_ACCESS_ID", raising=False)
    monkeypatch.delenv("SUMO_ACCESS_KEY", raising=False)
    # leave SUMO_ENDPOINT alone — capability_summary should still default
    monkeypatch.delenv("SUMO_ENDPOINT", raising=False)
    from core.sumologic_siem_engine import reset_sumologic_siem_engine
    reset_sumologic_siem_engine()
    yield
    reset_sumologic_siem_engine()


@pytest.fixture()
def app() -> FastAPI:
    from apps.api.sumologic_router import router
    a = FastAPI()
    a.include_router(router)
    return a


@pytest.fixture()
def client(app) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# httpx stub helpers
# ---------------------------------------------------------------------------


def _install_httpx_stub(monkeypatch, handler):
    """Replace httpx.Client with a transport-mocked instance."""
    import httpx as _httpx

    real_client_init = _httpx.Client.__init__

    def _patched_init(self, *args, **kwargs):
        kwargs.pop("verify", None)
        kwargs["transport"] = _httpx.MockTransport(handler)
        real_client_init(self, *args, **kwargs)

    monkeypatch.setattr(_httpx.Client, "__init__", _patched_init)


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(client, no_sumo_env):
    resp = client.get("/api/v1/sumologic/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Sumo Logic"
    assert body["sumo_access_id_present"] is False
    assert body["sumo_access_key_present"] is False
    assert body["status"] == "unavailable"
    assert body["sumo_endpoint"] == "https://api.us2.sumologic.com"
    for ep in (
        "/api/v1/search/jobs",
        "/api/v1/dashboards",
        "/api/v1/collectors",
        "/api/sec/v1/insights",
        "/api/v1/health-events",
    ):
        assert ep in body["endpoints"]


def test_capability_summary_ok_when_configured(client, sumo_env):
    resp = client.get("/api/v1/sumologic/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["sumo_access_id_present"] is True
    assert body["sumo_access_key_present"] is True
    assert body["status"] == "ok"
    assert body["sumo_endpoint"] == "https://api.us2.sumologic.com"


# ---------------------------------------------------------------------------
# 503 NO MOCKS path
# ---------------------------------------------------------------------------


def test_create_search_job_503_when_unconfigured(client, no_sumo_env):
    resp = client.post(
        "/api/v1/sumologic/api/v1/search/jobs",
        json={
            "query": "_sourceCategory=prod | count",
            "from": "2026-05-01T00:00:00",
            "to": "2026-05-01T01:00:00",
        },
    )
    assert resp.status_code == 503
    assert "sumologic" in resp.json()["detail"].lower()


def test_get_messages_503_when_unconfigured(client, no_sumo_env):
    resp = client.get(
        "/api/v1/sumologic/api/v1/search/jobs/job-1/messages"
    )
    assert resp.status_code == 503


def test_list_collectors_503_when_unconfigured(client, no_sumo_env):
    resp = client.get("/api/v1/sumologic/api/v1/collectors")
    assert resp.status_code == 503


def test_list_dashboards_503_when_unconfigured(client, no_sumo_env):
    resp = client.get("/api/v1/sumologic/api/v1/dashboards")
    assert resp.status_code == 503


def test_list_insights_503_when_unconfigured(client, no_sumo_env):
    resp = client.get("/api/v1/sumologic/api/sec/v1/insights")
    assert resp.status_code == 503


def test_health_events_503_when_unconfigured(client, no_sumo_env):
    resp = client.get("/api/v1/sumologic/api/v1/health-events")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Search Job API (live-stubbed via httpx.MockTransport)
# ---------------------------------------------------------------------------


def test_create_search_job(client, sumo_env, monkeypatch):
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["body"] = request.content.decode()
        # Sumo Logic returns 202 Accepted with id + link
        return httpx.Response(
            202,
            json={
                "id": "9D69B43DC8B6E2A1",
                "link": {
                    "rel": "self",
                    "href": "https://api.us2.sumologic.com/api/v1/search/jobs/9D69B43DC8B6E2A1",
                },
            },
        )

    _install_httpx_stub(monkeypatch, handler)
    resp = client.post(
        "/api/v1/sumologic/api/v1/search/jobs",
        json={
            "query": "_sourceCategory=prod | count by _sourceHost",
            "from": "2026-05-01T00:00:00",
            "to": "2026-05-01T01:00:00",
            "timeZone": "UTC",
            "byReceiptTime": False,
            "autoParsingMode": "intelligent",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["id"] == "9D69B43DC8B6E2A1"
    assert body["link"]["rel"] == "self"
    assert seen["method"] == "POST"
    assert seen["path"] == "/api/v1/search/jobs"
    # Confirm body shape mirrors Sumo's contract
    assert "byReceiptTime" in seen["body"]
    assert "autoParsingMode" in seen["body"]


def test_get_search_job_state(client, sumo_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/search/jobs/9D69B43DC8B6E2A1"
        return httpx.Response(
            200,
            json={
                "state": "DONE GATHERING RESULTS",
                "messageCount": 1234,
                "histogramBuckets": [],
                "pendingErrors": [],
                "pendingWarnings": [],
                "recordCount": 56,
            },
        )

    _install_httpx_stub(monkeypatch, handler)
    resp = client.get("/api/v1/sumologic/api/v1/search/jobs/9D69B43DC8B6E2A1")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"] == "DONE GATHERING RESULTS"
    assert body["messageCount"] == 1234
    assert body["recordCount"] == 56


def test_get_search_job_messages(client, sumo_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        assert params["offset"] == "10"
        assert params["limit"] == "5"
        return httpx.Response(
            200,
            json={
                "messages": [
                    {
                        "map": {
                            "_messagetime": "1714521600000",
                            "_raw": "Some log line",
                            "_sourceHost": "host-a",
                        }
                    }
                ],
                "fields": [
                    {"name": "_messagetime", "fieldType": "long", "keyField": False},
                    {"name": "_raw", "fieldType": "string", "keyField": False},
                ],
            },
        )

    _install_httpx_stub(monkeypatch, handler)
    resp = client.get(
        "/api/v1/sumologic/api/v1/search/jobs/9D69B43DC8B6E2A1/messages",
        params={"offset": 10, "limit": 5},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["messages"]) == 1
    assert body["messages"][0]["map"]["_sourceHost"] == "host-a"
    assert any(f["name"] == "_raw" for f in body["fields"])


def test_get_search_job_records(client, sumo_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert "/records" in request.url.path
        return httpx.Response(
            200,
            json={
                "records": [{"map": {"_count": "42", "_sourceHost": "host-a"}}],
                "fields": [
                    {"name": "_count", "fieldType": "long", "keyField": False},
                ],
            },
        )

    _install_httpx_stub(monkeypatch, handler)
    resp = client.get(
        "/api/v1/sumologic/api/v1/search/jobs/9D69B43DC8B6E2A1/records"
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["records"][0]["map"]["_count"] == "42"


def test_delete_search_job(client, sumo_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        assert request.url.path == "/api/v1/search/jobs/9D69B43DC8B6E2A1"
        return httpx.Response(200, json={})

    _install_httpx_stub(monkeypatch, handler)
    resp = client.delete(
        "/api/v1/sumologic/api/v1/search/jobs/9D69B43DC8B6E2A1"
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body == {"id": "9D69B43DC8B6E2A1", "cancelled": True}


# ---------------------------------------------------------------------------
# Dashboards
# ---------------------------------------------------------------------------


def test_list_dashboards_with_pagination(client, sumo_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v2/dashboards"
        params = dict(request.url.params)
        assert params["limit"] == "25"
        assert params["token"] == "cursor-abc"
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "dash-1",
                        "title": "SOC Overview",
                        "description": "Real-time SOC dashboard",
                        "folderId": "folder-1",
                        "topologyLabelMap": {},
                        "refreshInterval": 60,
                        "timeRange": {},
                        "layout": {},
                        "panels": [],
                    }
                ],
                "next": "cursor-def",
            },
        )

    _install_httpx_stub(monkeypatch, handler)
    resp = client.get(
        "/api/v1/sumologic/api/v1/dashboards",
        params={"limit": 25, "token": "cursor-abc"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["dashboards"][0]["id"] == "dash-1"
    assert body["dashboards"][0]["title"] == "SOC Overview"
    assert body["next"] == "cursor-def"


# ---------------------------------------------------------------------------
# Collectors + sources
# ---------------------------------------------------------------------------


def test_list_collectors(client, sumo_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/collectors"
        params = dict(request.url.params)
        assert params["limit"] == "50"
        assert params["offset"] == "0"
        return httpx.Response(
            200,
            json={
                "collectors": [
                    {
                        "id": 100200,
                        "name": "host-a-collector",
                        "collectorType": "Installable",
                        "collectorVersion": "19.401-2",
                        "ephemeral": False,
                        "alive": True,
                        "lastSeenAlive": 1714521600000,
                        "sourceSyncMode": "UI",
                    }
                ]
            },
        )

    _install_httpx_stub(monkeypatch, handler)
    resp = client.get(
        "/api/v1/sumologic/api/v1/collectors",
        params={"limit": 50, "offset": 0},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["collectors"][0]["alive"] is True
    assert body["collectors"][0]["collectorType"] == "Installable"


def test_list_collector_sources(client, sumo_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/collectors/100200/sources"
        return httpx.Response(
            200,
            json={
                "sources": [
                    {
                        "id": 555,
                        "name": "syslog",
                        "category": "host/syslog",
                        "hostName": "host-a",
                        "automaticDateParsing": True,
                        "multilineProcessingEnabled": True,
                        "useAutolineMatching": True,
                        "forceTimeZone": False,
                    }
                ]
            },
        )

    _install_httpx_stub(monkeypatch, handler)
    resp = client.get("/api/v1/sumologic/api/v1/collectors/100200/sources")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["sources"][0]["name"] == "syslog"


# ---------------------------------------------------------------------------
# Cloud SIEM insights
# ---------------------------------------------------------------------------


def test_list_insights(client, sumo_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/sec/v1/insights"
        params = dict(request.url.params)
        assert params["limit"] == "10"
        return httpx.Response(
            200,
            json={
                "data": {
                    "objects": [
                        {
                            "id": "insight-9",
                            "readableId": "INS-9",
                            "name": "Brute force",
                            "severity": "HIGH",
                        }
                    ]
                }
            },
        )

    _install_httpx_stub(monkeypatch, handler)
    resp = client.get(
        "/api/v1/sumologic/api/sec/v1/insights",
        params={"limit": 10, "q": "severity:HIGH"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"]["objects"][0]["readableId"] == "INS-9"


# ---------------------------------------------------------------------------
# Health events
# ---------------------------------------------------------------------------


def test_list_health_events(client, sumo_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/healthEvents"
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "eventCode": "Collector_Stopped",
                        "severity": "Error",
                        "resourceType": "Collector",
                    }
                ]
            },
        )

    _install_httpx_stub(monkeypatch, handler)
    resp = client.get("/api/v1/sumologic/api/v1/health-events")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["eventCode"] == "Collector_Stopped"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_create_search_job_validation_rejects_empty_query(client, sumo_env):
    resp = client.post(
        "/api/v1/sumologic/api/v1/search/jobs",
        json={
            "query": "",
            "from": "2026-05-01T00:00:00",
            "to": "2026-05-01T01:00:00",
        },
    )
    assert resp.status_code == 422


def test_create_search_job_validation_rejects_bad_auto_parsing_mode(client, sumo_env):
    resp = client.post(
        "/api/v1/sumologic/api/v1/search/jobs",
        json={
            "query": "_sourceCategory=prod",
            "from": "2026-05-01T00:00:00",
            "to": "2026-05-01T01:00:00",
            "autoParsingMode": "bogus",
        },
    )
    assert resp.status_code == 422
