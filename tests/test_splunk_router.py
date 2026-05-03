"""Tests for splunk_router (Splunk SIEM REST proxy).

Covers:
- GET /                                    capability summary (unavailable + ok)
- POST /services/search/jobs               create normal + oneshot
- GET /services/search/jobs/{sid}          metadata
- GET /services/search/jobs/{sid}/results  results page
- DELETE /services/search/jobs/{sid}       cancel
- GET /services/saved/searches             listing
- POST /services/saved/searches/{n}/dispatch
- 503 on lookup endpoints when env unset (NO MOCKS rule)

Usage:
    pytest tests/test_splunk_router.py -x --tb=short -q
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict

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
def splunk_env(monkeypatch):
    """Configure SPLUNK_URL + SPLUNK_TOKEN for the engine."""
    monkeypatch.setenv("SPLUNK_URL", "https://splunk.example.com:8089")
    monkeypatch.setenv("SPLUNK_TOKEN", "test-token-abc")
    # Reset singleton so it picks up the new env.
    from core.splunk_siem_engine import reset_splunk_siem_engine
    reset_splunk_siem_engine()
    yield
    reset_splunk_siem_engine()


@pytest.fixture()
def no_splunk_env(monkeypatch):
    """Ensure env is unset (NO MOCKS — must surface 503)."""
    monkeypatch.delenv("SPLUNK_URL", raising=False)
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    from core.splunk_siem_engine import reset_splunk_siem_engine
    reset_splunk_siem_engine()
    yield
    reset_splunk_siem_engine()


@pytest.fixture()
def app() -> FastAPI:
    from apps.api.splunk_router import router
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


def test_capability_summary_unavailable(client, no_splunk_env):
    resp = client.get("/api/v1/splunk/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Splunk"
    assert body["splunk_url_present"] is False
    assert body["splunk_token_present"] is False
    assert body["status"] == "unavailable"
    assert "/services/search/jobs" in body["endpoints"]
    assert "/services/saved/searches" in body["endpoints"]
    assert "/services/data/inputs" in body["endpoints"]
    assert "/services/server/info" in body["endpoints"]


def test_capability_summary_ok_when_configured(client, splunk_env):
    resp = client.get("/api/v1/splunk/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["splunk_url_present"] is True
    assert body["splunk_token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 NO MOCKS path
# ---------------------------------------------------------------------------


def test_create_search_job_503_when_unconfigured(client, no_splunk_env):
    resp = client.post(
        "/api/v1/splunk/services/search/jobs",
        json={"search": "index=main"},
    )
    assert resp.status_code == 503
    assert "splunk" in resp.json()["detail"].lower()


def test_get_results_503_when_unconfigured(client, no_splunk_env):
    resp = client.get("/api/v1/splunk/services/search/jobs/abc/results")
    assert resp.status_code == 503


def test_list_saved_searches_503_when_unconfigured(client, no_splunk_env):
    resp = client.get("/api/v1/splunk/services/saved/searches")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Search jobs (live-stubbed via httpx.MockTransport)
# ---------------------------------------------------------------------------


def test_create_search_job_normal(client, splunk_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/services/search/jobs"
        assert request.method == "POST"
        body = request.content.decode()
        assert "search" in body
        return httpx.Response(201, json={"sid": "job-123"})

    _install_httpx_stub(monkeypatch, handler)
    resp = client.post(
        "/api/v1/splunk/services/search/jobs",
        json={"search": "index=main error", "earliest_time": "-15m@m"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"sid": "job-123"}


def test_create_search_job_oneshot_returns_results(client, splunk_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"results": [{"_raw": "event1"}, {"_raw": "event2"}]},
        )

    _install_httpx_stub(monkeypatch, handler)
    resp = client.post(
        "/api/v1/splunk/services/search/jobs",
        json={"search": "index=main", "exec_mode": "oneshot"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["sid"] is None
    assert body["content"]["results"] == [{"_raw": "event1"}, {"_raw": "event2"}]


def test_get_search_job_metadata(client, splunk_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/services/search/jobs/job-xyz"
        return httpx.Response(
            200,
            json={
                "entry": [
                    {
                        "content": {
                            "isDone": True,
                            "dispatchState": "DONE",
                            "eventCount": 42,
                            "resultCount": 42,
                            "runDuration": 1.23,
                            "scanCount": 100,
                            "ttl": 600,
                        }
                    }
                ]
            },
        )

    _install_httpx_stub(monkeypatch, handler)
    resp = client.get("/api/v1/splunk/services/search/jobs/job-xyz")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["entry"][0]["content"]["isDone"] is True
    assert body["entry"][0]["content"]["eventCount"] == 42


def test_get_search_job_results(client, splunk_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        assert params["offset"] == "10"
        assert params["count"] == "5"
        return httpx.Response(
            200,
            json={
                "results": [{"_raw": "evt"}],
                "preview": False,
                "init_offset": 10,
                "post_process_count": 1,
                "messages": [],
            },
        )

    _install_httpx_stub(monkeypatch, handler)
    resp = client.get(
        "/api/v1/splunk/services/search/jobs/job-xyz/results",
        params={"offset": 10, "count": 5},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["preview"] is False
    assert body["init_offset"] == 10
    assert body["results"] == [{"_raw": "evt"}]


def test_delete_search_job(client, splunk_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        return httpx.Response(200, json={"messages": []})

    _install_httpx_stub(monkeypatch, handler)
    resp = client.delete("/api/v1/splunk/services/search/jobs/job-xyz")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"sid": "job-xyz", "cancelled": True}


# ---------------------------------------------------------------------------
# Saved searches
# ---------------------------------------------------------------------------


def test_list_saved_searches(client, splunk_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/services/saved/searches"
        return httpx.Response(
            200,
            json={
                "entry": [
                    {
                        "name": "errors-15m",
                        "content": {
                            "search": "index=main error",
                            "dispatch.earliest_time": "-15m",
                            "dispatch.latest_time": "now",
                            "is_scheduled": True,
                            "cron_schedule": "*/15 * * * *",
                        },
                    }
                ]
            },
        )

    _install_httpx_stub(monkeypatch, handler)
    resp = client.get("/api/v1/splunk/services/saved/searches?count=10")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["entry"][0]["name"] == "errors-15m"
    assert body["entry"][0]["content"]["is_scheduled"] is True


def test_dispatch_saved_search(client, splunk_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert "/services/saved/searches/" in request.url.path
        assert request.url.path.endswith("/dispatch")
        return httpx.Response(201, json={"sid": "dispatched-789"})

    _install_httpx_stub(monkeypatch, handler)
    resp = client.post(
        "/api/v1/splunk/services/saved/searches/errors-15m/dispatch",
        json={"trigger_actions": 1},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"sid": "dispatched-789"}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_create_search_job_validation_rejects_empty_search(client, splunk_env):
    resp = client.post("/api/v1/splunk/services/search/jobs", json={"search": ""})
    assert resp.status_code == 422


def test_create_search_job_validation_rejects_bad_exec_mode(client, splunk_env):
    resp = client.post(
        "/api/v1/splunk/services/search/jobs",
        json={"search": "index=main", "exec_mode": "bogus"},
    )
    assert resp.status_code == 422
