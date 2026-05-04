"""Tests for splunk_soar_router (Splunk SOAR / Phantom REST proxy).

Covers:
- GET /                                capability summary (unavailable + ok)
- GET /rest/playbook                   list playbooks
- GET /rest/container                  list containers
- GET /rest/container/{id}             container detail
- POST /rest/playbook_run              trigger playbook
- GET /rest/playbook_run/{run_id}      run status
- GET /rest/action_run                 list action runs
- GET /rest/asset                      list assets
- 503 on lookup endpoints when env unset (NO MOCKS)
- ph-auth-token header forwarded

Usage:
    pytest tests/test_splunk_soar_router.py -x --tb=short -q
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

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
def soar_env(monkeypatch):
    """Configure SPLUNK_SOAR_URL + SPLUNK_SOAR_TOKEN."""
    monkeypatch.setenv("SPLUNK_SOAR_URL", "https://soar.test.example.com")
    monkeypatch.setenv("SPLUNK_SOAR_TOKEN", "test-soar-token")
    from core.splunk_soar_engine import reset_splunk_soar_engine
    reset_splunk_soar_engine()
    yield
    reset_splunk_soar_engine()


@pytest.fixture()
def no_soar_env(monkeypatch):
    """Ensure env unset (NO MOCKS — must surface 503)."""
    for var in ("SPLUNK_SOAR_URL", "SPLUNK_SOAR_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    from core.splunk_soar_engine import reset_splunk_soar_engine
    reset_splunk_soar_engine()
    yield
    reset_splunk_soar_engine()


@pytest.fixture()
def app() -> FastAPI:
    from apps.api.splunk_soar_router import router
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
    """Replace httpx.Client constructor with a transport-mocked instance."""
    import httpx as _httpx

    real_client_init = _httpx.Client.__init__

    def _patched_init(self, *args, **kwargs):
        kwargs.pop("verify", None)
        kwargs["transport"] = _httpx.MockTransport(handler)
        real_client_init(self, *args, **kwargs)

    monkeypatch.setattr(_httpx.Client, "__init__", _patched_init)


def _make_handler(routes: Dict[str, Dict[str, Any]], call_log: List[Dict[str, Any]] | None = None):
    """Build a handler that returns canned JSON keyed by ``METHOD path``.

    Use a path PREFIX match so we can stub ``/rest/container/123`` with
    a single key like ``GET /rest/container/``.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method
        if call_log is not None:
            call_log.append(
                {
                    "method": method,
                    "path": path,
                    "headers": dict(request.headers),
                    "params": dict(request.url.params),
                }
            )
        # Exact match first
        key = f"{method} {path}"
        if key in routes:
            return httpx.Response(200, json=routes[key])
        # Prefix match (sorted longest-first to prefer more specific matches)
        for k in sorted(routes.keys(), key=len, reverse=True):
            kmethod, _, kpath = k.partition(" ")
            if kmethod == method and path.startswith(kpath):
                return httpx.Response(200, json=routes[k])
        return httpx.Response(404, json={"error": f"unrouted: {key}"})

    return handler


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(client, no_soar_env):
    resp = client.get("/api/v1/splunk-soar-rest/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Splunk SOAR (Phantom)"
    assert body["splunk_soar_url_present"] is False
    assert body["splunk_soar_token_present"] is False
    assert body["status"] == "unavailable"
    for ep in (
        "/rest/playbook",
        "/rest/container",
        "/rest/playbook_run",
        "/rest/action_run",
        "/rest/asset",
    ):
        assert ep in body["endpoints"]


def test_capability_summary_ok_when_configured(client, soar_env):
    resp = client.get("/api/v1/splunk-soar-rest/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["splunk_soar_url_present"] is True
    assert body["splunk_soar_token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 NO MOCKS path
# ---------------------------------------------------------------------------


def test_playbook_list_503_when_unconfigured(client, no_soar_env):
    resp = client.get("/api/v1/splunk-soar-rest/rest/playbook")
    assert resp.status_code == 503
    assert "splunk-soar" in resp.json()["detail"].lower()


def test_container_list_503_when_unconfigured(client, no_soar_env):
    resp = client.get("/api/v1/splunk-soar-rest/rest/container")
    assert resp.status_code == 503


def test_container_detail_503_when_unconfigured(client, no_soar_env):
    resp = client.get("/api/v1/splunk-soar-rest/rest/container/42")
    assert resp.status_code == 503


def test_action_run_503_when_unconfigured(client, no_soar_env):
    resp = client.get("/api/v1/splunk-soar-rest/rest/action_run")
    assert resp.status_code == 503


def test_asset_503_when_unconfigured(client, no_soar_env):
    resp = client.get("/api/v1/splunk-soar-rest/rest/asset")
    assert resp.status_code == 503


def test_playbook_run_trigger_503_when_unconfigured(client, no_soar_env):
    resp = client.post(
        "/api/v1/splunk-soar-rest/rest/playbook_run",
        json={"playbook_id": 1, "container_id": 2, "scope": "new", "run": True},
    )
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# List playbooks
# ---------------------------------------------------------------------------


def test_list_playbooks_returns_data(client, soar_env, monkeypatch):
    routes = {
        "GET /rest/playbook": {
            "data": [
                {
                    "id": 1,
                    "name": "Auto-Remediate Phish",
                    "description": "Quarantine inbox + reset password",
                    "scm": "git",
                    "version": 3,
                    "draft_mode": False,
                    "active": True,
                    "category": "investigate",
                    "labels": ["phish"],
                    "tags": [],
                    "cef_keys": ["sourceAddress"],
                    "action_types": ["investigate"],
                    "create_time": "2026-01-01T00:00:00Z",
                    "update_time": "2026-04-01T00:00:00Z",
                    "owner_id": 7,
                    "owner_name": "soc",
                }
            ],
            "count": 1,
            "num_pages": 1,
            "page": 0,
            "page_size": 100,
        }
    }
    call_log: List[Dict[str, Any]] = []
    _install_httpx_stub(monkeypatch, _make_handler(routes, call_log))

    resp = client.get(
        "/api/v1/splunk-soar-rest/rest/playbook",
        params={"_filter_active": "true", "page_size": 25, "page": 0, "include_expensive": "true"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] == 1
    assert body["data"][0]["name"] == "Auto-Remediate Phish"
    # Auth header forwarded
    assert call_log
    assert call_log[0]["headers"].get("ph-auth-token") == "test-soar-token"
    assert call_log[0]["params"].get("_filter_active") == "true"
    assert call_log[0]["params"].get("include_expensive") == "true"


# ---------------------------------------------------------------------------
# List containers
# ---------------------------------------------------------------------------


def test_list_containers_with_filters(client, soar_env, monkeypatch):
    routes = {
        "GET /rest/container": {
            "data": [
                {
                    "id": 100,
                    "name": "Phishing Email - exec",
                    "description": "Suspicious email reported",
                    "label": "events",
                    "status": "open",
                    "severity": "high",
                    "owner_id": 1,
                    "owner_name": "soc",
                    "sensitivity": "amber",
                    "create_time": "2026-05-01T00:00:00Z",
                    "start_time": "2026-05-01T00:00:00Z",
                    "end_time": None,
                    "due_time": "2026-05-02T00:00:00Z",
                    "close_time": None,
                    "asset_id": 5,
                    "container_type": "default",
                    "custom_fields": {"impact": "high"},
                    "hash": "abc",
                    "kill_chain": "delivery",
                    "source_data_identifier": "msg-1",
                    "tags": ["phish"],
                    "tenant_id": 0,
                    "ingest_app_id": 12,
                }
            ],
            "count": 1,
            "num_pages": 1,
            "page": 0,
            "page_size": 100,
        }
    }
    call_log: List[Dict[str, Any]] = []
    _install_httpx_stub(monkeypatch, _make_handler(routes, call_log))

    resp = client.get(
        "/api/v1/splunk-soar-rest/rest/container",
        params={"_filter_status": "open", "_filter_severity": "high", "page_size": 50},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["status"] == "open"
    assert call_log[0]["params"].get("_filter_status") == "open"
    assert call_log[0]["params"].get("_filter_severity") == "high"


def test_get_container_detail(client, soar_env, monkeypatch):
    routes = {
        "GET /rest/container/": {
            "id": 42,
            "name": "Container 42",
            "status": "open",
            "severity": "medium",
        }
    }
    _install_httpx_stub(monkeypatch, _make_handler(routes))

    resp = client.get("/api/v1/splunk-soar-rest/rest/container/42")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["id"] == 42
    assert body["status"] == "open"


# ---------------------------------------------------------------------------
# Trigger + status playbook_run
# ---------------------------------------------------------------------------


def test_trigger_playbook_run(client, soar_env, monkeypatch):
    routes = {
        "POST /rest/playbook_run": {
            "playbook_run_id": 9001,
        }
    }
    call_log: List[Dict[str, Any]] = []
    _install_httpx_stub(monkeypatch, _make_handler(routes, call_log))

    resp = client.post(
        "/api/v1/splunk-soar-rest/rest/playbook_run",
        json={"playbook_id": 1, "container_id": 100, "scope": "new", "run": True},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["playbook_run_id"] == 9001
    assert call_log[0]["method"] == "POST"
    assert call_log[0]["path"] == "/rest/playbook_run"


def test_get_playbook_run_status(client, soar_env, monkeypatch):
    routes = {
        "GET /rest/playbook_run/": {
            "id": 9001,
            "status": "success",
            "message": "playbook completed",
            "log_level": "info",
            "message_type": "system",
            "start_time": "2026-05-01T00:00:00Z",
            "update_time": "2026-05-01T00:00:30Z",
            "end_time": "2026-05-01T00:00:30Z",
            "run_data": {},
            "container": 100,
            "playbook": 1,
            "version": 3,
            "container_id": 100,
        }
    }
    _install_httpx_stub(monkeypatch, _make_handler(routes))

    resp = client.get("/api/v1/splunk-soar-rest/rest/playbook_run/9001")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "success"
    assert body["id"] == 9001


# ---------------------------------------------------------------------------
# Action runs
# ---------------------------------------------------------------------------


def test_list_action_runs_with_filters(client, soar_env, monkeypatch):
    routes = {
        "GET /rest/action_run": {
            "data": [
                {
                    "id": 555,
                    "action": "investigate",
                    "app": "splunk",
                    "asset": 5,
                    "status": "success",
                    "message": "ok",
                    "container": 100,
                    "playbook_run": 9001,
                    "app_run_count": 1,
                    "app_run_id_list": [777],
                    "create_time": "2026-05-01T00:00:00Z",
                    "update_time": "2026-05-01T00:00:30Z",
                    "end_time": "2026-05-01T00:00:30Z",
                    "message_type": "system",
                    "log_level": "info",
                    "action_run_data": {},
                    "parameters_summary": "search",
                    "asset_id": 5,
                    "container_id": 100,
                    "app_id": 9,
                }
            ],
            "count": 1,
            "num_pages": 1,
            "page": 0,
            "page_size": 100,
        }
    }
    call_log: List[Dict[str, Any]] = []
    _install_httpx_stub(monkeypatch, _make_handler(routes, call_log))

    resp = client.get(
        "/api/v1/splunk-soar-rest/rest/action_run",
        params={"_filter_status": "success", "_filter_container_id": 100},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["status"] == "success"
    assert call_log[0]["params"].get("_filter_status") == "success"
    assert call_log[0]["params"].get("_filter_container_id") == "100"


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


def test_list_assets(client, soar_env, monkeypatch):
    routes = {
        "GET /rest/asset": {
            "data": [
                {
                    "id": 5,
                    "name": "splunk-prod",
                    "description": "Splunk Enterprise",
                    "asset_type": "siem",
                    "action_whitelist": ["*"],
                    "active": True,
                    "configuration": {},
                    "primary_voting": 0,
                    "secondary_voting": 0,
                    "tags": [],
                    "tenant_id": 0,
                    "primary_users": [],
                    "secondary_users": [],
                    "product_name": "Splunk",
                    "product_vendor": "Splunk Inc.",
                    "product_version": "9.0",
                    "ingest_app": False,
                    "automation_broker_id": None,
                }
            ],
            "count": 1,
            "num_pages": 1,
            "page": 0,
            "page_size": 100,
        }
    }
    call_log: List[Dict[str, Any]] = []
    _install_httpx_stub(monkeypatch, _make_handler(routes, call_log))

    resp = client.get(
        "/api/v1/splunk-soar-rest/rest/asset",
        params={"_filter_active": "true", "page_size": 50},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["product_name"] == "Splunk"
    assert call_log[0]["params"].get("_filter_active") == "true"


# ---------------------------------------------------------------------------
# Engine smoke / singleton
# ---------------------------------------------------------------------------


def test_engine_singleton_is_stable(soar_env):
    from core.splunk_soar_engine import (
        get_splunk_soar_engine,
        reset_splunk_soar_engine,
    )
    a = get_splunk_soar_engine()
    b = get_splunk_soar_engine()
    assert a is b
    reset_splunk_soar_engine()
    c = get_splunk_soar_engine()
    assert c is not a


def test_engine_capability_summary_reads_env(soar_env):
    from core.splunk_soar_engine import get_splunk_soar_engine
    eng = get_splunk_soar_engine()
    summary = eng.capability_summary()
    assert summary["service"] == "Splunk SOAR (Phantom)"
    assert summary["status"] == "ok"
    assert summary["splunk_soar_url_present"] is True
    assert summary["splunk_soar_token_present"] is True
