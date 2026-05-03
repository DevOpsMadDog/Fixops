"""Tests for orca_router (Orca Security REST proxy).

Covers:
- GET /                              capability summary (unavailable + ok)
- GET /api/alerts                    list alerts w/ filters + pagination
- GET /api/asset                     list assets w/ type filter
- GET /api/asset/{id}                single asset
- GET /api/policies                  list policies
- POST /api/sonar/query              Sonar DSL passthrough
- GET /api/clouds                    list cloud accounts
- GET /api/users                     list users
- 503 on lookup endpoints when env unset (NO MOCKS rule)
- Authorization: Token header sent

Usage:
    pytest tests/test_orca_router.py -x --tb=short -q
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

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
def orca_env(monkeypatch):
    """Configure ORCA_API_TOKEN."""
    monkeypatch.setenv("ORCA_API_TOKEN", "test-orca-token")
    monkeypatch.delenv("ORCA_API_URL", raising=False)
    from core.orca_engine import reset_orca_engine
    reset_orca_engine()
    yield
    reset_orca_engine()


@pytest.fixture()
def no_orca_env(monkeypatch):
    """Ensure env unset (NO MOCKS — must surface 503)."""
    for var in ("ORCA_API_TOKEN", "ORCA_API_URL"):
        monkeypatch.delenv(var, raising=False)
    from core.orca_engine import reset_orca_engine
    reset_orca_engine()
    yield
    reset_orca_engine()


@pytest.fixture()
def app() -> FastAPI:
    from apps.api.orca_router import router
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


def _make_orca_handler(
    routes: Dict[Tuple[str, str], Dict[str, Any]],
    call_log: List[Tuple[str, str, Dict[str, str]]] = None,
):
    """Build a handler that serves canned responses keyed by (method, path)."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method.upper()
        if call_log is not None:
            call_log.append((method, path, dict(request.headers)))
        # Try exact match first
        if (method, path) in routes:
            return httpx.Response(200, json=routes[(method, path)])
        # Try prefix matches for path-style endpoints (asset/{id})
        for (m, p), body in routes.items():
            if m == method and path.startswith(p) and p.endswith("/"):
                return httpx.Response(200, json=body)
        return httpx.Response(404, json={"detail": f"unmatched {method} {path}"})

    return handler


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(client, no_orca_env):
    resp = client.get("/api/v1/orca/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Orca Security"
    assert body["orca_api_token_present"] is False
    assert body["status"] == "unavailable"
    for ep in ("/api/alerts", "/api/asset", "/api/policies",
               "/api/sonar/query", "/api/clouds"):
        assert ep in body["endpoints"]


def test_capability_summary_ok_when_configured(client, orca_env):
    resp = client.get("/api/v1/orca/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["orca_api_token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 NO MOCKS path
# ---------------------------------------------------------------------------


def test_alerts_503_when_unconfigured(client, no_orca_env):
    resp = client.get("/api/v1/orca/api/alerts")
    assert resp.status_code == 503
    assert "orca" in resp.json()["detail"].lower()


def test_assets_503_when_unconfigured(client, no_orca_env):
    resp = client.get("/api/v1/orca/api/asset")
    assert resp.status_code == 503


def test_asset_single_503_when_unconfigured(client, no_orca_env):
    resp = client.get("/api/v1/orca/api/asset/some-asset-id")
    assert resp.status_code == 503


def test_policies_503_when_unconfigured(client, no_orca_env):
    resp = client.get("/api/v1/orca/api/policies")
    assert resp.status_code == 503


def test_sonar_query_503_when_unconfigured(client, no_orca_env):
    resp = client.post(
        "/api/v1/orca/api/sonar/query",
        json={"query": "Asset.Type:Instance"},
    )
    assert resp.status_code == 503


def test_clouds_503_when_unconfigured(client, no_orca_env):
    resp = client.get("/api/v1/orca/api/clouds")
    assert resp.status_code == 503


def test_users_503_when_unconfigured(client, no_orca_env):
    resp = client.get("/api/v1/orca/api/users")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def test_alerts_returns_data_and_pagination(client, orca_env, monkeypatch):
    routes = {
        ("GET", "/api/alerts"): {
            "data": [
                {
                    "state": {
                        "alert_id": "alert-1",
                        "asset_unique_id": "aws_ec2_inst-abc",
                        "asset_name": "prod-webserver",
                        "asset_type": "instance",
                        "cloud_provider": "AWS",
                        "cloud_account_id": "111122223333",
                    },
                    "configuration": {
                        "description": "Public RDS exposed to 0.0.0.0/0",
                        "scan_type": "CSPM",
                        "severity_score": 9.1,
                    },
                    "score": 9.1,
                    "severity": "critical",
                    "priority": "critical",
                    "status": "open",
                    "in_verification_status": "UNVERIFIED",
                }
            ],
            "next_page_token": "token-page-2",
            "total_items": 42,
        }
    }
    call_log: List[Tuple[str, str, Dict[str, str]]] = []
    _install_httpx_stub(monkeypatch, _make_orca_handler(routes, call_log))

    resp = client.get(
        "/api/v1/orca/api/alerts",
        params={"status": "open", "priority": "critical", "limit": 50},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["data"]) == 1
    assert body["data"][0]["state"]["alert_id"] == "alert-1"
    assert body["next_page_token"] == "token-page-2"
    assert body["total_items"] == 42
    # Authorization: Token header sent
    assert any(
        h.get("authorization") == "Token test-orca-token"
        for _, _, h in call_log
    )


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


def test_assets_list_returns_data(client, orca_env, monkeypatch):
    routes = {
        ("GET", "/api/asset"): {
            "data": [
                {
                    "type": "bucket",
                    "asset_unique_id": "aws_s3_bucket-xyz",
                    "name": "prod-data",
                    "cloud_provider": "AWS",
                    "cloud_account_id": "111122223333",
                    "region": "us-east-1",
                    "tags": {"env": "prod"},
                }
            ],
            "next_page_token": None,
            "total_items": 1,
        }
    }
    _install_httpx_stub(monkeypatch, _make_orca_handler(routes))

    resp = client.get("/api/v1/orca/api/asset", params={"type": "bucket", "limit": 25})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["asset_unique_id"] == "aws_s3_bucket-xyz"
    assert body["total_items"] == 1


def test_asset_single_returns_object(client, orca_env, monkeypatch):
    routes = {
        ("GET", "/api/asset/aws_ec2_inst-abc"): {
            "type": "instance",
            "asset_unique_id": "aws_ec2_inst-abc",
            "name": "prod-webserver",
            "cloud_provider": "AWS",
        }
    }
    _install_httpx_stub(monkeypatch, _make_orca_handler(routes))

    resp = client.get("/api/v1/orca/api/asset/aws_ec2_inst-abc")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["asset_unique_id"] == "aws_ec2_inst-abc"


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


def test_policies_list(client, orca_env, monkeypatch):
    routes = {
        ("GET", "/api/policies"): {
            "data": [
                {
                    "id": "pol-1",
                    "name": "CIS AWS 1.5 — Public RDS",
                    "type": "built_in",
                    "enabled": True,
                    "version": 3,
                }
            ]
        }
    }
    _install_httpx_stub(monkeypatch, _make_orca_handler(routes))

    resp = client.get("/api/v1/orca/api/policies")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["id"] == "pol-1"
    assert body["data"][0]["type"] == "built_in"


# ---------------------------------------------------------------------------
# Sonar
# ---------------------------------------------------------------------------


def test_sonar_query_passthrough(client, orca_env, monkeypatch):
    routes = {
        ("POST", "/api/sonar/query"): {
            "data": [
                {
                    "asset_unique_id": "aws_ec2_inst-abc",
                    "vulnerability": {
                        "cve_id": "CVE-2024-12345",
                        "exploitable": {"kev": True},
                    },
                }
            ],
            "next_page_token": None,
            "total_items": 1,
            "query_meta": {"interpreted_query": "Asset.Type:Instance"},
        }
    }
    _install_httpx_stub(monkeypatch, _make_orca_handler(routes))

    resp = client.post(
        "/api/v1/orca/api/sonar/query",
        json={
            "query": "Asset.Type:Instance with vulnerability.exploitable.kev=true",
            "limit": 100,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["data"]) == 1
    assert body["data"][0]["vulnerability"]["exploitable"]["kev"] is True
    assert body["query_meta"]["interpreted_query"] == "Asset.Type:Instance"


def test_sonar_query_rejects_empty(client, orca_env):
    resp = client.post("/api/v1/orca/api/sonar/query", json={"query": ""})
    # Pydantic returns 422 for failed min_length validation
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Clouds
# ---------------------------------------------------------------------------


def test_clouds_list(client, orca_env, monkeypatch):
    routes = {
        ("GET", "/api/clouds"): {
            "data": [
                {
                    "cloud_account_id": "111122223333",
                    "name": "aldeci-prod",
                    "provider": "AWS",
                    "status": "enabled",
                    "region": "us-east-1",
                    "environment": "production",
                    "deployment_type": "account",
                }
            ]
        }
    }
    _install_httpx_stub(monkeypatch, _make_orca_handler(routes))

    resp = client.get("/api/v1/orca/api/clouds")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"][0]["provider"] == "AWS"
    assert body["data"][0]["status"] == "enabled"


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


def test_users_list(client, orca_env, monkeypatch):
    routes = {
        ("GET", "/api/users"): {
            "data": [
                {"id": "u-1", "email": "alice@aldeci.io", "role": "admin"},
                {"id": "u-2", "email": "bob@aldeci.io", "role": "viewer"},
            ]
        }
    }
    _install_httpx_stub(monkeypatch, _make_orca_handler(routes))

    resp = client.get("/api/v1/orca/api/users")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["data"]) == 2
    assert body["data"][0]["email"] == "alice@aldeci.io"


# ---------------------------------------------------------------------------
# Upstream error mapping
# ---------------------------------------------------------------------------


def test_upstream_500_mapped_to_502_or_status(client, orca_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "internal"})

    _install_httpx_stub(monkeypatch, handler)

    resp = client.get("/api/v1/orca/api/clouds")
    # httpx.HTTPStatusError → 500 surfaced
    assert resp.status_code == 500
