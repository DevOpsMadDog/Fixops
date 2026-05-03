"""Tests for the Terraform Cloud router (NO MOCKS, real httpx path).

Each test uses a stub ``httpx.Client`` so the engine's REAL request
construction + Bearer auth header + JSON-API parsing is exercised - only the
network is intercepted.

Coverage:
  1. Capability summary returns ``status="unavailable"`` when env unset.
  2. Capability summary returns ``status="ok"`` + token/org echo when env set.
  3. GET /workspaces returns 503 when env unset.
  4. GET /workspaces returns parsed JSON-API data via stub when configured + checks Bearer header + Content-Type.
  5. GET /workspaces/{ws_id}/runs returns 503 when env unset; returns runs page when configured.
  6. POST /runs creates a run and returns the data envelope when configured.
  7. POST /runs/{id}/actions/apply, /cancel, /discard return 503 unset; return 202 when configured.
  8. GET /workspaces/{id}/current-state-version returns 503 unset; returns parsed envelope when configured.
  9. GET /policies returns 503 unset; returns list when configured + propagates filter[organization][name].
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
        if text:
            self.text = text
        elif payload is None:
            self.text = ""
        else:
            self.text = json.dumps(payload)

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no JSON body")
        return self._payload


class _StubClient:
    """Minimal httpx.Client stand-in: matches by URL substring."""

    def __init__(self, responses: Dict[str, _StubResponse]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> _StubResponse:
        # Prefer the longest matching substring so /apply doesn't shadow /runs
        candidates = [
            (path, resp) for path, resp in self._responses.items() if path in url
        ]
        if candidates:
            candidates.sort(key=lambda kv: len(kv[0]), reverse=True)
            return candidates[0][1]
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

    def delete(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {
                "method": "DELETE",
                "url": url,
                "headers": headers or {},
                "params": params or {},
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


def _build_app(
    *,
    token: Optional[str],
    org: Optional[str] = None,
    base_url: Optional[str] = None,
    stub_responses: Optional[Dict[str, _StubResponse]] = None,
):
    """Build a minimal FastAPI app mounting the Terraform Cloud router."""
    from core import terraform_cloud_engine as eng_mod

    eng_mod.reset_terraform_cloud_engine()
    stub = _StubClient(stub_responses or {})
    eng_mod.get_terraform_cloud_engine(
        token=token,
        org=org,
        base_url=base_url,
        client=stub,
        force_refresh=True,
    )

    from apps.api.terraform_cloud_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


def _reset() -> None:
    from core import terraform_cloud_engine as eng_mod
    eng_mod.reset_terraform_cloud_engine()


# ============================================================ capability


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("TFC_TOKEN", raising=False)
    monkeypatch.delenv("TFC_ORG", raising=False)
    app, _ = _build_app(token="", org="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/terraform-cloud/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Terraform Cloud"
    for ep in [
        "/api/v2/organizations/{org}/workspaces",
        "/api/v2/workspaces/{id}/runs",
        "/api/v2/runs",
        "/api/v2/workspaces/{id}/current-state-version",
        "/api/v2/policies",
        "/api/v2/policy-checks",
    ]:
        assert ep in body["endpoints"], f"missing endpoint {ep}"
    assert body["tfc_token_present"] is False
    assert body["tfc_org_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_creds_present(monkeypatch):
    monkeypatch.setenv("TFC_TOKEN", "atlasv1.token")
    monkeypatch.setenv("TFC_ORG", "my-org")
    app, _ = _build_app(token="atlasv1.token", org="my-org")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/terraform-cloud/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tfc_token_present"] is True
    assert body["tfc_org_present"] is True
    assert body["status"] == "ok"
    _reset()


# ============================================================ workspaces


def test_workspaces_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("TFC_TOKEN", raising=False)
    app, _ = _build_app(token="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/terraform-cloud/api/v2/organizations/my-org/workspaces",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "TFC_TOKEN" in r.json()["detail"]
    _reset()


def test_workspaces_returns_jsonapi_via_stub(monkeypatch):
    monkeypatch.setenv("TFC_TOKEN", "atlasv1.token")
    payload = {
        "data": [
            {
                "id": "ws-abc123",
                "type": "workspaces",
                "attributes": {
                    "name": "production",
                    "description": "Prod infra",
                    "terraform-version": "1.6.0",
                    "working-directory": "infra/prod",
                    "vcs-repo": {
                        "identifier": "my-org/infra",
                        "branch": "main",
                    },
                    "environment": "production",
                    "latest-change-at": "2026-05-01T12:00:00Z",
                    "locked": False,
                    "created-at": "2025-01-01T00:00:00Z",
                    "updated-at": "2026-05-01T12:00:00Z",
                },
                "relationships": {},
                "links": {"self": "/api/v2/workspaces/ws-abc123"},
            }
        ],
        "meta": {"pagination": {"current-page": 1, "total-count": 1}},
    }
    stub = {"/api/v2/organizations/my-org/workspaces": _StubResponse(200, payload)}
    app, captured = _build_app(token="atlasv1.token", stub_responses=stub)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/terraform-cloud/api/v2/organizations/my-org/workspaces"
        "?page[number]=1&page[size]=20&search[name]=prod",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"][0]["id"] == "ws-abc123"
    assert body["data"][0]["attributes"]["name"] == "production"

    # Check Bearer header + Content-Type were sent
    call = captured.calls[-1]
    assert call["headers"]["Authorization"] == "Bearer atlasv1.token"
    assert call["headers"]["Content-Type"] == "application/vnd.api+json"
    # Check JSON-API style query params reached the engine
    assert call["params"].get("page[number]") == 1
    assert call["params"].get("page[size]") == 20
    assert call["params"].get("search[name]") == "prod"
    _reset()


# ============================================================ runs


def test_workspace_runs_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("TFC_TOKEN", raising=False)
    app, _ = _build_app(token="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/terraform-cloud/api/v2/workspaces/ws-1/runs",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_workspace_runs_returns_data_when_configured(monkeypatch):
    monkeypatch.setenv("TFC_TOKEN", "atlasv1.token")
    payload = {
        "data": [
            {
                "id": "run-xyz",
                "type": "runs",
                "attributes": {
                    "status": "applied",
                    "message": "Triggered via UI",
                    "source": "tfe-api",
                    "status-timestamps": {"applied-at": "2026-05-01T12:30:00Z"},
                    "plan-only": False,
                    "refresh": True,
                    "refresh-only": False,
                    "replace-addrs": [],
                },
            }
        ],
        "meta": {"pagination": {"current-page": 1}},
    }
    stub = {"/api/v2/workspaces/ws-1/runs": _StubResponse(200, payload)}
    app, _ = _build_app(token="atlasv1.token", stub_responses=stub)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/terraform-cloud/api/v2/workspaces/ws-1/runs?page[size]=10",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"][0]["id"] == "run-xyz"
    assert body["data"][0]["attributes"]["status"] == "applied"
    _reset()


def test_create_run_returns_envelope_via_stub(monkeypatch):
    monkeypatch.setenv("TFC_TOKEN", "atlasv1.token")
    payload = {
        "data": {
            "id": "run-new",
            "type": "runs",
            "attributes": {"status": "pending", "message": "from-test"},
        }
    }
    stub = {"/api/v2/runs": _StubResponse(201, payload)}
    app, captured = _build_app(token="atlasv1.token", stub_responses=stub)
    client = TestClient(app, raise_server_exceptions=True)

    body = {
        "data": {
            "type": "runs",
            "attributes": {
                "message": "from-test",
                "is-destroy": False,
                "refresh-only": False,
                "plan-only": False,
                "target-addrs": [],
            },
            "relationships": {
                "workspace": {"data": {"type": "workspaces", "id": "ws-1"}}
            },
        }
    }
    r = client.post(
        "/api/v1/terraform-cloud/api/v2/runs",
        headers=HEADERS,
        json=body,
    )
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["data"]["id"] == "run-new"
    # Verify the JSON-API body forwarded to the upstream client
    last = captured.calls[-1]
    assert last["json"]["data"]["type"] == "runs"
    assert (
        last["json"]["data"]["relationships"]["workspace"]["data"]["id"] == "ws-1"
    )
    _reset()


# ============================================================ run actions


def test_run_actions_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("TFC_TOKEN", raising=False)
    app, _ = _build_app(token="")
    client = TestClient(app, raise_server_exceptions=True)

    for action in ("apply", "cancel", "discard"):
        r = client.post(
            f"/api/v1/terraform-cloud/api/v2/runs/run-1/actions/{action}",
            headers=HEADERS,
            json={"comment": "stop"},
        )
        assert r.status_code == 503, f"{action}: {r.text}"
    _reset()


def test_run_actions_return_202_when_configured(monkeypatch):
    monkeypatch.setenv("TFC_TOKEN", "atlasv1.token")
    stub = {
        "/api/v2/runs/run-1/actions/apply": _StubResponse(202, None, text=""),
        "/api/v2/runs/run-1/actions/cancel": _StubResponse(202, None, text=""),
        "/api/v2/runs/run-1/actions/discard": _StubResponse(202, None, text=""),
    }
    app, _ = _build_app(token="atlasv1.token", stub_responses=stub)
    client = TestClient(app, raise_server_exceptions=True)

    for action in ("apply", "cancel", "discard"):
        r = client.post(
            f"/api/v1/terraform-cloud/api/v2/runs/run-1/actions/{action}",
            headers=HEADERS,
            json={"comment": "ok"},
        )
        assert r.status_code == 200, f"{action}: {r.text}"
        out = r.json()
        assert out["status"] == "accepted"
        assert out["code"] == 202
    _reset()


# ============================================================ state version


def test_current_state_version_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("TFC_TOKEN", raising=False)
    app, _ = _build_app(token="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/terraform-cloud/api/v2/workspaces/ws-1/current-state-version",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_current_state_version_returns_envelope(monkeypatch):
    monkeypatch.setenv("TFC_TOKEN", "atlasv1.token")
    payload = {
        "data": {
            "id": "sv-1",
            "type": "state-versions",
            "attributes": {
                "serial": 4,
                "vcs-commit-sha": "abc123",
                "hosted-state-download-url": "https://archivist/state",
                "resources": [],
            },
        }
    }
    stub = {
        "/api/v2/workspaces/ws-1/current-state-version": _StubResponse(200, payload)
    }
    app, _ = _build_app(token="atlasv1.token", stub_responses=stub)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/terraform-cloud/api/v2/workspaces/ws-1/current-state-version",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["id"] == "sv-1"
    assert body["data"]["attributes"]["serial"] == 4
    _reset()


# ============================================================ policies


def test_policies_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("TFC_TOKEN", raising=False)
    app, _ = _build_app(token="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/terraform-cloud/api/v2/policies",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_policies_returns_list_with_filter(monkeypatch):
    monkeypatch.setenv("TFC_TOKEN", "atlasv1.token")
    payload = {
        "data": [
            {
                "id": "pol-1",
                "type": "policies",
                "attributes": {"name": "require-tag", "kind": "sentinel"},
            },
            {
                "id": "pol-2",
                "type": "policies",
                "attributes": {"name": "deny-public-s3", "kind": "opa"},
            },
        ],
    }
    stub = {"/api/v2/policies": _StubResponse(200, payload)}
    app, captured = _build_app(token="atlasv1.token", stub_responses=stub)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/terraform-cloud/api/v2/policies"
        "?filter[organization][name]=my-org",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["data"]) == 2
    last = captured.calls[-1]
    assert last["params"].get("filter[organization][name]") == "my-org"
    _reset()
