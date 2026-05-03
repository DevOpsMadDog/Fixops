"""Tests for the ArgoCD GitOps router (NO MOCKS).

The engine talks to a real ArgoCD instance via httpx. We:
  - Verify capability summary reflects URL/token presence (status: ok|unavailable).
  - Verify endpoints return HTTP 503 when ARGOCD_URL/ARGOCD_TOKEN are unset.
  - Inject a stub httpx.Client into the singleton for happy-path tests so we
    still exercise the real parsing/normalisation code paths.

NO HARDCODED MOCK PAYLOADS in production code paths — the only stubs are
in this test file's local httpx adapter.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------- httpx stub


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Routes by URL substring. Records every call."""

    def __init__(self, responses: Dict[str, _StubResponse]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> _StubResponse:
        # Longest match wins so /sync isn't shadowed by /applications.
        best = None
        best_len = -1
        for path, resp in self._responses.items():
            if path in url and len(path) > best_len:
                best = resp
                best_len = len(path)
        if best is not None:
            return best
        return _StubResponse(404, {"error": "not_found"}, text="not found")

    def get(self, url, headers=None, params=None):
        self.calls.append(
            {"method": "GET", "url": url, "headers": dict(headers or {}), "params": params}
        )
        return self._match(url)

    def post(self, url, headers=None, json=None):
        self.calls.append(
            {"method": "POST", "url": url, "headers": dict(headers or {}), "json": json}
        )
        return self._match(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------- helpers


def _build_app(
    *,
    url: Optional[str],
    token: Optional[str],
    stub_responses: Optional[Dict[str, _StubResponse]] = None,
):
    from core import argocd_engine as eng_mod

    eng_mod.reset_argocd_engine()

    stub_client = _StubClient(stub_responses or {})
    eng_mod.get_argocd_engine(url=url, token=token, client=stub_client)

    from apps.api.argocd_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset() -> None:
    from core import argocd_engine as eng_mod

    eng_mod.reset_argocd_engine()


# ============================================================ capability


def test_capability_summary_unavailable_when_no_env(monkeypatch):
    monkeypatch.delenv("ARGOCD_URL", raising=False)
    monkeypatch.delenv("ARGOCD_TOKEN", raising=False)
    app, _ = _build_app(url=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/argocd/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "ArgoCD"
    assert "/api/v1/applications" in body["endpoints"]
    assert "/api/v1/projects" in body["endpoints"]
    assert "/api/v1/clusters" in body["endpoints"]
    assert "/api/v1/repositories" in body["endpoints"]
    assert body["argocd_url_present"] is False
    assert body["argocd_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_env_present(monkeypatch):
    monkeypatch.setenv("ARGOCD_URL", "https://argocd.example.com")
    monkeypatch.setenv("ARGOCD_TOKEN", "eyJhbGciOi.test")
    app, _ = _build_app(
        url="https://argocd.example.com", token="eyJhbGciOi.test"
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/argocd/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["argocd_url_present"] is True
    assert body["argocd_token_present"] is True
    assert body["status"] == "ok"
    _reset()


def test_capability_summary_unavailable_when_only_url(monkeypatch):
    monkeypatch.setenv("ARGOCD_URL", "https://argocd.example.com")
    monkeypatch.delenv("ARGOCD_TOKEN", raising=False)
    app, _ = _build_app(url="https://argocd.example.com", token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/argocd/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["argocd_url_present"] is True
    assert body["argocd_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


# ============================================================ 503 paths


def test_list_applications_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGOCD_URL", raising=False)
    monkeypatch.delenv("ARGOCD_TOKEN", raising=False)
    app, _ = _build_app(url=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/argocd/api/v1/applications", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "ARGOCD_URL" in detail or "ARGOCD_TOKEN" in detail
    _reset()


def test_get_application_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGOCD_URL", raising=False)
    monkeypatch.delenv("ARGOCD_TOKEN", raising=False)
    app, _ = _build_app(url=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/argocd/api/v1/applications/guestbook", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_sync_application_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGOCD_URL", raising=False)
    monkeypatch.delenv("ARGOCD_TOKEN", raising=False)
    app, _ = _build_app(url=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/argocd/api/v1/applications/guestbook/sync",
        headers=HEADERS,
        json={"revision": "HEAD", "prune": True},
    )
    assert r.status_code == 503, r.text
    _reset()


def test_list_projects_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGOCD_URL", raising=False)
    monkeypatch.delenv("ARGOCD_TOKEN", raising=False)
    app, _ = _build_app(url=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/argocd/api/v1/projects", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_list_clusters_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGOCD_URL", raising=False)
    monkeypatch.delenv("ARGOCD_TOKEN", raising=False)
    app, _ = _build_app(url=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/argocd/api/v1/clusters", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_list_repositories_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGOCD_URL", raising=False)
    monkeypatch.delenv("ARGOCD_TOKEN", raising=False)
    app, _ = _build_app(url=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/argocd/api/v1/repositories", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


# ============================================================ happy paths


def test_list_applications_happy_path(monkeypatch):
    monkeypatch.setenv("ARGOCD_URL", "https://argocd.example.com")
    monkeypatch.setenv("ARGOCD_TOKEN", "eyJhbGciOi.test")
    raw = {
        "items": [
            {
                "metadata": {
                    "name": "guestbook",
                    "namespace": "argocd",
                    "labels": {"env": "prod"},
                },
                "spec": {
                    "project": "default",
                    "source": {
                        "repoURL": "https://github.com/argoproj/argocd-example-apps",
                        "path": "guestbook",
                        "targetRevision": "HEAD",
                    },
                    "destination": {
                        "server": "https://kubernetes.default.svc",
                        "namespace": "guestbook",
                    },
                    "syncPolicy": {
                        "automated": {"prune": True, "selfHeal": True},
                    },
                },
                "status": {
                    "sync": {"status": "Synced", "revision": "abc123"},
                    "health": {"status": "Healthy"},
                    "history": [],
                    "operationState": {"phase": "Succeeded"},
                },
            }
        ]
    }
    app, stub = _build_app(
        url="https://argocd.example.com",
        token="eyJhbGciOi.test",
        stub_responses={"/api/v1/applications": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/argocd/api/v1/applications",
        headers=HEADERS,
        params=[("projects", "default"), ("selector", "env=prod")],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["metadata"]["name"] == "guestbook"
    assert item["spec"]["source"]["repoURL"].startswith("https://github.com/")
    assert item["status"]["sync"]["status"] == "Synced"
    assert item["status"]["health"]["status"] == "Healthy"

    # Verify Authorization: Bearer header was set with the token
    auth = stub.calls[0]["headers"].get("Authorization", "")
    assert auth == "Bearer eyJhbGciOi.test"

    # Verify the projects/selector params propagated
    sent_params = stub.calls[0]["params"]
    flat = (
        [(k, v) for k, v in sent_params]
        if isinstance(sent_params, list)
        else list(sent_params.items())
    )
    assert ("projects", "default") in flat
    assert ("selector", "env=prod") in flat
    _reset()


def test_get_application_happy_path(monkeypatch):
    monkeypatch.setenv("ARGOCD_URL", "https://argocd.example.com")
    monkeypatch.setenv("ARGOCD_TOKEN", "eyJhbGciOi.test")
    raw = {
        "metadata": {
            "name": "guestbook",
            "namespace": "argocd",
            "labels": {"env": "prod"},
        },
        "spec": {
            "project": "default",
            "source": {
                "repoURL": "https://github.com/argoproj/argocd-example-apps",
                "path": "guestbook",
                "targetRevision": "HEAD",
            },
            "destination": {
                "server": "https://kubernetes.default.svc",
                "namespace": "guestbook",
            },
        },
        "status": {
            "sync": {"status": "OutOfSync", "revision": "def456"},
            "health": {"status": "Progressing"},
            "history": [],
            "operationState": {"phase": "Running"},
        },
    }
    app, stub = _build_app(
        url="https://argocd.example.com",
        token="eyJhbGciOi.test",
        stub_responses={"/api/v1/applications/guestbook": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/argocd/api/v1/applications/guestbook",
        headers=HEADERS,
        params={"refresh": "normal"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["metadata"]["name"] == "guestbook"
    assert body["status"]["sync"]["status"] == "OutOfSync"
    assert body["status"]["health"]["status"] == "Progressing"

    sent_params = stub.calls[0]["params"]
    flat = (
        [(k, v) for k, v in sent_params]
        if isinstance(sent_params, list)
        else list(sent_params.items())
    )
    assert ("refresh", "normal") in flat
    _reset()


def test_sync_application_happy_path(monkeypatch):
    monkeypatch.setenv("ARGOCD_URL", "https://argocd.example.com")
    monkeypatch.setenv("ARGOCD_TOKEN", "eyJhbGciOi.test")
    raw = {
        "metadata": {"name": "guestbook"},
        "status": {
            "sync": {"status": "Synced", "revision": "abc123"},
            "health": {"status": "Healthy"},
            "operationState": {"phase": "Succeeded"},
        },
    }
    app, stub = _build_app(
        url="https://argocd.example.com",
        token="eyJhbGciOi.test",
        stub_responses={
            "/api/v1/applications/guestbook/sync": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/argocd/api/v1/applications/guestbook/sync",
        headers=HEADERS,
        json={
            "revision": "HEAD",
            "prune": True,
            "dryRun": False,
            "syncOptions": ["CreateNamespace=true"],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"]["sync"]["status"] == "Synced"

    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert posts, "expected at least one POST to /sync"
    sent = posts[0]["json"]
    assert sent["revision"] == "HEAD"
    assert sent["prune"] is True
    assert sent["syncOptions"] == ["CreateNamespace=true"]
    _reset()


def test_list_projects_happy_path(monkeypatch):
    monkeypatch.setenv("ARGOCD_URL", "https://argocd.example.com")
    monkeypatch.setenv("ARGOCD_TOKEN", "eyJhbGciOi.test")
    raw = {
        "items": [
            {
                "metadata": {"name": "default"},
                "spec": {
                    "description": "Default project",
                    "sourceRepos": ["*"],
                    "destinations": [
                        {"server": "https://kubernetes.default.svc", "namespace": "*"}
                    ],
                    "clusterResourceWhitelist": [{"group": "*", "kind": "*"}],
                },
            }
        ]
    }
    app, _ = _build_app(
        url="https://argocd.example.com",
        token="eyJhbGciOi.test",
        stub_responses={"/api/v1/projects": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/argocd/api/v1/projects", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["items"][0]["metadata"]["name"] == "default"
    assert body["items"][0]["spec"]["sourceRepos"] == ["*"]
    _reset()


def test_list_clusters_happy_path(monkeypatch):
    monkeypatch.setenv("ARGOCD_URL", "https://argocd.example.com")
    monkeypatch.setenv("ARGOCD_TOKEN", "eyJhbGciOi.test")
    raw = {
        "items": [
            {
                "server": "https://kubernetes.default.svc",
                "name": "in-cluster",
                "config": {},
                "info": {
                    "version": "v1.28.0",
                    "connectionState": {
                        "status": "Successful",
                        "message": "Connected",
                    },
                },
            }
        ]
    }
    app, _ = _build_app(
        url="https://argocd.example.com",
        token="eyJhbGciOi.test",
        stub_responses={"/api/v1/clusters": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/argocd/api/v1/clusters", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["items"][0]["name"] == "in-cluster"
    assert body["items"][0]["info"]["connectionState"]["status"] == "Successful"
    _reset()


def test_list_repositories_happy_path(monkeypatch):
    monkeypatch.setenv("ARGOCD_URL", "https://argocd.example.com")
    monkeypatch.setenv("ARGOCD_TOKEN", "eyJhbGciOi.test")
    raw = {
        "items": [
            {
                "repo": "https://github.com/argoproj/argocd-example-apps",
                "type": "git",
                "name": "argocd-example-apps",
                "project": "default",
                "connectionState": {"status": "Successful"},
            }
        ]
    }
    app, _ = _build_app(
        url="https://argocd.example.com",
        token="eyJhbGciOi.test",
        stub_responses={"/api/v1/repositories": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/argocd/api/v1/repositories", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["items"][0]["repo"].startswith("https://github.com/")
    assert body["items"][0]["type"] == "git"
    _reset()


# ============================================================ error mapping


def test_list_applications_returns_503_on_upstream_401(monkeypatch):
    monkeypatch.setenv("ARGOCD_URL", "https://argocd.example.com")
    monkeypatch.setenv("ARGOCD_TOKEN", "bad-token")
    app, _ = _build_app(
        url="https://argocd.example.com",
        token="bad-token",
        stub_responses={
            "/api/v1/applications": _StubResponse(
                401, {"error": "unauthorized"}, text="unauthorized"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/argocd/api/v1/applications", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"].lower()
    assert "401" in detail or "invalid token" in detail
    _reset()


def test_get_application_refresh_validation_rejects_bad_value(monkeypatch):
    monkeypatch.setenv("ARGOCD_URL", "https://argocd.example.com")
    monkeypatch.setenv("ARGOCD_TOKEN", "eyJhbGciOi.test")
    app, _ = _build_app(url="https://argocd.example.com", token="eyJhbGciOi.test")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/argocd/api/v1/applications/guestbook",
        headers=HEADERS,
        params={"refresh": "BAD-VALUE"},
    )
    assert r.status_code == 422, r.text
    _reset()
