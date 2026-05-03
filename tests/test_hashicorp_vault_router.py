"""Tests for hashicorp_vault_router — ALDECI HashiCorp Vault integration.

NO MOCKS rule:
  * When VAULT_ADDR or VAULT_TOKEN is unset, the capability summary reports
    ``status="unavailable"`` and every live endpoint returns 503.
  * Happy-path tests inject a stub httpx.Client so we still exercise the
    real header construction + JSON parsing paths.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import pytest

# ── env bootstrap (mirrors tests/conftest.py defaults) ────────────────────
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-for-jwt-validation-32chars")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from tests.conftest import API_TOKEN  # noqa: E402

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# Stub httpx client
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Routes calls by URL substring -> queued response."""

    def __init__(
        self,
        get_responses: Optional[Dict[str, Any]] = None,
        post_responses: Optional[Dict[str, Any]] = None,
    ):
        self._get = get_responses or {}
        self._post = post_responses or {}
        self.calls: List[Dict[str, Any]] = []

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.calls.append(
            {"method": "GET", "url": url, "params": params or {}, "headers": headers or {}}
        )
        for needle, resp in self._get.items():
            if needle in url:
                return resp
        return _StubResponse(404, {"errors": ["not found"]}, text="not found")

    def post(
        self,
        url: str,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "data": data,
                "json": json,
                "headers": headers or {},
            }
        )
        for needle, resp in self._post.items():
            if needle in url:
                return resp
        return _StubResponse(404, {"errors": ["not found"]}, text="not found")

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# App builder
# ---------------------------------------------------------------------------


def _build_app(
    *,
    vault_addr: Optional[str],
    vault_token: Optional[str],
    vault_namespace: Optional[str] = None,
    get_responses: Optional[Dict[str, Any]] = None,
    post_responses: Optional[Dict[str, Any]] = None,
):
    from core import hashicorp_vault_engine as engine_mod

    engine_mod.reset_hashicorp_vault_engine()
    stub = _StubClient(get_responses, post_responses)

    engine_mod.get_hashicorp_vault_engine(
        vault_addr=vault_addr,
        vault_token=vault_token,
        vault_namespace=vault_namespace,
        client=stub,
    )

    from apps.api.hashicorp_vault_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


def _reset() -> None:
    from core import hashicorp_vault_engine as engine_mod
    engine_mod.reset_hashicorp_vault_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_env(monkeypatch):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.delenv("VAULT_NAMESPACE", raising=False)
    app, _ = _build_app(vault_addr=None, vault_token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/hashicorp-vault/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "HashiCorp Vault"
    for ep in (
        "/v1/sys/health",
        "/v1/secret/data/{path}",
        "/v1/sys/policies/acl",
        "/v1/sys/auth",
        "/v1/sys/mounts",
    ):
        assert ep in body["endpoints"]
    assert body["vault_addr_present"] is False
    assert body["vault_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_empty_when_env_present(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "s.test-root-token")
    app, _ = _build_app(
        vault_addr="http://127.0.0.1:8200", vault_token="s.test-root-token"
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/hashicorp-vault/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["vault_addr_present"] is True
    assert body["vault_token_present"] is True
    assert body["status"] == "empty"
    _reset()


# ---------------------------------------------------------------------------
# 503 — env missing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("GET", "/api/v1/hashicorp-vault/v1/sys/health", None),
        ("GET", "/api/v1/hashicorp-vault/v1/sys/seal-status", None),
        ("GET", "/api/v1/hashicorp-vault/v1/secret/data/foo/bar", None),
        ("POST", "/api/v1/hashicorp-vault/v1/secret/data/foo/bar", {"data": {"k": "v"}}),
        ("GET", "/api/v1/hashicorp-vault/v1/sys/policies/acl?list=true", None),
        ("GET", "/api/v1/hashicorp-vault/v1/sys/policies/acl/default", None),
        ("GET", "/api/v1/hashicorp-vault/v1/sys/auth", None),
        ("GET", "/api/v1/hashicorp-vault/v1/sys/mounts", None),
    ],
)
def test_endpoint_returns_503_when_env_missing(monkeypatch, method, path, body):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    app, _ = _build_app(vault_addr=None, vault_token=None)
    client = TestClient(app, raise_server_exceptions=True)
    if method == "GET":
        r = client.get(path, headers=HEADERS)
    else:
        r = client.post(path, headers=HEADERS, json=body)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "VAULT_ADDR" in detail or "VAULT_TOKEN" in detail
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx
# ---------------------------------------------------------------------------


def test_health_happy_path(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "s.test-root-token")
    raw = {
        "initialized": True,
        "sealed": False,
        "standby": False,
        "performance_standby": False,
        "replication_performance_mode": "disabled",
        "replication_dr_mode": "disabled",
        "server_time_utc": 1714820000,
        "version": "1.16.2",
        "cluster_name": "vault-cluster-abc",
        "cluster_id": "11111111-1111-1111-1111-111111111111",
    }
    app, stub = _build_app(
        vault_addr="http://127.0.0.1:8200",
        vault_token="s.test-root-token",
        get_responses={"/v1/sys/health": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/hashicorp-vault/v1/sys/health", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["initialized"] is True
    assert body["sealed"] is False
    assert body["version"] == "1.16.2"
    assert body["cluster_name"] == "vault-cluster-abc"

    call = stub.calls[0]
    assert call["method"] == "GET"
    assert "/v1/sys/health" in call["url"]
    assert call["headers"]["X-Vault-Token"] == "s.test-root-token"
    # Defaults forwarded as query params
    assert call["params"]["standbyok"] == "true"
    assert call["params"]["perfstandbyok"] == "true"
    assert call["params"]["sealedcode"] == 503
    assert call["params"]["uninitcode"] == 501
    _reset()


def test_seal_status_happy_path(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "s.test-root-token")
    raw = {
        "type": "shamir",
        "initialized": True,
        "sealed": False,
        "t": 3,
        "n": 5,
        "progress": 0,
        "nonce": "",
        "version": "1.16.2",
        "build_date": "2024-04-22T16:25:54Z",
        "migration": False,
        "recovery_seal": False,
        "storage_type": "raft",
    }
    app, stub = _build_app(
        vault_addr="http://127.0.0.1:8200",
        vault_token="s.test-root-token",
        get_responses={"/v1/sys/seal-status": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/hashicorp-vault/v1/sys/seal-status", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["type"] == "shamir"
    assert body["t"] == 3
    assert body["n"] == 5
    assert body["storage_type"] == "raft"
    _reset()


def test_read_secret_happy_path(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "s.test-root-token")
    raw = {
        "request_id": "req-1",
        "data": {
            "data": {"username": "alice", "password": "p4ssw0rd"},
            "metadata": {
                "created_time": "2026-01-01T00:00:00Z",
                "custom_metadata": {"owner": "platform"},
                "deletion_time": "",
                "destroyed": False,
                "version": 3,
            },
        },
    }
    app, stub = _build_app(
        vault_addr="http://127.0.0.1:8200",
        vault_token="s.test-root-token",
        get_responses={"/v1/secret/data/app/db": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/hashicorp-vault/v1/secret/data/app/db", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["data"]["username"] == "alice"
    assert body["data"]["metadata"]["version"] == 3
    assert body["data"]["metadata"]["custom_metadata"]["owner"] == "platform"
    assert body["data"]["metadata"]["destroyed"] is False

    call = stub.calls[0]
    assert "/v1/secret/data/app/db" in call["url"]
    assert call["headers"]["X-Vault-Token"] == "s.test-root-token"
    _reset()


def test_write_secret_happy_path(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "s.test-root-token")
    raw = {
        "request_id": "req-2",
        "data": {
            "created_time": "2026-05-04T00:00:00Z",
            "custom_metadata": None,
            "deletion_time": "",
            "destroyed": False,
            "version": 4,
        },
    }
    app, stub = _build_app(
        vault_addr="http://127.0.0.1:8200",
        vault_token="s.test-root-token",
        post_responses={"/v1/secret/data/app/db": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/hashicorp-vault/v1/secret/data/app/db",
        headers=HEADERS,
        json={"data": {"username": "bob", "password": "n3w"}, "options": {"cas": 3}},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["version"] == 4
    assert body["data"]["destroyed"] is False

    post_call = next(c for c in stub.calls if c["method"] == "POST")
    assert post_call["json"]["data"] == {"username": "bob", "password": "n3w"}
    assert post_call["json"]["options"]["cas"] == 3
    assert post_call["headers"]["X-Vault-Token"] == "s.test-root-token"
    _reset()


def test_list_acl_policies_happy_path(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "s.test-root-token")
    raw = {"data": {"keys": ["default", "root", "readonly", "ci-deploy"]}}
    app, stub = _build_app(
        vault_addr="http://127.0.0.1:8200",
        vault_token="s.test-root-token",
        get_responses={"/v1/sys/policies/acl": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/hashicorp-vault/v1/sys/policies/acl?list=true", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["keys"] == ["default", "root", "readonly", "ci-deploy"]
    call = stub.calls[0]
    assert call["params"].get("list") == "true"
    _reset()


def test_read_acl_policy_happy_path(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "s.test-root-token")
    raw = {
        "data": {
            "name": "ci-deploy",
            "policy": 'path "secret/data/ci/*" { capabilities = ["read"] }',
        }
    }
    app, _ = _build_app(
        vault_addr="http://127.0.0.1:8200",
        vault_token="s.test-root-token",
        get_responses={"/v1/sys/policies/acl/ci-deploy": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/hashicorp-vault/v1/sys/policies/acl/ci-deploy", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["name"] == "ci-deploy"
    assert "secret/data/ci/*" in body["data"]["policy"]
    _reset()


def test_list_auth_methods_happy_path(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "s.test-root-token")
    raw = {
        "token/": {
            "accessor": "auth_token_abc",
            "type": "token",
            "description": "token based credentials",
            "config": {"default_lease_ttl": 0, "max_lease_ttl": 0},
            "options": None,
            "local": False,
            "seal_wrap": False,
            "external_entropy_access": False,
        },
        "approle/": {
            "accessor": "auth_approle_def",
            "type": "approle",
            "description": "AppRole",
            "config": {"default_lease_ttl": 3600, "max_lease_ttl": 86400},
            "options": {},
            "local": False,
            "seal_wrap": False,
            "external_entropy_access": False,
        },
        "request_id": "req-3",
    }
    app, _ = _build_app(
        vault_addr="http://127.0.0.1:8200",
        vault_token="s.test-root-token",
        get_responses={"/v1/sys/auth": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/hashicorp-vault/v1/sys/auth", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    # Noise keys filtered
    assert "request_id" not in body
    assert body["token/"]["type"] == "token"
    assert body["approle/"]["accessor"] == "auth_approle_def"
    assert body["approle/"]["local"] is False
    _reset()


def test_list_mounts_happy_path(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "s.test-root-token")
    raw = {
        "secret/": {
            "accessor": "kv_abc",
            "type": "kv",
            "description": "key/value v2",
            "config": {
                "default_lease_ttl": 0,
                "max_lease_ttl": 0,
                "force_no_cache": False,
            },
            "options": {"version": "2"},
            "local": False,
            "seal_wrap": False,
            "external_entropy_access": False,
        },
        "transit/": {
            "accessor": "transit_xyz",
            "type": "transit",
            "description": "encryption as a service",
            "config": {
                "default_lease_ttl": 0,
                "max_lease_ttl": 0,
                "force_no_cache": False,
            },
            "options": None,
            "local": False,
            "seal_wrap": False,
            "external_entropy_access": False,
        },
    }
    app, _ = _build_app(
        vault_addr="http://127.0.0.1:8200",
        vault_token="s.test-root-token",
        get_responses={"/v1/sys/mounts": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/hashicorp-vault/v1/sys/mounts", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["secret/"]["type"] == "kv"
    assert body["secret/"]["options"]["version"] == "2"
    assert body["transit/"]["type"] == "transit"
    assert body["transit/"]["config"]["force_no_cache"] is False
    _reset()


def test_namespace_header_forwarded(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "s.test-root-token")
    monkeypatch.setenv("VAULT_NAMESPACE", "team-platform")
    raw = {"data": {"keys": ["default"]}}
    app, stub = _build_app(
        vault_addr="http://127.0.0.1:8200",
        vault_token="s.test-root-token",
        vault_namespace="team-platform",
        get_responses={"/v1/sys/policies/acl": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/hashicorp-vault/v1/sys/policies/acl?list=true", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    call = stub.calls[0]
    assert call["headers"]["X-Vault-Namespace"] == "team-platform"
    _reset()


def test_upstream_403_translates_to_503(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "s.bad-token")
    app, _ = _build_app(
        vault_addr="http://127.0.0.1:8200",
        vault_token="s.bad-token",
        get_responses={
            "/v1/secret/data/forbidden": _StubResponse(
                403, {"errors": ["permission denied"]}
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/hashicorp-vault/v1/secret/data/forbidden", headers=HEADERS
    )
    assert r.status_code == 503
    assert "rejected token" in r.json()["detail"].lower()
    _reset()
