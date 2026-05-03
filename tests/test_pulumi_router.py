"""Tests for pulumi_router — ALDECI.

Spins up a minimal FastAPI app with the Pulumi router mounted. Each test
gets an isolated engine singleton with a stub httpx.Client.

NO MOCKS rule:
  * All live endpoints return HTTP 503 when PULUMI_ACCESS_TOKEN is unset.
  * Capability summary reports ``status="unavailable"`` with no token.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real networking + parsing code paths.
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
# httpx stubs
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL suffix."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> Any:
        # Longest-prefix match so nested paths win over short ones.
        best_key: Optional[str] = None
        for path in self._responses:
            if path in url and (best_key is None or len(path) > len(best_key)):
                best_key = path
        if best_key is not None:
            return self._responses[best_key]
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):  # noqa: D401
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "headers": headers or {},
                "params": params or {},
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(
    *,
    api_key: Optional[str],
    stub_responses: Dict[str, Any],
    base_url: Optional[str] = None,
):
    """Construct an isolated app+engine bound to a stub client."""
    from core import pulumi_engine as engine_mod

    engine_mod.reset_pulumi_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_pulumi_engine(
        api_key=api_key, client=stub_client, base_url=base_url
    )

    from apps.api.pulumi_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import pulumi_engine as engine_mod

    engine_mod.reset_pulumi_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_token(monkeypatch):
    monkeypatch.delenv("PULUMI_ACCESS_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pulumi/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Pulumi Cloud"
    assert "/api/user" in body["endpoints"]
    assert "/api/orgs/{org}/stacks" in body["endpoints"]
    assert "/api/stacks/{org}/{project}/{stack}" in body["endpoints"]
    assert "/api/orgs/{org}/policygroups" in body["endpoints"]
    assert "/api/orgs/{org}/policypacks" in body["endpoints"]
    assert body["pulumi_access_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_token_present(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "test-token")
    app, _ = _build_app(api_key="test-token", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pulumi/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["pulumi_access_token_present"] is True
    assert body["status"] == "ok"
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when no token
# ---------------------------------------------------------------------------


def test_user_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("PULUMI_ACCESS_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pulumi/api/user", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "PULUMI_ACCESS_TOKEN" in r.json()["detail"]
    _reset()


def test_stacks_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("PULUMI_ACCESS_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pulumi/api/orgs/acme/stacks", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_stack_detail_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("PULUMI_ACCESS_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pulumi/api/stacks/acme/web/prod", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    _reset()


def test_exports_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("PULUMI_ACCESS_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pulumi/api/stacks/acme/web/prod/exports", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    _reset()


def test_policy_groups_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("PULUMI_ACCESS_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pulumi/api/orgs/acme/policygroups", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    _reset()


def test_policy_packs_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("PULUMI_ACCESS_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pulumi/api/orgs/acme/policypacks", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_get_user_happy_path(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "test-token")
    raw = {
        "name": "Pat Pulumi",
        "githubLogin": "pat",
        "email": "pat@example.com",
        "avatarUrl": "https://avatars/pat.png",
        "organizations": [
            {
                "githubLogin": "acme",
                "name": "Acme",
                "avatarUrl": "https://avatars/acme.png",
            },
            {"githubLogin": "solo", "name": "Solo Inc"},
        ],
    }
    app, stub = _build_app(
        api_key="test-token",
        stub_responses={"/api/user": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pulumi/api/user", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "Pat Pulumi"
    assert body["githubLogin"] == "pat"
    assert len(body["organizations"]) == 2
    assert body["organizations"][0]["githubLogin"] == "acme"
    assert body["organizations"][1]["avatarUrl"] == ""
    # Authorization header uses 'token' prefix, not 'Bearer'
    assert stub.calls[0]["headers"]["Authorization"] == "token test-token"
    _reset()


def test_list_stacks_happy_path(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "test-token")
    raw = {
        "stacks": [
            {
                "orgName": "acme",
                "projectName": "web",
                "stackName": "prod",
                "lastUpdate": 1714512000,
                "resourceCount": 42,
            },
            {
                "orgName": "acme",
                "projectName": "api",
                "stackName": "staging",
                "lastUpdate": 1714400000,
                "resourceCount": 17,
            },
        ],
        "continuationToken": "tok-next",
    }
    app, stub = _build_app(
        api_key="test-token",
        stub_responses={"/api/orgs/acme/stacks": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pulumi/api/orgs/acme/stacks",
        params={
            "continuationToken": "abc",
            "project": "web",
            "tag": "env:prod",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["stacks"]) == 2
    assert body["stacks"][0]["projectName"] == "web"
    assert body["stacks"][0]["resourceCount"] == 42
    assert body["continuationToken"] == "tok-next"
    upstream_params = stub.calls[0]["params"]
    assert upstream_params["continuationToken"] == "abc"
    assert upstream_params["project"] == "web"
    assert upstream_params["tag"] == "env:prod"
    _reset()


def test_get_stack_detail_happy_path(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "test-token")
    raw = {
        "orgName": "acme",
        "projectName": "web",
        "stackName": "prod",
        "currentOperation": "",
        "lastUpdate": 1714512000,
        "resourceCount": 42,
        "version": 17,
        "tags": {"env": "prod", "owner": "platform"},
        "links": {"self": "https://app.pulumi.com/acme/web/prod"},
        "config": {"aws:region": "us-east-1"},
        "settings": {"secretsProvider": "awskms://xyz"},
        "runtime": "nodejs",
        "environments": ["acme/prod-env"],
    }
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/stacks/acme/web/prod": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pulumi/api/stacks/acme/web/prod", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["projectName"] == "web"
    assert body["version"] == 17
    assert body["tags"]["env"] == "prod"
    assert body["settings"]["secretsProvider"] == "awskms://xyz"
    assert body["runtime"] == "nodejs"
    assert body["environments"] == ["acme/prod-env"]
    _reset()


def test_list_updates_happy_path(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "test-token")
    raw = {
        "updates": [
            {
                "info": {
                    "version": 17,
                    "kind": "update",
                    "startTime": 1714510000,
                    "endTime": 1714510120,
                    "message": "deploy from CI",
                    "environment": {"git.head": "abc123"},
                    "resourceChanges": {
                        "create": 3,
                        "update": 1,
                        "delete": 0,
                        "replace": 0,
                        "same": 38,
                    },
                    "resourceCount": 42,
                    "deployment": {"operations": []},
                },
                "environment": {},
                "deployment": {},
            }
        ]
    }
    app, stub = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/stacks/acme/web/prod/updates": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pulumi/api/stacks/acme/web/prod/updates",
        params={"page": 1, "pageSize": 50},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["updates"]) == 1
    info = body["updates"][0]["info"]
    assert info["version"] == 17
    assert info["kind"] == "update"
    assert info["resourceChanges"]["create"] == 3
    assert info["resourceChanges"]["same"] == 38
    upstream_params = stub.calls[0]["params"]
    assert upstream_params["page"] == 1
    assert upstream_params["pageSize"] == 50
    _reset()


def test_get_latest_update_happy_path(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "test-token")
    raw = {
        "info": {
            "version": 17,
            "kind": "preview",
            "startTime": 1714510000,
            "endTime": 1714510020,
            "message": "preview",
            "environment": {},
            "resourceChanges": {
                "create": 0,
                "update": 0,
                "delete": 0,
                "replace": 0,
                "same": 42,
            },
            "resourceCount": 42,
            "deployment": {"operations": []},
        }
    }
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/stacks/acme/web/prod/updates/latest": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pulumi/api/stacks/acme/web/prod/updates/latest",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["info"]["kind"] == "preview"
    assert body["info"]["version"] == 17
    _reset()


def test_get_update_by_version_happy_path(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "test-token")
    raw = {
        "info": {
            "version": 12,
            "kind": "destroy",
            "startTime": 1714400000,
            "endTime": 1714400060,
            "message": "tear down dev",
            "environment": {},
            "resourceChanges": {
                "create": 0,
                "update": 0,
                "delete": 17,
                "replace": 0,
                "same": 0,
            },
            "resourceCount": 0,
            "deployment": {"operations": []},
        }
    }
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/stacks/acme/web/prod/updates/12": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pulumi/api/stacks/acme/web/prod/updates/12",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["info"]["kind"] == "destroy"
    assert body["info"]["resourceChanges"]["delete"] == 17
    _reset()


def test_get_exports_happy_path(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "test-token")
    raw = {
        "version": 3,
        "deployment": {
            "manifest": {"time": "2026-05-04T00:00:00Z", "magic": "abc"},
            "secrets_providers": [],
            "resources": [
                {
                    "urn": "urn:pulumi:prod::web::aws:s3/bucket:Bucket::data",
                    "custom": True,
                    "id": "data-bucket",
                    "type": "aws:s3/bucket:Bucket",
                    "inputs": {"acl": "private"},
                    "outputs": {"arn": "arn:aws:s3:::data-bucket"},
                    "parent": "urn:pulumi:prod::web::pulumi:Stack",
                    "dependencies": [],
                    "propertyDependencies": {},
                    "provider": "urn:pulumi:prod::web::pulumi:providers:aws::default",
                    "protect": True,
                    "externalDependencies": [],
                    "additionalSecretOutputs": ["secretAccessKey"],
                    "aliases": [],
                    "created": "2026-05-01T00:00:00Z",
                    "modified": "2026-05-03T00:00:00Z",
                    "sourcePosition": {
                        "uri": "file:///workspace/src/index.ts",
                        "line": 42,
                        "column": 5,
                    },
                }
            ],
            "pendingOperations": [],
            "secretsProviders": {
                "type": "service",
                "state": {"endpoint": "https://api.pulumi.com"},
            },
        },
    }
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/stacks/acme/web/prod/exports": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pulumi/api/stacks/acme/web/prod/exports", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["version"] == 3
    res = body["deployment"]["resources"]
    assert len(res) == 1
    assert res[0]["urn"].startswith("urn:pulumi:prod::web::aws:s3/bucket")
    assert res[0]["protect"] is True
    assert res[0]["additionalSecretOutputs"] == ["secretAccessKey"]
    assert res[0]["sourcePosition"]["line"] == 42
    assert body["deployment"]["secretsProviders"]["type"] == "service"
    _reset()


def test_list_policy_groups_happy_path(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "test-token")
    raw = {
        "policyGroups": [
            {
                "name": "default-policy-group",
                "description": "Org default",
                "isOrgDefault": True,
                "numStacks": 12,
                "numEnabledPolicyPacks": 3,
            },
            {
                "name": "prod-only",
                "description": "Stricter prod controls",
                "isOrgDefault": False,
                "numStacks": 4,
                "numEnabledPolicyPacks": 5,
            },
        ]
    }
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/orgs/acme/policygroups": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pulumi/api/orgs/acme/policygroups", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["policyGroups"]) == 2
    assert body["policyGroups"][0]["isOrgDefault"] is True
    assert body["policyGroups"][1]["numEnabledPolicyPacks"] == 5
    _reset()


def test_get_policy_group_detail_happy_path(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "test-token")
    raw = {
        "name": "prod-only",
        "description": "Stricter prod controls",
        "isOrgDefault": False,
        "numStacks": 4,
        "numEnabledPolicyPacks": 5,
        "stacks": [{"orgName": "acme", "projectName": "web", "stackName": "prod"}],
        "policyPacks": [{"name": "aws-baseline", "version": 3}],
    }
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/orgs/acme/policygroups/prod-only": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pulumi/api/orgs/acme/policygroups/prod-only", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "prod-only"
    assert body["isOrgDefault"] is False
    assert len(body["stacks"]) == 1
    _reset()


def test_list_policy_packs_happy_path(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "test-token")
    raw = {
        "requiredPolicies": [
            {
                "name": "aws-baseline",
                "displayName": "AWS Baseline",
                "version": 3,
                "versionTag": "v3",
                "latestVersion": 4,
                "latestVersionTag": "v4",
                "enforcementLevel": "mandatory",
            }
        ],
        "policyPacks": [
            {
                "name": "kubernetes-best-practices",
                "displayName": "K8s BPs",
                "latestVersion": 7,
                "latestVersionTag": "v7",
            }
        ],
    }
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/orgs/acme/policypacks": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pulumi/api/orgs/acme/policypacks", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["requiredPolicies"]) == 1
    assert body["requiredPolicies"][0]["enforcementLevel"] == "mandatory"
    assert body["requiredPolicies"][0]["latestVersion"] == 4
    assert len(body["policyPacks"]) == 1
    assert body["policyPacks"][0]["latestVersionTag"] == "v7"
    _reset()


def test_get_policy_pack_policies_happy_path(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "test-token")
    raw = {
        "policies": [
            {
                "name": "no-public-buckets",
                "displayName": "No Public S3 Buckets",
                "enforcementLevel": "mandatory",
                "configSchema": {},
            }
        ]
    }
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/orgs/acme/policypacks/aws-baseline/versions/3/policies": _StubResponse(
                200, raw
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/pulumi/api/orgs/acme/policypacks/aws-baseline/versions/3/policies",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body.get("policies"), list)
    assert body["policies"][0]["name"] == "no-public-buckets"
    _reset()


# ---------------------------------------------------------------------------
# Upstream error paths
# ---------------------------------------------------------------------------


def test_user_returns_503_on_upstream_401(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "bad-token")
    app, _ = _build_app(
        api_key="bad-token",
        stub_responses={
            "/api/user": _StubResponse(
                401, {"error": "unauthorized"}, text="unauthorized"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pulumi/api/user", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert (
        "401" in r.json()["detail"]
        or "credential" in r.json()["detail"].lower()
    )
    _reset()


def test_stacks_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "test-token")
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/orgs/acme/stacks": _StubResponse(
                429, {"error": "rate limit"}, text="rate limit"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pulumi/api/orgs/acme/stacks", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "rate-limit" in detail.lower() or "429" in detail
    _reset()


# ---------------------------------------------------------------------------
# Self-hosted base URL override
# ---------------------------------------------------------------------------


def test_self_hosted_backend_url_used(monkeypatch):
    monkeypatch.setenv("PULUMI_ACCESS_TOKEN", "test-token")
    app, stub = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/user": _StubResponse(
                200,
                {
                    "name": "Self-Hosted User",
                    "githubLogin": "selfhost",
                    "email": "u@selfhost.example",
                    "avatarUrl": "",
                    "organizations": [],
                },
            )
        },
        base_url="https://pulumi.internal.example.com",
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/pulumi/api/user", headers=HEADERS)
    assert r.status_code == 200, r.text
    assert stub.calls[0]["url"].startswith(
        "https://pulumi.internal.example.com/api/user"
    )
    _reset()
