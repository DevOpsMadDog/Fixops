"""Tests for the Crossplane (k8s API proxy) router (NO MOCKS).

The engine talks to a real Kubernetes API server via httpx. We:
  - Verify capability summary reflects API/token presence (status: ok|unavailable).
  - Verify endpoints return HTTP 503 when KUBE_API_SERVER / KUBE_TOKEN are unset.
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
        # Longest match wins so /lock isn't shadowed by /providers etc.
        best: Optional[_StubResponse] = None
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
    api_server: Optional[str],
    token: Optional[str],
    stub_responses: Optional[Dict[str, _StubResponse]] = None,
):
    from core import crossplane_engine as eng_mod

    eng_mod.reset_crossplane_engine()

    stub_client = _StubClient(stub_responses or {})
    eng_mod.get_crossplane_engine(
        api_server=api_server, token=token, client=stub_client
    )

    from apps.api.crossplane_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset() -> None:
    from core import crossplane_engine as eng_mod

    eng_mod.reset_crossplane_engine()


# ============================================================ capability


def test_capability_summary_unavailable_when_no_env(monkeypatch):
    monkeypatch.delenv("KUBE_API_SERVER", raising=False)
    monkeypatch.delenv("KUBE_TOKEN", raising=False)
    monkeypatch.delenv("KUBE_TOKEN_PATH", raising=False)
    app, _ = _build_app(api_server=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/crossplane/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Crossplane (k8s)"
    assert "/apis/pkg.crossplane.io/v1/providers" in body["endpoints"]
    assert "/apis/apiextensions.crossplane.io/v1/compositions" in body["endpoints"]
    assert "/apis/apiextensions.crossplane.io/v1/compositeresourcedefinitions" in body["endpoints"]
    assert "/apis/{group}/{version}/{plural}" in body["endpoints"]
    assert "/apis/pkg.crossplane.io/v1/configurations" in body["endpoints"]
    assert "/apis/pkg.crossplane.io/v1/functions" in body["endpoints"]
    assert body["kube_api_server_present"] is False
    assert body["kube_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_env_present(monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.setenv("KUBE_TOKEN", "eyJhbGciOi.test")
    app, _ = _build_app(
        api_server="https://kube.example.com:6443",
        token="eyJhbGciOi.test",
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/crossplane/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kube_api_server_present"] is True
    assert body["kube_token_present"] is True
    assert body["status"] == "ok"
    _reset()


def test_capability_summary_unavailable_when_only_api(monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.delenv("KUBE_TOKEN", raising=False)
    monkeypatch.delenv("KUBE_TOKEN_PATH", raising=False)
    app, _ = _build_app(
        api_server="https://kube.example.com:6443", token=None
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/crossplane/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kube_api_server_present"] is True
    assert body["kube_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_token_loaded_from_token_path_file(tmp_path, monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.delenv("KUBE_TOKEN", raising=False)
    p = tmp_path / "sa.token"
    p.write_text("file-token-xyz\n")
    monkeypatch.setenv("KUBE_TOKEN_PATH", str(p))

    from core import crossplane_engine as eng_mod

    eng_mod.reset_crossplane_engine()
    eng = eng_mod.get_crossplane_engine()
    assert eng.is_configured()
    assert eng._token == "file-token-xyz"
    eng_mod.reset_crossplane_engine()


# ============================================================ 503 paths


def test_list_providers_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("KUBE_API_SERVER", raising=False)
    monkeypatch.delenv("KUBE_TOKEN", raising=False)
    monkeypatch.delenv("KUBE_TOKEN_PATH", raising=False)
    app, _ = _build_app(api_server=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/pkg.crossplane.io/v1/providers", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "KUBE_API_SERVER" in detail or "KUBE_TOKEN" in detail
    _reset()


def test_list_compositions_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("KUBE_API_SERVER", raising=False)
    monkeypatch.delenv("KUBE_TOKEN", raising=False)
    monkeypatch.delenv("KUBE_TOKEN_PATH", raising=False)
    app, _ = _build_app(api_server=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/apiextensions.crossplane.io/v1/compositions",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_list_xrds_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("KUBE_API_SERVER", raising=False)
    monkeypatch.delenv("KUBE_TOKEN", raising=False)
    monkeypatch.delenv("KUBE_TOKEN_PATH", raising=False)
    app, _ = _build_app(api_server=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/apiextensions.crossplane.io/v1/compositeresourcedefinitions",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_list_managed_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("KUBE_API_SERVER", raising=False)
    monkeypatch.delenv("KUBE_TOKEN", raising=False)
    monkeypatch.delenv("KUBE_TOKEN_PATH", raising=False)
    app, _ = _build_app(api_server=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/ec2.aws.upbound.io/v1beta1/instances",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_list_configurations_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("KUBE_API_SERVER", raising=False)
    monkeypatch.delenv("KUBE_TOKEN", raising=False)
    monkeypatch.delenv("KUBE_TOKEN_PATH", raising=False)
    app, _ = _build_app(api_server=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/pkg.crossplane.io/v1/configurations",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_list_functions_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("KUBE_API_SERVER", raising=False)
    monkeypatch.delenv("KUBE_TOKEN", raising=False)
    monkeypatch.delenv("KUBE_TOKEN_PATH", raising=False)
    app, _ = _build_app(api_server=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/pkg.crossplane.io/v1/functions", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    _reset()


def test_get_lock_returns_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("KUBE_API_SERVER", raising=False)
    monkeypatch.delenv("KUBE_TOKEN", raising=False)
    monkeypatch.delenv("KUBE_TOKEN_PATH", raising=False)
    app, _ = _build_app(api_server=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/pkg.crossplane.io/v1beta1/lock", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    _reset()


# ============================================================ happy paths


def test_list_providers_happy_path(monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.setenv("KUBE_TOKEN", "eyJhbGciOi.test")
    raw = {
        "kind": "ProviderList",
        "apiVersion": "pkg.crossplane.io/v1",
        "metadata": {"resourceVersion": "12345", "continue": ""},
        "items": [
            {
                "kind": "Provider",
                "apiVersion": "pkg.crossplane.io/v1",
                "metadata": {
                    "name": "provider-aws",
                    "uid": "aaaa-bbbb-cccc",
                    "resourceVersion": "111",
                    "creationTimestamp": "2026-05-04T00:00:00Z",
                    "generation": 1,
                    "labels": {},
                    "annotations": {},
                },
                "spec": {
                    "package": "xpkg.upbound.io/upbound/provider-aws:v0.42.0",
                    "packagePullPolicy": "IfNotPresent",
                    "revisionActivationPolicy": "Automatic",
                    "revisionHistoryLimit": 1,
                    "ignoreCrossplaneConstraints": False,
                    "skipDependencyResolution": False,
                },
                "status": {
                    "conditions": [
                        {
                            "type": "Healthy",
                            "status": "True",
                            "lastTransitionTime": "2026-05-04T00:01:00Z",
                            "reason": "HealthyPackageRevision",
                            "message": "",
                        },
                        {
                            "type": "Installed",
                            "status": "True",
                            "lastTransitionTime": "2026-05-04T00:00:30Z",
                            "reason": "ActivePackageRevision",
                            "message": "",
                        },
                    ],
                    "currentRevision": "provider-aws-abc",
                    "currentIdentifier": "xpkg.upbound.io/upbound/provider-aws:v0.42.0",
                },
            }
        ],
    }
    app, stub = _build_app(
        api_server="https://kube.example.com:6443",
        token="eyJhbGciOi.test",
        stub_responses={"/apis/pkg.crossplane.io/v1/providers": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/pkg.crossplane.io/v1/providers",
        headers=HEADERS,
        params=[
            ("limit", "50"),
            ("continue", "cont-tok"),
            ("labelSelector", "env=prod"),
            ("fieldSelector", "metadata.name=provider-aws"),
        ],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kind"] == "ProviderList"
    assert body["items"][0]["spec"]["package"].startswith("xpkg.upbound.io/")
    assert body["items"][0]["status"]["conditions"][0]["type"] == "Healthy"

    # Verify Authorization: Bearer header was set with the token
    auth = stub.calls[0]["headers"].get("Authorization", "")
    assert auth == "Bearer eyJhbGciOi.test"

    sent_params = stub.calls[0]["params"]
    flat = (
        [(k, v) for k, v in sent_params]
        if isinstance(sent_params, list)
        else list(sent_params.items())
    )
    assert ("limit", "50") in flat
    assert ("continue", "cont-tok") in flat
    assert ("labelSelector", "env=prod") in flat
    assert ("fieldSelector", "metadata.name=provider-aws") in flat
    _reset()


def test_list_compositions_happy_path(monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.setenv("KUBE_TOKEN", "eyJhbGciOi.test")
    raw = {
        "kind": "CompositionList",
        "apiVersion": "apiextensions.crossplane.io/v1",
        "metadata": {"resourceVersion": "5"},
        "items": [
            {
                "kind": "Composition",
                "apiVersion": "apiextensions.crossplane.io/v1",
                "metadata": {"name": "xinstance.aws.example.org"},
                "spec": {
                    "compositeTypeRef": {
                        "apiVersion": "example.org/v1alpha1",
                        "kind": "XInstance",
                    },
                    "mode": "Pipeline",
                    "pipeline": [
                        {
                            "step": "patch-and-transform",
                            "functionRef": {"name": "function-patch-and-transform"},
                            "input": {},
                        }
                    ],
                    "writeConnectionSecretsToNamespace": "crossplane-system",
                },
            }
        ],
    }
    app, _ = _build_app(
        api_server="https://kube.example.com:6443",
        token="eyJhbGciOi.test",
        stub_responses={
            "/apis/apiextensions.crossplane.io/v1/compositions": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/apiextensions.crossplane.io/v1/compositions",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kind"] == "CompositionList"
    assert body["items"][0]["spec"]["mode"] == "Pipeline"
    assert body["items"][0]["spec"]["pipeline"][0]["functionRef"]["name"] == (
        "function-patch-and-transform"
    )
    _reset()


def test_list_xrds_happy_path(monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.setenv("KUBE_TOKEN", "eyJhbGciOi.test")
    raw = {
        "kind": "CompositeResourceDefinitionList",
        "apiVersion": "apiextensions.crossplane.io/v1",
        "items": [
            {
                "kind": "CompositeResourceDefinition",
                "apiVersion": "apiextensions.crossplane.io/v1",
                "metadata": {"name": "xinstances.example.org"},
                "spec": {
                    "group": "example.org",
                    "names": {"kind": "XInstance", "plural": "xinstances"},
                    "claimNames": {"kind": "Instance", "plural": "instances"},
                    "versions": [
                        {
                            "name": "v1alpha1",
                            "served": True,
                            "referenceable": True,
                            "schema": {"openAPIV3Schema": {"type": "object"}},
                        }
                    ],
                },
            }
        ],
    }
    app, _ = _build_app(
        api_server="https://kube.example.com:6443",
        token="eyJhbGciOi.test",
        stub_responses={
            "/apis/apiextensions.crossplane.io/v1/compositeresourcedefinitions": _StubResponse(
                200, raw
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/apiextensions.crossplane.io/v1/compositeresourcedefinitions",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["items"][0]["spec"]["group"] == "example.org"
    assert body["items"][0]["spec"]["names"]["plural"] == "xinstances"
    _reset()


def test_list_managed_cluster_scoped_happy_path(monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.setenv("KUBE_TOKEN", "eyJhbGciOi.test")
    raw = {
        "kind": "InstanceList",
        "apiVersion": "ec2.aws.upbound.io/v1beta1",
        "items": [
            {
                "kind": "Instance",
                "apiVersion": "ec2.aws.upbound.io/v1beta1",
                "metadata": {"name": "i-aaaa", "uid": "u-1"},
                "spec": {"forProvider": {"region": "us-west-2"}},
                "status": {"conditions": []},
            }
        ],
    }
    app, stub = _build_app(
        api_server="https://kube.example.com:6443",
        token="eyJhbGciOi.test",
        stub_responses={
            "/apis/ec2.aws.upbound.io/v1beta1/instances": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/ec2.aws.upbound.io/v1beta1/instances",
        headers=HEADERS,
        params=[("limit", "10")],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kind"] == "InstanceList"
    assert body["items"][0]["metadata"]["name"] == "i-aaaa"

    # Confirm we hit the cluster-scoped path (no /namespaces/ in the URL)
    assert "/namespaces/" not in stub.calls[0]["url"]
    _reset()


def test_list_managed_namespaced_happy_path(monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.setenv("KUBE_TOKEN", "eyJhbGciOi.test")
    raw = {
        "kind": "BucketList",
        "apiVersion": "s3.aws.upbound.io/v1beta1",
        "items": [
            {
                "kind": "Bucket",
                "apiVersion": "s3.aws.upbound.io/v1beta1",
                "metadata": {"name": "my-bucket", "namespace": "team-a"},
                "spec": {"forProvider": {"region": "us-east-1"}},
                "status": {},
            }
        ],
    }
    app, stub = _build_app(
        api_server="https://kube.example.com:6443",
        token="eyJhbGciOi.test",
        stub_responses={
            "/apis/s3.aws.upbound.io/v1beta1/namespaces/team-a/buckets": _StubResponse(
                200, raw
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/s3.aws.upbound.io/v1beta1/namespaces/team-a/buckets",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["items"][0]["metadata"]["namespace"] == "team-a"
    assert "/namespaces/team-a/buckets" in stub.calls[0]["url"]
    _reset()


def test_get_managed_single_resource_happy_path(monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.setenv("KUBE_TOKEN", "eyJhbGciOi.test")
    raw = {
        "kind": "Instance",
        "apiVersion": "ec2.aws.upbound.io/v1beta1",
        "metadata": {"name": "i-aaaa"},
        "spec": {"forProvider": {"region": "us-west-2"}},
        "status": {"atProvider": {"id": "i-aaaa"}},
    }
    app, _ = _build_app(
        api_server="https://kube.example.com:6443",
        token="eyJhbGciOi.test",
        stub_responses={
            "/apis/ec2.aws.upbound.io/v1beta1/instances/i-aaaa": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/ec2.aws.upbound.io/v1beta1/instances/i-aaaa",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kind"] == "Instance"
    assert body["status"]["atProvider"]["id"] == "i-aaaa"
    _reset()


def test_list_configurations_happy_path(monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.setenv("KUBE_TOKEN", "eyJhbGciOi.test")
    raw = {
        "kind": "ConfigurationList",
        "apiVersion": "pkg.crossplane.io/v1",
        "items": [
            {
                "kind": "Configuration",
                "apiVersion": "pkg.crossplane.io/v1",
                "metadata": {"name": "platform-ref-aws"},
                "spec": {"package": "xpkg.upbound.io/upbound/platform-ref-aws:v0.6.0"},
                "status": {"currentRevision": "rev-1"},
            }
        ],
    }
    app, _ = _build_app(
        api_server="https://kube.example.com:6443",
        token="eyJhbGciOi.test",
        stub_responses={
            "/apis/pkg.crossplane.io/v1/configurations": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/pkg.crossplane.io/v1/configurations", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["items"][0]["spec"]["package"].startswith("xpkg.upbound.io/")
    _reset()


def test_list_functions_happy_path(monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.setenv("KUBE_TOKEN", "eyJhbGciOi.test")
    raw = {
        "kind": "FunctionList",
        "apiVersion": "pkg.crossplane.io/v1",
        "items": [
            {
                "kind": "Function",
                "apiVersion": "pkg.crossplane.io/v1",
                "metadata": {"name": "function-patch-and-transform"},
                "spec": {
                    "package": "xpkg.upbound.io/crossplane-contrib/function-patch-and-transform:v0.2.1"
                },
                "status": {"currentRevision": "rev-1"},
            }
        ],
    }
    app, _ = _build_app(
        api_server="https://kube.example.com:6443",
        token="eyJhbGciOi.test",
        stub_responses={
            "/apis/pkg.crossplane.io/v1/functions": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/pkg.crossplane.io/v1/functions", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["items"][0]["spec"]["package"].startswith("xpkg.upbound.io/")
    _reset()


def test_get_lock_happy_path(monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.setenv("KUBE_TOKEN", "eyJhbGciOi.test")
    raw = {
        "kind": "Lock",
        "apiVersion": "pkg.crossplane.io/v1beta1",
        "metadata": {"name": "lock", "uid": "lock-uid"},
        "packages": [
            {
                "name": "provider-aws",
                "type": "Provider",
                "source": "xpkg.upbound.io/upbound/provider-aws",
                "version": "v0.42.0",
                "dependencies": [
                    {
                        "package": "xpkg.upbound.io/crossplane/provider-helm",
                        "type": "Provider",
                        "constraints": ">=v0.1.0",
                    }
                ],
            }
        ],
    }
    app, _ = _build_app(
        api_server="https://kube.example.com:6443",
        token="eyJhbGciOi.test",
        stub_responses={
            "/apis/pkg.crossplane.io/v1beta1/locks/lock": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/pkg.crossplane.io/v1beta1/lock", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kind"] == "Lock"
    assert body["packages"][0]["type"] == "Provider"
    assert body["packages"][0]["dependencies"][0]["constraints"] == ">=v0.1.0"
    _reset()


# ============================================================ error mapping


def test_list_providers_returns_503_on_upstream_401(monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.setenv("KUBE_TOKEN", "bad-token")
    app, _ = _build_app(
        api_server="https://kube.example.com:6443",
        token="bad-token",
        stub_responses={
            "/apis/pkg.crossplane.io/v1/providers": _StubResponse(
                401, {"error": "unauthorized"}, text="unauthorized"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/pkg.crossplane.io/v1/providers", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"].lower()
    assert "401" in detail or "invalid token" in detail
    _reset()


def test_list_providers_returns_503_on_upstream_500(monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.setenv("KUBE_TOKEN", "tok")
    app, _ = _build_app(
        api_server="https://kube.example.com:6443",
        token="tok",
        stub_responses={
            "/apis/pkg.crossplane.io/v1/providers": _StubResponse(
                500, {"error": "boom"}, text="boom"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/pkg.crossplane.io/v1/providers", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    _reset()


def test_list_providers_negative_limit_returns_422(monkeypatch):
    monkeypatch.setenv("KUBE_API_SERVER", "https://kube.example.com:6443")
    monkeypatch.setenv("KUBE_TOKEN", "tok")
    app, _ = _build_app(api_server="https://kube.example.com:6443", token="tok")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/crossplane/apis/pkg.crossplane.io/v1/providers",
        headers=HEADERS,
        params=[("limit", "-1")],
    )
    assert r.status_code == 422, r.text
    _reset()
