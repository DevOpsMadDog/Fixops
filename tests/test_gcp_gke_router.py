"""Tests for gcp_gke_router — ALDECI GCP GKE.

NO MOCKS rule:
  * When GOOGLE_APPLICATION_CREDENTIALS is unset OR the file is missing,
    the capability summary reports ``status="unavailable"`` and every live
    GKE endpoint returns 503.
  * Happy-path tests inject a stub httpx.Client + an in-memory service-account
    key so we still exercise the real OAuth + parsing code paths.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

# env bootstrap (mirrors tests/conftest.py defaults)
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
        get_responses: Dict[str, Any],
        post_responses: Dict[str, Any],
    ):
        self._get = get_responses
        self._post = post_responses
        self.calls: List[Dict[str, Any]] = []

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "params": params or {},
                "headers": headers or {},
            }
        )
        for needle, resp in self._get.items():
            if needle in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

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
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def close(self) -> None:
        pass


_FAKE_SA_KEY = {
    "type": "service_account",
    "project_id": "test-project",
    "private_key_id": "deadbeef",
    "private_key": "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n",
    "client_email": "ci@test-project.iam.gserviceaccount.com",
    "client_id": "1",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
}


def _write_fake_sa(tmp_path: Path) -> Path:
    p = tmp_path / "sa.json"
    p.write_text(json.dumps(_FAKE_SA_KEY), encoding="utf-8")
    return p


def _build_app(
    tmp_path: Path,
    *,
    creds_path: Optional[str],
    get_responses: Optional[Dict[str, Any]] = None,
    post_responses: Optional[Dict[str, Any]] = None,
):
    """Construct an isolated FastAPI app with the GCP GKE router mounted."""
    from core import gcp_gke_engine as engine_mod

    engine_mod.reset_gcp_gke_engine()
    stub = _StubClient(get_responses or {}, post_responses or {})

    eng = engine_mod.get_gcp_gke_engine(
        creds_path=creds_path,
        client=stub,
    )
    # Pre-seed token cache so we don't need PyJWT for happy-path tests.
    eng._token_cache["access_token"] = "stub-bearer"
    eng._token_cache["expires_at"] = 9_999_999_999.0

    from apps.api.gcp_gke_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


def _reset() -> None:
    from core import gcp_gke_engine as engine_mod
    engine_mod.reset_gcp_gke_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/gcp-gke/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "GCP GKE"
    assert any("clusters" in ep for ep in body["endpoints"])
    assert any("nodePools" in ep for ep in body["endpoints"])
    assert any("operations" in ep for ep in body["endpoints"])
    assert body["google_app_creds_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_empty_when_creds_present(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    app, _ = _build_app(tmp_path, creds_path=str(sa))
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/gcp-gke/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["google_app_creds_present"] is True
    assert body["status"] == "empty"
    _reset()


def test_capability_summary_unavailable_when_creds_file_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(tmp_path / "nope.json"))
    app, _ = _build_app(tmp_path, creds_path=str(tmp_path / "nope.json"))
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/gcp-gke/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["google_app_creds_present"] is False
    assert body["status"] == "unavailable"
    _reset()


# ---------------------------------------------------------------------------
# 503 — credentials missing on every live endpoint
# ---------------------------------------------------------------------------


def test_clusters_returns_503_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-gke/v1/projects/p1/locations/us-central1/clusters",
        headers=HEADERS,
    )
    assert r.status_code == 503
    assert "GOOGLE_APPLICATION_CREDENTIALS" in r.json()["detail"]
    _reset()


def test_get_cluster_returns_503_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-gke/v1/projects/p1/locations/us-central1/clusters/c1",
        headers=HEADERS,
    )
    assert r.status_code == 503
    _reset()


def test_node_pools_returns_503_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-gke/v1/projects/p1/locations/us-central1/clusters/c1/nodePools",
        headers=HEADERS,
    )
    assert r.status_code == 503
    _reset()


def test_jwks_returns_503_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/gcp-gke/v1/projects/p1/locations/us-central1/clusters/c1:getJwks",
        headers=HEADERS,
    )
    assert r.status_code == 503
    _reset()


def test_operations_returns_503_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-gke/v1/projects/p1/locations/us-central1/operations",
        headers=HEADERS,
    )
    assert r.status_code == 503
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx + pre-seeded token
# ---------------------------------------------------------------------------


def test_list_clusters_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    raw = {
        "clusters": [
            {
                "name": "prod-cluster",
                "description": "Production GKE cluster",
                "initialNodeCount": 3,
                "nodeConfig": {
                    "machineType": "e2-standard-4",
                    "diskSizeGb": 100,
                    "oauthScopes": ["https://www.googleapis.com/auth/cloud-platform"],
                    "serviceAccount": "default",
                    "imageType": "COS_CONTAINERD",
                    "labels": {"env": "prod"},
                    "preemptible": False,
                    "diskType": "pd-ssd",
                    "shieldedInstanceConfig": {
                        "enableSecureBoot": True,
                        "enableIntegrityMonitoring": True,
                    },
                    "accelerators": [
                        {
                            "acceleratorCount": 1,
                            "acceleratorType": "nvidia-tesla-t4",
                            "gpuPartitionSize": "",
                        }
                    ],
                },
                "loggingService": "logging.googleapis.com/kubernetes",
                "monitoringService": "monitoring.googleapis.com/kubernetes",
                "network": "default",
                "subnetwork": "default",
                "clusterIpv4Cidr": "10.0.0.0/14",
                "locations": ["us-central1-a", "us-central1-b"],
                "status": "RUNNING",
                "currentMasterVersion": "1.28.7-gke.1700",
                "currentNodeVersion": "1.28.7-gke.1700",
                "endpoint": "1.2.3.4",
                "createTime": "2026-01-01T00:00:00Z",
                "location": "us-central1",
                "currentNodeCount": 3,
                "releaseChannel": {"channel": "REGULAR"},
                "autopilot": {"enabled": False},
                "binaryAuthorization": {
                    "enabled": True,
                    "evaluationMode": "PROJECT_SINGLETON_POLICY_ENFORCE",
                },
                "securityPostureConfig": {
                    "mode": "ENTERPRISE",
                    "vulnerabilityMode": "VULNERABILITY_ENTERPRISE",
                },
                "enterpriseConfig": {"clusterTier": "ENTERPRISE"},
                "satisfiesPzs": True,
                "satisfiesPzi": False,
            },
            {
                "name": "staging-cluster",
                "initialNodeCount": 1,
                "status": "PROVISIONING",
                "location": "us-central1",
                "autopilot": {"enabled": True},
            },
        ],
        "missingZones": [],
    }
    app, stub = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={"/locations/us-central1/clusters": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-gke/v1/projects/p1/locations/us-central1/clusters"
        "?parent=projects/p1/locations/us-central1&pageToken=tok-1",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["clusters"]) == 2
    cluster = body["clusters"][0]
    assert cluster["name"] == "prod-cluster"
    assert cluster["nodeConfig"]["machineType"] == "e2-standard-4"
    assert cluster["nodeConfig"]["diskType"] == "pd-ssd"
    assert cluster["nodeConfig"]["shieldedInstanceConfig"]["enableSecureBoot"] is True
    assert cluster["nodeConfig"]["accelerators"][0]["acceleratorType"] == "nvidia-tesla-t4"
    assert cluster["status"] == "RUNNING"
    assert cluster["releaseChannel"]["channel"] == "REGULAR"
    assert cluster["binaryAuthorization"]["evaluationMode"] == "PROJECT_SINGLETON_POLICY_ENFORCE"
    assert cluster["securityPostureConfig"]["mode"] == "ENTERPRISE"
    assert cluster["enterpriseConfig"]["clusterTier"] == "ENTERPRISE"
    assert cluster["satisfiesPzs"] is True
    assert body["clusters"][1]["autopilot"]["enabled"] is True

    call = stub.calls[0]
    assert call["method"] == "GET"
    assert "/clusters" in call["url"]
    assert call["params"].get("parent") == "projects/p1/locations/us-central1"
    assert call["params"].get("pageToken") == "tok-1"
    assert call["headers"]["Authorization"] == "Bearer stub-bearer"
    _reset()


def test_get_cluster_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    raw = {
        "name": "single-cluster",
        "description": "single",
        "initialNodeCount": 5,
        "nodeConfig": {"machineType": "n2-standard-8"},
        "status": "RUNNING",
        "location": "europe-west1",
        "currentMasterVersion": "1.29.0-gke.100",
        "ipAllocationPolicy": {
            "useIpAliases": True,
            "stackType": "IPV4_IPV6",
            "ipv6AccessType": "INTERNAL",
        },
        "networkPolicy": {"provider": "CALICO", "enabled": True},
        "workloadIdentityConfig": {
            "workloadPool": "p1.svc.id.goog",
        },
        "fleet": {
            "project": "p1",
            "membership": "projects/p1/locations/global/memberships/single-cluster",
            "preRegistered": False,
        },
    }
    app, _ = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={"/clusters/single-cluster": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-gke/v1/projects/p1/locations/europe-west1/clusters/single-cluster",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "single-cluster"
    assert body["nodeConfig"]["machineType"] == "n2-standard-8"
    assert body["ipAllocationPolicy"]["stackType"] == "IPV4_IPV6"
    assert body["networkPolicy"]["provider"] == "CALICO"
    assert body["workloadIdentityConfig"]["workloadPool"] == "p1.svc.id.goog"
    assert body["fleet"]["membership"].endswith("single-cluster")
    _reset()


def test_node_pools_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    raw = {
        "nodePools": [
            {
                "name": "default-pool",
                "config": {
                    "machineType": "e2-medium",
                    "diskSizeGb": 50,
                    "preemptible": False,
                    "imageType": "COS_CONTAINERD",
                },
                "initialNodeCount": 3,
                "locations": ["us-central1-a"],
                "version": "1.28.7-gke.1700",
                "status": "RUNNING",
                "autoscaling": {
                    "enabled": True,
                    "minNodeCount": 1,
                    "maxNodeCount": 10,
                    "autoprovisioned": False,
                    "locationPolicy": "BALANCED",
                },
                "management": {
                    "autoUpgrade": True,
                    "autoRepair": True,
                },
                "maxPodsConstraint": {"maxPodsPerNode": "110"},
                "upgradeSettings": {
                    "maxSurge": 1,
                    "maxUnavailable": 0,
                    "strategy": "SURGE",
                },
                "placementPolicy": {"type": "COMPACT", "tpuTopology": ""},
                "queuedProvisioning": {"enabled": False},
                "bestEffortProvisionEnabled": False,
            },
            {
                "name": "gpu-pool",
                "config": {
                    "machineType": "n1-standard-8",
                    "accelerators": [
                        {
                            "acceleratorCount": 2,
                            "acceleratorType": "nvidia-tesla-v100",
                        }
                    ],
                },
                "initialNodeCount": 1,
                "status": "RUNNING",
                "upgradeSettings": {
                    "strategy": "BLUE_GREEN",
                    "blueGreenSettings": {
                        "standardRolloutPolicy": {
                            "batchPercentage": 0.25,
                            "batchSoakDuration": "60s",
                        },
                        "nodePoolSoakDuration": "300s",
                    },
                },
            },
        ]
    }
    app, _ = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={"/clusters/c1/nodePools": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-gke/v1/projects/p1/locations/us-central1/clusters/c1/nodePools",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["nodePools"]) == 2
    np0 = body["nodePools"][0]
    assert np0["name"] == "default-pool"
    assert np0["autoscaling"]["enabled"] is True
    assert np0["autoscaling"]["minNodeCount"] == 1
    assert np0["upgradeSettings"]["strategy"] == "SURGE"
    assert np0["placementPolicy"]["type"] == "COMPACT"
    assert np0["management"]["autoUpgrade"] is True
    np1 = body["nodePools"][1]
    assert np1["name"] == "gpu-pool"
    assert np1["config"]["accelerators"][0]["acceleratorType"] == "nvidia-tesla-v100"
    assert np1["upgradeSettings"]["strategy"] == "BLUE_GREEN"
    _reset()


def test_jwks_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    raw = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "abc123",
                "alg": "RS256",
                "use": "sig",
                "n": "modulus",
                "e": "AQAB",
            }
        ],
        "cacheHeader": {"age": "0", "directive": "public, max-age=3600"},
    }
    app, stub = _build_app(
        tmp_path,
        creds_path=str(sa),
        post_responses={"/clusters/c1:getJwks": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/gcp-gke/v1/projects/p1/locations/us-central1/clusters/c1:getJwks",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["keys"]) == 1
    assert body["keys"][0]["kid"] == "abc123"
    assert body["cacheHeader"]["directive"] == "public, max-age=3600"

    post_call = next(c for c in stub.calls if c["method"] == "POST")
    assert ":getJwks" in post_call["url"]
    _reset()


def test_operations_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    raw = {
        "operations": [
            {
                "name": "operation-1234",
                "zone": "us-central1-a",
                "operationType": "CREATE_CLUSTER",
                "status": "DONE",
                "detail": "Created cluster",
                "selfLink": "https://container.googleapis.com/v1/projects/p1/zones/us-central1-a/operations/operation-1234",
                "targetLink": "https://container.googleapis.com/v1/projects/p1/zones/us-central1-a/clusters/c1",
                "location": "us-central1-a",
                "startTime": "2026-01-01T00:00:00Z",
                "endTime": "2026-01-01T00:05:00Z",
                "progress": {
                    "name": "create-progress",
                    "status": "DONE",
                    "metrics": [
                        {"name": "nodes", "intValue": "3"},
                    ],
                },
            },
            {
                "name": "operation-5678",
                "operationType": "UPGRADE_NODES",
                "status": "RUNNING",
                "location": "us-central1",
                "startTime": "2026-02-01T00:00:00Z",
                "error": {
                    "code": 0,
                    "message": "",
                    "details": [],
                },
            },
        ],
        "missingZones": ["us-east1-a"],
    }
    app, stub = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={"/locations/us-central1/operations": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-gke/v1/projects/p1/locations/us-central1/operations"
        "?pageToken=tok-1",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["operations"]) == 2
    op0 = body["operations"][0]
    assert op0["name"] == "operation-1234"
    assert op0["operationType"] == "CREATE_CLUSTER"
    assert op0["status"] == "DONE"
    assert op0["progress"]["status"] == "DONE"
    assert body["operations"][1]["operationType"] == "UPGRADE_NODES"
    assert body["missingZones"] == ["us-east1-a"]

    call = stub.calls[0]
    assert call["params"].get("pageToken") == "tok-1"
    _reset()


def test_clusters_translates_upstream_403_to_503(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    app, _ = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={
            "/locations/us-central1/clusters": _StubResponse(403, {"error": "denied"}),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-gke/v1/projects/p1/locations/us-central1/clusters",
        headers=HEADERS,
    )
    assert r.status_code == 503
    assert "permission denied" in r.json()["detail"].lower()
    _reset()


def test_get_cluster_translates_upstream_404_to_503(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    app, _ = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={
            "/clusters/missing": _StubResponse(404, {"error": "not found"}),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-gke/v1/projects/p1/locations/us-central1/clusters/missing",
        headers=HEADERS,
    )
    assert r.status_code == 503
    assert "not found" in r.json()["detail"].lower()
    _reset()
