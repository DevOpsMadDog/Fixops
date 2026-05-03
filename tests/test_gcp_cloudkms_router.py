"""Tests for gcp_cloudkms_router — ALDECI GCP Cloud KMS.

NO MOCKS rule:
  * When GOOGLE_APPLICATION_CREDENTIALS is unset OR the file is missing,
    the capability summary reports ``status="unavailable"`` and every live
    KMS endpoint returns 503.
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
    """Construct an isolated FastAPI app with the GCP Cloud KMS router mounted."""
    from core import gcp_cloudkms_engine as engine_mod

    engine_mod.reset_gcp_cloudkms_engine()
    stub = _StubClient(get_responses or {}, post_responses or {})

    eng = engine_mod.get_gcp_cloudkms_engine(
        creds_path=creds_path,
        client=stub,
    )
    # Pre-seed token cache so we don't need PyJWT for happy-path tests.
    eng._token_cache["access_token"] = "stub-bearer"
    eng._token_cache["expires_at"] = 9_999_999_999.0

    from apps.api.gcp_cloudkms_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


def _reset() -> None:
    from core import gcp_cloudkms_engine as engine_mod
    engine_mod.reset_gcp_cloudkms_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/gcp-cloudkms/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "GCP Cloud KMS"
    # endpoint catalogue advertises the published path templates
    assert any("/v1/projects/" in ep and "locations" in ep for ep in body["endpoints"])
    assert any("keyRings" in ep for ep in body["endpoints"])
    assert any("cryptoKeys" in ep for ep in body["endpoints"])
    assert any("cryptoKeyVersions" in ep for ep in body["endpoints"])
    assert any("IAM policy" in ep for ep in body["endpoints"])
    assert body["google_app_creds_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_empty_when_creds_present(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    app, _ = _build_app(tmp_path, creds_path=str(sa))
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/gcp-cloudkms/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["google_app_creds_present"] is True
    assert body["status"] == "empty"
    _reset()


def test_capability_summary_unavailable_when_creds_file_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(tmp_path / "nope.json"))
    app, _ = _build_app(tmp_path, creds_path=str(tmp_path / "nope.json"))
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/gcp-cloudkms/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["google_app_creds_present"] is False
    assert body["status"] == "unavailable"
    _reset()


# ---------------------------------------------------------------------------
# 503 — credentials missing on every live endpoint
# ---------------------------------------------------------------------------


def test_locations_returns_503_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations", headers=HEADERS
    )
    assert r.status_code == 503
    assert "GOOGLE_APPLICATION_CREDENTIALS" in r.json()["detail"]
    _reset()


def test_keyrings_returns_503_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations/us/keyRings",
        headers=HEADERS,
    )
    assert r.status_code == 503
    _reset()


def test_cryptokeys_returns_503_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations/us/keyRings/kr1/cryptoKeys",
        headers=HEADERS,
    )
    assert r.status_code == 503
    _reset()


def test_iam_policy_returns_503_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations/us/keyRings/kr1"
        "/cryptoKeys/ck1:getIamPolicy",
        headers=HEADERS,
        json={"options": {"requestedPolicyVersion": 3}},
    )
    assert r.status_code == 503
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx + pre-seeded token
# ---------------------------------------------------------------------------


def test_locations_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    raw = {
        "locations": [
            {
                "name": "projects/p1/locations/us-central1",
                "locationId": "us-central1",
                "displayName": "Iowa",
                "labels": {"region": "us"},
                "metadata": {"hsmAvailable": True},
            },
            {
                "name": "projects/p1/locations/europe-west1",
                "locationId": "europe-west1",
                "displayName": "Belgium",
            },
        ],
        "nextPageToken": "",
    }
    app, stub = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={"/projects/p1/locations": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["locations"]) == 2
    assert body["locations"][0]["locationId"] == "us-central1"
    assert body["locations"][0]["labels"] == {"region": "us"}
    assert body["locations"][1]["displayName"] == "Belgium"

    call = stub.calls[0]
    assert call["method"] == "GET"
    assert "/projects/p1/locations" in call["url"]
    assert call["headers"]["Authorization"] == "Bearer stub-bearer"
    _reset()


def test_keyrings_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    raw = {
        "keyRings": [
            {
                "name": "projects/p1/locations/us/keyRings/ring-1",
                "createTime": "2026-01-01T00:00:00Z",
            },
            {
                "name": "projects/p1/locations/us/keyRings/ring-2",
                "createTime": "2026-02-01T00:00:00Z",
            },
        ],
        "nextPageToken": "tok-2",
        "totalSize": 2,
    }
    app, stub = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={"/locations/us/keyRings": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations/us/keyRings"
        "?pageSize=10&pageToken=tok-1",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalSize"] == 2
    assert body["nextPageToken"] == "tok-2"
    assert len(body["keyRings"]) == 2
    assert body["keyRings"][0]["name"] == "projects/p1/locations/us/keyRings/ring-1"

    call = stub.calls[0]
    assert call["params"].get("pageSize") == 10
    assert call["params"].get("pageToken") == "tok-1"
    _reset()


def test_get_keyring_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    raw = {
        "name": "projects/p1/locations/us/keyRings/ring-1",
        "createTime": "2026-01-01T00:00:00Z",
    }
    app, _ = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={"/keyRings/ring-1": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations/us/keyRings/ring-1",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "projects/p1/locations/us/keyRings/ring-1"
    assert body["createTime"] == "2026-01-01T00:00:00Z"
    _reset()


def test_cryptokeys_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    raw = {
        "cryptoKeys": [
            {
                "name": "projects/p1/locations/us/keyRings/ring-1/cryptoKeys/key-a",
                "primary": {
                    "name": (
                        "projects/p1/locations/us/keyRings/ring-1/cryptoKeys/"
                        "key-a/cryptoKeyVersions/1"
                    ),
                    "state": "ENABLED",
                    "createTime": "2026-01-01T00:00:00Z",
                    "generateTime": "2026-01-01T00:00:01Z",
                    "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
                },
                "purpose": "ENCRYPT_DECRYPT",
                "createTime": "2026-01-01T00:00:00Z",
                "rotationPeriod": "7776000s",
                "versionTemplate": {
                    "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
                    "protectionLevel": "SOFTWARE",
                },
                "labels": {"env": "prod"},
            }
        ],
        "nextPageToken": "",
        "totalSize": 1,
    }
    app, stub = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={
            "/keyRings/ring-1/cryptoKeys": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations/us/keyRings/ring-1/cryptoKeys"
        "?pageSize=50&versionView=FULL",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalSize"] == 1
    ck = body["cryptoKeys"][0]
    assert ck["purpose"] == "ENCRYPT_DECRYPT"
    assert ck["primary"]["state"] == "ENABLED"
    assert ck["primary"]["algorithm"] == "GOOGLE_SYMMETRIC_ENCRYPTION"
    assert ck["versionTemplate"]["protectionLevel"] == "SOFTWARE"
    assert ck["labels"] == {"env": "prod"}

    call = stub.calls[0]
    assert call["params"].get("pageSize") == 50
    assert call["params"].get("versionView") == "FULL"
    _reset()


def test_get_cryptokey_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    raw = {
        "name": "projects/p1/locations/us/keyRings/ring-1/cryptoKeys/key-a",
        "purpose": "ASYMMETRIC_SIGN",
        "createTime": "2026-01-01T00:00:00Z",
        "versionTemplate": {
            "algorithm": "RSA_SIGN_PSS_2048_SHA256",
            "protectionLevel": "HSM",
        },
        "labels": {},
    }
    app, _ = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={
            "/cryptoKeys/key-a": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations/us/keyRings/ring-1"
        "/cryptoKeys/key-a",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["purpose"] == "ASYMMETRIC_SIGN"
    assert body["versionTemplate"]["protectionLevel"] == "HSM"
    _reset()


def test_versions_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    raw = {
        "cryptoKeyVersions": [
            {
                "name": (
                    "projects/p1/locations/us/keyRings/ring-1/cryptoKeys/key-a"
                    "/cryptoKeyVersions/1"
                ),
                "state": "ENABLED",
                "createTime": "2026-01-01T00:00:00Z",
                "generateTime": "2026-01-01T00:00:01Z",
                "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
                "attestation": {"format": "CAVIUM_V2_COMPRESSED"},
            },
            {
                "name": (
                    "projects/p1/locations/us/keyRings/ring-1/cryptoKeys/key-a"
                    "/cryptoKeyVersions/2"
                ),
                "state": "DESTROY_SCHEDULED",
                "createTime": "2026-02-01T00:00:00Z",
                "destroyTime": "2026-03-01T00:00:00Z",
                "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
            },
        ],
        "nextPageToken": "",
        "totalSize": 2,
    }
    app, stub = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={
            "/cryptoKeys/key-a/cryptoKeyVersions": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations/us/keyRings/ring-1"
        "/cryptoKeys/key-a/cryptoKeyVersions"
        "?view=FULL&filter=state%3DENABLED&orderBy=createTime",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalSize"] == 2
    assert body["cryptoKeyVersions"][0]["state"] == "ENABLED"
    assert body["cryptoKeyVersions"][1]["state"] == "DESTROY_SCHEDULED"
    assert body["cryptoKeyVersions"][0]["attestation"]["format"] == "CAVIUM_V2_COMPRESSED"

    call = stub.calls[0]
    assert call["params"].get("view") == "FULL"
    assert call["params"].get("filter") == "state=ENABLED"
    assert call["params"].get("orderBy") == "createTime"
    _reset()


def test_get_version_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    raw = {
        "name": (
            "projects/p1/locations/us/keyRings/ring-1/cryptoKeys/key-a"
            "/cryptoKeyVersions/1"
        ),
        "state": "ENABLED",
        "algorithm": "EC_SIGN_P256_SHA256",
        "createTime": "2026-01-01T00:00:00Z",
        "generateTime": "2026-01-01T00:00:01Z",
    }
    app, _ = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={
            "/cryptoKeyVersions/1": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations/us/keyRings/ring-1"
        "/cryptoKeys/key-a/cryptoKeyVersions/1",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == "ENABLED"
    assert body["algorithm"] == "EC_SIGN_P256_SHA256"
    _reset()


def test_iam_policy_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    raw = {
        "version": 3,
        "etag": "BwXyZ==",
        "bindings": [
            {
                "role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
                "members": ["serviceAccount:svc@p1.iam.gserviceaccount.com"],
            },
            {
                "role": "roles/cloudkms.viewer",
                "members": ["user:alice@example.com", "group:secops@example.com"],
            },
        ],
        "auditConfigs": [
            {
                "service": "cloudkms.googleapis.com",
                "auditLogConfigs": [{"logType": "DATA_READ"}],
            }
        ],
    }
    app, stub = _build_app(
        tmp_path,
        creds_path=str(sa),
        post_responses={
            "/cryptoKeys/key-a:getIamPolicy": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations/us/keyRings/ring-1"
        "/cryptoKeys/key-a:getIamPolicy",
        headers=HEADERS,
        json={"options": {"requestedPolicyVersion": 3}},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["version"] == 3
    assert body["etag"] == "BwXyZ=="
    assert len(body["bindings"]) == 2
    assert body["bindings"][0]["role"] == "roles/cloudkms.cryptoKeyEncrypterDecrypter"
    assert "alice" in body["bindings"][1]["members"][0]
    assert body["auditConfigs"][0]["service"] == "cloudkms.googleapis.com"

    post_call = next(c for c in stub.calls if c["method"] == "POST")
    assert post_call["json"] == {"options": {"requestedPolicyVersion": 3}}
    _reset()


def test_iam_policy_rejects_invalid_version(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    app, _ = _build_app(tmp_path, creds_path=str(sa))
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations/us/keyRings/ring-1"
        "/cryptoKeys/key-a:getIamPolicy",
        headers=HEADERS,
        json={"options": {"requestedPolicyVersion": 7}},
    )
    assert r.status_code == 422
    assert "1, 2 or 3" in r.json()["detail"]
    _reset()


def test_cryptokeys_translates_upstream_403_to_503(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    app, _ = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={
            "/keyRings/ring-1/cryptoKeys": _StubResponse(403, {"error": "denied"}),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations/us/keyRings/ring-1"
        "/cryptoKeys",
        headers=HEADERS,
    )
    assert r.status_code == 503
    assert "permission denied" in r.json()["detail"].lower()
    _reset()


def test_keyrings_translates_upstream_404_to_503(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    app, _ = _build_app(
        tmp_path,
        creds_path=str(sa),
        get_responses={
            "/locations/us/keyRings": _StubResponse(404, {"error": "missing"}),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-cloudkms/v1/projects/p1/locations/us/keyRings",
        headers=HEADERS,
    )
    assert r.status_code == 503
    assert "not found" in r.json()["detail"].lower()
    _reset()
