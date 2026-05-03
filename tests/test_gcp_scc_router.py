"""Tests for gcp_scc_router — ALDECI GCP Security Command Center.

NO MOCKS rule:
  * When GOOGLE_APPLICATION_CREDENTIALS is unset OR the file is missing,
    the capability summary reports ``status="unavailable"`` and every live
    SCC endpoint returns 503.
  * Happy-path tests inject a stub httpx.Client + an in-memory service-account
    key so we still exercise the real OAuth + parsing code paths.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
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

    def __init__(self, get_responses: Dict[str, Any], post_responses: Dict[str, Any]):
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
            {"method": "GET", "url": url, "params": params or {}, "headers": headers or {}}
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


# A throwaway service-account JSON key (PyJWT may not be installed in the
# test env; tests cover the cred-missing path against that). We still write
# a real file so ``Path.is_file()`` returns True.
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
    org_id: Optional[str],
    get_responses: Optional[Dict[str, Any]] = None,
    post_responses: Optional[Dict[str, Any]] = None,
):
    """Construct an isolated FastAPI app with the GCP SCC router mounted."""
    from core import gcp_scc_engine as engine_mod

    engine_mod.reset_gcp_scc_engine()
    stub = _StubClient(get_responses or {}, post_responses or {})

    eng = engine_mod.get_gcp_scc_engine(
        creds_path=creds_path,
        org_id=org_id,
        client=stub,
    )
    # Pre-seed token cache so we don't need PyJWT for happy-path tests.
    eng._token_cache["access_token"] = "stub-bearer"
    eng._token_cache["expires_at"] = 9_999_999_999.0

    from apps.api.gcp_scc_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


def _reset() -> None:
    from core import gcp_scc_engine as engine_mod
    engine_mod.reset_gcp_scc_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GCP_ORG_ID", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None, org_id=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/gcp-scc/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "GCP Security Command Center"
    assert "/findings" in body["endpoints"]
    assert "/sources" in body["endpoints"]
    assert "/assets" in body["endpoints"]
    assert "/findings/group" in body["endpoints"]
    assert "/findings/list" in body["endpoints"]
    assert body["google_app_creds_present"] is False
    assert body["org_id_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_empty_when_creds_present(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    monkeypatch.setenv("GCP_ORG_ID", "123456789")
    app, _ = _build_app(tmp_path, creds_path=str(sa), org_id="123456789")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/gcp-scc/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["google_app_creds_present"] is True
    assert body["org_id_present"] is True
    assert body["status"] == "empty"
    _reset()


def test_capability_summary_unavailable_when_creds_file_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(tmp_path / "nope.json"))
    monkeypatch.setenv("GCP_ORG_ID", "123456789")
    app, _ = _build_app(
        tmp_path, creds_path=str(tmp_path / "nope.json"), org_id="123456789"
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/gcp-scc/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["google_app_creds_present"] is False
    assert body["status"] == "unavailable"
    _reset()


# ---------------------------------------------------------------------------
# 503 — credentials missing
# ---------------------------------------------------------------------------


def test_findings_returns_503_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GCP_ORG_ID", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None, org_id=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/gcp-scc/findings?orgId=123", headers=HEADERS)
    assert r.status_code == 503
    assert "GOOGLE_APPLICATION_CREDENTIALS" in r.json()["detail"]
    _reset()


def test_sources_returns_503_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GCP_ORG_ID", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None, org_id=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/gcp-scc/sources?orgId=123", headers=HEADERS)
    assert r.status_code == 503
    _reset()


def test_assets_returns_503_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GCP_ORG_ID", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None, org_id=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/gcp-scc/assets?orgId=123", headers=HEADERS)
    assert r.status_code == 503
    _reset()


def test_group_returns_503_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GCP_ORG_ID", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None, org_id=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-scc/findings/group?orgId=123&groupBy=category", headers=HEADERS
    )
    assert r.status_code == 503
    _reset()


def test_set_mute_returns_503_when_no_creds(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GCP_ORG_ID", raising=False)
    app, _ = _build_app(tmp_path, creds_path=None, org_id=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/gcp-scc/findings/organizations/123/sources/1/findings/abc:setMute",
        headers=HEADERS,
        json={"mute": "MUTED"},
    )
    assert r.status_code == 503
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx + pre-seeded token
# ---------------------------------------------------------------------------


def test_findings_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    monkeypatch.setenv("GCP_ORG_ID", "123456789")
    raw = {
        "listFindingsResults": [
            {
                "finding": {
                    "name": "organizations/123456789/sources/55/findings/abc",
                    "parent": "organizations/123456789/sources/55",
                    "resourceName": "//storage.googleapis.com/my-bucket",
                    "state": "ACTIVE",
                    "category": "PUBLIC_BUCKET_ACL",
                    "externalUri": "https://console.cloud.google.com/storage",
                    "sourceProperties": {"SeverityLevel": "High"},
                    "securityMarks": {
                        "name": "organizations/123456789/sources/55/findings/abc/securityMarks",
                        "marks": {"reviewed": "true"},
                    },
                    "eventTime": "2026-01-01T00:00:00Z",
                    "createTime": "2026-01-01T00:00:00Z",
                    "severity": "HIGH",
                }
            }
        ],
        "totalSize": 1,
        "nextPageToken": "tok-2",
    }
    app, stub = _build_app(
        tmp_path,
        creds_path=str(sa),
        org_id="123456789",
        get_responses={"/sources/-/findings": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-scc/findings?orgId=123456789&filter=severity%3D%22HIGH%22"
        "&pageSize=10",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalSize"] == 1
    assert body["nextPageToken"] == "tok-2"
    assert body["findings"][0]["category"] == "PUBLIC_BUCKET_ACL"
    assert body["findings"][0]["severity"] == "HIGH"
    assert body["findings"][0]["securityMarks"]["marks"]["reviewed"] == "true"

    # Bearer token + filter forwarded to the SCC URL
    call = stub.calls[0]
    assert call["method"] == "GET"
    assert "/sources/-/findings" in call["url"]
    assert call["headers"]["Authorization"] == "Bearer stub-bearer"
    assert call["params"].get("filter") == 'severity="HIGH"'
    assert call["params"].get("pageSize") == 10
    _reset()


def test_sources_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    monkeypatch.setenv("GCP_ORG_ID", "123456789")
    raw = {
        "sources": [
            {
                "name": "organizations/123456789/sources/55",
                "displayName": "Security Health Analytics",
                "description": "Managed vuln scanner.",
                "canonicalName": "organizations/123456789/sources/55",
            },
            {
                "name": "organizations/123456789/sources/77",
                "displayName": "Event Threat Detection",
                "description": "Threat det.",
            },
        ],
        "nextPageToken": "",
    }
    app, _ = _build_app(
        tmp_path,
        creds_path=str(sa),
        org_id="123456789",
        get_responses={"/organizations/123456789/sources": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/gcp-scc/sources?orgId=123456789", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["sources"]) == 2
    assert body["sources"][0]["displayName"] == "Security Health Analytics"
    # canonicalName falls back to name when missing
    assert body["sources"][1]["canonicalName"] == "organizations/123456789/sources/77"
    _reset()


def test_assets_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    monkeypatch.setenv("GCP_ORG_ID", "123456789")
    raw = {
        "listAssetsResults": [
            {
                "asset": {
                    "name": "organizations/123456789/assets/asset-001",
                    "securityCenterProperties": {
                        "resourceName": "//storage.googleapis.com/my-bucket",
                        "resourceType": "google.cloud.storage.Bucket",
                        "resourceParent": "//cloudresourcemanager.googleapis.com/projects/p1",
                        "resourceProject": "projects/123",
                        "resourceOwners": ["user:owner@example.com"],
                    },
                    "resourceProperties": {"location": "US"},
                },
                "stateChange": "ACTIVE",
            }
        ],
        "totalSize": 1,
        "nextPageToken": "",
    }
    app, _ = _build_app(
        tmp_path,
        creds_path=str(sa),
        org_id="123456789",
        get_responses={"/organizations/123456789/assets": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/gcp-scc/assets?orgId=123456789", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalSize"] == 1
    asset = body["listAssetsResults"][0]["asset"]
    assert asset["securityCenterProperties"]["resourceType"] == "google.cloud.storage.Bucket"
    assert asset["resourceProperties"]["location"] == "US"
    assert body["listAssetsResults"][0]["stateChange"] == "ACTIVE"
    _reset()


def test_group_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    monkeypatch.setenv("GCP_ORG_ID", "123456789")
    raw = {
        "groupByResults": [
            {"properties": {"category": "PUBLIC_BUCKET_ACL"}, "count": 5},
            {"properties": {"category": "OPEN_FIREWALL"}, "count": 3},
        ],
        "totalSize": 2,
    }
    app, stub = _build_app(
        tmp_path,
        creds_path=str(sa),
        org_id="123456789",
        post_responses={"/sources/-/findings:group": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-scc/findings/group?orgId=123456789&groupBy=category",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalSize"] == 2
    assert body["groupByResults"][0]["count"] == 5
    assert body["groupByResults"][0]["properties"]["category"] == "PUBLIC_BUCKET_ACL"

    post_call = next(c for c in stub.calls if c["method"] == "POST")
    assert post_call["json"]["groupBy"] == "category"
    _reset()


def test_set_mute_happy_path(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    monkeypatch.setenv("GCP_ORG_ID", "123456789")
    finding_name = "organizations/123456789/sources/55/findings/abc"
    raw = {
        "name": finding_name,
        "state": "ACTIVE",
        "mute": "MUTED",
        "category": "PUBLIC_BUCKET_ACL",
    }
    app, stub = _build_app(
        tmp_path,
        creds_path=str(sa),
        org_id="123456789",
        post_responses={f"/{finding_name}:setMute": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        f"/api/v1/gcp-scc/findings/{finding_name}:setMute",
        headers=HEADERS,
        json={"mute": "MUTED"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mute"] == "MUTED"
    assert body["name"] == finding_name

    post_call = next(c for c in stub.calls if c["method"] == "POST")
    assert post_call["json"] == {"mute": "MUTED"}
    _reset()


def test_set_mute_rejects_invalid_value(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    monkeypatch.setenv("GCP_ORG_ID", "123456789")
    app, _ = _build_app(
        tmp_path, creds_path=str(sa), org_id="123456789"
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/gcp-scc/findings/organizations/123/sources/1/findings/abc:setMute",
        headers=HEADERS,
        json={"mute": "BOGUS"},
    )
    assert r.status_code == 422
    assert "MUTED" in r.json()["detail"]
    _reset()


def test_findings_translates_upstream_403_to_503(tmp_path, monkeypatch):
    sa = _write_fake_sa(tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    monkeypatch.setenv("GCP_ORG_ID", "123456789")
    app, _ = _build_app(
        tmp_path,
        creds_path=str(sa),
        org_id="123456789",
        get_responses={
            "/sources/-/findings": _StubResponse(403, {"error": "denied"})
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/gcp-scc/findings?orgId=123456789", headers=HEADERS
    )
    assert r.status_code == 503
    assert "permission denied" in r.json()["detail"].lower()
    _reset()
