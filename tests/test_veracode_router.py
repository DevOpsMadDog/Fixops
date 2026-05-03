"""Tests for veracode_router — ALDECI.

Spins up a minimal FastAPI app with the Veracode router mounted. Each test
gets an isolated engine singleton with a stub httpx.Client.

NO MOCKS rule:
  * /appsec/v1/applications, /appsec/v1/applications/{guid},
    /appsec/v2/applications/{guid}/findings,
    /appsec/v1/findings/{id}/annotations, /appsec/v1/policies
    return HTTP 503 when VERACODE_API_ID / VERACODE_API_KEY are unset.
  * Capability summary reports ``status="unavailable"`` when creds missing.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real signing + parsing code paths.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from tests.conftest import API_TOKEN

from fastapi import FastAPI
from fastapi.testclient import TestClient

HEADERS = {"X-API-Key": API_TOKEN}

# Hex strings used as test API key bytes (HMAC requires hex-decodable key).
VALID_HEX_KEY = "deadbeefcafefacef00dfeedbabe1234deadbeefcafefacef00dfeedbabe5678"


# ---------------------------------------------------------------------------
# httpx stubs
# ---------------------------------------------------------------------------


class _StubResponse:
    """Minimal stand-in for httpx.Response with .json() + .status_code."""

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
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):  # noqa: D401
        self.calls.append(
            {"method": "GET", "url": url, "headers": headers or {}, "params": params or {}}
        )
        return self._match(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(
    *,
    api_id: Optional[str],
    api_key: Optional[str],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine bound to a stub client."""
    from core import veracode_engine as engine_mod

    engine_mod.reset_veracode_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_veracode_engine(
        api_id=api_id, api_key=api_key, client=stub_client
    )

    from apps.api.veracode_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import veracode_engine as engine_mod

    engine_mod.reset_veracode_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("VERACODE_API_ID", raising=False)
    monkeypatch.delenv("VERACODE_API_KEY", raising=False)
    app, _ = _build_app(api_id=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/veracode/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Veracode"
    assert "/appsec/v1/applications" in body["endpoints"]
    assert "/appsec/v1/applications/{guid}" in body["endpoints"]
    assert "/appsec/v2/applications/{guid}/findings" in body["endpoints"]
    assert "/appsec/v1/findings/{id}/annotations" in body["endpoints"]
    assert "/appsec/v1/policies" in body["endpoints"]
    assert body["veracode_api_id_present"] is False
    assert body["veracode_api_key_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_creds_present(monkeypatch):
    monkeypatch.setenv("VERACODE_API_ID", "test-id")
    monkeypatch.setenv("VERACODE_API_KEY", VALID_HEX_KEY)
    app, _ = _build_app(
        api_id="test-id", api_key=VALID_HEX_KEY, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/veracode/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["veracode_api_id_present"] is True
    assert body["veracode_api_key_present"] is True
    assert body["status"] == "ok"
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when no creds
# ---------------------------------------------------------------------------


def test_applications_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("VERACODE_API_ID", raising=False)
    monkeypatch.delenv("VERACODE_API_KEY", raising=False)
    app, _ = _build_app(api_id=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/veracode/appsec/v1/applications", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "VERACODE" in r.json()["detail"]
    _reset()


def test_get_application_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("VERACODE_API_ID", raising=False)
    monkeypatch.delenv("VERACODE_API_KEY", raising=False)
    app, _ = _build_app(api_id=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/veracode/appsec/v1/applications/abc-123", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    _reset()


def test_findings_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("VERACODE_API_ID", raising=False)
    monkeypatch.delenv("VERACODE_API_KEY", raising=False)
    app, _ = _build_app(api_id=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/veracode/appsec/v2/applications/abc-123/findings",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_annotations_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("VERACODE_API_ID", raising=False)
    monkeypatch.delenv("VERACODE_API_KEY", raising=False)
    app, _ = _build_app(api_id=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/veracode/appsec/v1/findings/9999/annotations",
        params={"app_guid": "abc-123"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_policies_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("VERACODE_API_ID", raising=False)
    monkeypatch.delenv("VERACODE_API_KEY", raising=False)
    app, _ = _build_app(api_id=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/veracode/appsec/v1/policies", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_list_applications_happy_path(monkeypatch):
    monkeypatch.setenv("VERACODE_API_ID", "test-id")
    monkeypatch.setenv("VERACODE_API_KEY", VALID_HEX_KEY)
    raw = {
        "_embedded": {
            "applications": [
                {
                    "guid": "app-uuid-1",
                    "id": 12345,
                    "profile": {
                        "name": "Acme Web",
                        "business_criticality": "VERY_HIGH",
                        "business_owners": [
                            {"email": "owner@acme.test", "name": "Owner"}
                        ],
                        "business_unit": {
                            "guid": "bu-uuid-1",
                            "name": "Engineering",
                        },
                        "policies": [
                            {
                                "guid": "pol-1",
                                "name": "Veracode Recommended",
                                "policy_compliance_status": "DID_NOT_PASS",
                            }
                        ],
                        "settings": {
                            "dynamic_scan_approval_not_required": False,
                            "nextday_consultation_allowed": True,
                            "sca_enabled": True,
                            "static_scan_dependencies_allowed": False,
                        },
                    },
                    "scans": [
                        {
                            "scan_type": "STATIC",
                            "internal_status": "PUBLISHED",
                            "modified_date": "2026-04-01T12:00:00Z",
                            "status": "FINISHED",
                            "fullname": "Acme Web",
                            "scan_url": "https://web.veracode.com/scan/1",
                        }
                    ],
                    "created": "2025-01-01T00:00:00Z",
                    "modified": "2026-04-01T12:00:00Z",
                    "last_completed_scan_date": "2026-04-01T12:00:00Z",
                    "last_policy_compliance_check_date": "2026-04-01T12:00:00Z",
                    "oss_components_count": 47,
                    "status": "UPDATED",
                }
            ]
        },
        "page": {
            "number": 0,
            "size": 1,
            "total_elements": 1,
            "total_pages": 1,
        },
    }
    app, stub = _build_app(
        api_id="test-id",
        api_key=VALID_HEX_KEY,
        stub_responses={"/appsec/v1/applications": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/veracode/appsec/v1/applications",
        params={"size": 1, "page": 0, "name": "Acme"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "_embedded" in body
    apps = body["_embedded"]["applications"]
    assert len(apps) == 1
    assert apps[0]["guid"] == "app-uuid-1"
    assert apps[0]["profile"]["business_criticality"] == "VERY_HIGH"
    assert apps[0]["scans"][0]["scan_type"] == "STATIC"
    assert body["page"]["total_elements"] == 1

    # Auth header was assembled correctly
    auth = stub.calls[0]["headers"]["Authorization"]
    assert auth.startswith("VERACODE-HMAC-SHA-256 ")
    assert "id=test-id" in auth
    assert "ts=" in auth
    assert "nonce=" in auth
    assert "sig=" in auth
    # Params forwarded to upstream
    upstream_params = stub.calls[0]["params"]
    assert upstream_params["size"] == 1
    assert upstream_params["name"] == "Acme"
    _reset()


def test_get_application_happy_path(monkeypatch):
    monkeypatch.setenv("VERACODE_API_ID", "test-id")
    monkeypatch.setenv("VERACODE_API_KEY", VALID_HEX_KEY)
    raw = {
        "guid": "app-uuid-1",
        "id": 12345,
        "profile": {"name": "Acme Web"},
        "status": "UPDATED",
    }
    app, _ = _build_app(
        api_id="test-id",
        api_key=VALID_HEX_KEY,
        stub_responses={
            "/appsec/v1/applications/app-uuid-1": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/veracode/appsec/v1/applications/app-uuid-1", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["guid"] == "app-uuid-1"
    assert body["profile"]["name"] == "Acme Web"
    _reset()


def test_list_findings_happy_path(monkeypatch):
    monkeypatch.setenv("VERACODE_API_ID", "test-id")
    monkeypatch.setenv("VERACODE_API_KEY", VALID_HEX_KEY)
    raw = {
        "_embedded": {
            "findings": [
                {
                    "issue_id": 9001,
                    "scan_type": "STATIC",
                    "violates_policy": True,
                    "finding_status": {
                        "status": "OPEN",
                        "first_found_date": "2026-04-01T12:00:00Z",
                        "last_seen_date": "2026-04-25T12:00:00Z",
                        "new_finding": False,
                        "resolution": "UNRESOLVED",
                        "resolution_status": "NONE",
                        "mitigation_review_status": "NONE",
                        "reopened_finding": False,
                        "mitigations": [],
                    },
                    "finding_details": {
                        "severity": 4,
                        "cwe": {"id": 89, "name": "SQL Injection"},
                        "file_name": "Repo.java",
                        "file_line_number": 42,
                    },
                }
            ]
        },
        "page": {"number": 0, "size": 1, "total_elements": 1, "total_pages": 1},
    }
    app, stub = _build_app(
        api_id="test-id",
        api_key=VALID_HEX_KEY,
        stub_responses={
            "/appsec/v2/applications/app-uuid-1/findings": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/veracode/appsec/v2/applications/app-uuid-1/findings",
        params={
            "size": 50,
            "page": 0,
            "scan_type": "STATIC",
            "severity_gte": 3,
            "violates_policy": "true",
            "include_annot": "true",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    findings = body["_embedded"]["findings"]
    assert len(findings) == 1
    assert findings[0]["issue_id"] == 9001
    assert findings[0]["scan_type"] == "STATIC"
    assert findings[0]["violates_policy"] is True
    assert findings[0]["finding_status"]["status"] == "OPEN"

    # Forwarded params include the filter set
    upstream_params = stub.calls[0]["params"]
    assert upstream_params["scan_type"] == "STATIC"
    assert upstream_params["severity_gte"] == 3
    assert upstream_params["violates_policy"] == "true"
    _reset()


def test_list_findings_rejects_invalid_scan_type(monkeypatch):
    """FastAPI Query validator rejects unknown scan_type with 422 before
    dispatching to the engine."""
    monkeypatch.setenv("VERACODE_API_ID", "test-id")
    monkeypatch.setenv("VERACODE_API_KEY", VALID_HEX_KEY)
    app, _ = _build_app(
        api_id="test-id", api_key=VALID_HEX_KEY, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/veracode/appsec/v2/applications/app-uuid-1/findings",
        params={"scan_type": "FUZZ"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text
    _reset()


def test_list_findings_rejects_invalid_severity(monkeypatch):
    monkeypatch.setenv("VERACODE_API_ID", "test-id")
    monkeypatch.setenv("VERACODE_API_KEY", VALID_HEX_KEY)
    app, _ = _build_app(
        api_id="test-id", api_key=VALID_HEX_KEY, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/veracode/appsec/v2/applications/app-uuid-1/findings",
        params={"severity": 9},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text
    _reset()


def test_list_annotations_happy_path(monkeypatch):
    monkeypatch.setenv("VERACODE_API_ID", "test-id")
    monkeypatch.setenv("VERACODE_API_KEY", VALID_HEX_KEY)
    raw = {
        "_embedded": {
            "annotations": [
                {
                    "action": "COMMENT",
                    "comment": "investigating",
                    "created": "2026-04-15T10:00:00Z",
                    "finding_id": 9001,
                    "reviewer": {"id": 42, "name": "Sec Engineer"},
                }
            ]
        }
    }
    app, _ = _build_app(
        api_id="test-id",
        api_key=VALID_HEX_KEY,
        stub_responses={
            "/appsec/v1/findings/9001/annotations": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/veracode/appsec/v1/findings/9001/annotations",
        params={"app_guid": "app-uuid-1"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    annots = body["_embedded"]["annotations"]
    assert len(annots) == 1
    assert annots[0]["action"] == "COMMENT"
    assert annots[0]["finding_id"] == 9001
    _reset()


def test_list_annotations_requires_app_guid(monkeypatch):
    monkeypatch.setenv("VERACODE_API_ID", "test-id")
    monkeypatch.setenv("VERACODE_API_KEY", VALID_HEX_KEY)
    app, _ = _build_app(
        api_id="test-id", api_key=VALID_HEX_KEY, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/veracode/appsec/v1/findings/9001/annotations", headers=HEADERS
    )
    assert r.status_code == 422, r.text
    _reset()


def test_list_policies_happy_path(monkeypatch):
    monkeypatch.setenv("VERACODE_API_ID", "test-id")
    monkeypatch.setenv("VERACODE_API_KEY", VALID_HEX_KEY)
    raw = {
        "_embedded": {
            "policy_versions": [
                {
                    "guid": "pol-uuid-1",
                    "name": "Veracode Recommended",
                    "description": "Default recommended policy",
                    "type": "SYSTEM",
                    "capet_non_compliance_severity": 4,
                    "finding_rules": [
                        {
                            "type": "SEVERITY",
                            "value": "4",
                            "scan_type": "STATIC",
                            "severity": 4,
                        }
                    ],
                }
            ]
        },
        "page": {"number": 0, "size": 1, "total_elements": 1, "total_pages": 1},
    }
    app, _ = _build_app(
        api_id="test-id",
        api_key=VALID_HEX_KEY,
        stub_responses={"/appsec/v1/policies": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/veracode/appsec/v1/policies",
        params={"name": "Veracode", "size": 1, "page": 0},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    pols = body["_embedded"]["policy_versions"]
    assert len(pols) == 1
    assert pols[0]["guid"] == "pol-uuid-1"
    assert pols[0]["type"] == "SYSTEM"
    _reset()


# ---------------------------------------------------------------------------
# Upstream error paths
# ---------------------------------------------------------------------------


def test_applications_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("VERACODE_API_ID", "test-id")
    monkeypatch.setenv("VERACODE_API_KEY", VALID_HEX_KEY)
    app, _ = _build_app(
        api_id="test-id",
        api_key=VALID_HEX_KEY,
        stub_responses={
            "/appsec/v1/applications": _StubResponse(
                429, {"error": "rate limit"}, text="rate limit"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/veracode/appsec/v1/applications", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"].lower()
    assert "rate-limit" in detail or "429" in detail
    _reset()


def test_findings_returns_503_on_upstream_401(monkeypatch):
    monkeypatch.setenv("VERACODE_API_ID", "bad-id")
    monkeypatch.setenv("VERACODE_API_KEY", VALID_HEX_KEY)
    app, _ = _build_app(
        api_id="bad-id",
        api_key=VALID_HEX_KEY,
        stub_responses={
            "/appsec/v2/applications/abc/findings": _StubResponse(
                401, {"error": "unauthorized"}, text="unauthorized"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/veracode/appsec/v2/applications/abc/findings",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "401" in r.json()["detail"] or "credential" in r.json()["detail"].lower()
    _reset()


def test_engine_rejects_non_hex_key(monkeypatch):
    """A non-hex API key surfaces as 503 (credentials un-usable)."""
    monkeypatch.setenv("VERACODE_API_ID", "test-id")
    monkeypatch.setenv("VERACODE_API_KEY", "not-hex-at-all-zzzz")
    app, _ = _build_app(
        api_id="test-id",
        api_key="not-hex-at-all-zzzz",
        stub_responses={"/appsec/v1/applications": _StubResponse(200, {})},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/veracode/appsec/v1/applications", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "hex" in r.json()["detail"].lower()
    _reset()
