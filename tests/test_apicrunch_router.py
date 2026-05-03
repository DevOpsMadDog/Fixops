"""Tests for apicrunch_router — ALDECI.

Spins up a minimal FastAPI app with the 42Crunch router mounted. Each test
gets an isolated engine singleton with a stub httpx.Client.

NO MOCKS rule:
  * Live endpoints return HTTP 503 when APICRUNCH_API_TOKEN is unset.
  * Capability summary reports ``status="unavailable"`` with no token.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real networking + parsing code paths.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}


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
        # Prefer the longest matching suffix to avoid /scanReport vs
        # /scanReport/{id} collisions.
        candidates = sorted(
            (p for p in self._responses if p in url),
            key=len,
            reverse=True,
        )
        if candidates:
            return self._responses[candidates[0]]
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

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ):  # noqa: D401, A002 (json is keyword used by httpx)
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": headers or {},
                "params": params or {},
                "json": json or {},
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
):
    """Construct an isolated app+engine bound to a stub client."""
    from core import apicrunch_engine as engine_mod

    engine_mod.reset_apicrunch_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_apicrunch_engine(api_key=api_key, client=stub_client)

    from apps.api.apicrunch_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import apicrunch_engine as engine_mod

    engine_mod.reset_apicrunch_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_token(monkeypatch):
    monkeypatch.delenv("APICRUNCH_API_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/apicrunch/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "42Crunch"
    assert "/api/v2/collections" in body["endpoints"]
    assert "/api/v2/apis" in body["endpoints"]
    assert "/api/v2/apis/{id}/auditReport" in body["endpoints"]
    assert "/api/v2/apis/{id}/scan" in body["endpoints"]
    assert "/api/v2/apis/{id}/scanReport" in body["endpoints"]
    assert body["apicrunch_api_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_token_present(monkeypatch):
    monkeypatch.setenv("APICRUNCH_API_TOKEN", "test-token")
    app, _ = _build_app(api_key="test-token", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/apicrunch/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["apicrunch_api_token_present"] is True
    assert body["status"] == "ok"
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when no token
# ---------------------------------------------------------------------------


def test_collections_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("APICRUNCH_API_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/apicrunch/api/v2/collections", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "APICRUNCH_API_TOKEN" in r.json()["detail"]
    _reset()


def test_collection_apis_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("APICRUNCH_API_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apicrunch/api/v2/collections/coll-1/apis",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_audit_report_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("APICRUNCH_API_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apicrunch/api/v2/apis/api-1/auditReport",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_scan_trigger_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("APICRUNCH_API_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/apicrunch/api/v2/apis/api-1/scan",
        json={"scanConfiguration": {"useDefaults": True, "parameters": {}}},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_scan_report_latest_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("APICRUNCH_API_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apicrunch/api/v2/apis/api-1/scanReport",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_collections_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("APICRUNCH_API_TOKEN", "test-token")
    raw = {
        "list": [
            {
                "desc": {
                    "id": "coll-uuid-1",
                    "name": "Payments APIs",
                    "description": "All payment surfaces",
                    "source": "API",
                    "owner": {
                        "id": "u-1",
                        "name": "Sec Lead",
                        "email": "sec@acme.io",
                    },
                    "source_id": "src-1",
                    "source_name": "github",
                    "summary": {"apis": 4, "requirements": 12},
                },
                "sharing": {
                    "groups": [
                        {
                            "group_id": "g-1",
                            "name": "AppSec",
                            "scope": "FULL_ACCESS",
                        }
                    ],
                    "users": [
                        {"user_id": "u-2", "scope": "READ_ONLY"}
                    ],
                },
                "write": True,
                "read": True,
                "requirements": [],
            }
        ],
        "totalCount": 1,
    }
    app, stub = _build_app(
        api_key="test-token",
        stub_responses={"/api/v2/collections": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apicrunch/api/v2/collections",
        params={"listOption": "ALL", "limit": 10, "page": 0},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalCount"] == 1
    assert len(body["list"]) == 1
    entry = body["list"][0]
    assert entry["desc"]["id"] == "coll-uuid-1"
    assert entry["desc"]["source"] == "API"
    assert entry["desc"]["owner"]["email"] == "sec@acme.io"
    assert entry["desc"]["summary"]["apis"] == 4
    assert entry["sharing"]["groups"][0]["scope"] == "FULL_ACCESS"
    assert entry["sharing"]["users"][0]["scope"] == "READ_ONLY"
    # Authorization header was set as Bearer token
    assert (
        stub.calls[0]["headers"]["Authorization"] == "Bearer test-token"
    )
    # listOption is forwarded
    assert stub.calls[0]["params"]["listOption"] == "ALL"
    _reset()


def test_collection_apis_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("APICRUNCH_API_TOKEN", "test-token")
    raw = {
        "list": [
            {
                "desc": {
                    "id": "api-uuid-1",
                    "name": "PaymentsV2",
                    "cid": "coll-uuid-1",
                    "technicalName": "payments-v2",
                    "description": "Stripe-style payments",
                    "owner": {"id": "u-1", "name": "Owner", "email": "o@x"},
                    "summary": {
                        "errors": 1,
                        "warnings": 3,
                        "info": 5,
                        "low": 2,
                        "medium": 4,
                        "high": 1,
                        "critical": 0,
                    },
                    "score": 84.2,
                    "audit": {
                        "score": 84.2,
                        "latestAuditId": "audit-1",
                        "latestAuditDate": "2026-05-01T00:00:00Z",
                        "lastAuditScore": 80.0,
                    },
                },
                "write": False,
                "read": True,
            }
        ],
        "totalCount": 1,
    }
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/v2/collections/coll-uuid-1/apis": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apicrunch/api/v2/collections/coll-uuid-1/apis",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalCount"] == 1
    assert body["list"][0]["desc"]["id"] == "api-uuid-1"
    assert body["list"][0]["desc"]["summary"]["high"] == 1
    assert body["list"][0]["desc"]["audit"]["latestAuditId"] == "audit-1"
    # The collection-apis listing should not include a scan block
    assert body["list"][0]["desc"].get("scan") is None
    assert body["list"][0]["read"] is True
    _reset()


def test_get_api_includes_scan_block(monkeypatch):
    monkeypatch.setenv("APICRUNCH_API_TOKEN", "test-token")
    raw = {
        "desc": {
            "id": "api-uuid-1",
            "name": "PaymentsV2",
            "cid": "coll-uuid-1",
            "technicalName": "payments-v2",
            "description": "Stripe-style payments",
            "owner": {"id": "u-1", "name": "Owner", "email": "o@x"},
            "summary": {
                "errors": 1,
                "warnings": 3,
                "info": 5,
                "low": 2,
                "medium": 4,
                "high": 1,
                "critical": 0,
            },
            "score": 84.2,
            "audit": {
                "score": 84.2,
                "latestAuditId": "audit-1",
                "latestAuditDate": "2026-05-01T00:00:00Z",
                "lastAuditScore": 80.0,
            },
            "scan": {
                "conformanceScore": 92.5,
                "latestScanId": "scan-1",
                "latestScanDate": "2026-05-02T00:00:00Z",
            },
        }
    }
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={"/api/v2/apis/api-uuid-1": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/apicrunch/api/v2/apis/api-uuid-1", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["desc"]["id"] == "api-uuid-1"
    assert body["desc"]["scan"]["conformanceScore"] == 92.5
    assert body["desc"]["scan"]["latestScanId"] == "scan-1"
    _reset()


def test_audit_report_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("APICRUNCH_API_TOKEN", "test-token")
    raw = {
        "data": {
            "report": {
                "summary": {
                    "score": 78.0,
                    "criticality": "HIGH",
                    "errors": [
                        {
                            "id": "err-1",
                            "severity": "CRITICAL",
                            "code": "missing-auth",
                            "message": "Endpoint missing security",
                            "pointer": "/paths/~1pay/post",
                            "requirementId": "req-1",
                            "severityRationale": "Unauthenticated POST",
                        }
                    ],
                    "warnings": [
                        {
                            "id": "warn-1",
                            "severity": "MEDIUM",
                            "code": "weak-schema",
                            "message": "Schema permissive",
                            "pointer": "/components/schemas/Pay",
                            "requirementId": "",
                            "severityRationale": "",
                        }
                    ],
                    "info": [],
                    "details": {"version": "3.1"},
                    "scoringRules": {"weights": {"critical": 30}},
                }
            }
        }
    }
    app, stub = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/v2/apis/api-uuid-1/auditReport": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apicrunch/api/v2/apis/api-uuid-1/auditReport",
        params={"reportType": "FINDINGS"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    summary = body["data"]["report"]["summary"]
    assert summary["score"] == 78.0
    assert summary["criticality"] == "HIGH"
    assert len(summary["errors"]) == 1
    assert summary["errors"][0]["severity"] == "CRITICAL"
    assert summary["errors"][0]["code"] == "missing-auth"
    assert summary["details"] == {"version": "3.1"}
    assert summary["scoringRules"]["weights"]["critical"] == 30
    # reportType forwarded
    assert stub.calls[0]["params"]["reportType"] == "FINDINGS"
    _reset()


def test_audit_report_invalid_report_type_rejected(monkeypatch):
    """FastAPI Query validator rejects unknown reportType (422)."""
    monkeypatch.setenv("APICRUNCH_API_TOKEN", "test-token")
    app, _ = _build_app(api_key="test-token", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apicrunch/api/v2/apis/api-1/auditReport",
        params={"reportType": "BOGUS"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text
    _reset()


def test_scan_trigger_happy_path(monkeypatch):
    monkeypatch.setenv("APICRUNCH_API_TOKEN", "test-token")
    raw = {"scanId": "scan-uuid-9", "status": "queued"}
    app, stub = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/v2/apis/api-uuid-1/scan": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/apicrunch/api/v2/apis/api-uuid-1/scan",
        json={"scanConfiguration": {"useDefaults": True, "parameters": {}}},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scanId"] == "scan-uuid-9"
    assert body["status"] == "queued"
    posted = stub.calls[0]["json"]
    assert posted["scanConfiguration"]["useDefaults"] is True
    _reset()


def test_scan_report_latest_happy_path(monkeypatch):
    monkeypatch.setenv("APICRUNCH_API_TOKEN", "test-token")
    raw = {
        "data": {
            "summary": {
                "conformanceScore": 88.0,
                "errors": 2,
                "warnings": 5,
                "vulnerabilities": 3,
                "executionTime": 12.5,
                "totalRequests": 42,
                "totalIssues": 10,
            },
            "paths": [
                {
                    "path": "/payments",
                    "method": "POST",
                    "statusCode": "200",
                    "expectations": [],
                    "findings": [
                        {
                            "type": "security",
                            "severity": "HIGH",
                            "status": "FAIL",
                            "message": "Missing CSRF",
                            "request": {"headers": {}},
                            "response": {"status": 200},
                            "cwe": "CWE-352",
                            "owasp": ["API2:2023"],
                            "description": "Cross-site request forgery",
                        }
                    ],
                }
            ],
        }
    }
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/v2/apis/api-uuid-1/scanReport": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apicrunch/api/v2/apis/api-uuid-1/scanReport",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    summary = body["data"]["summary"]
    assert summary["conformanceScore"] == 88.0
    assert summary["totalIssues"] == 10
    assert len(body["data"]["paths"]) == 1
    finding = body["data"]["paths"][0]["findings"][0]
    assert finding["severity"] == "HIGH"
    assert finding["cwe"] == "CWE-352"
    assert finding["owasp"] == ["API2:2023"]
    _reset()


def test_scan_report_by_id_routes_to_specific_path(monkeypatch):
    monkeypatch.setenv("APICRUNCH_API_TOKEN", "test-token")
    raw = {
        "data": {
            "summary": {
                "conformanceScore": 91.0,
                "errors": 0,
                "warnings": 1,
                "vulnerabilities": 0,
                "executionTime": 7.1,
                "totalRequests": 33,
                "totalIssues": 1,
            },
            "paths": [],
        }
    }
    app, stub = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/v2/apis/api-uuid-1/scanReport/scan-9": _StubResponse(
                200, raw
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apicrunch/api/v2/apis/api-uuid-1/scanReport/scan-9",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["summary"]["conformanceScore"] == 91.0
    # Confirm we hit the suffixed path (not the latest one)
    assert any(
        "/scanReport/scan-9" in c["url"] for c in stub.calls
    ), [c["url"] for c in stub.calls]
    _reset()


# ---------------------------------------------------------------------------
# Upstream error paths
# ---------------------------------------------------------------------------


def test_collections_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("APICRUNCH_API_TOKEN", "test-token")
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={
            "/api/v2/collections": _StubResponse(
                429, {"error": "rate limit"}, text="rate limit"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/apicrunch/api/v2/collections", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "rate-limit" in detail.lower() or "429" in detail
    _reset()


def test_audit_report_returns_503_on_upstream_401(monkeypatch):
    monkeypatch.setenv("APICRUNCH_API_TOKEN", "bad-token")
    app, _ = _build_app(
        api_key="bad-token",
        stub_responses={
            "/api/v2/apis/api-1/auditReport": _StubResponse(
                401, {"error": "unauthorized"}, text="unauthorized"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/apicrunch/api/v2/apis/api-1/auditReport",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "401" in detail or "credential" in detail.lower()
    _reset()
