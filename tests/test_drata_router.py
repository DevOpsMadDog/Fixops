"""Router-level HTTP tests for Drata Compliance pass-through API.

Covers /api/v1/drata/* via FastAPI TestClient with a stub httpx.Client
so no real Drata call is made.

Tests:
1. GET /                            — capability summary (unavailable when env unset)
2. GET /                            — capability summary (ok when env set)
3. GET /api/controls                — list controls with filters & paging cursor
4. GET /api/controls/{id}           — single control
5. GET /api/controls/{id}/tests     — control tests
6. GET /api/integrations            — integrations
7. GET /api/audits                  — audits with framework filter
8. GET /api/people                  — people with role filter
9. GET /api/findings                — findings with severity filter
10. GET /api/policies?published=true
11. unavailable env returns 503 on lookup endpoint
12. upstream 404 surfaces as 404 with payload echo
13. invalid framework filter rejected (422)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite paths are importable regardless of cwd
for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

import apps.api.drata_router as _router_mod
from apps.api.drata_router import router
from core.drata_compliance_engine import (
    DrataComplianceEngine,
    reset_drata_compliance_engine,
)


# ---------------------------------------------------------------------------
# Stub httpx.Client
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code: int, json_payload: Any = None, text: str = "") -> None:
        self.status_code = status_code
        self._json = json_payload
        self.text = text
        if json_payload is not None:
            self.content = b"{}"
        else:
            self.content = text.encode() if text else b""

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("no json")
        return self._json


class StubHTTPXClient:
    """Captures requests and returns scripted responses keyed by (method, path-suffix)."""

    def __init__(self, routes: Optional[Dict[str, _StubResponse]] = None) -> None:
        # routes keyed by f"{METHOD} {path-suffix-after-/}"
        self.routes: Dict[str, _StubResponse] = routes or {}
        self.calls: List[Dict[str, Any]] = []

    def set(self, method: str, suffix: str, response: _StubResponse) -> None:
        self.routes[f"{method.upper()} {suffix}"] = response

    def request(
        self,
        method: str,
        url: str,
        json: Any = None,  # noqa: A002
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> _StubResponse:
        marker = "public-api.drata.com/"
        idx = url.find(marker)
        suffix = url[idx + len(marker):] if idx >= 0 else url
        key = f"{method.upper()} {suffix}"
        self.calls.append(
            {
                "method": method.upper(),
                "url": url,
                "suffix": suffix,
                "json": json,
                "params": params,
                "headers": headers,
            }
        )
        if key in self.routes:
            return self.routes[key]
        return _StubResponse(200, {"results": [], "pagination": {"cursor": None, "has_next": False}})

    def close(self) -> None:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton():
    reset_drata_compliance_engine()
    yield
    reset_drata_compliance_engine()


def _build_app(engine: DrataComplianceEngine) -> TestClient:
    _router_mod._get_engine = lambda: engine  # type: ignore[attr-defined]
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def stub() -> StubHTTPXClient:
    return StubHTTPXClient()


@pytest.fixture
def configured_engine(stub: StubHTTPXClient) -> DrataComplianceEngine:
    return DrataComplianceEngine(
        api_key="drata-test-key-abc123",
        client=stub,  # type: ignore[arg-type]
    )


@pytest.fixture
def unavailable_engine() -> DrataComplianceEngine:
    return DrataComplianceEngine(api_key="", client=httpx.Client())


# ---------------------------------------------------------------------------
# 1. Capability summary — unavailable
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(unavailable_engine: DrataComplianceEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/drata/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Drata"
    assert body["drata_api_key_present"] is False
    assert body["status"] == "unavailable"
    assert "/api/controls" in body["endpoints"]
    assert "/api/integrations" in body["endpoints"]
    assert "/api/audits" in body["endpoints"]
    assert "/api/people" in body["endpoints"]
    assert "/api/findings" in body["endpoints"]


# ---------------------------------------------------------------------------
# 2. Capability summary — ok when configured
# ---------------------------------------------------------------------------


def test_capability_summary_ok(configured_engine: DrataComplianceEngine) -> None:
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/drata/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["drata_api_key_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 3. List controls with filters
# ---------------------------------------------------------------------------


def test_list_controls_with_filters(configured_engine: DrataComplianceEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "api/controls",
        _StubResponse(
            200,
            {
                "results": [
                    {
                        "id": "ctrl-001",
                        "name": "Encryption at rest",
                        "description": "All databases encrypted",
                        "status": "passing",
                        "framework_codes": ["SOC2", "ISO27001"],
                        "owner": {
                            "id": "usr-1",
                            "displayName": "Alice",
                            "email": "alice@example.com",
                        },
                        "type": "automated",
                        "last_evaluated_at": "2026-05-04T10:00:00Z",
                        "evidence_required_count": 3,
                        "evidence_provided_count": 3,
                        "automated": True,
                    }
                ],
                "pagination": {"cursor": "cur-2", "has_next": True},
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/drata/api/controls",
        params={"status": "passing", "framework": "SOC2", "pageSize": 25, "pageCursor": "cur-1"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["results"][0]["id"] == "ctrl-001"
    assert body["results"][0]["framework_codes"] == ["SOC2", "ISO27001"]
    assert body["pagination"]["cursor"] == "cur-2"
    assert body["pagination"]["has_next"] is True
    # Verify upstream call shaped params correctly
    sent = stub.calls[0]["params"]
    assert sent["status"] == "passing"
    assert sent["framework"] == "SOC2"
    assert sent["pageSize"] == 25
    assert sent["pageCursor"] == "cur-1"
    # Auth header
    assert stub.calls[0]["headers"]["Authorization"] == "Bearer drata-test-key-abc123"


# ---------------------------------------------------------------------------
# 4. Single control
# ---------------------------------------------------------------------------


def test_get_single_control(configured_engine: DrataComplianceEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "api/controls/ctrl-001",
        _StubResponse(
            200,
            {
                "id": "ctrl-001",
                "name": "Encryption at rest",
                "status": "passing",
                "framework_codes": ["SOC2"],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/drata/api/controls/ctrl-001")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "ctrl-001"
    assert body["status"] == "passing"


# ---------------------------------------------------------------------------
# 5. Control tests
# ---------------------------------------------------------------------------


def test_list_control_tests(configured_engine: DrataComplianceEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "api/controls/ctrl-001/tests",
        _StubResponse(
            200,
            {
                "results": [
                    {
                        "id": "test-1",
                        "name": "Daily encryption check",
                        "description": "Verifies AES-256 across all RDS instances",
                        "controlId": "ctrl-001",
                        "status": "passing",
                        "lastRunAt": "2026-05-04T08:00:00Z",
                        "frequency": "daily",
                        "severity": "high",
                        "automated": True,
                    }
                ],
                "pagination": {"cursor": None, "has_next": False},
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/drata/api/controls/ctrl-001/tests",
        params={"pageSize": 50},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["results"][0]["id"] == "test-1"
    assert body["results"][0]["frequency"] == "daily"
    assert body["results"][0]["automated"] is True
    sent = stub.calls[0]["params"]
    assert sent["pageSize"] == 50


# ---------------------------------------------------------------------------
# 6. Integrations
# ---------------------------------------------------------------------------


def test_list_integrations(configured_engine: DrataComplianceEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "api/integrations",
        _StubResponse(
            200,
            {
                "results": [
                    {
                        "id": "int-aws-1",
                        "name": "Production AWS",
                        "vendor": {"slug": "aws", "name": "aws", "displayName": "Amazon Web Services"},
                        "status": "connected",
                        "scopes": ["read"],
                        "lastSyncAt": "2026-05-04T09:55:00Z",
                        "lastErrorAt": None,
                        "lastErrorMessage": None,
                        "accountId": "123456789012",
                        "displayName": "prod-account",
                    }
                ],
                "pagination": {"cursor": None, "has_next": False},
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/drata/api/integrations")
    assert resp.status_code == 200
    body = resp.json()
    assert body["results"][0]["vendor"]["slug"] == "aws"
    assert body["results"][0]["status"] == "connected"


# ---------------------------------------------------------------------------
# 7. Audits with framework
# ---------------------------------------------------------------------------


def test_list_audits_with_framework(configured_engine: DrataComplianceEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "api/audits",
        _StubResponse(
            200,
            {
                "results": [
                    {
                        "id": "audit-1",
                        "name": "SOC2 Type II 2026",
                        "framework_code": "SOC2",
                        "status": "in_progress",
                        "auditor": {"name": "AcmeCPA", "email": "audit@acmecpa.com"},
                        "startDate": "2026-01-01",
                        "endDate": "2026-12-31",
                        "observations": [],
                    }
                ],
                "pagination": {"cursor": None, "has_next": False},
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/drata/api/audits",
        params={"status": "in_progress", "framework": "SOC2"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["results"][0]["framework_code"] == "SOC2"
    assert body["results"][0]["status"] == "in_progress"


# ---------------------------------------------------------------------------
# 8. People
# ---------------------------------------------------------------------------


def test_list_people(configured_engine: DrataComplianceEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "api/people",
        _StubResponse(
            200,
            {
                "results": [
                    {
                        "id": "ppl-1",
                        "displayName": "Alice Engineer",
                        "email": "alice@example.com",
                        "role": "Employee",
                        "status": "Active",
                        "hireDate": "2024-03-01",
                        "terminationDate": None,
                        "manager": {"id": "ppl-99", "displayName": "Bob Boss"},
                        "department": "Engineering",
                        "isAdmin": False,
                    }
                ],
                "pagination": {"cursor": None, "has_next": False},
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/drata/api/people",
        params={"role": "Employee", "status": "Active"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["results"][0]["role"] == "Employee"
    assert body["results"][0]["status"] == "Active"


# ---------------------------------------------------------------------------
# 9. Findings
# ---------------------------------------------------------------------------


def test_list_findings(configured_engine: DrataComplianceEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "api/findings",
        _StubResponse(
            200,
            {
                "results": [
                    {
                        "id": "find-1",
                        "title": "MFA missing for admin user",
                        "description": "User alice@ does not have MFA enabled",
                        "severity": "high",
                        "status": "open",
                        "controlId": "ctrl-mfa-1",
                        "integrationId": "int-okta-1",
                        "createdAt": "2026-05-01T00:00:00Z",
                        "updatedAt": "2026-05-04T00:00:00Z",
                        "dueDate": "2026-05-10",
                        "assignee": {"id": "ppl-1", "displayName": "Alice"},
                    }
                ],
                "pagination": {"cursor": None, "has_next": False},
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/drata/api/findings",
        params={"severity": "high", "status": "open"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["results"][0]["severity"] == "high"
    assert body["results"][0]["status"] == "open"


# ---------------------------------------------------------------------------
# 10. Policies (published=true)
# ---------------------------------------------------------------------------


def test_list_policies_published(configured_engine: DrataComplianceEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "api/policies",
        _StubResponse(
            200,
            {
                "results": [
                    {
                        "id": "pol-1",
                        "name": "Information Security Policy",
                        "description": "Top-level ISP",
                        "publishedAt": "2026-04-01T00:00:00Z",
                        "version": "v3",
                        "status": "published",
                        "framework_codes": ["SOC2", "ISO27001"],
                    }
                ],
                "pagination": {"cursor": None, "has_next": False},
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/drata/api/policies", params={"published": "true"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["results"][0]["status"] == "published"
    sent = stub.calls[0]["params"]
    assert sent["published"] == "true"


# ---------------------------------------------------------------------------
# 11. Lookup endpoint returns 503 when env unset
# ---------------------------------------------------------------------------


def test_lookup_endpoint_503_when_unavailable(unavailable_engine: DrataComplianceEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/drata/api/controls")
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"]["error"] == "drata_unavailable"


# ---------------------------------------------------------------------------
# 12. Upstream 404 surfaces as 404 with payload echo
# ---------------------------------------------------------------------------


def test_upstream_404_surfaces(configured_engine: DrataComplianceEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "api/controls/ctrl-missing",
        _StubResponse(404, {"error": "Control not found", "code": "not_found"}),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/drata/api/controls/ctrl-missing")
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["error"] == "drata_upstream_error"
    assert body["detail"]["upstream_status"] == 404
    assert body["detail"]["payload"]["error"] == "Control not found"


# ---------------------------------------------------------------------------
# 13. Invalid framework filter rejected (422)
# ---------------------------------------------------------------------------


def test_invalid_framework_filter_rejected(configured_engine: DrataComplianceEngine) -> None:
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/drata/api/controls", params={"framework": "NOT_A_FRAMEWORK"})
    assert resp.status_code == 422
