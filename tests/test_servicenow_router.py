"""Router-level HTTP tests for the ServiceNow ITSM pass-through API.

Covers /api/v1/servicenow/* via FastAPI TestClient with a stub httpx.Client
so no real ServiceNow call is made.

Tests:
1. GET /                                           — capability summary (unavailable when env unset)
2. GET /                                           — capability summary (ok when env set)
3. GET /api/now/table/incident                     — list incidents w/ sysparm_* params
4. POST /api/now/table/incident                    — create incident (envelope shape)
5. PATCH /api/now/table/incident/{sys_id}          — partial update incident
6. DELETE /api/now/table/incident/{sys_id}         — 204 No Content
7. GET /api/now/table/change_request               — list change requests
8. GET /api/now/table/task                         — list tasks
9. GET /api/now/table/sys_user?sysparm_query=email — user lookup
10. GET /api/now/table/cmdb_ci                     — list CIs
11. lookup endpoint returns 503 when env unset
12. upstream 404 surfaces as 404 with payload echo
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

import apps.api.servicenow_router as _router_mod
from apps.api.servicenow_router import router
from core.servicenow_itsm_engine import (
    ServiceNowITSMEngine,
    reset_servicenow_itsm_engine,
)


# ---------------------------------------------------------------------------
# Stub httpx.Client
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(
        self,
        status_code: int,
        json_payload: Any = None,
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self._json = json_payload
        self.text = text
        if text:
            self.content = text.encode("utf-8") if isinstance(text, str) else text
        elif json_payload is not None:
            self.content = b"{}"
        else:
            self.content = b""

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("no json")
        return self._json


class StubHTTPXClient:
    """Captures requests and returns scripted responses keyed by (method, path-suffix)."""

    def __init__(self, routes: Optional[Dict[str, _StubResponse]] = None) -> None:
        # routes keyed by f"{METHOD} {path-suffix-after-/api/now/table/}"
        self.routes: Dict[str, _StubResponse] = routes or {}
        self.calls: List[Dict[str, Any]] = []

    def set(self, method: str, suffix: str, response: _StubResponse) -> None:
        self.routes[f"{method.upper()} {suffix}"] = response

    def request(
        self,
        method: str,
        url: str,
        json: Any = None,  # noqa: A002 - mirror httpx signature
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Any = None,
    ) -> _StubResponse:
        marker = "/api/now/table/"
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
                "auth": auth,
            }
        )
        if key in self.routes:
            return self.routes[key]
        # Default: echo a generic 200 with empty body
        return _StubResponse(200, {"result": []})

    def close(self) -> None:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Each test gets a fresh engine singleton."""
    reset_servicenow_itsm_engine()
    yield
    reset_servicenow_itsm_engine()


def _build_app(engine: ServiceNowITSMEngine) -> TestClient:
    """Mount the router with engine injection."""
    _router_mod._get_engine = lambda: engine  # type: ignore[attr-defined]
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def stub() -> StubHTTPXClient:
    return StubHTTPXClient()


@pytest.fixture
def configured_engine(stub: StubHTTPXClient) -> ServiceNowITSMEngine:
    return ServiceNowITSMEngine(
        servicenow_url="https://acme.service-now.com",
        servicenow_user="aldeci_bot",
        servicenow_password="s3cret",
        client=stub,  # type: ignore[arg-type]
    )


@pytest.fixture
def unavailable_engine() -> ServiceNowITSMEngine:
    return ServiceNowITSMEngine(
        servicenow_url="",
        servicenow_user="",
        servicenow_password="",
        client=httpx.Client(),
    )


# ---------------------------------------------------------------------------
# 1. Capability summary — unavailable
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(unavailable_engine: ServiceNowITSMEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/servicenow/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "ServiceNow ITSM"
    assert body["servicenow_url_present"] is False
    assert body["servicenow_user_present"] is False
    assert body["servicenow_password_present"] is False
    assert body["status"] == "unavailable"
    for ep in (
        "/api/now/table/incident",
        "/api/now/table/change_request",
        "/api/now/table/task",
        "/api/now/table/sys_user",
        "/api/now/table/cmdb_ci",
    ):
        assert ep in body["endpoints"]


# ---------------------------------------------------------------------------
# 2. Capability summary — ok when configured
# ---------------------------------------------------------------------------


def test_capability_summary_ok(configured_engine: ServiceNowITSMEngine) -> None:
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/servicenow/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["servicenow_url_present"] is True
    assert body["servicenow_user_present"] is True
    assert body["servicenow_password_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 3. List incidents w/ sysparm_* params
# ---------------------------------------------------------------------------


def test_list_incidents_passes_sysparm_params(
    configured_engine: ServiceNowITSMEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "incident",
        _StubResponse(
            200,
            {
                "result": [
                    {
                        "sys_id": "abc123",
                        "number": "INC0010001",
                        "short_description": "Login issue",
                        "urgency": "2",
                        "impact": "2",
                        "priority": "3",
                        "state": "2",
                        "assignment_group": {
                            "display_value": "Security Operations",
                            "value": "grp001",
                        },
                        "assigned_to": {
                            "display_value": "Alice Smith",
                            "value": "usr042",
                        },
                        "caller_id": {
                            "display_value": "Bob Caller",
                            "value": "usr099",
                        },
                        "category": "inquiry",
                        "subcategory": "internal",
                        "contact_type": "self-service",
                    }
                ]
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/servicenow/api/now/table/incident",
        params={
            "sysparm_query": "active=true^urgency=1",
            "sysparm_fields": "sys_id,number,short_description",
            "sysparm_limit": 25,
            "sysparm_offset": 50,
            "sysparm_display_value": "all",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"][0]["number"] == "INC0010001"
    assert body["result"][0]["assignment_group"]["display_value"] == "Security Operations"
    # Verify upstream call carried the sysparm params
    sent = stub.calls[0]["params"]
    assert sent["sysparm_query"] == "active=true^urgency=1"
    assert sent["sysparm_fields"] == "sys_id,number,short_description"
    assert sent["sysparm_limit"] == 25
    assert sent["sysparm_offset"] == 50
    assert sent["sysparm_display_value"] == "all"
    # Verify basic auth carried
    assert stub.calls[0]["auth"] is not None
    # Verify Accept header
    assert stub.calls[0]["headers"]["Accept"] == "application/json"


# ---------------------------------------------------------------------------
# 4. Create incident
# ---------------------------------------------------------------------------


def test_create_incident_envelope(
    configured_engine: ServiceNowITSMEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "POST",
        "incident",
        _StubResponse(
            201,
            {
                "result": {
                    "sys_id": "new123",
                    "number": "INC0010099",
                    "short_description": "Phishing alert",
                    "urgency": "1",
                    "impact": "2",
                    "state": "1",
                }
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/servicenow/api/now/table/incident",
        json={
            "short_description": "Phishing alert",
            "description": "User reported suspicious email",
            "urgency": 1,
            "impact": 2,
            "caller_id": "usr099",
            "category": "security",
            "subcategory": "phishing",
            "assignment_group": "grp001",
            "work_notes": "Triage in progress",
            "contact_type": "email",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["number"] == "INC0010099"
    assert body["result"]["sys_id"] == "new123"
    # Verify upstream payload contains all submitted fields
    sent = stub.calls[0]["json"]
    assert sent["short_description"] == "Phishing alert"
    assert sent["urgency"] == 1
    assert sent["impact"] == 2
    assert sent["caller_id"] == "usr099"
    assert sent["category"] == "security"
    assert sent["assignment_group"] == "grp001"
    assert sent["contact_type"] == "email"


# ---------------------------------------------------------------------------
# 5. PATCH partial update
# ---------------------------------------------------------------------------


def test_patch_incident_partial_update(
    configured_engine: ServiceNowITSMEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "PATCH",
        "incident/abc123",
        _StubResponse(
            200,
            {
                "result": {
                    "sys_id": "abc123",
                    "number": "INC0010001",
                    "state": "6",
                    "resolution_code": "Solved (Permanently)",
                }
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.patch(
        "/api/v1/servicenow/api/now/table/incident/abc123",
        json={
            "state": 6,
            "work_notes": "Patched the auth proxy.",
            "resolution_code": "Solved (Permanently)",
            "resolution_notes": "Rolled out hotfix v2.1.4",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["state"] == "6"
    assert body["result"]["resolution_code"] == "Solved (Permanently)"
    sent = stub.calls[0]["json"]
    assert sent["state"] == 6
    assert sent["work_notes"] == "Patched the auth proxy."
    assert "resolved_by" not in sent  # unset fields are pruned
    assert "assignment_group" not in sent


# ---------------------------------------------------------------------------
# 6. DELETE returns 204
# ---------------------------------------------------------------------------


def test_delete_incident_returns_204(
    configured_engine: ServiceNowITSMEngine, stub: StubHTTPXClient
) -> None:
    stub.set("DELETE", "incident/abc123", _StubResponse(204, None, text=""))
    client = _build_app(configured_engine)
    resp = client.delete("/api/v1/servicenow/api/now/table/incident/abc123")
    assert resp.status_code == 204
    # Body should be empty
    assert resp.content == b""
    assert stub.calls[0]["method"] == "DELETE"
    assert stub.calls[0]["suffix"] == "incident/abc123"


# ---------------------------------------------------------------------------
# 7. List change requests
# ---------------------------------------------------------------------------


def test_list_change_requests(
    configured_engine: ServiceNowITSMEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "change_request",
        _StubResponse(
            200,
            {
                "result": [
                    {
                        "sys_id": "chg001",
                        "number": "CHG0001234",
                        "short_description": "Patch nginx CVE",
                        "type": "normal",
                        "state": "-2",
                        "category": "Software",
                        "risk": "3",
                        "risk_impact_analysis": "Low risk — staging validated",
                        "requested_by": {
                            "display_value": "Charlie Releaser",
                            "value": "usr200",
                        },
                        "assignment_group": {
                            "display_value": "Platform Eng",
                            "value": "grp020",
                        },
                        "start_date": "2026-05-10 02:00:00",
                        "end_date": "2026-05-10 04:00:00",
                    }
                ]
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/servicenow/api/now/table/change_request",
        params={"sysparm_query": "active=true", "sysparm_limit": 10},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"][0]["number"] == "CHG0001234"
    assert body["result"][0]["type"] == "normal"
    assert body["result"][0]["risk"] == "3"


# ---------------------------------------------------------------------------
# 8. List tasks
# ---------------------------------------------------------------------------


def test_list_tasks(
    configured_engine: ServiceNowITSMEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "task",
        _StubResponse(
            200,
            {
                "result": [
                    {
                        "sys_id": "tsk001",
                        "number": "TASK0001234",
                        "short_description": "Generic task",
                        "state": "1",
                    }
                ]
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/servicenow/api/now/table/task")
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"][0]["number"] == "TASK0001234"


# ---------------------------------------------------------------------------
# 9. User lookup by email
# ---------------------------------------------------------------------------


def test_user_lookup_by_email(
    configured_engine: ServiceNowITSMEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "sys_user",
        _StubResponse(
            200,
            {
                "result": [
                    {
                        "sys_id": "usr042",
                        "user_name": "alice",
                        "email": "alice@acme.com",
                        "name": "Alice Smith",
                    }
                ]
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/servicenow/api/now/table/sys_user",
        params={"sysparm_query": "email=alice@acme.com"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"][0]["email"] == "alice@acme.com"
    assert (
        stub.calls[0]["params"]["sysparm_query"] == "email=alice@acme.com"
    )


# ---------------------------------------------------------------------------
# 10. List CMDB CIs
# ---------------------------------------------------------------------------


def test_list_cmdb_cis(
    configured_engine: ServiceNowITSMEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "cmdb_ci",
        _StubResponse(
            200,
            {
                "result": [
                    {
                        "sys_id": "ci001",
                        "name": "api-gateway-prod-1",
                        "sys_class_name": "cmdb_ci_linux_server",
                        "operational_status": "1",
                    }
                ]
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/servicenow/api/now/table/cmdb_ci",
        params={"sysparm_query": "name=api-gateway-prod-1", "sysparm_limit": 5},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"][0]["name"] == "api-gateway-prod-1"


# ---------------------------------------------------------------------------
# 11. 503 when env unset on lookup endpoint
# ---------------------------------------------------------------------------


def test_lookup_endpoint_503_when_unavailable(
    unavailable_engine: ServiceNowITSMEngine,
) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/servicenow/api/now/table/incident")
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"]["error"] == "servicenow_unavailable"


# ---------------------------------------------------------------------------
# 12. Upstream 404 surfaces with payload echo
# ---------------------------------------------------------------------------


def test_upstream_404_surfaces(
    configured_engine: ServiceNowITSMEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "PATCH",
        "incident/missing",
        _StubResponse(
            404,
            {
                "error": {
                    "message": "No Record found",
                    "detail": "Record doesn't exist or ACL restricts the record retrieval",
                },
                "status": "failure",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.patch(
        "/api/v1/servicenow/api/now/table/incident/missing",
        json={"state": 6},
    )
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["error"] == "servicenow_upstream_error"
    assert body["detail"]["upstream_status"] == 404
    assert "No Record found" in body["detail"]["payload"]["error"]["message"]
