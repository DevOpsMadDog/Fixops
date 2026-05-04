"""Router-level HTTP tests for the Workday HCM pass-through API.

Covers /api/v1/workday/* via FastAPI TestClient with a stub httpx.Client
so no real Workday call is made.

Tests:
1.  GET /                                                                   — capability summary unavailable
2.  GET /                                                                   — capability summary ok
3.  GET /ccx/api/staffing/v6/{tenant}/workers                               — list workers w/ paging+search
4.  GET /ccx/api/staffing/v6/{tenant}/workers/{wid}                         — single worker
5.  GET /ccx/api/staffing/v6/{tenant}/workers/{wid}/historyChange           — change history
6.  GET /ccx/api/staffing/v6/{tenant}/positions                             — list positions
7.  GET /ccx/api/staffing/v6/{tenant}/organizations                         — list organizations
8.  GET /ccx/api/staffing/v6/{tenant}/orgChart/{org_id}                     — org chart node + descendants
9.  GET /ccx/api/staffing/v6/{tenant}/orgChart/{org_id}/managementChain     — management chain
10. workers endpoint returns 503 when env unset
11. upstream 404 surfaces as 404 with payload echo
12. basic auth username uses ``{username}@{tenant}`` format
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

import apps.api.workday_router as _router_mod
from apps.api.workday_router import router
from core.workday_engine import (
    WorkdayEngine,
    reset_workday_engine,
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
        # routes keyed by f"{METHOD} {path-suffix-after-/staffing/v6/{tenant}/}"
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
        marker = "/staffing/v6/"
        idx = url.find(marker)
        if idx >= 0:
            after = url[idx + len(marker):]
            # Strip the leading {tenant}/ segment
            slash = after.find("/")
            suffix = after[slash + 1:] if slash >= 0 else after
        else:
            suffix = url
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
        return _StubResponse(200, {"data": [], "total": 0})

    def close(self) -> None:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Each test gets a fresh engine singleton."""
    reset_workday_engine()
    yield
    reset_workday_engine()


def _build_app(engine: WorkdayEngine) -> TestClient:
    """Mount the router with engine injection."""
    _router_mod._get_engine = lambda: engine  # type: ignore[attr-defined]
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def stub() -> StubHTTPXClient:
    return StubHTTPXClient()


@pytest.fixture
def configured_engine(stub: StubHTTPXClient) -> WorkdayEngine:
    return WorkdayEngine(
        workday_tenant="acme_pilot",
        workday_base_url="https://wd2-impl-services1.workday.com",
        workday_username="aldeci_isu",
        workday_password="s3cret",
        client=stub,  # type: ignore[arg-type]
    )


@pytest.fixture
def unavailable_engine() -> WorkdayEngine:
    return WorkdayEngine(
        workday_tenant="",
        workday_base_url="",
        workday_username="",
        workday_password="",
        client=httpx.Client(),
    )


# ---------------------------------------------------------------------------
# 1. Capability summary — unavailable
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(unavailable_engine: WorkdayEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/workday/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Workday HCM"
    assert body["workday_tenant_present"] is False
    assert body["workday_base_url_present"] is False
    assert body["workday_username_present"] is False
    assert body["workday_password_present"] is False
    assert body["status"] == "unavailable"
    for ep in (
        "/ccx/api/staffing/v6/{tenant}/workers",
        "/ccx/api/staffing/v6/{tenant}/positions",
        "/ccx/api/staffing/v6/{tenant}/organizations",
        "/ccx/api/staffing/v6/{tenant}/orgChart",
    ):
        assert ep in body["endpoints"]


# ---------------------------------------------------------------------------
# 2. Capability summary — ok
# ---------------------------------------------------------------------------


def test_capability_summary_ok(configured_engine: WorkdayEngine) -> None:
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/workday/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["workday_tenant_present"] is True
    assert body["workday_base_url_present"] is True
    assert body["workday_username_present"] is True
    assert body["workday_password_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 3. List workers
# ---------------------------------------------------------------------------


def test_list_workers_passes_paging_and_search(
    configured_engine: WorkdayEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "workers",
        _StubResponse(
            200,
            {
                "data": [
                    {
                        "id": "wrk001",
                        "descriptor": "Alice Smith",
                        "businessTitle": "Senior Security Engineer",
                        "person": {
                            "descriptor": "Alice Smith",
                            "primaryName": {
                                "firstName": "Alice",
                                "lastName": "Smith",
                                "formatted": "Alice Smith",
                            },
                            "contactInformation": {
                                "emailAddressData": [
                                    {
                                        "emailAddress": "alice@acme.com",
                                        "usage": {"type": "WORK", "public": True},
                                    }
                                ],
                                "phoneData": [
                                    {
                                        "type": "MOBILE",
                                        "areaCode": "415",
                                        "country": "US",
                                        "phoneNumber": "5551234",
                                    }
                                ],
                            },
                        },
                        "primarySupervisoryOrganization": {
                            "descriptor": "Security Engineering"
                        },
                        "primaryWorkPosition": {
                            "descriptor": "Senior Security Engineer",
                            "businessTitle": "Senior Security Engineer",
                            "jobProfile": "JP-SE-3",
                            "jobClassification": "Engineering",
                            "location": "SF HQ",
                            "payRate": "150000 USD/yr",
                            "position": "P-001",
                        },
                    }
                ],
                "total": 1,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/workday/ccx/api/staffing/v6/acme_pilot/workers",
        params={
            "limit": 25,
            "offset": 50,
            "search": "alice",
            "inactiveAndTerminated": "false",
            "supervisoryOrganization": "org-sec-eng",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["data"][0]["person"]["primaryName"]["firstName"] == "Alice"
    # Verify upstream call carried the params
    sent = stub.calls[0]["params"]
    assert sent["limit"] == 25
    assert sent["offset"] == 50
    assert sent["search"] == "alice"
    assert sent["inactiveAndTerminated"] is False
    assert sent["supervisoryOrganization"] == "org-sec-eng"
    # Verify URL contains tenant
    assert "/staffing/v6/acme_pilot/workers" in stub.calls[0]["url"]
    # Verify Accept header
    assert stub.calls[0]["headers"]["Accept"] == "application/json"


# ---------------------------------------------------------------------------
# 4. Single worker
# ---------------------------------------------------------------------------


def test_get_single_worker(
    configured_engine: WorkdayEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "workers/wrk001",
        _StubResponse(
            200,
            {
                "id": "wrk001",
                "descriptor": "Alice Smith",
                "businessTitle": "Senior Security Engineer",
                "employmentData": {
                    "workerStatus": {
                        "active": True,
                        "hireDate": "2022-03-01",
                        "terminationDate": None,
                    },
                    "position": {
                        "descriptor": "Senior Security Engineer",
                        "businessTitle": "Senior Security Engineer",
                        "jobProfile": {"descriptor": "JP-SE-3"},
                        "location": {"descriptor": "SF HQ"},
                        "payRate": {
                            "amount": 150000,
                            "currency": "USD",
                            "frequency": "YEARLY",
                        },
                    },
                    "manager": {"descriptor": "Bob Manager"},
                    "organization": {"descriptor": "Security Engineering"},
                },
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/workday/ccx/api/staffing/v6/acme_pilot/workers/wrk001"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "wrk001"
    assert body["employmentData"]["workerStatus"]["active"] is True
    assert body["employmentData"]["position"]["payRate"]["amount"] == 150000


# ---------------------------------------------------------------------------
# 5. Worker history
# ---------------------------------------------------------------------------


def test_get_worker_history(
    configured_engine: WorkdayEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "workers/wrk001/historyChange",
        _StubResponse(
            200,
            {
                "data": [
                    {
                        "id": "evt001",
                        "effectiveDate": "2024-06-01",
                        "businessProcessType": "Promote Employee",
                        "descriptor": "Promotion to Senior Security Engineer",
                    },
                    {
                        "id": "evt002",
                        "effectiveDate": "2022-03-01",
                        "businessProcessType": "Hire",
                        "descriptor": "Initial hire",
                    },
                ],
                "total": 2,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/workday/ccx/api/staffing/v6/acme_pilot/workers/wrk001/historyChange",
        params={"limit": 10, "offset": 0},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert body["data"][0]["businessProcessType"] == "Promote Employee"
    sent = stub.calls[0]["params"]
    assert sent["limit"] == 10
    assert sent["offset"] == 0


# ---------------------------------------------------------------------------
# 6. List positions
# ---------------------------------------------------------------------------


def test_list_positions(
    configured_engine: WorkdayEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "positions",
        _StubResponse(
            200,
            {
                "data": [
                    {
                        "id": "pos001",
                        "descriptor": "Senior Security Engineer",
                        "jobProfile": {"descriptor": "JP-SE-3"},
                        "businessTitle": "Senior Security Engineer",
                        "jobClassification": "Engineering",
                        "supervisoryOrganization": {
                            "descriptor": "Security Engineering"
                        },
                        "location": {"descriptor": "SF HQ"},
                        "hiringFreeze": False,
                        "availableForOverlap": True,
                        "availability": {
                            "availableForHire": True,
                            "hireDate": "2026-06-01",
                            "position": "P-001",
                        },
                        "occupants": [{"descriptor": "Alice Smith"}],
                        "status": "filled",
                    }
                ],
                "total": 1,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/workday/ccx/api/staffing/v6/acme_pilot/positions",
        params={"limit": 10, "offset": 0, "search": "engineer"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"][0]["status"] == "filled"
    assert body["data"][0]["availableForOverlap"] is True
    sent = stub.calls[0]["params"]
    assert sent["search"] == "engineer"


# ---------------------------------------------------------------------------
# 7. List organizations
# ---------------------------------------------------------------------------


def test_list_organizations(
    configured_engine: WorkdayEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "organizations",
        _StubResponse(
            200,
            {
                "data": [
                    {
                        "id": "org-sec-eng",
                        "descriptor": "Security Engineering",
                        "organizationCode": "SEC-ENG",
                        "organizationType": {"descriptor": "Supervisory"},
                        "organizationSubtype": "Engineering",
                        "manager": {"descriptor": "Bob Manager"},
                        "parent": {"descriptor": "Engineering"},
                        "ownerCompany": {"descriptor": "Acme Inc"},
                        "available": True,
                        "hierarchyLevel": 3,
                    }
                ],
                "total": 1,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/workday/ccx/api/staffing/v6/acme_pilot/organizations",
        params={"limit": 50, "offset": 0},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"][0]["organizationCode"] == "SEC-ENG"
    assert body["data"][0]["hierarchyLevel"] == 3


# ---------------------------------------------------------------------------
# 8. Org chart node
# ---------------------------------------------------------------------------


def test_get_org_chart(
    configured_engine: WorkdayEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "orgChart/org-sec-eng",
        _StubResponse(
            200,
            {
                "id": "org-sec-eng",
                "descriptor": "Security Engineering",
                "manager": {"descriptor": "Bob Manager"},
                "descendants": [
                    {
                        "id": "org-appsec",
                        "descriptor": "AppSec",
                        "manager": {"descriptor": "Charlie Lead"},
                    },
                    {
                        "id": "org-redteam",
                        "descriptor": "Red Team",
                        "manager": {"descriptor": "Dana Lead"},
                    },
                ],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/workday/ccx/api/staffing/v6/acme_pilot/orgChart/org-sec-eng"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "org-sec-eng"
    assert len(body["descendants"]) == 2


# ---------------------------------------------------------------------------
# 9. Management chain
# ---------------------------------------------------------------------------


def test_get_management_chain(
    configured_engine: WorkdayEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "orgChart/org-sec-eng/managementChain",
        _StubResponse(
            200,
            {
                "data": [
                    {"id": "org-sec-eng", "descriptor": "Security Engineering",
                     "manager": {"descriptor": "Bob Manager"}},
                    {"id": "org-eng", "descriptor": "Engineering",
                     "manager": {"descriptor": "Eve VP"}},
                    {"id": "org-acme", "descriptor": "Acme Inc",
                     "manager": {"descriptor": "Frank CEO"}},
                ],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/workday/ccx/api/staffing/v6/acme_pilot/orgChart/"
        "org-sec-eng/managementChain"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["data"]) == 3
    assert body["data"][-1]["descriptor"] == "Acme Inc"


# ---------------------------------------------------------------------------
# 10. 503 when env unset on lookup endpoint
# ---------------------------------------------------------------------------


def test_lookup_endpoint_503_when_unavailable(
    unavailable_engine: WorkdayEngine,
) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get(
        "/api/v1/workday/ccx/api/staffing/v6/acme_pilot/workers"
    )
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"]["error"] == "workday_unavailable"


# ---------------------------------------------------------------------------
# 11. Upstream 404 surfaces with payload echo
# ---------------------------------------------------------------------------


def test_upstream_404_surfaces(
    configured_engine: WorkdayEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "workers/missing",
        _StubResponse(
            404,
            {
                "error": "Worker not found",
                "detail": "No worker with that id in tenant acme_pilot",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/workday/ccx/api/staffing/v6/acme_pilot/workers/missing"
    )
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["error"] == "workday_upstream_error"
    assert body["detail"]["upstream_status"] == 404
    assert body["detail"]["payload"]["error"] == "Worker not found"


# ---------------------------------------------------------------------------
# 12. Basic-auth username uses ``{username}@{tenant}`` format
# ---------------------------------------------------------------------------


def test_basic_auth_username_format(
    configured_engine: WorkdayEngine, stub: StubHTTPXClient
) -> None:
    stub.set("GET", "workers", _StubResponse(200, {"data": [], "total": 0}))
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/workday/ccx/api/staffing/v6/acme_pilot/workers"
    )
    assert resp.status_code == 200
    auth = stub.calls[0]["auth"]
    assert auth is not None
    # httpx.BasicAuth carries credentials in ._auth_header. Inspect via .auth_flow.
    # The simplest cross-version assertion: render the header it would attach.
    import base64

    request = httpx.Request("GET", "https://example.com")
    flow = auth.auth_flow(request)
    authed = next(flow)
    header = authed.headers["Authorization"]
    assert header.startswith("Basic ")
    decoded = base64.b64decode(header[len("Basic "):]).decode("utf-8")
    assert decoded == "aldeci_isu@acme_pilot:s3cret"
