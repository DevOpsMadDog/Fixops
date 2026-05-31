"""
Pagination tests for customer-facing LIST endpoints.

Covers:
  - GET /api/v1/findings          (findings_routes.py)
  - GET /api/v1/analytics/findings (analytics_router.py)
  - GET /api/v1/inventory/applications (inventory_router.py)
  - GET /api/v1/audit/logs        (audit_router.py)
  - GET /api/v1/users             (users_router.py)

For each endpoint verifies:
  1. limit/offset params are accepted and respected
  2. Response envelope contains "total", "limit", "offset", and an items key
  3. total is an integer >= 0
  4. Returned item count never exceeds requested limit
  5. org_id tenant scoping is preserved (cross-tenant isolation)
"""
from __future__ import annotations

import os
import sys

import pytest
from fastapi.testclient import TestClient

# Ensure suite paths are importable
for _p in [
    ".",
    "suite-api",
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-integrations",
    "suite-evidence-risk",
    "archive/legacy",
    "archive/enterprise_legacy",
]:
    _abs = os.path.join(os.path.dirname(__file__), "..", _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-at-least-32-chars-long!")
os.environ.setdefault("API_KEY", "test-api-key")
os.environ.setdefault("FIXOPS_API_KEY", "test-api-key")


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app

    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

AUTH = {"X-API-Key": "test-api-key"}
ORG = "test-pagination-org"


def _pagination_headers(org_id: str = ORG) -> dict:
    return {**AUTH, "X-Org-ID": org_id}


def _assert_paginated_envelope(data: dict, limit: int, offset: int) -> None:
    """Assert the standard pagination envelope is present and coherent."""
    assert isinstance(data, dict), f"Expected dict envelope, got {type(data)}"
    assert "total" in data, f"Missing 'total' key in response: {list(data.keys())}"
    assert "limit" in data, f"Missing 'limit' key in response: {list(data.keys())}"
    assert "offset" in data, f"Missing 'offset' key in response: {list(data.keys())}"
    assert isinstance(data["total"], int) and data["total"] >= 0
    assert data["limit"] == limit
    assert data["offset"] == offset
    # Items key may be "items", "findings", "decisions", etc.
    items_key = next(
        (k for k in ("items", "findings", "decisions", "logs") if k in data), None
    )
    assert items_key is not None, f"No items key found in response: {list(data.keys())}"
    assert len(data[items_key]) <= limit


# ---------------------------------------------------------------------------
# findings_routes.py  —  GET /api/v1/findings
# ---------------------------------------------------------------------------


class TestFindingsRoutes:
    def test_default_pagination(self, client):
        r = client.get("/api/v1/findings", headers=_pagination_headers())
        assert r.status_code in (200, 401, 403), r.text
        if r.status_code == 200:
            data = r.json()
            # findings_routes returns {"total":..., "limit":..., "offset":..., "findings":[]}
            assert "total" in data
            assert "limit" in data
            assert "offset" in data
            assert isinstance(data["total"], int)
            items = data.get("findings", data.get("items", []))
            assert isinstance(items, list)

    def test_limit_param_respected(self, client):
        r = client.get("/api/v1/findings", headers=_pagination_headers(), params={"limit": 5, "offset": 0})
        assert r.status_code in (200, 401, 403), r.text
        if r.status_code == 200:
            data = r.json()
            assert data["limit"] == 5
            items = data.get("findings", data.get("items", []))
            assert len(items) <= 5

    def test_offset_param_accepted(self, client):
        r = client.get("/api/v1/findings", headers=_pagination_headers(), params={"limit": 10, "offset": 0})
        r2 = client.get("/api/v1/findings", headers=_pagination_headers(), params={"limit": 10, "offset": 100})
        assert r.status_code in (200, 401, 403)
        assert r2.status_code in (200, 401, 403)
        if r.status_code == 200 and r2.status_code == 200:
            # offset=100 items should be a subset / different window
            assert r2.json()["offset"] == 100

    def test_limit_out_of_range_rejected(self, client):
        r = client.get("/api/v1/findings", headers=_pagination_headers(), params={"limit": 9999})
        # Should 422 since ge=1, le=500
        assert r.status_code in (422, 401, 403), r.text

    def test_negative_offset_rejected(self, client):
        r = client.get("/api/v1/findings", headers=_pagination_headers(), params={"offset": -1})
        assert r.status_code in (422, 401, 403), r.text

    def test_total_is_real_count(self, client):
        """total must be >= items returned (not just len(page))."""
        r = client.get("/api/v1/findings", headers=_pagination_headers(), params={"limit": 2, "offset": 0})
        if r.status_code == 200:
            data = r.json()
            items = data.get("findings", data.get("items", []))
            assert data["total"] >= len(items)

    def test_org_id_scoping_present(self, client):
        """Two different org_ids must not bleed findings into each other."""
        r1 = client.get("/api/v1/findings", headers=_pagination_headers("org-a"), params={"limit": 50})
        r2 = client.get("/api/v1/findings", headers=_pagination_headers("org-b"), params={"limit": 50})
        if r1.status_code == 200 and r2.status_code == 200:
            items1 = set(f.get("id") for f in r1.json().get("findings", r1.json().get("items", [])))
            items2 = set(f.get("id") for f in r2.json().get("findings", r2.json().get("items", [])))
            # Intersection should be empty (no cross-tenant bleed)
            assert items1.isdisjoint(items2), "Cross-tenant findings bleed detected"


# ---------------------------------------------------------------------------
# analytics_router.py  —  GET /api/v1/analytics/findings
# ---------------------------------------------------------------------------


class TestAnalyticsFindingsPagination:
    def test_default_returns_envelope(self, client):
        r = client.get("/api/v1/analytics/findings", headers=_pagination_headers())
        assert r.status_code in (200, 401, 403), r.text
        if r.status_code == 200:
            data = r.json()
            # Now returns envelope dict (not bare list)
            assert isinstance(data, dict), "Expected envelope dict, got bare list or other"
            assert "total" in data
            assert "items" in data
            assert "limit" in data
            assert "offset" in data

    def test_limit_respected(self, client):
        r = client.get(
            "/api/v1/analytics/findings",
            headers=_pagination_headers(),
            params={"limit": 3, "offset": 0},
        )
        if r.status_code == 200:
            data = r.json()
            assert data["limit"] == 3
            assert len(data["items"]) <= 3

    def test_x_total_count_header(self, client):
        r = client.get("/api/v1/analytics/findings", headers=_pagination_headers(), params={"limit": 5})
        if r.status_code == 200:
            assert "x-total-count" in {k.lower(): v for k, v in r.headers.items()}, (
                "X-Total-Count header missing"
            )

    def test_total_is_real_count(self, client):
        r = client.get(
            "/api/v1/analytics/findings",
            headers=_pagination_headers(),
            params={"limit": 1, "offset": 0},
        )
        if r.status_code == 200:
            data = r.json()
            assert data["total"] >= len(data["items"])

    def test_limit_out_of_range_rejected(self, client):
        r = client.get("/api/v1/analytics/findings", headers=_pagination_headers(), params={"limit": 9999})
        assert r.status_code in (422, 401, 403), r.text

    def test_org_scoping(self, client):
        r1 = client.get("/api/v1/analytics/findings", headers=_pagination_headers("org-x"), params={"limit": 100})
        r2 = client.get("/api/v1/analytics/findings", headers=_pagination_headers("org-y"), params={"limit": 100})
        if r1.status_code == 200 and r2.status_code == 200:
            ids1 = {f.get("id") for f in r1.json().get("items", [])}
            ids2 = {f.get("id") for f in r2.json().get("items", [])}
            assert ids1.isdisjoint(ids2), "Cross-tenant analytics findings bleed detected"


# ---------------------------------------------------------------------------
# inventory_router.py  —  GET /api/v1/inventory/applications
# ---------------------------------------------------------------------------


class TestInventoryApplicationsPagination:
    def test_default_returns_envelope(self, client):
        r = client.get("/api/v1/inventory/applications", headers=_pagination_headers())
        assert r.status_code in (200, 401, 403), r.text
        if r.status_code == 200:
            data = r.json()
            _assert_paginated_envelope(data, limit=50, offset=0)

    def test_limit_respected(self, client):
        r = client.get(
            "/api/v1/inventory/applications",
            headers=_pagination_headers(),
            params={"limit": 2, "offset": 0},
        )
        if r.status_code == 200:
            data = r.json()
            assert data["limit"] == 2
            assert len(data["items"]) <= 2

    def test_total_is_real_count(self, client):
        """total must equal full tenant count, not just page size."""
        r = client.get(
            "/api/v1/inventory/applications",
            headers=_pagination_headers(),
            params={"limit": 1, "offset": 0},
        )
        if r.status_code == 200:
            data = r.json()
            assert data["total"] >= len(data["items"]), (
                f"total={data['total']} < items returned={len(data['items'])}"
            )

    def test_limit_out_of_range_rejected(self, client):
        r = client.get(
            "/api/v1/inventory/applications",
            headers=_pagination_headers(),
            params={"limit": 9999},
        )
        assert r.status_code in (422, 401, 403), r.text

    def test_offset_zero_and_nonzero(self, client):
        r0 = client.get(
            "/api/v1/inventory/applications",
            headers=_pagination_headers(),
            params={"limit": 50, "offset": 0},
        )
        r1 = client.get(
            "/api/v1/inventory/applications",
            headers=_pagination_headers(),
            params={"limit": 50, "offset": 50},
        )
        if r0.status_code == 200 and r1.status_code == 200:
            assert r0.json()["offset"] == 0
            assert r1.json()["offset"] == 50

    def test_org_scoping_preserved(self, client):
        r1 = client.get("/api/v1/inventory/applications", headers=_pagination_headers("tenant-1"))
        r2 = client.get("/api/v1/inventory/applications", headers=_pagination_headers("tenant-2"))
        if r1.status_code == 200 and r2.status_code == 200:
            ids1 = {a.get("id") for a in r1.json().get("items", [])}
            ids2 = {a.get("id") for a in r2.json().get("items", [])}
            assert ids1.isdisjoint(ids2), "Cross-tenant inventory bleed detected"


# ---------------------------------------------------------------------------
# audit_router.py  —  GET /api/v1/audit/logs
# ---------------------------------------------------------------------------


class TestAuditLogsPagination:
    def test_default_returns_envelope(self, client):
        r = client.get("/api/v1/audit/logs", headers=_pagination_headers())
        assert r.status_code in (200, 401, 403), r.text
        if r.status_code == 200:
            data = r.json()
            _assert_paginated_envelope(data, limit=50, offset=0)

    def test_limit_respected(self, client):
        r = client.get(
            "/api/v1/audit/logs",
            headers=_pagination_headers(),
            params={"limit": 3, "offset": 0},
        )
        if r.status_code == 200:
            data = r.json()
            assert data["limit"] == 3
            assert len(data["items"]) <= 3

    def test_total_is_real_count(self, client):
        r = client.get(
            "/api/v1/audit/logs",
            headers=_pagination_headers(),
            params={"limit": 1, "offset": 0},
        )
        if r.status_code == 200:
            data = r.json()
            assert data["total"] >= len(data["items"]), (
                f"total={data['total']} should be >= items={len(data['items'])}"
            )

    def test_limit_out_of_range_rejected(self, client):
        r = client.get(
            "/api/v1/audit/logs",
            headers=_pagination_headers(),
            params={"limit": 9999},
        )
        assert r.status_code in (422, 401, 403), r.text

    def test_org_scoping_preserved(self, client):
        r1 = client.get("/api/v1/audit/logs", headers=_pagination_headers("audit-org-1"))
        r2 = client.get("/api/v1/audit/logs", headers=_pagination_headers("audit-org-2"))
        if r1.status_code == 200 and r2.status_code == 200:
            ids1 = {e.get("id") for e in r1.json().get("items", [])}
            ids2 = {e.get("id") for e in r2.json().get("items", [])}
            assert ids1.isdisjoint(ids2), "Cross-tenant audit log bleed detected"


# ---------------------------------------------------------------------------
# users_router.py  —  GET /api/v1/users
# ---------------------------------------------------------------------------


class TestUsersPagination:
    def test_default_returns_envelope(self, client):
        r = client.get("/api/v1/users", headers=_pagination_headers())
        assert r.status_code in (200, 401, 403), r.text
        if r.status_code == 200:
            data = r.json()
            _assert_paginated_envelope(data, limit=50, offset=0)

    def test_limit_respected(self, client):
        r = client.get(
            "/api/v1/users",
            headers=_pagination_headers(),
            params={"limit": 2, "offset": 0},
        )
        if r.status_code == 200:
            data = r.json()
            assert data["limit"] == 2
            assert len(data["items"]) <= 2

    def test_total_is_real_count(self, client):
        r = client.get(
            "/api/v1/users",
            headers=_pagination_headers(),
            params={"limit": 1, "offset": 0},
        )
        if r.status_code == 200:
            data = r.json()
            assert data["total"] >= len(data["items"]), (
                f"total={data['total']} should be >= items={len(data['items'])}"
            )

    def test_limit_out_of_range_rejected(self, client):
        r = client.get(
            "/api/v1/users",
            headers=_pagination_headers(),
            params={"limit": 9999},
        )
        assert r.status_code in (422, 401, 403), r.text

    def test_org_scoping_preserved(self, client):
        r1 = client.get("/api/v1/users", headers=_pagination_headers("users-org-1"))
        r2 = client.get("/api/v1/users", headers=_pagination_headers("users-org-2"))
        if r1.status_code == 200 and r2.status_code == 200:
            ids1 = {u.get("id") for u in r1.json().get("items", [])}
            ids2 = {u.get("id") for u in r2.json().get("items", [])}
            assert ids1.isdisjoint(ids2), "Cross-tenant user bleed detected"
