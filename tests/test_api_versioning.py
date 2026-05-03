"""
Tests for the API versioning module and versioning router.

Covers:
- APIVersion and DeprecationStatus enums
- EndpointVersion and VersionNegotiation Pydantic models
- APIVersionManager: register, deprecate, get, list, stats, negotiation,
  migration guides, sunset schedule, deprecation warnings
- VersioningMiddleware header injection
- versioning_router HTTP endpoints via TestClient
"""
from __future__ import annotations

import os
import tempfile

import pytest

# ---------------------------------------------------------------------------
# Environment setup (must come before any app imports)
# ---------------------------------------------------------------------------
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.api_versioning import (
    APIVersion,
    APIVersionManager,
    DeprecationStatus,
    EndpointVersion,
    VersionNegotiation,
    VersioningMiddleware,
    get_version_manager,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db(tmp_path):
    """Return a temporary SQLite database path."""
    return str(tmp_path / "test_versioning.db")


@pytest.fixture()
def manager(tmp_db):
    """Fresh APIVersionManager backed by a temp DB."""
    return APIVersionManager(db_path=tmp_db)


@pytest.fixture()
def populated_manager(manager):
    """Manager with several endpoints registered."""
    manager.register_endpoint("/api/v1/findings", APIVersion.V1)
    manager.register_endpoint("/api/v1/alerts", APIVersion.V1)
    manager.register_endpoint("/api/v2/findings", APIVersion.V2)
    manager.deprecate_endpoint(
        "/api/v1/findings",
        APIVersion.V1,
        replacement_path="/api/v2/findings",
        sunset_date="2027-01-01",
        migration_guide="Use /api/v2/findings instead.",
    )
    return manager


@pytest.fixture()
def app_with_middleware(tmp_db):
    """FastAPI app with VersioningMiddleware attached."""
    mgr = APIVersionManager(db_path=tmp_db)
    mgr.register_endpoint("/api/v1/findings", APIVersion.V1)
    mgr.deprecate_endpoint(
        "/api/v1/findings",
        APIVersion.V1,
        replacement_path="/api/v2/findings",
        sunset_date="2027-06-01",
    )

    app = FastAPI()
    app.add_middleware(VersioningMiddleware, version_manager=mgr)

    @app.get("/api/v1/findings")
    async def findings():
        return {"data": []}

    @app.get("/api/v1/alerts")
    async def alerts():
        return {"data": []}

    return TestClient(app)


@pytest.fixture()
def router_client(tmp_db, monkeypatch):
    """TestClient for the versioning_router with an isolated DB."""
    monkeypatch.setenv("FIXOPS_VERSIONING_DB", tmp_db)

    # Reset module-level singleton so it picks up the monkeypatched env
    import core.api_versioning as _av
    _av._default_manager = None

    from apps.api.versioning_router import router
    import core.api_versioning as _av2
    _av2._default_manager = None

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ===========================================================================
# 1. Enum tests
# ===========================================================================


def test_api_version_values():
    assert APIVersion.V1.value == "v1"
    assert APIVersion.V2.value == "v2"


def test_deprecation_status_values():
    assert DeprecationStatus.ACTIVE.value == "active"
    assert DeprecationStatus.DEPRECATED.value == "deprecated"
    assert DeprecationStatus.SUNSET.value == "sunset"


def test_api_version_str_comparison():
    assert APIVersion.V1 == "v1"
    assert APIVersion.V2 == "v2"


# ===========================================================================
# 2. Pydantic model tests
# ===========================================================================


def test_endpoint_version_defaults():
    ev = EndpointVersion(path="/api/v1/test", version=APIVersion.V1)
    assert ev.status == DeprecationStatus.ACTIVE
    assert ev.deprecated_at is None
    assert ev.sunset_date is None
    assert ev.replacement_path is None
    assert ev.migration_guide is None


def test_endpoint_version_full():
    ev = EndpointVersion(
        path="/api/v1/findings",
        version=APIVersion.V1,
        status=DeprecationStatus.DEPRECATED,
        deprecated_at="2026-01-01T00:00:00+00:00",
        sunset_date="2027-01-01",
        replacement_path="/api/v2/findings",
        migration_guide="Upgrade to v2.",
    )
    assert ev.replacement_path == "/api/v2/findings"
    assert ev.status == DeprecationStatus.DEPRECATED


def test_version_negotiation_model():
    vn = VersionNegotiation(
        requested="v2", resolved=APIVersion.V2, method="header"
    )
    assert vn.resolved == APIVersion.V2
    assert vn.method == "header"


# ===========================================================================
# 3. APIVersionManager — register / get
# ===========================================================================


def test_register_endpoint_returns_model(manager):
    ev = manager.register_endpoint("/api/v1/findings", APIVersion.V1)
    assert isinstance(ev, EndpointVersion)
    assert ev.path == "/api/v1/findings"
    assert ev.version == APIVersion.V1
    assert ev.status == DeprecationStatus.ACTIVE


def test_register_endpoint_persists(manager):
    manager.register_endpoint("/api/v1/alerts", APIVersion.V1)
    ev = manager.get_endpoint_version("/api/v1/alerts")
    assert ev is not None
    assert ev.path == "/api/v1/alerts"


def test_get_endpoint_version_missing(manager):
    result = manager.get_endpoint_version("/api/v1/nonexistent")
    assert result is None


def test_register_upsert_idempotent(manager):
    manager.register_endpoint("/api/v1/test", APIVersion.V1)
    manager.register_endpoint("/api/v1/test", APIVersion.V1)
    endpoints = manager.list_endpoints(version=APIVersion.V1)
    paths = [e.path for e in endpoints]
    assert paths.count("/api/v1/test") == 1


# ===========================================================================
# 4. APIVersionManager — deprecate
# ===========================================================================


def test_deprecate_existing_endpoint(manager):
    manager.register_endpoint("/api/v1/findings", APIVersion.V1)
    ev = manager.deprecate_endpoint(
        "/api/v1/findings",
        APIVersion.V1,
        replacement_path="/api/v2/findings",
        sunset_date="2027-01-01",
        migration_guide="Use v2.",
    )
    assert ev.status == DeprecationStatus.DEPRECATED
    assert ev.replacement_path == "/api/v2/findings"
    assert ev.sunset_date == "2027-01-01"
    assert ev.migration_guide == "Use v2."
    assert ev.deprecated_at is not None


def test_deprecate_inserts_if_missing(manager):
    ev = manager.deprecate_endpoint(
        "/api/v1/legacy",
        APIVersion.V1,
        replacement_path="/api/v2/legacy",
    )
    assert ev.status == DeprecationStatus.DEPRECATED


def test_deprecate_persists_in_db(manager):
    manager.register_endpoint("/api/v1/findings", APIVersion.V1)
    manager.deprecate_endpoint("/api/v1/findings", APIVersion.V1)
    ev = manager.get_endpoint_version("/api/v1/findings")
    assert ev is not None
    assert ev.status == DeprecationStatus.DEPRECATED


# ===========================================================================
# 5. APIVersionManager — list
# ===========================================================================


def test_list_all_endpoints(populated_manager):
    endpoints = populated_manager.list_endpoints()
    assert len(endpoints) == 3


def test_list_filter_by_version(populated_manager):
    v1_eps = populated_manager.list_endpoints(version=APIVersion.V1)
    assert all(e.version == APIVersion.V1 for e in v1_eps)
    assert len(v1_eps) == 2


def test_list_filter_by_status(populated_manager):
    deprecated = populated_manager.list_endpoints(
        status_filter=DeprecationStatus.DEPRECATED
    )
    assert len(deprecated) == 1
    assert deprecated[0].path == "/api/v1/findings"


def test_list_filter_by_version_and_status(populated_manager):
    result = populated_manager.list_endpoints(
        version=APIVersion.V2, status_filter=DeprecationStatus.ACTIVE
    )
    assert len(result) == 1
    assert result[0].path == "/api/v2/findings"


# ===========================================================================
# 6. APIVersionManager — version negotiation
# ===========================================================================


def _make_mock_request(path: str, headers: dict | None = None):
    """Build a minimal Starlette Request mock for negotiate_version tests."""
    from starlette.datastructures import Headers
    from starlette.testclient import TestClient
    from starlette.types import Receive, Scope, Send

    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "query_string": b"",
        "headers": [
            (k.lower().encode(), v.encode())
            for k, v in (headers or {}).items()
        ],
    }
    # Use starlette's Request directly — it only needs a scope dict
    from starlette.requests import Request as StarletteRequest
    return StarletteRequest(scope)


def test_negotiate_via_header(manager):
    req = _make_mock_request("/probe", headers={"Accept-Version": "v2"})
    neg = manager.negotiate_version(req)
    assert neg.resolved == APIVersion.V2
    assert neg.method == "header"


def test_negotiate_via_url(manager):
    req = _make_mock_request("/api/v2/findings")
    neg = manager.negotiate_version(req)
    assert neg.resolved == APIVersion.V2
    assert neg.method == "url"


def test_negotiate_default(manager):
    req = _make_mock_request("/health")
    neg = manager.negotiate_version(req)
    assert neg.resolved == APIVersion.V1
    assert neg.method == "default"


def test_negotiate_invalid_header_falls_back_to_url(manager):
    req = _make_mock_request("/api/v1/test", headers={"Accept-Version": "vBAD"})
    neg = manager.negotiate_version(req)
    assert neg.resolved == APIVersion.V1
    assert neg.method == "url"


# ===========================================================================
# 7. APIVersionManager — deprecation warnings / migration / sunset
# ===========================================================================


def test_get_deprecation_warnings(populated_manager):
    warnings = populated_manager.get_deprecation_warnings(APIVersion.V1)
    assert len(warnings) == 1
    assert warnings[0].path == "/api/v1/findings"


def test_get_deprecation_warnings_empty(populated_manager):
    warnings = populated_manager.get_deprecation_warnings(APIVersion.V2)
    assert warnings == []


def test_get_migration_guide_with_stored_guide(populated_manager):
    guide = populated_manager.get_migration_guide(
        "/api/v1/findings", APIVersion.V1, APIVersion.V2
    )
    assert "v2" in guide.lower() or "Use /api/v2/findings" in guide


def test_get_migration_guide_auto_generated(manager):
    manager.register_endpoint("/api/v1/alerts", APIVersion.V1)
    guide = manager.get_migration_guide(
        "/api/v1/alerts", APIVersion.V1, APIVersion.V2
    )
    assert "v2" in guide.lower()


def test_get_migration_guide_missing_endpoint(manager):
    guide = manager.get_migration_guide(
        "/api/v1/ghost", APIVersion.V1, APIVersion.V2
    )
    assert "No version record" in guide or "register" in guide.lower()


def test_get_sunset_schedule(populated_manager):
    schedule = populated_manager.get_sunset_schedule()
    assert len(schedule) == 1
    assert schedule[0].sunset_date == "2027-01-01"


def test_get_sunset_schedule_empty(manager):
    manager.register_endpoint("/api/v1/findings", APIVersion.V1)
    schedule = manager.get_sunset_schedule()
    assert schedule == []


# ===========================================================================
# 8. APIVersionManager — stats
# ===========================================================================


def test_get_versioning_stats_empty(manager):
    stats = manager.get_versioning_stats()
    assert stats["total_endpoints"] == 0
    assert stats["deprecated_count"] == 0
    assert "supported_versions" in stats


def test_get_versioning_stats_populated(populated_manager):
    stats = populated_manager.get_versioning_stats()
    assert stats["total_endpoints"] == 3
    assert stats["deprecated_count"] == 1
    assert "v1" in stats["endpoints_per_version"]
    assert "v2" in stats["endpoints_per_version"]
    assert stats["endpoints_with_sunset_date"] == 1


# ===========================================================================
# 9. VersioningMiddleware
# ===========================================================================


def test_middleware_adds_api_version_header(app_with_middleware):
    resp = app_with_middleware.get("/api/v1/alerts")
    assert "x-api-version" in resp.headers
    assert resp.headers["x-api-version"] == "v1"


def test_middleware_adds_deprecation_header(app_with_middleware):
    resp = app_with_middleware.get("/api/v1/findings")
    assert "deprecation" in resp.headers


def test_middleware_adds_sunset_header(app_with_middleware):
    resp = app_with_middleware.get("/api/v1/findings")
    assert "sunset" in resp.headers
    assert resp.headers["sunset"] == "2027-06-01"


def test_middleware_adds_link_header(app_with_middleware):
    resp = app_with_middleware.get("/api/v1/findings")
    assert "link" in resp.headers
    assert "/api/v2/findings" in resp.headers["link"]


def test_middleware_no_deprecation_for_active(app_with_middleware):
    resp = app_with_middleware.get("/api/v1/alerts")
    assert "deprecation" not in resp.headers
    assert "sunset" not in resp.headers


# ===========================================================================
# 10. versioning_router HTTP endpoints
# ===========================================================================


def test_router_list_versions(router_client):
    resp = router_client.get("/api/versions")
    assert resp.status_code == 200
    data = resp.json()
    assert "versions" in data
    assert len(data["versions"]) == 2
    versions = [v["version"] for v in data["versions"]]
    assert "v1" in versions
    assert "v2" in versions


def test_router_list_endpoints_empty(router_client):
    resp = router_client.get("/api/versions/endpoints")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 0
    assert data["endpoints"] == []


def test_router_list_endpoints_with_version_filter(router_client, tmp_db, monkeypatch):
    import core.api_versioning as _av
    mgr = _av.get_version_manager(db_path=tmp_db)
    mgr.register_endpoint("/api/v1/findings", APIVersion.V1)
    mgr.register_endpoint("/api/v2/findings", APIVersion.V2)

    resp = router_client.get("/api/versions/endpoints?version=v1")
    assert resp.status_code == 200
    data = resp.json()
    assert all(e["version"] == "v1" for e in data["endpoints"])


def test_router_list_endpoints_invalid_version(router_client):
    resp = router_client.get("/api/versions/endpoints?version=v99")
    assert resp.status_code == 422


def test_router_deprecated_empty(router_client):
    resp = router_client.get("/api/versions/deprecated")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 0


def test_router_deprecated_returns_items(router_client, tmp_db):
    import core.api_versioning as _av
    mgr = _av.get_version_manager(db_path=tmp_db)
    mgr.register_endpoint("/api/v1/findings", APIVersion.V1)
    mgr.deprecate_endpoint("/api/v1/findings", APIVersion.V1)

    resp = router_client.get("/api/versions/deprecated")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 1
    assert data["deprecated_endpoints"][0]["path"] == "/api/v1/findings"


def test_router_sunset_schedule_empty(router_client):
    resp = router_client.get("/api/versions/sunset-schedule")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 0


def test_router_sunset_schedule_with_entries(router_client, tmp_db):
    import core.api_versioning as _av
    mgr = _av.get_version_manager(db_path=tmp_db)
    mgr.register_endpoint("/api/v1/old", APIVersion.V1)
    mgr.deprecate_endpoint("/api/v1/old", APIVersion.V1, sunset_date="2027-03-01")

    resp = router_client.get("/api/versions/sunset-schedule")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 1
    assert data["sunset_schedule"][0]["sunset_date"] == "2027-03-01"


def test_router_migration_guide_auto(router_client, tmp_db):
    import core.api_versioning as _av
    mgr = _av.get_version_manager(db_path=tmp_db)
    mgr.register_endpoint("/api/v1/alerts", APIVersion.V1)

    resp = router_client.get(
        "/api/versions/migration/api/v1/alerts?from_version=v1&to_version=v2"
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "migration_guide" in data
    assert data["from_version"] == "v1"
    assert data["to_version"] == "v2"


def test_router_migration_guide_stored(router_client, tmp_db):
    import core.api_versioning as _av
    mgr = _av.get_version_manager(db_path=tmp_db)
    mgr.register_endpoint("/api/v1/findings", APIVersion.V1)
    mgr.deprecate_endpoint(
        "/api/v1/findings",
        APIVersion.V1,
        replacement_path="/api/v2/findings",
        migration_guide="Switch to /api/v2/findings for improved performance.",
    )

    resp = router_client.get(
        "/api/versions/migration/api/v1/findings?from_version=v1&to_version=v2"
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "improved performance" in data["migration_guide"]
    assert data["replacement_path"] == "/api/v2/findings"


def test_router_migration_invalid_from_version(router_client):
    resp = router_client.get(
        "/api/versions/migration/api/v1/test?from_version=vXXX&to_version=v2"
    )
    assert resp.status_code == 422


def test_router_stats(router_client):
    resp = router_client.get("/api/versions/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_endpoints" in data
    assert "supported_versions" in data
    assert "deprecated_count" in data


def test_router_stats_reflects_data(router_client, tmp_db):
    import core.api_versioning as _av
    mgr = _av.get_version_manager(db_path=tmp_db)
    mgr.register_endpoint("/api/v1/ep1", APIVersion.V1)
    mgr.register_endpoint("/api/v1/ep2", APIVersion.V1)
    mgr.register_endpoint("/api/v2/ep1", APIVersion.V2)
    mgr.deprecate_endpoint("/api/v1/ep1", APIVersion.V1)

    resp = router_client.get("/api/versions/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_endpoints"] == 3
    assert data["deprecated_count"] == 1


# ===========================================================================
# 11. Singleton get_version_manager
# ===========================================================================


def test_get_version_manager_singleton(tmp_db):
    import core.api_versioning as _av
    _av._default_manager = None  # reset

    m1 = get_version_manager(db_path=tmp_db)
    m2 = get_version_manager(db_path=tmp_db)
    assert m1 is m2


def test_get_version_manager_returns_instance(tmp_db):
    import core.api_versioning as _av
    _av._default_manager = None

    mgr = get_version_manager(db_path=tmp_db)
    assert isinstance(mgr, APIVersionManager)


# ===========================================================================
# 12. POST /api/versions/register
# ===========================================================================


def test_router_register_endpoint_created(router_client):
    resp = router_client.post(
        "/api/versions/register",
        json={"path": "/api/v1/assets", "version": "v1"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["registered"] is True
    assert data["endpoint"]["path"] == "/api/v1/assets"
    assert data["endpoint"]["version"] == "v1"
    assert data["endpoint"]["status"] == "active"


def test_router_register_endpoint_invalid_version(router_client):
    resp = router_client.post(
        "/api/versions/register",
        json={"path": "/api/v99/test", "version": "v99"},
    )
    assert resp.status_code == 422


def test_router_register_endpoint_invalid_status(router_client):
    resp = router_client.post(
        "/api/versions/register",
        json={"path": "/api/v1/test", "version": "v1", "status": "bogus"},
    )
    assert resp.status_code == 422


def test_router_register_endpoint_persists_and_visible(router_client, tmp_db):
    router_client.post(
        "/api/versions/register",
        json={"path": "/api/v1/sbom", "version": "v1"},
    )
    resp = router_client.get("/api/versions/endpoints?version=v1")
    assert resp.status_code == 200
    paths = [e["path"] for e in resp.json()["endpoints"]]
    assert "/api/v1/sbom" in paths


# ===========================================================================
# 13. POST /api/versions/deprecate
# ===========================================================================


def test_router_deprecate_endpoint(router_client, tmp_db):
    import core.api_versioning as _av
    mgr = _av.get_version_manager(db_path=tmp_db)
    mgr.register_endpoint("/api/v1/findings", APIVersion.V1)

    resp = router_client.post(
        "/api/versions/deprecate",
        json={
            "path": "/api/v1/findings",
            "version": "v1",
            "replacement_path": "/api/v2/findings",
            "sunset_date": "2027-06-01",
            "migration_guide": "Switch to /api/v2/findings.",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["deprecated"] is True
    assert data["endpoint"]["status"] == "deprecated"
    assert data["sunset_date"] == "2027-06-01"
    assert data["replacement_path"] == "/api/v2/findings"


def test_router_deprecate_nonexistent_inserts(router_client):
    resp = router_client.post(
        "/api/versions/deprecate",
        json={"path": "/api/v1/legacy-search", "version": "v1"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["deprecated"] is True
    assert data["endpoint"]["status"] == "deprecated"


def test_router_deprecate_shows_in_deprecated_list(router_client, tmp_db):
    import core.api_versioning as _av
    mgr = _av.get_version_manager(db_path=tmp_db)
    mgr.register_endpoint("/api/v1/old-reports", APIVersion.V1)

    router_client.post(
        "/api/versions/deprecate",
        json={
            "path": "/api/v1/old-reports",
            "version": "v1",
            "sunset_date": "2027-09-01",
        },
    )
    resp = router_client.get("/api/versions/deprecated")
    assert resp.status_code == 200
    paths = [e["path"] for e in resp.json()["deprecated_endpoints"]]
    assert "/api/v1/old-reports" in paths


def test_router_deprecate_invalid_version(router_client):
    resp = router_client.post(
        "/api/versions/deprecate",
        json={"path": "/api/v1/test", "version": "v99"},
    )
    assert resp.status_code == 422


def test_router_deprecate_appears_in_sunset_schedule(router_client, tmp_db):
    import core.api_versioning as _av
    mgr = _av.get_version_manager(db_path=tmp_db)
    mgr.register_endpoint("/api/v1/scans", APIVersion.V1)

    router_client.post(
        "/api/versions/deprecate",
        json={
            "path": "/api/v1/scans",
            "version": "v1",
            "sunset_date": "2027-12-31",
        },
    )
    resp = router_client.get("/api/versions/sunset-schedule")
    assert resp.status_code == 200
    dates = [e["sunset_date"] for e in resp.json()["sunset_schedule"]]
    assert "2027-12-31" in dates
