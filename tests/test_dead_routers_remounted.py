"""tests/test_dead_routers_remounted.py

FIX-E verification: 3 routers that were silently unmounted (404 to customers)
due to wrong-symbol import bugs are now correctly wired.

  1. compliance_dashboard_router  — prefix /api/v1/compliance-dashboard
     Was broken: from apps.api.compliance_router import get_compliance_engine
     Real symbol: _get_engine() (module-private factory)

  2. siem_router (suite-integrations) — prefix /api/v1/siem (targets/forward/stats/health)
     Was broken: loaded in app.py but never passed to include_router()
     Real class: SIEMEngine (not SIEMConnector); real module: integrations.siem_engine

  3. data_residency_router — prefix /api/v1/data-residency
     Was broken: from core.geo_engine import ...  (module does not exist)
     Real module: core.data_security; real engine: DataSecurityEngine.get_residency_status()

For each router this test asserts:
  a) The prefix appears in the mounted route table (mount confirmed)
  b) A sample GET on a real endpoint returns something other than 404
     (401 = auth wall hit = router IS mounted; 200 = bonus pass; 404 = FAIL)
"""

from __future__ import annotations

import os
import sys

import pytest

# ── Ensure correct PYTHONPATH ────────────────────────────────────────────────
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in [
    _REPO,
    os.path.join(_REPO, "suite-api"),
    os.path.join(_REPO, "suite-core"),
    os.path.join(_REPO, "suite-integrations"),
    os.path.join(_REPO, "suite-evidence-risk"),
    os.path.join(_REPO, "suite-attack"),
    os.path.join(_REPO, "suite-feeds"),
]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ── Auth token (mirrors conftest.py pattern) ────────────────────────────────
_API_TOKEN = os.getenv(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)
os.environ.setdefault("FIXOPS_API_TOKEN", _API_TOKEN)
_AUTH_HEADERS = {"X-API-Key": _API_TOKEN}


# ── App fixture (module-scoped for speed) ────────────────────────────────────

@pytest.fixture(scope="module")
def app():
    from apps.api.app import create_app  # noqa: PLC0415
    return create_app()


@pytest.fixture(scope="module")
def client(app):
    from fastapi.testclient import TestClient  # noqa: PLC0415
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(scope="module")
def mounted_paths(app):
    return {r.path for r in app.routes if hasattr(r, "path")}


# ═══════════════════════════════════════════════════════════════════════════
# 1. compliance_dashboard_router
# ═══════════════════════════════════════════════════════════════════════════

class TestComplianceDashboardMounted:
    """Prefix /api/v1/compliance-dashboard must be present and not 404."""

    def test_prefix_in_route_table(self, mounted_paths):
        """At least one route under /api/v1/compliance-dashboard is registered."""
        matches = [p for p in mounted_paths if p.startswith("/api/v1/compliance-dashboard")]
        assert matches, (
            "No routes under /api/v1/compliance-dashboard — router not mounted. "
            f"Available /api/v1/compliance-* prefixes: "
            f"{sorted(p for p in mounted_paths if 'compliance' in p)[:10]}"
        )

    def test_health_endpoint_not_404(self, client):
        """GET /api/v1/compliance-dashboard/health must not 404."""
        r = client.get("/api/v1/compliance-dashboard/health", headers=_AUTH_HEADERS)
        assert r.status_code != 404, (
            f"GET /api/v1/compliance-dashboard/health returned 404 — router is unmounted. "
            f"Got: {r.status_code} {r.text[:200]}"
        )

    def test_summary_endpoint_not_404(self, client):
        """GET /api/v1/compliance-dashboard/summary must not 404 (401/200/503 all acceptable)."""
        r = client.get("/api/v1/compliance-dashboard/summary", headers=_AUTH_HEADERS)
        assert r.status_code != 404, (
            f"GET /api/v1/compliance-dashboard/summary returned 404 — router is unmounted. "
            f"Got: {r.status_code} {r.text[:200]}"
        )

    def test_frameworks_endpoint_not_404(self, client):
        """GET /api/v1/compliance-dashboard/frameworks must not 404."""
        r = client.get("/api/v1/compliance-dashboard/frameworks", headers=_AUTH_HEADERS)
        assert r.status_code != 404, (
            f"GET /api/v1/compliance-dashboard/frameworks returned 404 — router is unmounted. "
            f"Got: {r.status_code} {r.text[:200]}"
        )

    def test_gaps_endpoint_not_404(self, client):
        """GET /api/v1/compliance-dashboard/gaps must not 404."""
        r = client.get("/api/v1/compliance-dashboard/gaps", headers=_AUTH_HEADERS)
        assert r.status_code != 404, (
            f"GET /api/v1/compliance-dashboard/gaps returned 404 — router is unmounted. "
            f"Got: {r.status_code} {r.text[:200]}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# 2. siem_router (suite-integrations)
# ═══════════════════════════════════════════════════════════════════════════

class TestSIEMRouterMounted:
    """
    siem_router prefix /api/v1/siem — specifically the suite-integrations router
    endpoints (/targets, /forward, /stats, /health) must be mounted.
    Note: /api/v1/siem/alerts etc come from siem_integration_router (separate).
    """

    def test_siem_targets_in_route_table(self, mounted_paths):
        """Route /api/v1/siem/targets must be registered."""
        assert "/api/v1/siem/targets" in mounted_paths, (
            "Route /api/v1/siem/targets not in route table — siem_router not mounted. "
            f"Available /api/v1/siem/* routes: "
            f"{sorted(p for p in mounted_paths if '/siem/' in p)[:10]}"
        )

    def test_siem_health_not_404(self, client):
        """GET /api/v1/siem/health must not 404."""
        r = client.get("/api/v1/siem/health", headers=_AUTH_HEADERS)
        assert r.status_code != 404, (
            f"GET /api/v1/siem/health returned 404 — siem_router unmounted. "
            f"Got: {r.status_code} {r.text[:200]}"
        )

    def test_siem_targets_list_not_404(self, client):
        """GET /api/v1/siem/targets must not 404 (200 = empty list, 401 = auth wall)."""
        r = client.get("/api/v1/siem/targets", headers=_AUTH_HEADERS)
        assert r.status_code != 404, (
            f"GET /api/v1/siem/targets returned 404 — siem_router unmounted. "
            f"Got: {r.status_code} {r.text[:200]}"
        )

    def test_siem_stats_not_404(self, client):
        """GET /api/v1/siem/stats must not 404."""
        r = client.get("/api/v1/siem/stats", headers=_AUTH_HEADERS)
        assert r.status_code != 404, (
            f"GET /api/v1/siem/stats returned 404 — siem_router unmounted. "
            f"Got: {r.status_code} {r.text[:200]}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# 3. data_residency_router
# ═══════════════════════════════════════════════════════════════════════════

class TestDataResidencyMounted:
    """Prefix /api/v1/data-residency must be present and not 404."""

    def test_prefix_in_route_table(self, mounted_paths):
        """At least one route under /api/v1/data-residency is registered."""
        matches = [p for p in mounted_paths if p.startswith("/api/v1/data-residency")]
        assert matches, (
            "No routes under /api/v1/data-residency — router not mounted. "
            f"Available /api/v1/data-* prefixes: "
            f"{sorted(p for p in mounted_paths if '/data-' in p)[:10]}"
        )

    def test_health_endpoint_not_404(self, client):
        """GET /api/v1/data-residency/health must not 404."""
        r = client.get("/api/v1/data-residency/health", headers=_AUTH_HEADERS)
        assert r.status_code != 404, (
            f"GET /api/v1/data-residency/health returned 404 — router is unmounted. "
            f"Got: {r.status_code} {r.text[:200]}"
        )

    def test_records_endpoint_not_404(self, client):
        """GET /api/v1/data-residency/records must not 404."""
        r = client.get("/api/v1/data-residency/records", headers=_AUTH_HEADERS)
        assert r.status_code != 404, (
            f"GET /api/v1/data-residency/records returned 404 — router is unmounted. "
            f"Got: {r.status_code} {r.text[:200]}"
        )

    def test_violations_endpoint_not_404(self, client):
        """GET /api/v1/data-residency/violations must not 404."""
        r = client.get("/api/v1/data-residency/violations", headers=_AUTH_HEADERS)
        assert r.status_code != 404, (
            f"GET /api/v1/data-residency/violations returned 404 — router is unmounted. "
            f"Got: {r.status_code} {r.text[:200]}"
        )
