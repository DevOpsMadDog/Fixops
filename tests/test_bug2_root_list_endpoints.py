"""BUG-2 regression test — root GET / endpoints on priority routers.

The CTO push: 44% of frontend API calls returned 404 because routers were
mounted at e.g. `/api/v1/access-anomaly` but had no `GET /` handler.

This test asserts that for every priority router, hitting the root path
returns a non-404 status (200 success, 307 trailing-slash redirect, or
401/403 auth). A 404 means the route literally does not exist and the
hub/landing page that fans out into the router will fail.

Auth is supplied so that 200 is the expected normal path; 401/403 are
accepted for routers wired with extra scope checks. 405 is accepted for
routers that explicitly only allow non-GET methods at the root (rare).
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

# Test API key — set BEFORE app import so middleware picks it up.
TEST_API_KEY = "test-bug2-key"
os.environ.setdefault("FIXOPS_API_KEY", TEST_API_KEY)
os.environ.setdefault("API_KEY", TEST_API_KEY)
os.environ.setdefault("FIXOPS_AUTH_DISABLED", "0")

from apps.api.app import create_app  # noqa: E402

PRIORITY_ROUTERS = [
    "/api/v1/access-anomaly/",
    "/api/v1/access-governance/",
    "/api/v1/cloud-accounts/",
    "/api/v1/cloud-ir/",
    "/api/v1/control-testing/",
    "/api/v1/cost-optimization/",
    "/api/v1/compliance-calendar/",
    "/api/v1/identity-lifecycle/",
    "/api/v1/intel-enrichment/",
    "/api/v1/ioc-enrichment/",
    "/api/v1/posture-history/",
    "/api/v1/posture-trends/",
    "/api/v1/ransomware-protection/",
    "/api/v1/threat-indicators/",
    "/api/v1/threat-response/",
    "/api/v1/training-effectiveness/",
    "/api/v1/security-findings/",
    "/api/v1/security-benchmarks/",
    "/api/v1/security-baselines/",
    "/api/v1/soc-metrics/",
    "/api/v1/sbom-export/",
    "/api/v1/secrets/",
    "/api/v1/reports/",
]

ACCEPTABLE = {200, 201, 204, 307, 308, 401, 403, 422}


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Create a single TestClient for the whole module (app boot is expensive)."""
    app = create_app()
    # follow_redirects=False so we can validate that 307 (trailing-slash redirect)
    # is itself a non-404 response — the redirect target is exercised separately.
    return TestClient(app, follow_redirects=False)


@pytest.mark.parametrize("path", PRIORITY_ROUTERS)
def test_priority_router_root_not_404(client: TestClient, path: str) -> None:
    """Each priority router must respond non-404 at its root path."""
    headers = {
        "X-API-Key": TEST_API_KEY,
        "Authorization": f"Bearer {TEST_API_KEY}",
    }
    resp = client.get(path, headers=headers)
    assert resp.status_code != 404, (
        f"BUG-2 regression: {path} returned 404 — root list endpoint missing. "
        f"Body: {resp.text[:300]}"
    )
    assert resp.status_code in ACCEPTABLE, (
        f"{path} returned unexpected status {resp.status_code}: {resp.text[:300]}"
    )


def test_priority_router_count() -> None:
    """Sanity: priority list size is what BUG-2 task expected (23)."""
    assert len(PRIORITY_ROUTERS) == 23, (
        f"Priority router list drifted from BUG-2 spec (23): got {len(PRIORITY_ROUTERS)}"
    )
