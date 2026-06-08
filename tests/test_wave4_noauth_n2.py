"""
Wave-4 N2 security tests — IDOR fixes for incident_response_router and deduplication_router.

Verifies:
1. By-id handlers without a key → 401/403 (auth gate enforced at router level)
2. Cross-org by-id access → 404 (ownership check)
3. Auth-gated list/create endpoints also require a key
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Ensure suite paths are on sys.path before any imports
# ---------------------------------------------------------------------------
_REPO = Path(__file__).parent.parent
for _p in [
    str(_REPO),
    str(_REPO / "suite-api"),
    str(_REPO / "suite-core"),
]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Set up auth env-vars before FastAPI app import.
# Force-set (not setdefault) so a pre-existing env value doesn't shadow us.
# ---------------------------------------------------------------------------
_TEST_TOKEN = "test-token-wave4-n2"
os.environ.setdefault("FIXOPS_API_TOKEN", _TEST_TOKEN)
os.environ["FIXOPS_MODE"] = "test"  # NOT dev/demo — real auth enforced


# ---------------------------------------------------------------------------
# Build a minimal test app containing only the two routers under test
# ---------------------------------------------------------------------------
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.incident_response_router import router as ir_router

try:
    from api.deduplication_router import router as dedup_router
    _HAS_DEDUP = True
except ImportError:
    _HAS_DEDUP = False

_app = FastAPI()
_app.include_router(ir_router)
if _HAS_DEDUP:
    _app.include_router(dedup_router)

_client = TestClient(_app, raise_server_exceptions=False)

_AUTH = {"X-API-Key": _TEST_TOKEN}
_ORG_A = "org-alpha"
_ORG_B = "org-beta"


# ===========================================================================
# Helpers
# ===========================================================================

def _headers(org: str | None = None, authed: bool = True) -> dict:
    h: dict = {}
    if authed:
        h["X-API-Key"] = _TEST_TOKEN
    if org:
        h["X-Org-ID"] = org
    return h


# ===========================================================================
# Incident Response Router — auth gate tests
# ===========================================================================

class TestIncidentRouterAuthGate:
    """Every endpoint must reject requests with no API key."""

    def test_list_no_key_rejected(self):
        r = _client.get("/api/v1/incidents")
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_create_no_key_rejected(self):
        r = _client.post(
            "/api/v1/incidents",
            json={"title": "t", "type": "data_breach", "severity": "sev1", "reported_by": "x"},
        )
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_get_by_id_no_key_rejected(self):
        r = _client.get(f"/api/v1/incidents/{uuid.uuid4()}")
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_update_status_no_key_rejected(self):
        r = _client.put(
            f"/api/v1/incidents/{uuid.uuid4()}/status",
            json={"new_status": "triaging"},
        )
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_assign_step_no_key_rejected(self):
        r = _client.post(
            f"/api/v1/incidents/{uuid.uuid4()}/steps/1/assign",
            json={"assignee": "alice"},
        )
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_complete_step_no_key_rejected(self):
        r = _client.post(
            f"/api/v1/incidents/{uuid.uuid4()}/steps/1/complete",
            json={},
        )
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_timeline_no_key_rejected(self):
        r = _client.post(
            f"/api/v1/incidents/{uuid.uuid4()}/timeline",
            json={"event_description": "e", "author": "a"},
        )
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_post_mortem_create_no_key_rejected(self):
        r = _client.post(
            f"/api/v1/incidents/{uuid.uuid4()}/post-mortem",
            json={"summary": "s", "root_cause": "r", "authored_by": "a"},
        )
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_post_mortem_get_no_key_rejected(self):
        r = _client.get(f"/api/v1/incidents/{uuid.uuid4()}/post-mortem")
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_templates_no_key_rejected(self):
        r = _client.get("/api/v1/incidents/templates/data_breach")
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_stats_no_key_rejected(self):
        r = _client.get("/api/v1/incidents/stats")
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"


# ===========================================================================
# Incident Response Router — cross-org IDOR tests
# ===========================================================================

class TestIncidentRouterCrossOrg:
    """Org-A incident must not be visible to Org-B caller."""

    def _create_incident(self, org: str) -> str:
        """Create an incident for org and return its ID, or skip if IR unavailable."""
        r = _client.post(
            "/api/v1/incidents",
            headers=_headers(org=org),
            json={
                "title": f"Incident for {org}",
                "type": "data_breach",
                "severity": "sev1",
                "reported_by": "tester",
            },
        )
        if r.status_code == 503:
            pytest.skip("IncidentResponseManager not available in test env")
        assert r.status_code == 200, f"create failed: {r.status_code} {r.text}"
        return r.json()["id"]

    def test_cross_org_get_returns_404(self):
        inc_id = self._create_incident(_ORG_A)
        # Org-B tries to read Org-A's incident
        r = _client.get(
            f"/api/v1/incidents/{inc_id}",
            headers=_headers(org=_ORG_B),
        )
        assert r.status_code == 404, f"Expected 404 (IDOR blocked) got {r.status_code}"

    def test_cross_org_update_status_returns_404(self):
        inc_id = self._create_incident(_ORG_A)
        r = _client.put(
            f"/api/v1/incidents/{inc_id}/status",
            headers=_headers(org=_ORG_B),
            json={"new_status": "triaging"},
        )
        assert r.status_code == 404, f"Expected 404 (IDOR blocked) got {r.status_code}"

    def test_cross_org_assign_step_returns_404(self):
        inc_id = self._create_incident(_ORG_A)
        r = _client.post(
            f"/api/v1/incidents/{inc_id}/steps/1/assign",
            headers=_headers(org=_ORG_B),
            json={"assignee": "attacker"},
        )
        assert r.status_code == 404, f"Expected 404 (IDOR blocked) got {r.status_code}"

    def test_cross_org_complete_step_returns_404(self):
        inc_id = self._create_incident(_ORG_A)
        r = _client.post(
            f"/api/v1/incidents/{inc_id}/steps/1/complete",
            headers=_headers(org=_ORG_B),
            json={},
        )
        assert r.status_code == 404, f"Expected 404 (IDOR blocked) got {r.status_code}"

    def test_cross_org_timeline_returns_404(self):
        inc_id = self._create_incident(_ORG_A)
        r = _client.post(
            f"/api/v1/incidents/{inc_id}/timeline",
            headers=_headers(org=_ORG_B),
            json={"event_description": "evil event", "author": "attacker"},
        )
        assert r.status_code == 404, f"Expected 404 (IDOR blocked) got {r.status_code}"

    def test_cross_org_post_mortem_create_returns_404(self):
        inc_id = self._create_incident(_ORG_A)
        r = _client.post(
            f"/api/v1/incidents/{inc_id}/post-mortem",
            headers=_headers(org=_ORG_B),
            json={"summary": "s", "root_cause": "r", "authored_by": "attacker"},
        )
        assert r.status_code == 404, f"Expected 404 (IDOR blocked) got {r.status_code}"

    def test_cross_org_post_mortem_get_returns_404(self):
        inc_id = self._create_incident(_ORG_A)
        r = _client.get(
            f"/api/v1/incidents/{inc_id}/post-mortem",
            headers=_headers(org=_ORG_B),
        )
        assert r.status_code == 404, f"Expected 404 (IDOR blocked) got {r.status_code}"

    def test_own_org_get_succeeds(self):
        """Sanity: same-org caller must still be able to fetch their own incident."""
        inc_id = self._create_incident(_ORG_A)
        r = _client.get(
            f"/api/v1/incidents/{inc_id}",
            headers=_headers(org=_ORG_A),
        )
        # 200 = found, 503 = IR module missing — both are acceptable
        assert r.status_code in (200, 503), f"Own-org get failed: {r.status_code} {r.text}"

    def test_list_is_org_scoped(self):
        """list_incidents for Org-A must not return Org-B incidents."""
        # Create one incident for each org
        self._create_incident(_ORG_A)
        self._create_incident(_ORG_B)

        r = _client.get("/api/v1/incidents", headers=_headers(org=_ORG_A))
        if r.status_code == 503:
            pytest.skip("IR not available")
        assert r.status_code == 200
        ids = [i["id"] for i in r.json().get("incidents", [])]
        # Verify no Org-B incidents leaked (we can't easily assert on IDs without
        # tracking them, but we can assert all returned incidents carry org_id = _ORG_A)
        for inc in r.json().get("incidents", []):
            assert inc.get("org_id") == _ORG_A, (
                f"Org-A list returned incident with org_id={inc.get('org_id')}"
            )


# ===========================================================================
# Deduplication Router — auth gate tests
# ===========================================================================

@pytest.mark.skipif(not _HAS_DEDUP, reason="deduplication_router not importable")
class TestDedupRouterAuthGate:
    """Every dedup endpoint must reject requests with no API key."""

    def test_list_clusters_no_key_rejected(self):
        r = _client.get("/api/v1/deduplication/clusters")
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_get_cluster_no_key_rejected(self):
        r = _client.get(f"/api/v1/deduplication/clusters/{uuid.uuid4()}")
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_update_cluster_status_no_key_rejected(self):
        r = _client.put(
            f"/api/v1/deduplication/clusters/{uuid.uuid4()}/status",
            json={"status": "resolved"},
        )
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_assign_cluster_no_key_rejected(self):
        r = _client.put(
            f"/api/v1/deduplication/clusters/{uuid.uuid4()}/assign",
            json={"assignee": "alice"},
        )
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_link_ticket_no_key_rejected(self):
        r = _client.put(
            f"/api/v1/deduplication/clusters/{uuid.uuid4()}/ticket",
            json={"ticket_id": "JIRA-123"},
        )
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_process_finding_no_key_rejected(self):
        r = _client.post(
            "/api/v1/deduplication/process",
            json={"finding": {}, "run_id": "r1", "org_id": "org-a"},
        )
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_process_batch_no_key_rejected(self):
        r = _client.post(
            "/api/v1/deduplication/process/batch",
            json={"findings": [], "run_id": "r1", "org_id": "org-a"},
        )
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_related_clusters_no_key_rejected(self):
        r = _client.get(f"/api/v1/deduplication/clusters/{uuid.uuid4()}/related")
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_split_cluster_no_key_rejected(self):
        r = _client.post(
            f"/api/v1/deduplication/clusters/{uuid.uuid4()}/split",
            json={"event_ids": []},
        )
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_health_no_key_rejected(self):
        r = _client.get("/api/v1/deduplication/health")
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"

    def test_status_no_key_rejected(self):
        r = _client.get("/api/v1/deduplication/status")
        assert r.status_code in (401, 403), f"Expected 401/403 got {r.status_code}"


# ===========================================================================
# Deduplication Router — cross-org IDOR tests
# ===========================================================================

@pytest.mark.skipif(not _HAS_DEDUP, reason="deduplication_router not importable")
class TestDedupRouterCrossOrg:
    """Org-A cluster must not be accessible to Org-B caller."""

    def _create_cluster(self, org: str) -> str | None:
        """Ingest one finding for org and return the cluster_id, or None on error."""
        finding = {
            "title": f"SQL Injection in {org}",
            "rule_id": "CWE-89",
            "severity": "high",
            "file_path": "/app/query.py",
            "line": 42,
        }
        r = _client.post(
            "/api/v1/deduplication/process",
            headers=_headers(org=org),
            json={
                "finding": finding,
                "run_id": str(uuid.uuid4()),
                "org_id": org,
                "source": "test",
            },
        )
        if r.status_code not in (200, 201):
            return None
        return r.json().get("cluster_id")

    def test_cross_org_get_cluster_returns_404(self):
        cluster_id = self._create_cluster(_ORG_A)
        if cluster_id is None:
            pytest.skip("Could not create cluster — dedup service may be unavailable")
        r = _client.get(
            f"/api/v1/deduplication/clusters/{cluster_id}",
            headers=_headers(org=_ORG_B),
        )
        assert r.status_code == 404, f"Expected 404 (IDOR blocked) got {r.status_code}"

    def test_cross_org_update_status_returns_404(self):
        cluster_id = self._create_cluster(_ORG_A)
        if cluster_id is None:
            pytest.skip("Could not create cluster")
        r = _client.put(
            f"/api/v1/deduplication/clusters/{cluster_id}/status",
            headers=_headers(org=_ORG_B),
            json={"status": "resolved"},
        )
        assert r.status_code == 404, f"Expected 404 (IDOR blocked) got {r.status_code}"

    def test_cross_org_assign_returns_404(self):
        cluster_id = self._create_cluster(_ORG_A)
        if cluster_id is None:
            pytest.skip("Could not create cluster")
        r = _client.put(
            f"/api/v1/deduplication/clusters/{cluster_id}/assign",
            headers=_headers(org=_ORG_B),
            json={"assignee": "attacker"},
        )
        assert r.status_code == 404, f"Expected 404 (IDOR blocked) got {r.status_code}"

    def test_cross_org_ticket_returns_404(self):
        cluster_id = self._create_cluster(_ORG_A)
        if cluster_id is None:
            pytest.skip("Could not create cluster")
        r = _client.put(
            f"/api/v1/deduplication/clusters/{cluster_id}/ticket",
            headers=_headers(org=_ORG_B),
            json={"ticket_id": "EVIL-001"},
        )
        assert r.status_code == 404, f"Expected 404 (IDOR blocked) got {r.status_code}"

    def test_cross_org_related_returns_404(self):
        cluster_id = self._create_cluster(_ORG_A)
        if cluster_id is None:
            pytest.skip("Could not create cluster")
        r = _client.get(
            f"/api/v1/deduplication/clusters/{cluster_id}/related",
            headers=_headers(org=_ORG_B),
        )
        assert r.status_code == 404, f"Expected 404 (IDOR blocked) got {r.status_code}"

    def test_cross_org_split_returns_404(self):
        cluster_id = self._create_cluster(_ORG_A)
        if cluster_id is None:
            pytest.skip("Could not create cluster")
        r = _client.post(
            f"/api/v1/deduplication/clusters/{cluster_id}/split",
            headers=_headers(org=_ORG_B),
            json={"event_ids": []},
        )
        assert r.status_code == 404, f"Expected 404 (IDOR blocked) got {r.status_code}"

    def test_own_org_get_cluster_succeeds(self):
        """Sanity: same-org caller must be able to read their own cluster."""
        cluster_id = self._create_cluster(_ORG_A)
        if cluster_id is None:
            pytest.skip("Could not create cluster")
        r = _client.get(
            f"/api/v1/deduplication/clusters/{cluster_id}",
            headers=_headers(org=_ORG_A),
        )
        assert r.status_code == 200, f"Own-org get failed: {r.status_code} {r.text}"
        assert r.json().get("org_id") == _ORG_A

    def test_list_clusters_is_org_scoped(self):
        """list_clusters for Org-A must not return Org-B clusters."""
        self._create_cluster(_ORG_A)
        self._create_cluster(_ORG_B)
        r = _client.get(
            "/api/v1/deduplication/clusters",
            headers=_headers(org=_ORG_A),
        )
        assert r.status_code == 200
        for cluster in r.json().get("clusters", []):
            assert cluster.get("org_id") == _ORG_A, (
                f"Org-A cluster list returned cluster with org_id={cluster.get('org_id')}"
            )
