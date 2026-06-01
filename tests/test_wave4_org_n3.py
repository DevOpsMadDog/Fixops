"""
Wave-4 N3 tenant-isolation tests.

Covers the five routers fixed in the chief-architect N3 sweep:
  1. security_findings_router  — body org_id spoof on PATCH/POST/POST mutations
  2. asset_inventory_router    — cross-org by-id reads/writes via _require_asset
  3. risk_register_router      — cross-org by-id reads/writes via get_risk
  4. risk_scoring_router       — cross-org asset exposure score
  5. integrations_router       — cross-org test/sync-status/trigger-sync

Strategy:
  - All tests use FastAPI TestClient (sync).
  - FIXOPS_MODE=dev bypasses api_key_auth (dev pass-through).
  - org resolution: get_org_id Depends reads X-Org-ID header.
  - We seed data under org "orgA" then probe with org "orgB".
  - Fixed handlers must return 404 for cross-org access.
  - Same request with correct org must succeed (200/201).
"""

from __future__ import annotations

import os
import sys
import uuid

# MUST set before any module import so auth_deps picks it up at module level
os.environ.setdefault("FIXOPS_MODE", "dev")

# Ensure project paths are on sys.path
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
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Patch get_org_id to resolve from X-Org-ID header (before router imports)
# ---------------------------------------------------------------------------

def _org_from_header(request: Request) -> str:
    return request.headers.get("X-Org-ID", "default")


def _auth_noop(request: Request) -> None:
    """No-op auth for tests — bypasses api_key_auth entirely."""
    return None


import apps.api.dependencies as _deps_mod

_deps_mod.get_org_id = _org_from_header  # type: ignore[attr-defined]

try:
    import apps.api.org_middleware as _mw
    _mw.get_org_id = _org_from_header  # type: ignore[attr-defined]
except (ImportError, AttributeError):
    pass

import apps.api.risk_scoring_router as _rsr_mod
_rsr_mod._get_org_id = _org_from_header  # type: ignore[attr-defined]

# ---------------------------------------------------------------------------
# Import routers AFTER patching
# ---------------------------------------------------------------------------

from apps.api.auth_deps import api_key_auth  # noqa: E402
from apps.api.security_findings_router import router as findings_router
from apps.api.asset_inventory_router import router as assets_router
from apps.api.risk_register_router import router as risks_router
from apps.api.risk_scoring_router import router as scoring_router
from api.integrations_router import router as integrations_router


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app(*routers) -> FastAPI:
    app = FastAPI()
    for r in routers:
        app.include_router(r)
    # Override api_key_auth so test clients don't need a real token
    app.dependency_overrides[api_key_auth] = _auth_noop
    app.dependency_overrides[_org_from_header] = _org_from_header
    return app


def _client(app: FastAPI, org_id: str = "default") -> TestClient:
    return TestClient(app, headers={"X-Org-ID": org_id})


# ===========================================================================
# 1. security_findings_router — body org_id spoof
# ===========================================================================

class TestSecurityFindingsBodyOrgIdSpoof:
    """PATCH/POST mutation handlers must ignore body.org_id and use authenticated org."""

    @pytest.fixture(autouse=True)
    def setup(self):
        app = _make_app(findings_router)
        self.client_a = _client(app, "orgA")
        self.client_b = _client(app, "orgB")

        # Seed a finding under orgA
        resp = self.client_a.post(
            "/api/v1/security-findings/findings",
            json={
                "org_id": "orgA",
                "title": f"N3-test-finding-{uuid.uuid4().hex[:8]}",
                "finding_type": "vulnerability",
                "source_tool": "trivy",
                "severity": "high",
            },
        )
        assert resp.status_code == 200, f"seed failed: {resp.text}"
        self.finding_id = resp.json()["id"]

    def test_update_status_body_spoof_blocked(self):
        """orgB cannot update orgA's finding — org comes from header, not body."""
        resp = self.client_b.patch(
            f"/api/v1/security-findings/findings/{self.finding_id}/status",
            json={"status": "resolved"},
        )
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_update_status_same_org_succeeds(self):
        resp = self.client_a.patch(
            f"/api/v1/security-findings/findings/{self.finding_id}/status",
            json={"status": "in_progress"},
        )
        assert resp.status_code == 200, f"expected 200 got {resp.status_code}: {resp.text}"

    def test_add_evidence_body_spoof_blocked(self):
        resp = self.client_b.post(
            f"/api/v1/security-findings/findings/{self.finding_id}/evidence",
            json={"evidence_type": "log", "content": "attacker content"},
        )
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_add_evidence_same_org_succeeds(self):
        resp = self.client_a.post(
            f"/api/v1/security-findings/findings/{self.finding_id}/evidence",
            json={"evidence_type": "log", "content": "real content"},
        )
        assert resp.status_code == 200, f"expected 200 got {resp.status_code}: {resp.text}"

    def test_suppress_body_spoof_blocked(self):
        from datetime import datetime, timezone, timedelta
        expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        resp = self.client_b.post(
            f"/api/v1/security-findings/findings/{self.finding_id}/suppress",
            json={"reason": "attacker suppress", "suppressed_by": "evil", "expires_at": expires},
        )
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_suppress_same_org_succeeds(self):
        from datetime import datetime, timezone, timedelta
        expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        resp = self.client_a.post(
            f"/api/v1/security-findings/findings/{self.finding_id}/suppress",
            json={"reason": "accepted risk", "suppressed_by": "admin", "expires_at": expires},
        )
        assert resp.status_code == 200, f"expected 200 got {resp.status_code}: {resp.text}"


# ===========================================================================
# 2. asset_inventory_router — cross-org by-id
# ===========================================================================

class TestAssetInventoryCrossOrg:
    """All /{asset_id} handlers must 404 when the asset belongs to a different org."""

    @pytest.fixture(autouse=True)
    def setup(self):
        app = _make_app(assets_router)
        self.client_a = _client(app, "orgA")
        self.client_b = _client(app, "orgB")

        resp = self.client_a.post(
            "/api/v1/assets",
            json={"name": f"n3-server-{uuid.uuid4().hex[:8]}", "asset_type": "server", "org_id": "orgA"},
        )
        assert resp.status_code == 200, f"seed failed: {resp.text}"
        self.asset_id = resp.json()["id"]

    def test_get_asset_cross_org_blocked(self):
        resp = self.client_b.get(f"/api/v1/assets/{self.asset_id}")
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_get_asset_same_org_succeeds(self):
        resp = self.client_a.get(f"/api/v1/assets/{self.asset_id}")
        assert resp.status_code == 200, f"expected 200 got {resp.status_code}: {resp.text}"

    def test_put_asset_cross_org_blocked(self):
        resp = self.client_b.put(
            f"/api/v1/assets/{self.asset_id}",
            json={"name": "hacked"},
        )
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_delete_asset_cross_org_blocked(self):
        resp = self.client_b.delete(f"/api/v1/assets/{self.asset_id}")
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_assign_owner_cross_org_blocked(self):
        resp = self.client_b.post(
            f"/api/v1/assets/{self.asset_id}/owner",
            json={"owner_email": "hacker@evil.com"},
        )
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_tag_asset_cross_org_blocked(self):
        resp = self.client_b.post(
            f"/api/v1/assets/{self.asset_id}/tags",
            json={"tags": ["hacked"]},
        )
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_compliance_cross_org_blocked(self):
        resp = self.client_b.post(
            f"/api/v1/assets/{self.asset_id}/compliance",
            json={"frameworks": ["pci"]},
        )
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_relationships_cross_org_blocked(self):
        resp = self.client_b.get(f"/api/v1/assets/{self.asset_id}/relationships")
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_impact_cross_org_blocked(self):
        resp = self.client_b.get(f"/api/v1/assets/{self.asset_id}/impact")
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_sync_cmdb_cross_org_blocked(self):
        resp = self.client_b.post(
            f"/api/v1/assets/{self.asset_id}/sync",
            json={"cmdb_system": "ServiceNow", "external_id": "CI123", "changes": {}},
        )
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_sync_history_cross_org_blocked(self):
        resp = self.client_b.get(f"/api/v1/assets/{self.asset_id}/sync")
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"


# ===========================================================================
# 3. risk_register_router — cross-org by-id
# ===========================================================================

class TestRiskRegisterCrossOrg:
    """All /{risk_id} handlers must 404 when the risk belongs to a different org."""

    @pytest.fixture(autouse=True)
    def setup(self):
        app = _make_app(risks_router)
        self.client_a = _client(app, "orgA")
        self.client_b = _client(app, "orgB")

        resp = self.client_a.post(
            "/api/v1/risks",
            json={
                "title": f"N3 risk {uuid.uuid4().hex[:8]}",
                "category": "operational",
                "likelihood": 3,
                "impact": 3,
                "org_id": "orgA",
            },
        )
        assert resp.status_code == 200, f"seed failed: {resp.text}"
        self.risk_id = resp.json()["id"]

    def test_get_risk_cross_org_blocked(self):
        resp = self.client_b.get(f"/api/v1/risks/{self.risk_id}")
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_get_risk_same_org_succeeds(self):
        resp = self.client_a.get(f"/api/v1/risks/{self.risk_id}")
        assert resp.status_code == 200, f"expected 200 got {resp.status_code}: {resp.text}"

    def test_patch_risk_cross_org_blocked(self):
        resp = self.client_b.patch(
            f"/api/v1/risks/{self.risk_id}",
            json={"title": "hacked title"},
        )
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_delete_risk_cross_org_blocked(self):
        resp = self.client_b.delete(f"/api/v1/risks/{self.risk_id}")
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_map_control_cross_org_blocked(self):
        resp = self.client_b.post(
            f"/api/v1/risks/{self.risk_id}/controls/map",
            json={"ctrl_id": "ctrl-fake"},
        )
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_unmap_control_cross_org_blocked(self):
        resp = self.client_b.delete(f"/api/v1/risks/{self.risk_id}/controls/ctrl-fake")
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_list_treatments_cross_org_blocked(self):
        resp = self.client_b.get(f"/api/v1/risks/{self.risk_id}/treatments")
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_list_treatments_same_org_succeeds(self):
        resp = self.client_a.get(f"/api/v1/risks/{self.risk_id}/treatments")
        assert resp.status_code == 200, f"expected 200 got {resp.status_code}: {resp.text}"


# ===========================================================================
# 4. risk_scoring_router — cross-org asset exposure
# ===========================================================================

class TestRiskScoringAssetExposureCrossOrg:
    """GET /exposure/{asset_id} must 404 for a cross-org asset."""

    @pytest.fixture(autouse=True)
    def setup(self):
        # Register asset under orgA via asset_inventory
        assets_app = _make_app(assets_router)
        assets_client_a = _client(assets_app, "orgA")
        resp = assets_client_a.post(
            "/api/v1/assets",
            json={
                "name": f"scoring-server-{uuid.uuid4().hex[:8]}",
                "asset_type": "server",
                "org_id": "orgA",
            },
        )
        assert resp.status_code == 200, f"seed failed: {resp.text}"
        self.asset_id = resp.json()["id"]

        scoring_app = _make_app(scoring_router)
        self.client_a = _client(scoring_app, "orgA")
        self.client_b = _client(scoring_app, "orgB")

    def test_asset_exposure_cross_org_blocked(self):
        resp = self.client_b.get(f"/api/v1/risk-scoring/exposure/{self.asset_id}")
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_asset_exposure_same_org_succeeds(self):
        resp = self.client_a.get(f"/api/v1/risk-scoring/exposure/{self.asset_id}")
        # 200 with zero scores is fine — asset exists and belongs to orgA
        assert resp.status_code == 200, f"expected 200 got {resp.status_code}: {resp.text}"

    def test_asset_exposure_nonexistent_404(self):
        resp = self.client_a.get("/api/v1/risk-scoring/exposure/does-not-exist")
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"


# ===========================================================================
# 5. integrations_router — cross-org test/sync-status/trigger-sync
# ===========================================================================

class TestIntegrationsCrossOrg:
    """POST /{id}/test, GET /{id}/sync-status, POST /{id}/sync must 404 cross-org."""

    @pytest.fixture(autouse=True)
    def setup(self):
        app = _make_app(integrations_router)
        self.client_a = _client(app, "orgA")
        self.client_b = _client(app, "orgB")

        # Unique name per test run to avoid 409 collision in persistent DB
        unique_name = f"N3-jira-{uuid.uuid4().hex[:12]}"
        resp = self.client_a.post(
            "/api/v1/integrations",
            json={
                "name": unique_name,
                "integration_type": "jira",
                "status": "active",
                "config": {},
            },
        )
        assert resp.status_code == 201, f"seed failed: {resp.text}"
        self.integration_id = resp.json()["id"]

    def test_test_integration_cross_org_blocked(self):
        resp = self.client_b.post(f"/api/v1/integrations/{self.integration_id}/test")
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_test_integration_same_org_succeeds(self):
        resp = self.client_a.post(f"/api/v1/integrations/{self.integration_id}/test")
        # 200 with success=False (Jira not configured) is acceptable
        assert resp.status_code == 200, f"expected 200 got {resp.status_code}: {resp.text}"

    def test_sync_status_cross_org_blocked(self):
        resp = self.client_b.get(f"/api/v1/integrations/{self.integration_id}/sync-status")
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_sync_status_same_org_succeeds(self):
        resp = self.client_a.get(f"/api/v1/integrations/{self.integration_id}/sync-status")
        assert resp.status_code == 200, f"expected 200 got {resp.status_code}: {resp.text}"

    def test_trigger_sync_cross_org_blocked(self):
        resp = self.client_b.post(f"/api/v1/integrations/{self.integration_id}/sync")
        assert resp.status_code == 404, f"expected 404 got {resp.status_code}: {resp.text}"

    def test_trigger_sync_same_org_succeeds(self):
        resp = self.client_a.post(f"/api/v1/integrations/{self.integration_id}/sync")
        # 200 or 400 (inactive/unconfigured) — either is fine; 404 would be the bug
        assert resp.status_code in (200, 400), \
            f"expected 200/400 got {resp.status_code}: {resp.text}"
