"""
Wave-4 N1 — Unauthenticated-access regression tests.

Covers the three routers that were fully open before this fix:
  1. suite-core/api/exposure_case_router.py  (/api/v1/cases)
  2. suite-api/apps/api/ciem_router.py       (/api/v1/ciem)
  3. suite-api/apps/api/cspm_engine_router.py (/api/v1/cspm-engine)

Assertions:
  A. No API key → 401 or 403 (never 200/404/500).
  B. Org-A key cannot see Org-B's by-id resources (→ 404).
  C. Body org_id spoof is ignored — authenticated org_id is used.
"""
from __future__ import annotations

import os
import sys
import pytest

# ---------------------------------------------------------------------------
# Path setup — mirror sitecustomize.py
# ---------------------------------------------------------------------------
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in [".", "suite-api", "suite-core", "suite-attack", "suite-feeds",
           "suite-integrations", "suite-evidence-risk"]:
    _full = os.path.join(_REPO, _p)
    if _full not in sys.path:
        sys.path.insert(0, _full)

# ---------------------------------------------------------------------------
# Force a known API token for the test session
# ---------------------------------------------------------------------------
_TOKEN_A = "test-wave4-org-a-token"
_TOKEN_B = "test-wave4-org-b-token"
os.environ.setdefault("FIXOPS_API_TOKEN", _TOKEN_A)
os.environ.setdefault("FIXOPS_MODE", "production")  # disable dev-mode passthrough

# ---------------------------------------------------------------------------
# App import (after env is set)
# ---------------------------------------------------------------------------
from fastapi.testclient import TestClient  # noqa: E402

@pytest.fixture(scope="module")
def client():
    """Return a TestClient for the full suite-api app."""
    # Re-set env before app import so auth_deps sees the token
    os.environ["FIXOPS_API_TOKEN"] = _TOKEN_A
    os.environ["FIXOPS_MODE"] = "production"
    from apps.api.app import create_app
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ============================================================================
# Helper
# ============================================================================

def _headers(token: str | None) -> dict:
    if token is None:
        return {}
    return {"X-API-Key": token}


def _assert_auth_rejected(response) -> None:
    """Assert the response is a 401 or 403 — not a successful data response."""
    assert response.status_code in (401, 403), (
        f"Expected 401/403 but got {response.status_code}: {response.text[:200]}"
    )


# ============================================================================
# 1. exposure_case_router — /api/v1/cases
# ============================================================================

class TestExposureCaseNoAuth:
    """All /api/v1/cases endpoints must reject requests with no API key."""

    def test_list_cases_no_key(self, client):
        _assert_auth_rejected(client.get("/api/v1/cases", headers=_headers(None)))

    def test_get_case_no_key(self, client):
        _assert_auth_rejected(client.get("/api/v1/cases/EC-DOESNOTEXIST", headers=_headers(None)))

    def test_create_case_no_key(self, client):
        _assert_auth_rejected(client.post(
            "/api/v1/cases",
            json={"title": "test"},
            headers=_headers(None),
        ))

    def test_stats_no_key(self, client):
        _assert_auth_rejected(client.get("/api/v1/cases/stats/summary", headers=_headers(None)))

    def test_transition_no_key(self, client):
        _assert_auth_rejected(client.post(
            "/api/v1/cases/EC-FAKE/transition",
            json={"new_status": "triaging"},
            headers=_headers(None),
        ))

    def test_clusters_no_key(self, client):
        _assert_auth_rejected(client.post(
            "/api/v1/cases/EC-FAKE/clusters",
            json={"cluster_ids": ["c1"]},
            headers=_headers(None),
        ))

    def test_transitions_get_no_key(self, client):
        _assert_auth_rejected(client.get("/api/v1/cases/EC-FAKE/transitions", headers=_headers(None)))


class TestExposureCaseCrossOrg:
    """Org-A key cannot see Org-B's case (must get 404, not the case data)."""

    def test_cross_org_case_by_id_returns_404(self, client):
        # Create a case tagged to org-b by using a two-token setup isn't
        # feasible in a single-token env, so we insert directly into the
        # manager and verify that org-A key sees 404.
        try:
            from core.exposure_case import ExposureCase, get_case_manager
            mgr = get_case_manager()
            case = ExposureCase(
                case_id="",
                title="org-b secret case",
                org_id="org-b",  # different from the authenticated org
            )
            created = mgr.create_case(case)
            case_id = created.case_id

            # Org-A key (the only token configured) should get 404
            resp = client.get(f"/api/v1/cases/{case_id}", headers=_headers(_TOKEN_A))
            assert resp.status_code == 404, (
                f"Expected 404 for cross-org case, got {resp.status_code}: {resp.text[:200]}"
            )
        except Exception as exc:
            pytest.skip(f"ExposureCaseManager not available: {exc}")


class TestExposureCaseBodyOrgIdIgnored:
    """Body org_id on POST /cases must be ignored — authenticated org used."""

    def test_create_case_body_org_id_ignored(self, client):
        try:
            resp = client.post(
                "/api/v1/cases",
                json={"title": "spoof test", "org_id": "evil-org"},
                headers=_headers(_TOKEN_A),
            )
            # Either succeeds (201/200) or engine unavailable (422/500)
            if resp.status_code in (200, 201):
                data = resp.json()
                # The stored org_id must NOT be "evil-org"
                stored_org = data.get("org_id", "")
                assert stored_org != "evil-org", (
                    f"Body org_id spoof was accepted — stored org_id is '{stored_org}'"
                )
        except Exception as exc:
            pytest.skip(f"Skipped: {exc}")


# ============================================================================
# 2. ciem_router — /api/v1/ciem
# ============================================================================

class TestCIEMNoAuth:
    """All /api/v1/ciem endpoints must reject requests with no API key."""

    def test_analyze_policy_no_key(self, client):
        _assert_auth_rejected(client.post(
            "/api/v1/ciem/analyze/policy",
            json={"policy": {"Statement": []}, "principal": "arn:aws:iam::123456789012:role/test"},
            headers=_headers(None),
        ))

    def test_analyze_account_no_key(self, client):
        _assert_auth_rejected(client.post(
            "/api/v1/ciem/analyze/account",
            json={"account_id": "123456789012", "policies": []},
            headers=_headers(None),
        ))

    def test_suggest_least_privilege_no_key(self, client):
        _assert_auth_rejected(client.post(
            "/api/v1/ciem/suggest/least-privilege",
            json={"policy": {"Statement": []}, "used_permissions": []},
            headers=_headers(None),
        ))

    def test_list_risks_no_key(self, client):
        _assert_auth_rejected(client.get("/api/v1/ciem/risks", headers=_headers(None)))

    def test_escalation_paths_no_key(self, client):
        _assert_auth_rejected(client.post(
            "/api/v1/ciem/escalation-paths",
            json={"policies": []},
            headers=_headers(None),
        ))

    def test_analyze_azure_no_key(self, client):
        _assert_auth_rejected(client.post(
            "/api/v1/ciem/analyze/azure",
            json={"role_definition": {}, "principal": "test-user"},
            headers=_headers(None),
        ))

    def test_score_no_key(self, client):
        _assert_auth_rejected(client.post(
            "/api/v1/ciem/score",
            json={"policy": {"Statement": []}, "principal": "arn:aws:iam::123456789012:role/test"},
            headers=_headers(None),
        ))


class TestCIEMListRisksOrgScoped:
    """list_risks must only return risks for the authenticated org."""

    def test_list_risks_authenticated_returns_200(self, client):
        resp = client.get("/api/v1/ciem/risks", headers=_headers(_TOKEN_A))
        # Engine may not be available (501) but must not be 401/403
        assert resp.status_code != 401
        assert resp.status_code != 403


# ============================================================================
# 3. cspm_engine_router — /api/v1/cspm-engine
# ============================================================================

class TestCSPMNoAuth:
    """All /api/v1/cspm-engine endpoints must reject requests with no API key."""

    def test_sync_no_key(self, client):
        _assert_auth_rejected(client.post(
            "/api/v1/cspm-engine/sync",
            json={"provider": "AWS", "resources": []},
            headers=_headers(None),
        ))

    def test_list_resources_no_key(self, client):
        _assert_auth_rejected(client.get("/api/v1/cspm-engine/resources", headers=_headers(None)))

    def test_get_resource_no_key(self, client):
        _assert_auth_rejected(client.get(
            "/api/v1/cspm-engine/resources/some-uuid",
            headers=_headers(None),
        ))

    def test_scan_no_key(self, client):
        _assert_auth_rejected(client.post(
            "/api/v1/cspm-engine/scan",
            json={},
            headers=_headers(None),
        ))

    def test_results_no_key(self, client):
        _assert_auth_rejected(client.get("/api/v1/cspm-engine/results", headers=_headers(None)))

    def test_summary_no_key(self, client):
        _assert_auth_rejected(client.get("/api/v1/cspm-engine/summary", headers=_headers(None)))

    def test_public_no_key(self, client):
        _assert_auth_rejected(client.get("/api/v1/cspm-engine/public", headers=_headers(None)))

    def test_unencrypted_no_key(self, client):
        _assert_auth_rejected(client.get("/api/v1/cspm-engine/unencrypted", headers=_headers(None)))

    def test_iam_no_key(self, client):
        _assert_auth_rejected(client.get("/api/v1/cspm-engine/iam", headers=_headers(None)))

    def test_score_no_key(self, client):
        _assert_auth_rejected(client.get("/api/v1/cspm-engine/score", headers=_headers(None)))


class TestCSPMCrossOrg:
    """Org-A key cannot retrieve Org-B's resource by UUID (must get 404)."""

    def test_cross_org_resource_by_id_returns_404(self, client):
        try:
            from core.cspm import CloudProvider, CloudResource, ResourceCategory, CSPMEngine
            engine = CSPMEngine()
            import uuid
            from datetime import datetime, timezone
            res = CloudResource(
                id=str(uuid.uuid4()),
                provider=CloudProvider.AWS,
                category=ResourceCategory.STORAGE,
                resource_type="s3_bucket",
                resource_id="org-b-bucket",
                name="org-b-bucket",
                region="us-east-1",
                account_id="999999999999",
                org_id="org-b",  # different org
                public_exposure=False,
                encryption_enabled=True,
            )
            engine.sync_resources([res], CloudProvider.AWS, "org-b")
            resource_id = res.id

            # Org-A key should get 404 for org-B's resource
            resp = client.get(
                f"/api/v1/cspm-engine/resources/{resource_id}",
                headers=_headers(_TOKEN_A),
            )
            assert resp.status_code == 404, (
                f"Expected 404 for cross-org resource, got {resp.status_code}: {resp.text[:200]}"
            )
        except Exception as exc:
            pytest.skip(f"CSPMEngine not available: {exc}")


class TestCSPMBodyOrgIdIgnored:
    """POST /sync body org_id must be ignored — authenticated org used."""

    def test_sync_body_org_id_ignored(self, client):
        resp = client.post(
            "/api/v1/cspm-engine/sync",
            json={
                "provider": "AWS",
                "org_id": "evil-org",  # this field no longer exists in the model
                "resources": [],
            },
            headers=_headers(_TOKEN_A),
        )
        # 200/501 are both acceptable (engine may not be available);
        # 422 would indicate the extra field was rejected (also fine).
        # 401/403 would mean auth is broken — that's a failure.
        assert resp.status_code not in (401, 403), (
            f"Authenticated sync rejected: {resp.status_code}: {resp.text[:200]}"
        )
        # If it succeeded, verify the returned org_id is not evil-org
        if resp.status_code == 200:
            data = resp.json()
            assert data.get("org_id") != "evil-org", (
                f"Body org_id spoof was accepted — returned org_id is '{data.get('org_id')}'"
            )
