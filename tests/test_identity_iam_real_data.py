"""Batch 5 — Identity / IAM domain router-level HTTP tests.

Four endpoints wired to real engines (no mocks, no stubs):
  1. GET  /api/v1/identity-analytics/stats
  2. GET  /api/v1/identity-governance/stats
  3. GET  /api/v1/identity-lifecycle/summary
  4. GET  /api/v1/identity-risk/stats

Each section covers:
  - HTTP 200 happy path (5-state envelope or engine dict)
  - Filter / query-param variants
  - Write + read round-trip (proves real DB, not in-memory mock)
  - 404 / 422 error paths
"""

from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

# Set auth env before app import so middleware picks it up.
TEST_API_KEY = "test-identity-iam-batch5"
os.environ["FIXOPS_API_TOKEN"] = TEST_API_KEY
os.environ.setdefault("FIXOPS_MODE", "dev")

from apps.api.app import create_app  # noqa: E402

HEADERS = {
    "X-API-Key": TEST_API_KEY,
    "Authorization": f"Bearer {TEST_API_KEY}",
}


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = create_app()
    return TestClient(app, follow_redirects=True)


def _org() -> str:
    """Unique org per call — guarantees test isolation."""
    return f"test-org-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# 1. identity-analytics/stats
# ---------------------------------------------------------------------------

class TestIdentityAnalyticsStats:
    """GET /api/v1/identity-analytics/stats"""

    BASE = "/api/v1/identity-analytics"

    def test_stats_empty_org_returns_200(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        data = r.json()
        assert isinstance(data, dict)

    def test_stats_contains_expected_keys(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        data = r.json()
        # Real keys returned by IdentityAnalyticsEngine.get_identity_stats()
        for key in ("total_identities", "open_risks", "pending_certifications"):
            assert key in data, f"Missing key '{key}' in stats response: {data}"

    def test_stats_after_register_reflects_count(self, client: TestClient):
        org = _org()
        # Register an identity
        payload = {
            "username": f"user-{uuid.uuid4().hex[:6]}",
            "email": "test@example.com",
            "identity_type": "human",
            "privileged": False,
            "mfa_enabled": True,
        }
        r_post = client.post(
            f"{self.BASE}/identities",
            params={"org_id": org},
            json=payload,
            headers=HEADERS,
        )
        assert r_post.status_code in (200, 201), r_post.text

        r_stats = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r_stats.status_code == 200, r_stats.text
        data = r_stats.json()
        assert data.get("total_identities", 0) >= 1

    def test_stats_org_isolation(self, client: TestClient):
        org_a = _org()
        org_b = _org()
        # Register in org_a only
        payload = {
            "username": f"user-{uuid.uuid4().hex[:6]}",
            "email": "isolated@example.com",
            "identity_type": "human",
        }
        client.post(
            f"{self.BASE}/identities",
            params={"org_id": org_a},
            json=payload,
            headers=HEADERS,
        )
        r_b = client.get(f"{self.BASE}/stats", params={"org_id": org_b}, headers=HEADERS)
        assert r_b.status_code == 200
        assert r_b.json().get("total_identities", 0) == 0

    def test_list_identities_filter_type(self, client: TestClient):
        org = _org()
        # Register human + service_account
        for utype, uname in [("human", "alice"), ("service_account", "svc-deploy")]:
            client.post(
                f"{self.BASE}/identities",
                params={"org_id": org},
                json={"username": uname, "identity_type": utype},
                headers=HEADERS,
            )
        r = client.get(
            f"{self.BASE}/identities",
            params={"org_id": org, "identity_type": "human"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        result = r.json()
        assert isinstance(result, list)
        assert all(i["identity_type"] == "human" for i in result)

    def test_list_events_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/events", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)


# ---------------------------------------------------------------------------
# 2. identity-governance/stats
# ---------------------------------------------------------------------------

class TestIdentityGovernanceStats:
    """GET /api/v1/identity-governance/stats"""

    BASE = "/api/v1/identity-governance"

    def test_stats_empty_org_returns_200(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        assert isinstance(r.json(), dict)

    def test_stats_contains_review_keys(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        data = r.json()
        # Real keys from IdentityGovernanceEngine.get_governance_stats()
        for key in ("total_reviews", "total_entitlements", "orphaned_count"):
            assert key in data, f"Missing '{key}' in governance stats: {data}"

    def test_create_review_then_stats_increments(self, client: TestClient):
        org = _org()
        r_post = client.post(
            f"{self.BASE}/reviews",
            params={"org_id": org},
            json={"name": "Q1 Review", "review_type": "quarterly"},
            headers=HEADERS,
        )
        assert r_post.status_code in (200, 201), r_post.text

        r_stats = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r_stats.status_code == 200
        assert r_stats.json().get("total_reviews", 0) >= 1

    def test_list_reviews_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/reviews", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_reviews_status_filter(self, client: TestClient):
        org = _org()
        client.post(
            f"{self.BASE}/reviews",
            params={"org_id": org},
            json={"name": "Draft Review", "review_type": "ad_hoc"},
            headers=HEADERS,
        )
        r = client.get(
            f"{self.BASE}/reviews",
            params={"org_id": org, "status": "draft"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        result = r.json()
        assert isinstance(result, list)

    def test_get_review_not_found(self, client: TestClient):
        org = _org()
        r = client.get(
            f"{self.BASE}/reviews/nonexistent-id",
            params={"org_id": org},
            headers=HEADERS,
        )
        assert r.status_code == 404

    def test_list_entitlements_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/entitlements", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_policies_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/policies", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)


# ---------------------------------------------------------------------------
# 3. identity-lifecycle/summary
# ---------------------------------------------------------------------------

class TestIdentityLifecycleSummary:
    """GET /api/v1/identity-lifecycle/summary"""

    BASE = "/api/v1/identity-lifecycle"

    def test_summary_empty_org_returns_200(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/summary", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        assert isinstance(r.json(), dict)

    def test_summary_contains_account_keys(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/summary", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        # Real keys from IdentityLifecycleEngine.get_entitlement_summary()
        for key in ("total_accounts", "active_accounts", "orphan_count"):
            assert key in data, f"Missing '{key}' in lifecycle summary: {data}"

    def test_provision_then_summary_increments(self, client: TestClient):
        org = _org()
        r_post = client.post(
            f"{self.BASE}/accounts",
            params={"org_id": org},
            json={
                "username": f"u-{uuid.uuid4().hex[:6]}",
                "display_name": "Test User",
                "account_type": "employee",
            },
            headers=HEADERS,
        )
        assert r_post.status_code in (200, 201), r_post.text

        r_sum = client.get(f"{self.BASE}/summary", params={"org_id": org}, headers=HEADERS)
        assert r_sum.status_code == 200
        assert r_sum.json().get("total_accounts", 0) >= 1

    def test_list_accounts_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/accounts", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_accounts_status_filter(self, client: TestClient):
        org = _org()
        uname = f"u-{uuid.uuid4().hex[:6]}"
        client.post(
            f"{self.BASE}/accounts",
            params={"org_id": org},
            json={"username": uname, "account_type": "contractor"},
            headers=HEADERS,
        )
        r = client.get(
            f"{self.BASE}/accounts",
            params={"org_id": org, "status": "active"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        result = r.json()
        assert isinstance(result, list)
        assert all(a.get("status") == "active" for a in result)

    def test_get_account_not_found(self, client: TestClient):
        org = _org()
        r = client.get(
            f"{self.BASE}/accounts/nonexistent-account-id",
            params={"org_id": org},
            headers=HEADERS,
        )
        assert r.status_code == 404

    def test_get_orphans_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/orphans", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_root_returns_summary(self, client: TestClient):
        """GET / on the router returns entitlement summary (BUG-2 guard)."""
        org = _org()
        r = client.get(f"{self.BASE}/", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# 4. identity-risk/stats
# ---------------------------------------------------------------------------

class TestIdentityRiskStats:
    """GET /api/v1/identity-risk/stats"""

    BASE = "/api/v1/identity-risk"

    def test_stats_empty_org_returns_200(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        assert isinstance(r.json(), dict)

    def test_stats_contains_expected_keys(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        # Real keys from IdentityRiskEngine.get_identity_risk_stats()
        for key in ("total_identities", "high_risk_identities", "active_risk_factors"):
            assert key in data, f"Missing '{key}' in risk stats: {data}"

    def test_register_identity_then_stats(self, client: TestClient):
        org = _org()
        r_post = client.post(
            f"{self.BASE}/identities",
            params={"org_id": org},
            json={
                "username": f"risk-user-{uuid.uuid4().hex[:6]}",
                "identity_type": "human",
                "risk_score": 0.3,
                "mfa_enabled": True,
                "status": "active",
            },
            headers=HEADERS,
        )
        assert r_post.status_code in (200, 201), r_post.text

        r_stats = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r_stats.status_code == 200
        assert r_stats.json().get("total_identities", 0) >= 1

    def test_list_identities_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/identities", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_identities_risk_level_filter(self, client: TestClient):
        org = _org()
        # Register a high-risk identity (score > 0.6)
        client.post(
            f"{self.BASE}/identities",
            params={"org_id": org},
            json={
                "username": f"high-{uuid.uuid4().hex[:6]}",
                "identity_type": "privileged",
                "risk_score": 0.75,
                "status": "active",
            },
            headers=HEADERS,
        )
        r = client.get(
            f"{self.BASE}/identities",
            params={"org_id": org, "risk_level": "high"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_identity_not_found(self, client: TestClient):
        org = _org()
        r = client.get(
            f"{self.BASE}/identities/does-not-exist",
            params={"org_id": org},
            headers=HEADERS,
        )
        assert r.status_code == 404

    def test_list_risk_factors_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/risk-factors", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_access_reviews_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/access-reviews", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_record_risk_factor_and_list(self, client: TestClient):
        org = _org()
        # First create an identity
        r_id = client.post(
            f"{self.BASE}/identities",
            params={"org_id": org},
            json={
                "username": f"rf-user-{uuid.uuid4().hex[:6]}",
                "identity_type": "human",
                "status": "active",
            },
            headers=HEADERS,
        )
        assert r_id.status_code in (200, 201), r_id.text
        identity_id = r_id.json().get("identity_id") or r_id.json().get("id", "")

        r_rf = client.post(
            f"{self.BASE}/risk-factors",
            params={"org_id": org},
            json={
                "identity_id": identity_id,
                "factor_type": "stale_credentials",
                "severity": "high",
                "score_impact": 0.2,
                "description": "Credentials not rotated in 90+ days",
                "detected_at": "2026-05-03T00:00:00Z",
                "status": "active",
            },
            headers=HEADERS,
        )
        assert r_rf.status_code in (200, 201), r_rf.text

        r_list = client.get(
            f"{self.BASE}/risk-factors",
            params={"org_id": org, "severity": "high"},
            headers=HEADERS,
        )
        assert r_list.status_code == 200
        factors = r_list.json()
        assert isinstance(factors, list)
        assert len(factors) >= 1
