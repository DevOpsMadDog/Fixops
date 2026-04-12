"""
Tests for the Risk Acceptance Workflow.

Coverage:
- AcceptanceStatus and ReviewPriority enums
- RiskAcceptance and AcceptanceReview Pydantic models
- RiskAcceptanceManager: request, approve, reject, revoke, expiry,
  expiring-soon, listing, stats, finding lookup, review history
- API router endpoints via FastAPI TestClient
"""
from __future__ import annotations

import sys
import os
from datetime import datetime, timedelta, timezone

import pytest

# Ensure suite-core is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from core.risk_acceptance import (
    AcceptanceStatus,
    ReviewPriority,
    RiskAcceptance,
    AcceptanceReview,
    RiskAcceptanceManager,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _future(days: int = 90) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)


def _past(days: int = 1) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def _make_manager() -> RiskAcceptanceManager:
    """Return a fresh in-memory manager for each test."""
    return RiskAcceptanceManager(db_path=":memory:")


def _request(
    manager: RiskAcceptanceManager,
    finding_id: str = "finding-001",
    org_id: str = "org-test",
    expires_at: datetime | None = None,
    priority: ReviewPriority = ReviewPriority.ROUTINE,
) -> RiskAcceptance:
    return manager.request_acceptance(
        finding_id=finding_id,
        justification="Business needs require accepting this risk temporarily.",
        business_reason="Critical project deadline; mitigated by WAF rules.",
        compensating_controls="WAF rule CVE-2024-XYZ, increased monitoring",
        requested_by="alice@example.com",
        expires_at=expires_at or _future(90),
        org_id=org_id,
        priority=priority,
        conditions=["quarterly review required", "notify SOC on breach"],
        risk_score_at_acceptance=7.5,
    )


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestAcceptanceStatusEnum:
    def test_all_statuses_exist(self):
        values = {s.value for s in AcceptanceStatus}
        assert values == {"pending", "approved", "rejected", "expired", "revoked"}

    def test_status_is_str_enum(self):
        assert isinstance(AcceptanceStatus.PENDING, str)
        assert AcceptanceStatus.PENDING == "pending"

    def test_status_comparison(self):
        assert AcceptanceStatus.APPROVED != AcceptanceStatus.REJECTED


class TestReviewPriorityEnum:
    def test_all_priorities_exist(self):
        values = {p.value for p in ReviewPriority}
        assert values == {"routine", "elevated", "urgent"}

    def test_priority_is_str_enum(self):
        assert isinstance(ReviewPriority.URGENT, str)
        assert ReviewPriority.URGENT == "urgent"


# ---------------------------------------------------------------------------
# Pydantic model tests
# ---------------------------------------------------------------------------


class TestRiskAcceptanceModel:
    def test_default_status_is_pending(self):
        acc = RiskAcceptance(
            finding_id="f1",
            org_id="org1",
            justification="test",
            business_reason="test",
            requested_by="bob",
            expires_at=_future(),
            review_date=_future(60),
        )
        assert acc.status == AcceptanceStatus.PENDING

    def test_id_auto_generated(self):
        acc = RiskAcceptance(
            finding_id="f1",
            org_id="org1",
            justification="j",
            business_reason="b",
            requested_by="bob",
            expires_at=_future(),
            review_date=_future(60),
        )
        assert acc.id and len(acc.id) == 36  # UUID4 format

    def test_conditions_default_empty(self):
        acc = RiskAcceptance(
            finding_id="f1",
            org_id="org1",
            justification="j",
            business_reason="b",
            requested_by="bob",
            expires_at=_future(),
            review_date=_future(60),
        )
        assert acc.conditions == []


class TestAcceptanceReviewModel:
    def test_review_fields(self):
        rev = AcceptanceReview(
            acceptance_id="acc-1",
            reviewer="admin@corp.com",
            decision="approved",
            comment="Looks good.",
        )
        assert rev.decision == "approved"
        assert rev.reviewer == "admin@corp.com"
        assert rev.id  # auto-generated UUID


# ---------------------------------------------------------------------------
# RiskAcceptanceManager — core workflow
# ---------------------------------------------------------------------------


class TestRequestAcceptance:
    def test_request_creates_pending_record(self):
        m = _make_manager()
        acc = _request(m)
        assert acc.status == AcceptanceStatus.PENDING
        assert acc.finding_id == "finding-001"

    def test_request_stores_justification(self):
        m = _make_manager()
        acc = _request(m)
        assert "Business needs" in acc.justification

    def test_request_stores_compensating_controls(self):
        m = _make_manager()
        acc = _request(m)
        assert "WAF rule" in acc.compensating_controls

    def test_request_stores_conditions(self):
        m = _make_manager()
        acc = _request(m)
        assert len(acc.conditions) == 2

    def test_request_stores_risk_score(self):
        m = _make_manager()
        acc = _request(m)
        assert acc.risk_score_at_acceptance == 7.5

    def test_request_assigns_priority(self):
        m = _make_manager()
        acc = _request(m, priority=ReviewPriority.URGENT)
        assert acc.priority == ReviewPriority.URGENT

    def test_request_review_date_before_expiry(self):
        m = _make_manager()
        acc = _request(m)
        assert acc.review_date < acc.expires_at


class TestApproveWorkflow:
    def test_approve_changes_status(self):
        m = _make_manager()
        acc = _request(m)
        approved = m.approve(acc.id, approver="ciso@corp.com", approver_role="admin")
        assert approved.status == AcceptanceStatus.APPROVED

    def test_approve_records_approver(self):
        m = _make_manager()
        acc = _request(m)
        approved = m.approve(acc.id, approver="ciso@corp.com", approver_role="admin")
        assert approved.approved_by == "ciso@corp.com"
        assert approved.approved_at is not None

    def test_approve_security_analyst_role_allowed(self):
        m = _make_manager()
        acc = _request(m)
        approved = m.approve(acc.id, approver="analyst@corp.com", approver_role="security_analyst")
        assert approved.status == AcceptanceStatus.APPROVED

    def test_approve_insufficient_role_raises(self):
        m = _make_manager()
        acc = _request(m)
        with pytest.raises(ValueError, match="not permitted"):
            m.approve(acc.id, approver="dev@corp.com", approver_role="developer")

    def test_approve_nonexistent_raises(self):
        m = _make_manager()
        with pytest.raises(ValueError, match="not found"):
            m.approve("no-such-id", approver="admin", approver_role="admin")

    def test_double_approve_raises(self):
        m = _make_manager()
        acc = _request(m)
        m.approve(acc.id, approver="admin", approver_role="admin")
        with pytest.raises(ValueError, match="pending"):
            m.approve(acc.id, approver="admin2", approver_role="admin")

    def test_approve_creates_review_record(self):
        m = _make_manager()
        acc = _request(m)
        m.approve(acc.id, approver="admin@corp.com", comment="Approved after review.", approver_role="admin")
        history = m.get_review_history(acc.id)
        assert len(history) == 1
        assert history[0].decision == "approved"
        assert history[0].comment == "Approved after review."


class TestRejectWorkflow:
    def test_reject_changes_status(self):
        m = _make_manager()
        acc = _request(m)
        rejected = m.reject(acc.id, reviewer="ciso@corp.com", reason="Risk too high.")
        assert rejected.status == AcceptanceStatus.REJECTED

    def test_reject_nonexistent_raises(self):
        m = _make_manager()
        with pytest.raises(ValueError, match="not found"):
            m.reject("ghost-id", reviewer="admin")

    def test_reject_already_approved_raises(self):
        m = _make_manager()
        acc = _request(m)
        m.approve(acc.id, approver="admin", approver_role="admin")
        with pytest.raises(ValueError, match="pending"):
            m.reject(acc.id, reviewer="admin")

    def test_reject_creates_review_record(self):
        m = _make_manager()
        acc = _request(m)
        m.reject(acc.id, reviewer="security@corp.com", reason="Too risky.")
        history = m.get_review_history(acc.id)
        assert len(history) == 1
        assert history[0].decision == "rejected"


class TestRevokeWorkflow:
    def test_revoke_changes_status(self):
        m = _make_manager()
        acc = _request(m)
        m.approve(acc.id, approver="admin", approver_role="admin")
        revoked = m.revoke(acc.id, revoker="ciso@corp.com", reason="Conditions changed.")
        assert revoked.status == AcceptanceStatus.REVOKED

    def test_revoke_pending_raises(self):
        m = _make_manager()
        acc = _request(m)
        with pytest.raises(ValueError, match="approved"):
            m.revoke(acc.id, revoker="admin", reason="n/a")

    def test_revoke_nonexistent_raises(self):
        m = _make_manager()
        with pytest.raises(ValueError, match="not found"):
            m.revoke("ghost-id", revoker="admin")

    def test_revoke_creates_review_record(self):
        m = _make_manager()
        acc = _request(m)
        m.approve(acc.id, approver="admin", approver_role="admin")
        m.revoke(acc.id, revoker="ciso@corp.com", reason="Policy change.")
        history = m.get_review_history(acc.id)
        assert len(history) == 2  # approve + revoke
        decisions = [r.decision for r in history]
        assert "revoked" in decisions


# ---------------------------------------------------------------------------
# Expiration
# ---------------------------------------------------------------------------


class TestExpiration:
    def test_expire_overdue_marks_expired(self):
        m = _make_manager()
        acc = _request(m, expires_at=_past(1))
        # Manually set to approved in DB (bypass normal flow for past-expiry test)
        m._connect().execute(
            "UPDATE risk_acceptances SET status='approved' WHERE id=?", (acc.id,)
        )
        m._connect().execute("COMMIT")
        count = m.expire_overdue("org-test")
        assert count == 1
        refreshed = m.get_acceptance(acc.id)
        assert refreshed.status == AcceptanceStatus.EXPIRED

    def test_expire_overdue_ignores_pending(self):
        m = _make_manager()
        _request(m, expires_at=_past(1))  # still pending, should not be expired
        count = m.expire_overdue("org-test")
        assert count == 0

    def test_expire_overdue_ignores_different_org(self):
        m = _make_manager()
        acc = _request(m, org_id="org-a", expires_at=_past(1))
        m._connect().execute(
            "UPDATE risk_acceptances SET status='approved' WHERE id=?", (acc.id,)
        )
        m._connect().execute("COMMIT")
        count = m.expire_overdue("org-b")
        assert count == 0


class TestExpiringSoon:
    def test_expiring_soon_returns_approved_near_expiry(self):
        m = _make_manager()
        acc = _request(m, expires_at=_future(10))
        m.approve(acc.id, approver="admin", approver_role="admin")
        results = m.get_expiring_soon("org-test", days=30)
        assert any(r.id == acc.id for r in results)

    def test_expiring_soon_excludes_far_future(self):
        m = _make_manager()
        acc = _request(m, expires_at=_future(120))
        m.approve(acc.id, approver="admin", approver_role="admin")
        results = m.get_expiring_soon("org-test", days=30)
        assert not any(r.id == acc.id for r in results)

    def test_expiring_soon_excludes_pending(self):
        m = _make_manager()
        _request(m, expires_at=_future(5))  # pending, not approved
        results = m.get_expiring_soon("org-test", days=30)
        assert len(results) == 0


# ---------------------------------------------------------------------------
# Listing and lookup
# ---------------------------------------------------------------------------


class TestListAcceptances:
    def test_list_all_returns_all(self):
        m = _make_manager()
        _request(m, finding_id="f1")
        _request(m, finding_id="f2")
        results = m.list_acceptances("org-test")
        assert len(results) == 2

    def test_list_with_status_filter(self):
        m = _make_manager()
        acc = _request(m, finding_id="f1")
        _request(m, finding_id="f2")
        m.approve(acc.id, approver="admin", approver_role="admin")
        approved = m.list_acceptances("org-test", status_filter=AcceptanceStatus.APPROVED)
        assert len(approved) == 1
        assert approved[0].finding_id == "f1"

    def test_list_isolated_by_org(self):
        m = _make_manager()
        _request(m, org_id="org-a")
        _request(m, org_id="org-b")
        assert len(m.list_acceptances("org-a")) == 1
        assert len(m.list_acceptances("org-b")) == 1

    def test_get_pending_reviews(self):
        m = _make_manager()
        acc = _request(m, finding_id="pending-one")
        _request(m, finding_id="also-pending")
        m.approve(acc.id, approver="admin", approver_role="admin")
        pending = m.get_pending_reviews("org-test")
        assert len(pending) == 1
        assert pending[0].finding_id == "also-pending"


class TestFindingLookup:
    def test_get_acceptance_for_finding(self):
        m = _make_manager()
        acc = _request(m, finding_id="CVE-2024-99")
        result = m.get_acceptance_for_finding("CVE-2024-99")
        assert result is not None
        assert result.id == acc.id

    def test_get_acceptance_for_finding_none_when_missing(self):
        m = _make_manager()
        result = m.get_acceptance_for_finding("no-such-finding")
        assert result is None


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestStats:
    def test_stats_total_count(self):
        m = _make_manager()
        _request(m)
        _request(m, finding_id="f2")
        stats = m.get_acceptance_stats("org-test")
        assert stats["total"] == 2

    def test_stats_counts_by_status(self):
        m = _make_manager()
        acc1 = _request(m, finding_id="f1")
        acc2 = _request(m, finding_id="f2")
        m.approve(acc1.id, approver="admin", approver_role="admin")
        m.reject(acc2.id, reviewer="admin", reason="too risky")
        stats = m.get_acceptance_stats("org-test")
        assert stats["approved"] == 1
        assert stats["rejected"] == 1
        assert stats["pending"] == 0

    def test_stats_avg_duration_computed(self):
        m = _make_manager()
        acc = _request(m)
        m.approve(acc.id, approver="admin", approver_role="admin")
        stats = m.get_acceptance_stats("org-test")
        assert stats["avg_duration_days"] is not None
        assert stats["avg_duration_days"] >= 0

    def test_stats_empty_org(self):
        m = _make_manager()
        stats = m.get_acceptance_stats("org-empty")
        assert stats["total"] == 0
        assert stats["avg_duration_days"] is None


# ---------------------------------------------------------------------------
# Review history
# ---------------------------------------------------------------------------


class TestReviewHistory:
    def test_history_empty_before_any_action(self):
        m = _make_manager()
        acc = _request(m)
        assert m.get_review_history(acc.id) == []

    def test_history_records_approve_then_revoke(self):
        m = _make_manager()
        acc = _request(m)
        m.approve(acc.id, approver="a@corp.com", comment="ok", approver_role="admin")
        m.revoke(acc.id, revoker="b@corp.com", reason="change")
        history = m.get_review_history(acc.id)
        assert len(history) == 2
        assert history[0].decision == "approved"
        assert history[1].decision == "revoked"

    def test_history_ordered_chronologically(self):
        m = _make_manager()
        acc = _request(m)
        m.approve(acc.id, approver="first@corp.com", approver_role="admin")
        m.revoke(acc.id, revoker="second@corp.com", reason="n/a")
        history = m.get_review_history(acc.id)
        assert history[0].reviewer == "first@corp.com"
        assert history[1].reviewer == "second@corp.com"


# ---------------------------------------------------------------------------
# API Router tests
# ---------------------------------------------------------------------------


class TestRiskAcceptanceAPI:
    """Integration tests via FastAPI TestClient."""

    @pytest.fixture(autouse=True)
    def setup_app(self):
        """Build a test app with a fresh in-memory manager injected."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api.risk_acceptance_router import router, _get_manager

        # Fresh manager for each test
        fresh_manager = RiskAcceptanceManager(db_path=":memory:")

        app = FastAPI()

        # Override the org_id dependency to avoid needing API keys in tests
        from apps.api.dependencies import get_org_id as _get_org_id

        def _override_org() -> str:
            return "org-api-test"

        def _override_manager() -> RiskAcceptanceManager:
            return fresh_manager

        app.dependency_overrides[_get_org_id] = _override_org
        app.dependency_overrides[_get_manager] = _override_manager
        app.include_router(router)

        self.client = TestClient(app)
        self.manager = fresh_manager

    def _post_request(self, finding_id: str = "f-api-001", days: int = 90) -> dict:
        expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
        payload = {
            "finding_id": finding_id,
            "justification": "API test justification",
            "business_reason": "API test reason",
            "compensating_controls": "API WAF rule",
            "requested_by": "api-user@test.com",
            "expires_at": expires,
            "priority": "routine",
            "conditions": ["check monthly"],
            "risk_score_at_acceptance": 6.0,
        }
        resp = self.client.post("/api/v1/risk-acceptance/request", json=payload)
        assert resp.status_code == 201
        return resp.json()

    def test_api_request_returns_201(self):
        data = self._post_request()
        assert data["status"] == "pending"

    def test_api_list_acceptances(self):
        self._post_request("f-list-1")
        self._post_request("f-list-2")
        resp = self.client.get("/api/v1/risk-acceptance")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_api_get_single_acceptance(self):
        acc = self._post_request()
        resp = self.client.get(f"/api/v1/risk-acceptance/{acc['id']}")
        assert resp.status_code == 200
        assert resp.json()["id"] == acc["id"]

    def test_api_get_nonexistent_404(self):
        resp = self.client.get("/api/v1/risk-acceptance/ghost-id")
        assert resp.status_code == 404

    def test_api_approve(self):
        acc = self._post_request()
        resp = self.client.post(
            f"/api/v1/risk-acceptance/{acc['id']}/approve",
            json={"approver": "ciso@corp.com", "comment": "OK", "approver_role": "admin"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"

    def test_api_reject(self):
        acc = self._post_request()
        resp = self.client.post(
            f"/api/v1/risk-acceptance/{acc['id']}/reject",
            json={"reviewer": "security@corp.com", "reason": "Too risky"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "rejected"

    def test_api_revoke(self):
        acc = self._post_request()
        self.client.post(
            f"/api/v1/risk-acceptance/{acc['id']}/approve",
            json={"approver": "admin", "approver_role": "admin"},
        )
        resp = self.client.post(
            f"/api/v1/risk-acceptance/{acc['id']}/revoke",
            json={"revoker": "ciso@corp.com", "reason": "Policy changed"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

    def test_api_pending_list(self):
        acc1 = self._post_request("f-p1")
        self._post_request("f-p2")
        self.client.post(
            f"/api/v1/risk-acceptance/{acc1['id']}/approve",
            json={"approver": "admin", "approver_role": "admin"},
        )
        resp = self.client.get("/api/v1/risk-acceptance/pending")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_api_expire_endpoint(self):
        resp = self.client.post("/api/v1/risk-acceptance/expire")
        assert resp.status_code == 200
        assert "expired_count" in resp.json()

    def test_api_history_endpoint(self):
        acc = self._post_request()
        self.client.post(
            f"/api/v1/risk-acceptance/{acc['id']}/approve",
            json={"approver": "admin", "approver_role": "admin"},
        )
        resp = self.client.get(f"/api/v1/risk-acceptance/{acc['id']}/history")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_api_stats(self):
        self._post_request()
        resp = self.client.get("/api/v1/risk-acceptance/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert data["total"] >= 1

    def test_api_approve_bad_role_returns_400(self):
        acc = self._post_request()
        resp = self.client.post(
            f"/api/v1/risk-acceptance/{acc['id']}/approve",
            json={"approver": "dev@corp.com", "approver_role": "developer"},
        )
        assert resp.status_code == 400
