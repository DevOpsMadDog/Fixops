"""
Tests for Change Management Tracker — suite-core/core/change_tracker.py
and the change_tracker_router.py FastAPI router.

Covers:
- ChangeType / ChangeRisk enum values
- Change Pydantic model validation
- ChangeTracker.record_change
- ChangeTracker.assess_risk (heuristics)
- ChangeTracker.approve_change
- ChangeTracker.reject_change
- ChangeTracker.get_change
- ChangeTracker.get_pending_reviews
- ChangeTracker.get_high_risk_changes
- ChangeTracker.get_change_velocity
- ChangeTracker.get_change_stats
- ChangeTracker.correlate_with_incidents
- ChangeTracker.get_review_history
- All 9 router endpoints via TestClient
"""

from __future__ import annotations

import os
import sys
import pytest

# ---------------------------------------------------------------------------
# Environment stubs (must be set before any import of suite code)
# ---------------------------------------------------------------------------

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

from core.change_tracker import Change, ChangeRisk, ChangeTracker, ChangeType

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tracker():
    """Fresh in-memory ChangeTracker for each test."""
    return ChangeTracker()


@pytest.fixture()
def sample_change(tracker):
    """A recorded code change for reuse."""
    return tracker.record_change(
        type=ChangeType.CODE_CHANGE,
        description="Updated authentication middleware",
        author="alice@example.com",
        affected_assets=["suite-api/apps/api/auth.py"],
        org_id="acme",
    )


# ===========================================================================
# Enum tests
# ===========================================================================


def test_change_type_values():
    assert ChangeType.CODE_CHANGE == "code_change"
    assert ChangeType.CONFIG_CHANGE == "config_change"
    assert ChangeType.INFRA_CHANGE == "infra_change"
    assert ChangeType.ACCESS_CHANGE == "access_change"
    assert ChangeType.POLICY_CHANGE == "policy_change"
    assert ChangeType.VENDOR_CHANGE == "vendor_change"


def test_change_risk_values():
    assert ChangeRisk.NONE == "none"
    assert ChangeRisk.LOW == "low"
    assert ChangeRisk.MEDIUM == "medium"
    assert ChangeRisk.HIGH == "high"
    assert ChangeRisk.CRITICAL == "critical"


# ===========================================================================
# Change model tests
# ===========================================================================


def test_change_model_defaults():
    change = Change(
        type=ChangeType.CODE_CHANGE,
        description="test",
        author="dev@example.com",
    )
    assert change.review_status == "pending"
    assert change.risk_level == "none"
    assert change.affected_assets == []
    assert change.org_id == "default"
    assert change.id is not None
    assert change.created_at is not None


def test_change_model_invalid_review_status():
    with pytest.raises(Exception):
        Change(
            type=ChangeType.CODE_CHANGE,
            description="test",
            author="dev@example.com",
            review_status="invalid_status",
        )


def test_change_model_all_fields():
    change = Change(
        type=ChangeType.INFRA_CHANGE,
        description="Added firewall rule",
        author="ops@example.com",
        risk_level=ChangeRisk.HIGH,
        affected_assets=["vpc-prod", "sg-web"],
        review_status="approved",
        security_impact="Opens port 443 to internet",
        org_id="corp",
    )
    assert change.type == "infra_change"
    assert change.risk_level == "high"
    assert len(change.affected_assets) == 2
    assert change.review_status == "approved"


# ===========================================================================
# ChangeTracker.record_change
# ===========================================================================


def test_record_change_returns_change(tracker):
    change = tracker.record_change(
        type=ChangeType.CONFIG_CHANGE,
        description="Updated nginx.conf",
        author="bob@example.com",
        org_id="default",
    )
    assert isinstance(change, Change)
    assert change.type == "config_change"
    assert change.author == "bob@example.com"
    assert change.review_status == "pending"


def test_record_change_persists(tracker):
    change = tracker.record_change(
        type=ChangeType.VENDOR_CHANGE,
        description="Upgraded OpenSSL library",
        author="carol@example.com",
        org_id="default",
    )
    fetched = tracker.get_change(change.id)
    assert fetched is not None
    assert fetched.id == change.id
    assert fetched.description == "Upgraded OpenSSL library"


def test_record_change_with_assets(tracker):
    change = tracker.record_change(
        type=ChangeType.ACCESS_CHANGE,
        description="Added admin role to user",
        author="admin@example.com",
        affected_assets=["user:john", "role:admin"],
        org_id="acme",
    )
    fetched = tracker.get_change(change.id)
    assert fetched is not None
    assert "user:john" in fetched.affected_assets
    assert "role:admin" in fetched.affected_assets


def test_record_multiple_changes(tracker):
    for i in range(5):
        tracker.record_change(
            type=ChangeType.CODE_CHANGE,
            description=f"Change {i}",
            author="dev@example.com",
            org_id="acme",
        )
    stats = tracker.get_change_stats(org_id="acme")
    assert stats["total_changes"] == 5


# ===========================================================================
# ChangeTracker.assess_risk
# ===========================================================================


def test_assess_risk_infra_baseline(tracker):
    change = tracker.record_change(
        type=ChangeType.INFRA_CHANGE,
        description="Minor route table update",
        author="ops@example.com",
        org_id="acme",
    )
    assessed = tracker.assess_risk(change.id)
    assert assessed.risk_level in ("high", "critical", "medium")
    assert assessed.security_impact != ""


def test_assess_risk_critical_keywords(tracker):
    change = tracker.record_change(
        type=ChangeType.CODE_CHANGE,
        description="Rotated encryption key for production database",
        author="sec@example.com",
        org_id="acme",
    )
    assessed = tracker.assess_risk(change.id)
    assert assessed.risk_level == "critical"


def test_assess_risk_high_keywords(tracker):
    change = tracker.record_change(
        type=ChangeType.CODE_CHANGE,
        description="Modified authentication flow and RBAC rules",
        author="dev@example.com",
        org_id="acme",
    )
    assessed = tracker.assess_risk(change.id)
    assert assessed.risk_level in ("high", "critical")


def test_assess_risk_low_for_docs(tracker):
    change = tracker.record_change(
        type=ChangeType.CODE_CHANGE,
        description="Updated readme and documentation comments",
        author="dev@example.com",
        org_id="acme",
    )
    assessed = tracker.assess_risk(change.id)
    # docs should not escalate beyond code_change baseline (low)
    assert assessed.risk_level in ("none", "low")


def test_assess_risk_not_found(tracker):
    with pytest.raises(KeyError):
        tracker.assess_risk("nonexistent-id")


def test_assess_risk_persists_impact(tracker):
    change = tracker.record_change(
        type=ChangeType.ACCESS_CHANGE,
        description="Granted IAM admin privilege",
        author="sec@example.com",
        org_id="acme",
    )
    assessed = tracker.assess_risk(change.id)
    fetched = tracker.get_change(change.id)
    assert fetched is not None
    assert fetched.security_impact == assessed.security_impact


# ===========================================================================
# ChangeTracker.approve_change / reject_change
# ===========================================================================


def test_approve_change(tracker, sample_change):
    approved = tracker.approve_change(sample_change.id, approver="bob@example.com")
    assert approved.review_status == "approved"


def test_approve_change_not_found(tracker):
    with pytest.raises(KeyError):
        tracker.approve_change("bad-id", approver="bob@example.com")


def test_reject_change(tracker, sample_change):
    rejected = tracker.reject_change(
        sample_change.id, reviewer="sec@example.com", reason="Missing security review"
    )
    assert rejected.review_status == "rejected"


def test_reject_change_not_found(tracker):
    with pytest.raises(KeyError):
        tracker.reject_change("bad-id", reviewer="sec@example.com", reason="reason")


def test_approve_already_rejected_raises(tracker, sample_change):
    tracker.reject_change(sample_change.id, reviewer="sec@example.com", reason="reason")
    with pytest.raises(ValueError):
        tracker.approve_change(sample_change.id, approver="bob@example.com")


def test_reject_already_approved_raises(tracker, sample_change):
    tracker.approve_change(sample_change.id, approver="bob@example.com")
    with pytest.raises(ValueError):
        tracker.reject_change(sample_change.id, reviewer="sec@example.com", reason="reason")


def test_review_history_recorded(tracker, sample_change):
    tracker.approve_change(sample_change.id, approver="bob@example.com")
    history = tracker.get_review_history(sample_change.id)
    assert len(history) == 1
    assert history[0]["action"] == "approved"
    assert history[0]["reviewer"] == "bob@example.com"


# ===========================================================================
# ChangeTracker.get_pending_reviews
# ===========================================================================


def test_get_pending_reviews_empty(tracker):
    assert tracker.get_pending_reviews(org_id="empty-org") == []


def test_get_pending_reviews_includes_pending(tracker):
    c = tracker.record_change(
        type=ChangeType.POLICY_CHANGE,
        description="Updated data retention policy",
        author="dpo@example.com",
        org_id="acme",
    )
    pending = tracker.get_pending_reviews(org_id="acme")
    ids = [p.id for p in pending]
    assert c.id in ids


def test_get_pending_reviews_excludes_approved(tracker):
    c = tracker.record_change(
        type=ChangeType.CODE_CHANGE,
        description="Minor refactor",
        author="dev@example.com",
        org_id="acme",
    )
    tracker.approve_change(c.id, approver="mgr@example.com")
    pending = tracker.get_pending_reviews(org_id="acme")
    ids = [p.id for p in pending]
    assert c.id not in ids


# ===========================================================================
# ChangeTracker.get_high_risk_changes
# ===========================================================================


def test_get_high_risk_changes_empty(tracker):
    assert tracker.get_high_risk_changes(org_id="empty-org") == []


def test_get_high_risk_changes_returns_high_and_critical(tracker):
    c1 = tracker.record_change(
        type=ChangeType.INFRA_CHANGE,
        description="Changed security group",
        author="ops@example.com",
        risk_level=ChangeRisk.HIGH,
        org_id="acme",
    )
    c2 = tracker.record_change(
        type=ChangeType.ACCESS_CHANGE,
        description="Root access granted",
        author="admin@example.com",
        risk_level=ChangeRisk.CRITICAL,
        org_id="acme",
    )
    c3 = tracker.record_change(
        type=ChangeType.CODE_CHANGE,
        description="Readme update",
        author="dev@example.com",
        risk_level=ChangeRisk.LOW,
        org_id="acme",
    )
    high_risk = tracker.get_high_risk_changes(org_id="acme")
    ids = [c.id for c in high_risk]
    assert c1.id in ids
    assert c2.id in ids
    assert c3.id not in ids


# ===========================================================================
# ChangeTracker.get_change_velocity
# ===========================================================================


def test_get_change_velocity_empty(tracker):
    vel = tracker.get_change_velocity(org_id="empty-org", days=7)
    assert vel["total_changes"] == 0
    assert vel["avg_changes_per_day"] == 0.0
    assert vel["days"] == 7


def test_get_change_velocity_counts(tracker):
    for _ in range(4):
        tracker.record_change(
            type=ChangeType.CODE_CHANGE,
            description="daily change",
            author="dev@example.com",
            org_id="acme",
        )
    vel = tracker.get_change_velocity(org_id="acme", days=30)
    assert vel["total_changes"] == 4
    assert vel["avg_changes_per_day"] > 0


# ===========================================================================
# ChangeTracker.get_change_stats
# ===========================================================================


def test_get_change_stats_empty(tracker):
    stats = tracker.get_change_stats(org_id="empty-org")
    assert stats["total_changes"] == 0
    assert stats["review"]["approval_rate_pct"] == 0.0


def test_get_change_stats_by_type(tracker):
    tracker.record_change(
        type=ChangeType.CODE_CHANGE, description="c1", author="dev@example.com", org_id="acme"
    )
    tracker.record_change(
        type=ChangeType.CONFIG_CHANGE, description="c2", author="ops@example.com", org_id="acme"
    )
    stats = tracker.get_change_stats(org_id="acme")
    assert stats["by_type"].get("code_change") == 1
    assert stats["by_type"].get("config_change") == 1


def test_get_change_stats_approval_rate(tracker):
    c1 = tracker.record_change(
        type=ChangeType.CODE_CHANGE, description="c1", author="dev@example.com", org_id="acme"
    )
    c2 = tracker.record_change(
        type=ChangeType.CODE_CHANGE, description="c2", author="dev@example.com", org_id="acme"
    )
    tracker.approve_change(c1.id, approver="mgr@example.com")
    stats = tracker.get_change_stats(org_id="acme")
    assert stats["review"]["approved"] == 1
    assert stats["review"]["pending"] == 1
    assert stats["review"]["approval_rate_pct"] == 50.0


# ===========================================================================
# ChangeTracker.correlate_with_incidents
# ===========================================================================


def test_correlate_with_incidents_empty(tracker):
    result = tracker.correlate_with_incidents(org_id="empty-org")
    assert result == []


def test_correlate_with_incidents_only_high_risk(tracker):
    low = tracker.record_change(
        type=ChangeType.CODE_CHANGE,
        description="Readme update",
        author="dev@example.com",
        risk_level=ChangeRisk.LOW,
        org_id="acme",
    )
    high = tracker.record_change(
        type=ChangeType.INFRA_CHANGE,
        description="Firewall rule changed",
        author="ops@example.com",
        risk_level=ChangeRisk.HIGH,
        org_id="acme",
    )
    result = tracker.correlate_with_incidents(org_id="acme")
    ids = [r["change_id"] for r in result]
    assert high.id in ids
    assert low.id not in ids


def test_correlate_with_incidents_has_window(tracker):
    tracker.record_change(
        type=ChangeType.ACCESS_CHANGE,
        description="Root access granted",
        author="admin@example.com",
        risk_level=ChangeRisk.CRITICAL,
        org_id="acme",
    )
    result = tracker.correlate_with_incidents(org_id="acme", window_hours=48)
    assert len(result) == 1
    assert result[0]["correlation_window_hours"] == 48
    assert "correlation_window_start" in result[0]
    assert "correlation_window_end" in result[0]


# ===========================================================================
# Router (FastAPI TestClient) tests
# ===========================================================================


@pytest.fixture()
def app_client():
    """Create a TestClient with a fresh ChangeTracker injected into the router."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import apps.api.change_tracker_router as ct_router

    ct_router._tracker = ChangeTracker()  # fresh instance per test

    app = FastAPI()
    app.include_router(ct_router.router)
    return TestClient(app)


def test_router_record_change(app_client):
    resp = app_client.post("/api/v1/change-tracker/", json={
        "type": "code_change",
        "description": "Updated login handler",
        "author": "alice@example.com",
        "org_id": "acme",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "code_change"
    assert data["review_status"] == "pending"
    assert "id" in data


def test_router_get_change(app_client):
    create = app_client.post("/api/v1/change-tracker/", json={
        "type": "config_change",
        "description": "Updated TLS config",
        "author": "ops@example.com",
        "org_id": "acme",
    })
    cid = create.json()["id"]
    resp = app_client.get(f"/api/v1/change-tracker/{cid}")
    assert resp.status_code == 200
    assert resp.json()["id"] == cid


def test_router_get_change_not_found(app_client):
    resp = app_client.get("/api/v1/change-tracker/nonexistent-id")
    assert resp.status_code == 404


def test_router_assess_risk(app_client):
    create = app_client.post("/api/v1/change-tracker/", json={
        "type": "access_change",
        "description": "Granted IAM admin privilege",
        "author": "sec@example.com",
        "org_id": "acme",
    })
    cid = create.json()["id"]
    resp = app_client.post(f"/api/v1/change-tracker/{cid}/assess-risk")
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] in ("none", "low", "medium", "high", "critical")
    assert data["security_impact"] != ""


def test_router_assess_risk_not_found(app_client):
    resp = app_client.post("/api/v1/change-tracker/bad-id/assess-risk")
    assert resp.status_code == 404


def test_router_approve_change(app_client):
    create = app_client.post("/api/v1/change-tracker/", json={
        "type": "policy_change",
        "description": "Updated data retention policy",
        "author": "dpo@example.com",
        "org_id": "acme",
    })
    cid = create.json()["id"]
    resp = app_client.post(f"/api/v1/change-tracker/{cid}/approve", json={"approver": "mgr@example.com"})
    assert resp.status_code == 200
    assert resp.json()["review_status"] == "approved"


def test_router_reject_change(app_client):
    create = app_client.post("/api/v1/change-tracker/", json={
        "type": "vendor_change",
        "description": "Upgraded third-party auth library",
        "author": "dev@example.com",
        "org_id": "acme",
    })
    cid = create.json()["id"]
    resp = app_client.post(
        f"/api/v1/change-tracker/{cid}/reject",
        json={"reviewer": "sec@example.com", "reason": "Vendor not approved"},
    )
    assert resp.status_code == 200
    assert resp.json()["review_status"] == "rejected"


def test_router_approve_not_found(app_client):
    resp = app_client.post("/api/v1/change-tracker/bad-id/approve", json={"approver": "mgr@example.com"})
    assert resp.status_code == 404


def test_router_reject_not_found(app_client):
    resp = app_client.post(
        "/api/v1/change-tracker/bad-id/reject",
        json={"reviewer": "sec@example.com", "reason": "reason"},
    )
    assert resp.status_code == 404


def test_router_pending_reviews(app_client):
    app_client.post("/api/v1/change-tracker/", json={
        "type": "code_change",
        "description": "New feature branch merge",
        "author": "dev@example.com",
        "org_id": "acme",
    })
    resp = app_client.get("/api/v1/change-tracker/pending?org_id=acme")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1


def test_router_high_risk(app_client):
    app_client.post("/api/v1/change-tracker/", json={
        "type": "infra_change",
        "description": "Security group change",
        "author": "ops@example.com",
        "risk_level": "high",
        "org_id": "acme",
    })
    resp = app_client.get("/api/v1/change-tracker/high-risk?org_id=acme")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert all(c["risk_level"] in ("high", "critical") for c in data)


def test_router_velocity(app_client):
    resp = app_client.get("/api/v1/change-tracker/velocity?org_id=acme&days=7")
    assert resp.status_code == 200
    data = resp.json()
    assert "avg_changes_per_day" in data
    assert "total_changes" in data
    assert data["days"] == 7


def test_router_stats(app_client):
    app_client.post("/api/v1/change-tracker/", json={
        "type": "code_change",
        "description": "Stats test change",
        "author": "dev@example.com",
        "org_id": "acme",
    })
    resp = app_client.get("/api/v1/change-tracker/stats?org_id=acme")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_changes" in data
    assert "by_type" in data
    assert "by_risk" in data
    assert "review" in data


def test_router_correlate_incidents(app_client):
    app_client.post("/api/v1/change-tracker/", json={
        "type": "access_change",
        "description": "Root credential rotation",
        "author": "sec@example.com",
        "risk_level": "critical",
        "org_id": "acme",
    })
    resp = app_client.get("/api/v1/change-tracker/correlate-incidents?org_id=acme&window_hours=48")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["correlation_window_hours"] == 48


def test_router_double_approve_conflict(app_client):
    create = app_client.post("/api/v1/change-tracker/", json={
        "type": "code_change",
        "description": "conflict test",
        "author": "dev@example.com",
        "org_id": "acme",
    })
    cid = create.json()["id"]
    app_client.post(f"/api/v1/change-tracker/{cid}/reject", json={"reviewer": "r@example.com", "reason": "x"})
    resp = app_client.post(f"/api/v1/change-tracker/{cid}/approve", json={"approver": "mgr@example.com"})
    assert resp.status_code == 409
