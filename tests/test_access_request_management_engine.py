"""Tests for AccessRequestManagementEngine.

Covers: init, create_request validation, list/get, approve lifecycle,
reject lifecycle, revoke, stats (rejection_rate, avg_approval_time_hours,
by_resource_type, by_access_type), org isolation.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from core.access_request_management_engine import AccessRequestManagementEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return AccessRequestManagementEngine(db_path=str(tmp_path / "arm_test.db"))


def _req(**overrides):
    base = {
        "requester": "alice",
        "resource_id": "db-001",
        "resource_name": "Production DB",
        "resource_type": "database",
        "access_type": "read",
        "justification": "Incident investigation",
        "priority": "high",
        "duration_days": 7,
    }
    base.update(overrides)
    return base


def _create(engine, org_id="org1", **kw):
    return engine.create_request(org_id, _req(**kw))


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = tmp_path / "arm.db"
    AccessRequestManagementEngine(db_path=str(db))
    assert db.exists()


def test_init_twice_idempotent(tmp_path):
    db = str(tmp_path / "arm.db")
    AccessRequestManagementEngine(db_path=db)
    AccessRequestManagementEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. create_request — validation
# ---------------------------------------------------------------------------


def test_create_requires_requester(engine):
    with pytest.raises(ValueError, match="requester"):
        engine.create_request("org1", _req(requester=""))


def test_create_invalid_access_type(engine):
    with pytest.raises(ValueError, match="access_type"):
        engine.create_request("org1", _req(access_type="superpower"))


def test_create_invalid_resource_type(engine):
    with pytest.raises(ValueError, match="resource_type"):
        engine.create_request("org1", _req(resource_type="spaceship"))


def test_create_invalid_priority(engine):
    with pytest.raises(ValueError, match="priority"):
        engine.create_request("org1", _req(priority="asap"))


def test_create_all_valid_access_types(engine):
    for at in ("read", "write", "admin", "execute", "delete", "full_control"):
        r = _create(engine, access_type=at, resource_id=f"r-{at}")
        assert r["access_type"] == at


def test_create_all_valid_resource_types(engine):
    for rt in ("database", "application", "server", "network", "cloud_resource", "file_share", "api"):
        r = _create(engine, resource_type=rt, resource_id=f"r-{rt}")
        assert r["resource_type"] == rt


def test_create_all_valid_priorities(engine):
    for p in ("urgent", "high", "normal", "low"):
        r = _create(engine, priority=p, resource_id=f"r-{p}")
        assert r["priority"] == p


# ---------------------------------------------------------------------------
# 3. create_request — returned record
# ---------------------------------------------------------------------------


def test_create_returns_record_with_id(engine):
    r = _create(engine)
    assert r["id"]
    assert r["status"] == "pending"
    assert r["requester"] == "alice"
    assert r["duration_days"] == 7


def test_create_defaults_status_pending(engine):
    r = _create(engine)
    assert r["status"] == "pending"


def test_create_approved_at_none(engine):
    r = _create(engine)
    assert r["approved_at"] is None


def test_create_expires_at_none(engine):
    r = _create(engine)
    assert r["expires_at"] is None


def test_create_duration_days_default(engine):
    data = _req()
    del data["duration_days"]
    r = engine.create_request("org1", data)
    assert r["duration_days"] == 30


# ---------------------------------------------------------------------------
# 4. list_requests / get_request
# ---------------------------------------------------------------------------


def test_list_returns_all(engine):
    _create(engine); _create(engine, requester="bob")
    assert len(engine.list_requests("org1")) == 2


def test_list_filter_by_access_type(engine):
    _create(engine, access_type="read")
    _create(engine, access_type="write")
    results = engine.list_requests("org1", access_type="read")
    assert all(r["access_type"] == "read" for r in results)
    assert len(results) == 1


def test_list_filter_by_status(engine):
    r = _create(engine)
    engine.approve_request("org1", r["id"], "admin")
    results = engine.list_requests("org1", status="approved")
    assert all(r["status"] == "approved" for r in results)


def test_list_filter_by_resource_type(engine):
    _create(engine, resource_type="database")
    _create(engine, resource_type="api")
    results = engine.list_requests("org1", resource_type="api")
    assert len(results) == 1
    assert results[0]["resource_type"] == "api"


def test_get_request_existing(engine):
    r = _create(engine)
    fetched = engine.get_request("org1", r["id"])
    assert fetched["id"] == r["id"]


def test_get_request_nonexistent_returns_none(engine):
    assert engine.get_request("org1", "nonexistent-id") is None


# ---------------------------------------------------------------------------
# 5. approve_request
# ---------------------------------------------------------------------------


def test_approve_sets_status(engine):
    r = _create(engine)
    approved = engine.approve_request("org1", r["id"], "manager")
    assert approved["status"] == "approved"


def test_approve_sets_approver(engine):
    r = _create(engine)
    approved = engine.approve_request("org1", r["id"], "manager")
    assert approved["approver"] == "manager"


def test_approve_sets_approved_at(engine):
    r = _create(engine)
    approved = engine.approve_request("org1", r["id"], "manager")
    assert approved["approved_at"] is not None


def test_approve_sets_expires_at(engine):
    r = _create(engine, duration_days=10)
    approved = engine.approve_request("org1", r["id"], "manager")
    assert approved["expires_at"] is not None


def test_approve_expires_at_is_duration_days_later(engine):
    r = _create(engine, duration_days=7)
    approved = engine.approve_request("org1", r["id"], "manager")
    approved_dt = datetime.fromisoformat(approved["approved_at"])
    expires_dt = datetime.fromisoformat(approved["expires_at"])
    delta = expires_dt - approved_dt
    assert 6 <= delta.days <= 7  # allow for same-second edge


def test_approve_with_notes(engine):
    r = _create(engine)
    approved = engine.approve_request("org1", r["id"], "mgr", notes="LGTM")
    assert approved["notes"] == "LGTM"


def test_approve_nonexistent_raises(engine):
    with pytest.raises(ValueError):
        engine.approve_request("org1", "bad-id", "mgr")


# ---------------------------------------------------------------------------
# 6. reject_request
# ---------------------------------------------------------------------------


def test_reject_sets_status(engine):
    r = _create(engine)
    rejected = engine.reject_request("org1", r["id"], "mgr", "Not justified")
    assert rejected["status"] == "rejected"


def test_reject_sets_approver(engine):
    r = _create(engine)
    rejected = engine.reject_request("org1", r["id"], "mgr", "No")
    assert rejected["approver"] == "mgr"


def test_reject_stores_reason_in_notes(engine):
    r = _create(engine)
    rejected = engine.reject_request("org1", r["id"], "mgr", "Violates policy")
    assert rejected["notes"] == "Violates policy"


def test_reject_nonexistent_raises(engine):
    with pytest.raises(ValueError):
        engine.reject_request("org1", "bad-id", "mgr", "No")


# ---------------------------------------------------------------------------
# 7. revoke_access
# ---------------------------------------------------------------------------


def test_revoke_sets_status(engine):
    r = _create(engine)
    engine.approve_request("org1", r["id"], "mgr")
    revoked = engine.revoke_access("org1", r["id"], "Employee left")
    assert revoked["status"] == "revoked"


def test_revoke_stores_reason(engine):
    r = _create(engine)
    revoked = engine.revoke_access("org1", r["id"], "Security incident")
    assert revoked["notes"] == "Security incident"


def test_revoke_nonexistent_raises(engine):
    with pytest.raises(ValueError):
        engine.revoke_access("org1", "bad-id", "reason")


# ---------------------------------------------------------------------------
# 8. get_access_stats
# ---------------------------------------------------------------------------


def test_stats_empty(engine):
    s = engine.get_access_stats("org1")
    assert s["total_requests"] == 0
    assert s["pending_count"] == 0
    assert s["approved_count"] == 0
    assert s["rejection_rate"] == 0.0


def test_stats_counts(engine):
    r1 = _create(engine)
    r2 = _create(engine, requester="bob")
    engine.approve_request("org1", r1["id"], "mgr")
    engine.reject_request("org1", r2["id"], "mgr", "No")
    s = engine.get_access_stats("org1")
    assert s["total_requests"] == 2
    assert s["approved_count"] == 1
    assert s["pending_count"] == 0


def test_stats_rejection_rate(engine):
    r1 = _create(engine)
    r2 = _create(engine, requester="bob")
    engine.reject_request("org1", r1["id"], "mgr", "No")
    engine.reject_request("org1", r2["id"], "mgr", "No")
    s = engine.get_access_stats("org1")
    assert s["rejection_rate"] == 100.0


def test_stats_rejection_rate_partial(engine):
    r1 = _create(engine)
    r2 = _create(engine, requester="bob")
    engine.approve_request("org1", r1["id"], "mgr")
    engine.reject_request("org1", r2["id"], "mgr", "No")
    s = engine.get_access_stats("org1")
    assert s["rejection_rate"] == 50.0


def test_stats_avg_approval_time(engine):
    r = _create(engine)
    engine.approve_request("org1", r["id"], "mgr")
    s = engine.get_access_stats("org1")
    # avg_approval_time_hours should be >=0 (near-instant in tests)
    assert s["avg_approval_time_hours"] >= 0.0


def test_stats_by_resource_type(engine):
    _create(engine, resource_type="database")
    _create(engine, resource_type="api", requester="bob")
    s = engine.get_access_stats("org1")
    assert s["by_resource_type"].get("database", 0) >= 1
    assert s["by_resource_type"].get("api", 0) >= 1


def test_stats_by_access_type(engine):
    _create(engine, access_type="read")
    _create(engine, access_type="write", requester="bob")
    s = engine.get_access_stats("org1")
    assert s["by_access_type"].get("read", 0) >= 1
    assert s["by_access_type"].get("write", 0) >= 1


# ---------------------------------------------------------------------------
# 9. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_list(engine):
    _create(engine, org_id="orgA")
    _create(engine, org_id="orgB")
    assert len(engine.list_requests("orgA")) == 1
    assert len(engine.list_requests("orgB")) == 1


def test_org_isolation_get(engine):
    r = _create(engine, org_id="orgA")
    assert engine.get_request("orgB", r["id"]) is None


def test_org_isolation_stats(engine):
    _create(engine, org_id="orgA")
    s_b = engine.get_access_stats("orgB")
    assert s_b["total_requests"] == 0


def test_org_isolation_approve(engine):
    r = _create(engine, org_id="orgA")
    with pytest.raises(ValueError):
        engine.approve_request("orgB", r["id"], "mgr")
