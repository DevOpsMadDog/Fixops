"""Tests for SecurityChangeManagementEngine — 35 tests covering all methods."""
from __future__ import annotations

import pytest

from core.security_change_management_engine import SecurityChangeManagementEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_scm_engine.db")


@pytest.fixture
def engine(db_path):
    return SecurityChangeManagementEngine(db_path=db_path)


ORG = "org-scm-test"
ORG2 = "org-scm-other"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_change(engine, org=ORG, **kwargs):
    defaults = {
        "title": "Deploy security patch",
        "change_type": "patch",
        "priority": "high",
        "risk_level": "medium",
        "requested_by": "alice",
    }
    defaults.update(kwargs)
    return engine.create_change(org, defaults)


def _make_approval(engine, change_id, org=ORG, **kwargs):
    defaults = {
        "approver": "bob",
        "decision": "pending",
        "comments": "",
    }
    defaults.update(kwargs)
    return engine.add_approver(org, change_id, defaults)


# ---------------------------------------------------------------------------
# create_change — validation
# ---------------------------------------------------------------------------

def test_create_change_requires_title(engine):
    with pytest.raises(ValueError, match="title is required"):
        engine.create_change(ORG, {"title": ""})


def test_create_change_invalid_type(engine):
    with pytest.raises(ValueError, match="change_type"):
        engine.create_change(ORG, {"title": "T", "change_type": "unknown"})


def test_create_change_invalid_priority(engine):
    with pytest.raises(ValueError, match="priority"):
        engine.create_change(ORG, {"title": "T", "priority": "ultra"})


def test_create_change_invalid_risk_level(engine):
    with pytest.raises(ValueError, match="risk_level"):
        engine.create_change(ORG, {"title": "T", "risk_level": "extreme"})


def test_create_change_default_status_draft(engine):
    change = _make_change(engine)
    assert change["status"] == "draft"


def test_create_change_has_timestamps(engine):
    change = _make_change(engine)
    assert change["created_at"]
    assert change["completed_at"] is None


def test_create_change_all_types(engine):
    types = ["patch", "configuration", "architecture", "access_control",
             "firewall_rule", "certificate", "policy", "emergency"]
    for ct in types:
        c = _make_change(engine, title=f"Change {ct}", change_type=ct)
        assert c["change_type"] == ct


def test_create_change_all_priorities(engine):
    for p in ["critical", "high", "medium", "low"]:
        c = _make_change(engine, title=f"P {p}", priority=p)
        assert c["priority"] == p


# ---------------------------------------------------------------------------
# list_changes / get_change
# ---------------------------------------------------------------------------

def test_list_changes_empty(engine):
    assert engine.list_changes(ORG) == []


def test_list_changes_returns_created(engine):
    _make_change(engine, title="C1")
    _make_change(engine, title="C2")
    changes = engine.list_changes(ORG)
    assert len(changes) == 2


def test_list_changes_filter_type(engine):
    _make_change(engine, title="P1", change_type="patch")
    _make_change(engine, title="E1", change_type="emergency")
    result = engine.list_changes(ORG, change_type="emergency")
    assert len(result) == 1
    assert result[0]["change_type"] == "emergency"


def test_list_changes_filter_status(engine):
    c = _make_change(engine, title="C1")
    engine.update_change_status(ORG, c["id"], "review")
    _make_change(engine, title="C2")
    result = engine.list_changes(ORG, status="review")
    assert len(result) == 1
    assert result[0]["status"] == "review"


def test_list_changes_filter_priority(engine):
    _make_change(engine, title="Critical Change", priority="critical")
    _make_change(engine, title="Low Change", priority="low")
    result = engine.list_changes(ORG, priority="critical")
    assert len(result) == 1
    assert result[0]["priority"] == "critical"


def test_get_change_found(engine):
    created = _make_change(engine)
    fetched = engine.get_change(ORG, created["id"])
    assert fetched is not None
    assert fetched["id"] == created["id"]


def test_get_change_not_found(engine):
    assert engine.get_change(ORG, "nonexistent") is None


# ---------------------------------------------------------------------------
# org_id isolation
# ---------------------------------------------------------------------------

def test_org_isolation_list(engine):
    _make_change(engine, org=ORG, title="Org1 Change")
    _make_change(engine, org=ORG2, title="Org2 Change")
    assert len(engine.list_changes(ORG)) == 1
    assert len(engine.list_changes(ORG2)) == 1


def test_org_isolation_get(engine):
    change = _make_change(engine, org=ORG)
    assert engine.get_change(ORG2, change["id"]) is None


# ---------------------------------------------------------------------------
# update_change_status
# ---------------------------------------------------------------------------

def test_update_status_transitions(engine):
    c = _make_change(engine)
    for status in ["review", "approved", "scheduled", "implementing", "completed"]:
        updated = engine.update_change_status(ORG, c["id"], status)
        assert updated["status"] == status


def test_update_status_sets_completed_at(engine):
    c = _make_change(engine)
    updated = engine.update_change_status(ORG, c["id"], "completed")
    assert updated["completed_at"] is not None


def test_update_status_not_completed_no_completed_at(engine):
    c = _make_change(engine)
    updated = engine.update_change_status(ORG, c["id"], "review")
    assert updated["completed_at"] is None


def test_update_status_with_notes(engine):
    c = _make_change(engine)
    updated = engine.update_change_status(ORG, c["id"], "rejected", notes="Does not meet criteria")
    assert updated["notes"] == "Does not meet criteria"
    assert updated["status"] == "rejected"


def test_update_status_invalid(engine):
    c = _make_change(engine)
    with pytest.raises(ValueError, match="status"):
        engine.update_change_status(ORG, c["id"], "flying")


def test_update_status_rolled_back(engine):
    c = _make_change(engine)
    updated = engine.update_change_status(ORG, c["id"], "rolled_back")
    assert updated["status"] == "rolled_back"


def test_update_status_returns_none_for_missing(engine):
    result = engine.update_change_status(ORG, "bad-id", "review")
    assert result is None


# ---------------------------------------------------------------------------
# add_approver / list_approvals
# ---------------------------------------------------------------------------

def test_add_approver_pending(engine):
    c = _make_change(engine)
    approval = _make_approval(engine, c["id"], decision="pending")
    assert approval["decision"] == "pending"
    assert approval["decided_at"] is None


def test_add_approver_approved(engine):
    c = _make_change(engine)
    approval = _make_approval(engine, c["id"], decision="approved")
    assert approval["decision"] == "approved"
    assert approval["decided_at"] is not None


def test_add_approver_rejected(engine):
    c = _make_change(engine)
    approval = _make_approval(engine, c["id"], decision="rejected", comments="Risk too high")
    assert approval["decision"] == "rejected"
    assert approval["comments"] == "Risk too high"
    assert approval["decided_at"] is not None


def test_add_approver_invalid_decision(engine):
    c = _make_change(engine)
    with pytest.raises(ValueError, match="decision"):
        engine.add_approver(ORG, c["id"], {"approver": "alice", "decision": "maybe"})


def test_list_approvals_all(engine):
    c1 = _make_change(engine, title="C1")
    c2 = _make_change(engine, title="C2")
    _make_approval(engine, c1["id"])
    _make_approval(engine, c2["id"])
    approvals = engine.list_approvals(ORG)
    assert len(approvals) == 2


def test_list_approvals_filtered_by_change(engine):
    c1 = _make_change(engine, title="C1")
    c2 = _make_change(engine, title="C2")
    _make_approval(engine, c1["id"], approver="alice")
    _make_approval(engine, c2["id"], approver="bob")
    result = engine.list_approvals(ORG, change_id=c1["id"])
    assert len(result) == 1
    assert result[0]["approver"] == "alice"


def test_list_approvals_org_isolation(engine):
    c1 = _make_change(engine, org=ORG)
    c2 = _make_change(engine, org=ORG2)
    engine.add_approver(ORG, c1["id"], {"approver": "alice", "decision": "approved"})
    engine.add_approver(ORG2, c2["id"], {"approver": "bob", "decision": "pending"})
    assert len(engine.list_approvals(ORG)) == 1
    assert len(engine.list_approvals(ORG2)) == 1


# ---------------------------------------------------------------------------
# get_change_stats
# ---------------------------------------------------------------------------

def test_stats_empty(engine):
    stats = engine.get_change_stats(ORG)
    assert stats["total_changes"] == 0
    assert stats["pending_review"] == 0
    assert stats["approved_changes"] == 0
    assert stats["completed_today"] == 0
    assert stats["emergency_changes"] == 0
    assert stats["by_type"] == {}
    assert stats["by_status"] == {}


def test_stats_total_and_emergency(engine):
    _make_change(engine, title="Normal", change_type="patch")
    _make_change(engine, title="Urgent", change_type="emergency")
    stats = engine.get_change_stats(ORG)
    assert stats["total_changes"] == 2
    assert stats["emergency_changes"] == 1


def test_stats_pending_review(engine):
    c1 = _make_change(engine, title="C1")
    c2 = _make_change(engine, title="C2")
    engine.update_change_status(ORG, c1["id"], "review")
    engine.update_change_status(ORG, c2["id"], "review")
    stats = engine.get_change_stats(ORG)
    assert stats["pending_review"] == 2


def test_stats_approved_changes(engine):
    c = _make_change(engine)
    engine.update_change_status(ORG, c["id"], "approved")
    stats = engine.get_change_stats(ORG)
    assert stats["approved_changes"] == 1


def test_stats_completed_today(engine):
    c = _make_change(engine)
    engine.update_change_status(ORG, c["id"], "completed")
    stats = engine.get_change_stats(ORG)
    assert stats["completed_today"] == 1


def test_stats_by_type(engine):
    _make_change(engine, title="P1", change_type="patch")
    _make_change(engine, title="P2", change_type="patch")
    _make_change(engine, title="C1", change_type="configuration")
    stats = engine.get_change_stats(ORG)
    assert stats["by_type"]["patch"] == 2
    assert stats["by_type"]["configuration"] == 1


def test_stats_by_status(engine):
    c1 = _make_change(engine, title="C1")
    c2 = _make_change(engine, title="C2")
    engine.update_change_status(ORG, c1["id"], "review")
    stats = engine.get_change_stats(ORG)
    assert stats["by_status"]["review"] == 1
    assert stats["by_status"]["draft"] == 1


def test_stats_org_isolation(engine):
    _make_change(engine, org=ORG)
    _make_change(engine, org=ORG)
    _make_change(engine, org=ORG2)
    stats1 = engine.get_change_stats(ORG)
    stats2 = engine.get_change_stats(ORG2)
    assert stats1["total_changes"] == 2
    assert stats2["total_changes"] == 1
