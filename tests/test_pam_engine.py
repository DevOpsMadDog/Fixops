"""Tests for PAMEngine — Privileged Access Management engine.

25 tests covering: init, account CRUD, session lifecycle,
approve/deny/end, policies, stats, org isolation.
"""

from __future__ import annotations

import tempfile
import os
import pytest
from core.pam_engine import PAMEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "pam_test.db")
    return PAMEngine(db_path=db)


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "pam_init.db")
    eng = PAMEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "pam_idem.db")
    PAMEngine(db_path=db)
    PAMEngine(db_path=db)  # second init should not raise


# ---------------------------------------------------------------------------
# 2. Account CRUD
# ---------------------------------------------------------------------------

def test_register_account_returns_dict(engine):
    acct = engine.register_account("org1", {
        "username": "svc-deploy",
        "account_type": "service",
        "system": "k8s-prod",
        "department": "DevOps",
        "owner": "alice",
        "is_vaulted": True,
        "rotation_days": 30,
        "risk_score": 40,
    })
    assert acct["account_id"]
    assert acct["username"] == "svc-deploy"
    assert acct["account_type"] == "service"
    assert acct["is_vaulted"] is True
    assert acct["risk_score"] == 40


def test_register_account_defaults(engine):
    acct = engine.register_account("org1", {"username": "admin-user"})
    assert acct["account_type"] == "admin"
    assert acct["status"] == "active"
    assert acct["is_vaulted"] is False
    assert acct["rotation_days"] == 90


def test_register_account_invalid_type_defaults_to_admin(engine):
    acct = engine.register_account("org1", {"username": "x", "account_type": "bogus"})
    assert acct["account_type"] == "admin"


def test_register_all_account_types(engine):
    for t in ("service", "admin", "root", "sa", "shared", "emergency"):
        a = engine.register_account("org1", {"username": f"u-{t}", "account_type": t})
        assert a["account_type"] == t


def test_list_accounts_empty(engine):
    assert engine.list_accounts("org-none") == []


def test_list_accounts_returns_registered(engine):
    engine.register_account("org2", {"username": "adm1"})
    engine.register_account("org2", {"username": "adm2"})
    accts = engine.list_accounts("org2")
    assert len(accts) == 2


def test_list_accounts_filter_by_type(engine):
    engine.register_account("org3", {"username": "svc", "account_type": "service"})
    engine.register_account("org3", {"username": "adm", "account_type": "admin"})
    svc_only = engine.list_accounts("org3", account_type="service")
    assert len(svc_only) == 1
    assert svc_only[0]["account_type"] == "service"


def test_list_accounts_filter_by_status(engine):
    engine.register_account("org4", {"username": "a1", "status": "active"})
    engine.register_account("org4", {"username": "a2", "status": "disabled"})
    active = engine.list_accounts("org4", status="active")
    assert len(active) == 1
    assert active[0]["status"] == "active"


# ---------------------------------------------------------------------------
# 3. Session lifecycle
# ---------------------------------------------------------------------------

def test_create_session_returns_dict(engine):
    sess = engine.create_session("org1", {
        "account_id": "acct-abc",
        "requester": "bob",
        "justification": "emergency patch",
        "session_type": "interactive",
        "target_system": "prod-db",
        "requested_duration_minutes": 30,
    })
    assert sess["session_id"]
    assert sess["approval_status"] == "pending"
    assert sess["account_id"] == "acct-abc"
    assert sess["requester"] == "bob"
    assert sess["recording_enabled"] is True
    assert sess["ended_at"] is None


def test_create_session_defaults(engine):
    sess = engine.create_session("org1", {"account_id": "x"})
    assert sess["session_type"] == "interactive"
    assert sess["requested_duration_minutes"] == 60
    assert sess["approval_status"] == "pending"


def test_list_sessions_empty(engine):
    assert engine.list_sessions("org-empty") == []


def test_list_sessions_returns_created(engine):
    engine.create_session("org5", {"account_id": "a"})
    engine.create_session("org5", {"account_id": "b"})
    sessions = engine.list_sessions("org5")
    assert len(sessions) == 2


def test_list_sessions_filter_by_status(engine):
    engine.create_session("org6", {"account_id": "a"})
    sess = engine.create_session("org6", {"account_id": "b"})
    engine.approve_session("org6", sess["session_id"], "mgr", True)
    pending = engine.list_sessions("org6", approval_status="pending")
    approved = engine.list_sessions("org6", approval_status="approved")
    assert len(pending) == 1
    assert len(approved) == 1


# ---------------------------------------------------------------------------
# 4. Approve / Deny / End
# ---------------------------------------------------------------------------

def test_approve_session(engine):
    sess = engine.create_session("org1", {"account_id": "a"})
    result = engine.approve_session("org1", sess["session_id"], "alice", True)
    assert result is True
    sessions = engine.list_sessions("org1", approval_status="approved")
    assert any(s["session_id"] == sess["session_id"] for s in sessions)


def test_deny_session(engine):
    sess = engine.create_session("org1", {"account_id": "a"})
    result = engine.approve_session("org1", sess["session_id"], "alice", False)
    assert result is True
    denied = engine.list_sessions("org1", approval_status="denied")
    assert any(s["session_id"] == sess["session_id"] for s in denied)


def test_approve_nonexistent_session_returns_false(engine):
    result = engine.approve_session("org1", "no-such-id", "alice", True)
    assert result is False


def test_end_session(engine):
    sess = engine.create_session("org7", {"account_id": "a"})
    engine.approve_session("org7", sess["session_id"], "mgr", True)
    ended = engine.end_session("org7", sess["session_id"])
    assert ended is True


def test_end_session_sets_ended_at(engine):
    sess = engine.create_session("org7", {"account_id": "a"})
    engine.end_session("org7", sess["session_id"])
    sessions = engine.list_sessions("org7")
    s = next(s for s in sessions if s["session_id"] == sess["session_id"])
    assert s["ended_at"] is not None


def test_end_nonexistent_session_returns_false(engine):
    result = engine.end_session("org1", "ghost-id")
    assert result is False


# ---------------------------------------------------------------------------
# 5. Policies
# ---------------------------------------------------------------------------

def test_create_policy(engine):
    pol = engine.create_policy("org1", {
        "name": "High Risk Policy",
        "require_approval": True,
        "max_session_minutes": 120,
        "allowed_hours": ["09:00-17:00"],
        "mfa_required": True,
        "recording_required": True,
    })
    assert pol["policy_id"]
    assert pol["name"] == "High Risk Policy"
    assert pol["require_approval"] is True
    assert pol["max_session_minutes"] == 120
    assert pol["allowed_hours"] == ["09:00-17:00"]


def test_list_policies(engine):
    engine.create_policy("org8", {"name": "P1"})
    engine.create_policy("org8", {"name": "P2"})
    pols = engine.list_policies("org8")
    assert len(pols) == 2


def test_list_policies_empty(engine):
    assert engine.list_policies("org-no-pol") == []


# ---------------------------------------------------------------------------
# 6. Stats
# ---------------------------------------------------------------------------

def test_get_pam_stats_empty(engine):
    stats = engine.get_pam_stats("org-empty-stats")
    assert stats["total_accounts"] == 0
    assert stats["vaulted"] == 0
    assert stats["active_sessions"] == 0
    assert stats["pending_approvals"] == 0
    assert stats["accounts_expired"] == 0
    assert stats["avg_risk_score"] == 0.0


def test_get_pam_stats_populated(engine):
    engine.register_account("org9", {"username": "a1", "is_vaulted": True, "risk_score": 80})
    engine.register_account("org9", {"username": "a2", "risk_score": 20, "status": "expired"})
    engine.create_session("org9", {"account_id": "x"})
    sess2 = engine.create_session("org9", {"account_id": "y"})
    engine.approve_session("org9", sess2["session_id"], "mgr", True)

    stats = engine.get_pam_stats("org9")
    assert stats["total_accounts"] == 2
    assert stats["vaulted"] == 1
    assert stats["accounts_expired"] == 1
    assert stats["pending_approvals"] == 1
    assert stats["active_sessions"] == 1
    assert stats["avg_risk_score"] == 50.0


# ---------------------------------------------------------------------------
# 7. Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_accounts(engine):
    engine.register_account("org-a", {"username": "user-a"})
    engine.register_account("org-b", {"username": "user-b"})
    assert len(engine.list_accounts("org-a")) == 1
    assert len(engine.list_accounts("org-b")) == 1


def test_org_isolation_sessions(engine):
    engine.create_session("org-x", {"account_id": "1"})
    engine.create_session("org-y", {"account_id": "2"})
    assert len(engine.list_sessions("org-x")) == 1
    assert len(engine.list_sessions("org-y")) == 1
