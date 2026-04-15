"""Tests for IdentityLifecycleEngine.

Covers: provision/deprovision lifecycle, suspend/reactivate, entitlement
grant/revoke, orphan detection (julianday), event audit trail, org isolation,
summary counts, validation errors.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone

from core.identity_lifecycle_engine import IdentityLifecycleEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return IdentityLifecycleEngine(db_path=str(tmp_path / "ilc_test.db"))


def _provision(engine, org_id="org1", username="alice", **kwargs):
    defaults = dict(
        display_name="Alice Smith",
        email="alice@example.com",
        account_type="employee",
        department="Engineering",
        manager="bob",
    )
    defaults.update(kwargs)
    return engine.provision_account(org_id=org_id, username=username, **defaults)


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = tmp_path / "il.db"
    IdentityLifecycleEngine(db_path=str(db))
    assert db.exists()


def test_init_twice_idempotent(tmp_path):
    db = str(tmp_path / "il.db")
    IdentityLifecycleEngine(db_path=db)
    IdentityLifecycleEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. provision_account
# ---------------------------------------------------------------------------


def test_provision_returns_active_account(engine):
    acc = _provision(engine)
    assert acc["status"] == "active"
    assert acc["username"] == "alice"
    assert acc["account_type"] == "employee"
    assert acc["provisioned_at"] is not None
    assert acc["deprovisioned_at"] is None


def test_provision_requires_username(engine):
    with pytest.raises(ValueError, match="username"):
        engine.provision_account("org1", "")


def test_provision_invalid_account_type(engine):
    with pytest.raises(ValueError, match="account_type"):
        _provision(engine, account_type="robot")


def test_provision_creates_provisioned_event(engine):
    acc = _provision(engine)
    events = acc["events"]
    assert len(events) == 1
    assert events[0]["event_type"] == "provisioned"


def test_provision_starts_with_no_entitlements(engine):
    acc = _provision(engine)
    assert acc["active_entitlements"] == []


def test_provision_service_account_type(engine):
    acc = _provision(engine, account_type="service", username="svc-deploy")
    assert acc["account_type"] == "service"
    assert acc["status"] == "active"


def test_provision_contractor_type(engine):
    acc = _provision(engine, account_type="contractor", username="contractor1")
    assert acc["status"] == "active"


# ---------------------------------------------------------------------------
# 3. deprovision_account
# ---------------------------------------------------------------------------


def test_deprovision_sets_status(engine):
    acc = _provision(engine)
    result = engine.deprovision_account(acc["id"], "org1", "admin")
    assert result["status"] == "deprovisioned"
    assert result["deprovisioned_at"] is not None


def test_deprovision_revokes_all_entitlements(engine):
    acc = _provision(engine)
    engine.grant_access(acc["id"], "org1", "GitLab", "developer", "write", "", "admin")
    engine.grant_access(acc["id"], "org1", "Jira", "member", "read", "", "admin")
    result = engine.deprovision_account(acc["id"], "org1", "admin")
    # After deprovision, active entitlements should be empty
    assert result["active_entitlements"] == []


def test_deprovision_creates_event(engine):
    acc = _provision(engine)
    result = engine.deprovision_account(acc["id"], "org1", "admin")
    event_types = [e["event_type"] for e in result["events"]]
    assert "deprovisioned" in event_types


def test_deprovision_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.deprovision_account("nonexistent", "org1", "admin")


def test_deprovision_wrong_org_raises(engine):
    acc = _provision(engine, org_id="org1")
    with pytest.raises(ValueError, match="not found"):
        engine.deprovision_account(acc["id"], "org2", "admin")


# ---------------------------------------------------------------------------
# 4. suspend / reactivate
# ---------------------------------------------------------------------------


def test_suspend_sets_status(engine):
    acc = _provision(engine)
    result = engine.suspend_account(acc["id"], "org1", "security-team")
    assert result["status"] == "suspended"


def test_suspend_creates_event(engine):
    acc = _provision(engine)
    result = engine.suspend_account(acc["id"], "org1", "security-team")
    event_types = [e["event_type"] for e in result["events"]]
    assert "suspended" in event_types


def test_reactivate_after_suspend(engine):
    acc = _provision(engine)
    engine.suspend_account(acc["id"], "org1", "security")
    result = engine.reactivate_account(acc["id"], "org1", "hr")
    assert result["status"] == "active"


def test_reactivate_creates_event(engine):
    acc = _provision(engine)
    engine.suspend_account(acc["id"], "org1", "security")
    result = engine.reactivate_account(acc["id"], "org1", "hr")
    event_types = [e["event_type"] for e in result["events"]]
    assert "reactivated" in event_types


def test_suspend_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.suspend_account("bad-id", "org1", "admin")


def test_reactivate_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.reactivate_account("bad-id", "org1", "admin")


# ---------------------------------------------------------------------------
# 5. grant_access / revoke_access
# ---------------------------------------------------------------------------


def test_grant_access_creates_entitlement(engine):
    acc = _provision(engine)
    ent = engine.grant_access(acc["id"], "org1", "AWS", "developer", "write", "", "manager")
    assert ent["status"] == "active"
    assert ent["system_name"] == "AWS"
    assert ent["role"] == "developer"
    assert ent["access_level"] == "write"


def test_grant_access_invalid_level(engine):
    acc = _provision(engine)
    with pytest.raises(ValueError, match="access_level"):
        engine.grant_access(acc["id"], "org1", "AWS", "dev", "superuser", "", "mgr")


def test_grant_access_wrong_org_raises(engine):
    acc = _provision(engine, org_id="org1")
    with pytest.raises(ValueError, match="not found"):
        engine.grant_access(acc["id"], "org2", "AWS", "dev", "read", "", "mgr")


def test_grant_access_creates_event(engine):
    acc = _provision(engine)
    engine.grant_access(acc["id"], "org1", "Kubernetes", "viewer", "read", "", "ops")
    full = engine.get_account(acc["id"], "org1")
    event_types = [e["event_type"] for e in full["events"]]
    assert "access_granted" in event_types


def test_revoke_access_sets_revoked(engine):
    acc = _provision(engine)
    ent = engine.grant_access(acc["id"], "org1", "Vault", "reader", "read", "", "admin")
    result = engine.revoke_access(ent["id"], "org1", "admin")
    assert result["status"] == "revoked"


def test_revoke_access_removes_from_active_entitlements(engine):
    acc = _provision(engine)
    ent = engine.grant_access(acc["id"], "org1", "Vault", "reader", "read", "", "admin")
    engine.revoke_access(ent["id"], "org1", "admin")
    full = engine.get_account(acc["id"], "org1")
    assert not any(e["id"] == ent["id"] for e in full["active_entitlements"])


def test_revoke_access_creates_event(engine):
    acc = _provision(engine)
    ent = engine.grant_access(acc["id"], "org1", "Vault", "reader", "read", "", "admin")
    engine.revoke_access(ent["id"], "org1", "admin")
    full = engine.get_account(acc["id"], "org1")
    event_types = [e["event_type"] for e in full["events"]]
    assert "access_revoked" in event_types


def test_revoke_access_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.revoke_access("bad-ent-id", "org1", "admin")


def test_revoke_access_wrong_org_raises(engine):
    acc = _provision(engine, org_id="org1")
    ent = engine.grant_access(acc["id"], "org1", "Vault", "reader", "read", "", "admin")
    with pytest.raises(ValueError, match="not found"):
        engine.revoke_access(ent["id"], "org2", "admin")


# ---------------------------------------------------------------------------
# 6. update_last_active
# ---------------------------------------------------------------------------


def test_update_last_active(engine):
    acc = _provision(engine)
    assert acc["last_active"] is None
    engine.update_last_active(acc["id"], "org1")
    updated = engine.get_account(acc["id"], "org1")
    assert updated["last_active"] is not None


# ---------------------------------------------------------------------------
# 7. list_accounts
# ---------------------------------------------------------------------------


def test_list_accounts_all(engine):
    _provision(engine, username="u1")
    _provision(engine, username="u2")
    accounts = engine.list_accounts("org1")
    assert len(accounts) == 2


def test_list_accounts_filter_status(engine):
    acc = _provision(engine, username="u1")
    _provision(engine, username="u2")
    engine.suspend_account(acc["id"], "org1", "admin")
    suspended = engine.list_accounts("org1", status="suspended")
    assert len(suspended) == 1
    assert suspended[0]["id"] == acc["id"]


def test_list_accounts_filter_department(engine):
    _provision(engine, username="u1", department="Engineering")
    _provision(engine, username="u2", department="Finance")
    eng = engine.list_accounts("org1", department="Engineering")
    assert len(eng) == 1
    assert eng[0]["username"] == "u1"


def test_list_accounts_org_isolation(engine):
    _provision(engine, org_id="org1", username="u1")
    _provision(engine, org_id="org2", username="u2")
    assert len(engine.list_accounts("org1")) == 1
    assert len(engine.list_accounts("org2")) == 1


# ---------------------------------------------------------------------------
# 8. orphan detection
# ---------------------------------------------------------------------------


def test_orphan_accounts_null_last_active(engine):
    """Accounts with NULL last_active and status=active are orphans."""
    _provision(engine, username="ghost")
    orphans = engine.get_orphan_accounts("org1", days_inactive=90)
    assert len(orphans) == 1
    assert orphans[0]["username"] == "ghost"


def test_orphan_accounts_old_last_active(engine, tmp_path):
    """Accounts last active 100 days ago should be orphans."""
    db_path = str(tmp_path / "orphan_test.db")
    eng = IdentityLifecycleEngine(db_path=db_path)
    acc = eng.provision_account("org1", "olduser", account_type="employee")
    # Manually set last_active to 100 days ago
    old_ts = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE identity_accounts SET last_active=? WHERE id=?", (old_ts, acc["id"]))
    conn.commit()
    conn.close()
    orphans = eng.get_orphan_accounts("org1", days_inactive=90)
    assert len(orphans) == 1


def test_orphan_accounts_recent_last_active_excluded(engine, tmp_path):
    """Accounts active recently should NOT be orphans."""
    db_path = str(tmp_path / "recent_test.db")
    eng = IdentityLifecycleEngine(db_path=db_path)
    acc = eng.provision_account("org1", "activeuser", account_type="employee")
    recent_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE identity_accounts SET last_active=? WHERE id=?", (recent_ts, acc["id"]))
    conn.commit()
    conn.close()
    orphans = eng.get_orphan_accounts("org1", days_inactive=90)
    assert len(orphans) == 0


def test_orphan_excludes_service_accounts(engine):
    """Service accounts are excluded from orphan detection."""
    _provision(engine, username="svc-api", account_type="service")
    orphans = engine.get_orphan_accounts("org1", days_inactive=90)
    assert len(orphans) == 0


def test_orphan_excludes_deprovisioned(engine):
    """Deprovisioned accounts are not orphans (wrong status)."""
    acc = _provision(engine, username="olduser")
    engine.deprovision_account(acc["id"], "org1", "admin")
    orphans = engine.get_orphan_accounts("org1", days_inactive=0)
    assert all(o["id"] != acc["id"] for o in orphans)


# ---------------------------------------------------------------------------
# 9. get_entitlement_summary
# ---------------------------------------------------------------------------


def test_summary_empty_org(engine):
    summary = engine.get_entitlement_summary("org1")
    assert summary["total_accounts"] == 0
    assert summary["active_accounts"] == 0
    assert summary["orphan_count"] == 0
    assert summary["deprovisioned_count"] == 0
    assert summary["total_entitlements"] == 0


def test_summary_counts_accounts(engine):
    _provision(engine, username="u1")
    _provision(engine, username="u2")
    acc3 = _provision(engine, username="u3")
    engine.deprovision_account(acc3["id"], "org1", "admin")
    summary = engine.get_entitlement_summary("org1")
    assert summary["total_accounts"] == 3
    assert summary["active_accounts"] == 2
    assert summary["deprovisioned_count"] == 1


def test_summary_counts_entitlements(engine):
    acc = _provision(engine)
    engine.grant_access(acc["id"], "org1", "GitLab", "dev", "write", "", "mgr")
    engine.grant_access(acc["id"], "org1", "Jira", "member", "read", "", "mgr")
    summary = engine.get_entitlement_summary("org1")
    assert summary["total_entitlements"] == 2


def test_summary_by_account_type(engine):
    _provision(engine, username="emp1", account_type="employee")
    _provision(engine, username="emp2", account_type="employee")
    _provision(engine, username="svc1", account_type="service")
    summary = engine.get_entitlement_summary("org1")
    assert summary["by_account_type"]["employee"] == 2
    assert summary["by_account_type"]["service"] == 1


def test_summary_by_department(engine):
    _provision(engine, username="u1", department="Engineering")
    _provision(engine, username="u2", department="Engineering")
    _provision(engine, username="u3", department="Finance")
    summary = engine.get_entitlement_summary("org1")
    assert summary["by_department"]["Engineering"] == 2
    assert summary["by_department"]["Finance"] == 1


def test_summary_orphan_count(engine):
    _provision(engine, username="ghost")  # NULL last_active → orphan
    summary = engine.get_entitlement_summary("org1")
    assert summary["orphan_count"] == 1


# ---------------------------------------------------------------------------
# 10. get_account
# ---------------------------------------------------------------------------


def test_get_account_not_found(engine):
    assert engine.get_account("nonexistent", "org1") is None


def test_get_account_wrong_org(engine):
    acc = _provision(engine, org_id="org1")
    assert engine.get_account(acc["id"], "org2") is None


def test_get_account_includes_events(engine):
    acc = _provision(engine)
    engine.suspend_account(acc["id"], "org1", "admin")
    full = engine.get_account(acc["id"], "org1")
    event_types = [e["event_type"] for e in full["events"]]
    assert "provisioned" in event_types
    assert "suspended" in event_types


def test_get_account_multiple_entitlements(engine):
    acc = _provision(engine)
    engine.grant_access(acc["id"], "org1", "SysA", "roleA", "read", "", "mgr")
    engine.grant_access(acc["id"], "org1", "SysB", "roleB", "admin", "", "mgr")
    full = engine.get_account(acc["id"], "org1")
    assert len(full["active_entitlements"]) == 2
