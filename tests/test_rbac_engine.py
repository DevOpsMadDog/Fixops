"""Tests for suite-core/core/rbac_engine.py — Multi-tenant RBAC engine."""
import sys
import os
import tempfile
import pytest

sys.path.insert(0, "suite-core")

from core.rbac_engine import ROLES, RBACEngine


# ---------------------------------------------------------------------------
# Fixture: fresh engine per test (isolated temp DB)
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    """Return a fresh RBACEngine backed by a temp SQLite file."""
    db = tmp_path / "rbac_test.db"
    return RBACEngine(db_path=str(db))


# ---------------------------------------------------------------------------
# assign_role
# ---------------------------------------------------------------------------


def test_assign_role_returns_dict(engine):
    result = engine.assign_role("user1", "viewer", "org1")
    assert isinstance(result, dict)
    assert result["user_id"] == "user1"
    assert result["role"] == "viewer"
    assert result["org_id"] == "org1"
    assert "id" in result
    assert "assigned_at" in result


def test_assign_role_sets_assigned_by(engine):
    result = engine.assign_role("user1", "analyst", "org1", assigned_by="admin_user")
    assert result["assigned_by"] == "admin_user"


def test_assign_role_invalid_role_raises(engine):
    with pytest.raises(ValueError, match="Unknown role"):
        engine.assign_role("user1", "nonexistent_role", "org1")


def test_assign_role_multiple_roles_same_user(engine):
    engine.assign_role("user1", "viewer", "org1")
    engine.assign_role("user1", "analyst", "org1")
    roles = engine.get_user_roles("user1", "org1")
    assert "viewer" in roles
    assert "analyst" in roles


def test_assign_role_idempotent(engine):
    """Assigning the same role twice should not raise — just replace."""
    engine.assign_role("user1", "viewer", "org1")
    result = engine.assign_role("user1", "viewer", "org1")
    assert result["role"] == "viewer"
    roles = engine.get_user_roles("user1", "org1")
    assert roles.count("viewer") == 1


# ---------------------------------------------------------------------------
# get_user_roles
# ---------------------------------------------------------------------------


def test_get_user_roles_returns_assigned(engine):
    engine.assign_role("user2", "analyst", "org1")
    roles = engine.get_user_roles("user2", "org1")
    assert "analyst" in roles


def test_get_user_roles_different_org_isolation(engine):
    """User roles in org1 must NOT appear when querying org2."""
    engine.assign_role("user3", "security_engineer", "org1")
    roles = engine.get_user_roles("user3", "org2")
    assert roles == []


def test_get_user_roles_unknown_user_empty(engine):
    roles = engine.get_user_roles("nobody", "org1")
    assert roles == []


# ---------------------------------------------------------------------------
# revoke_role
# ---------------------------------------------------------------------------


def test_revoke_role_known_returns_true(engine):
    engine.assign_role("user4", "viewer", "org1")
    assert engine.revoke_role("user4", "viewer", "org1") is True


def test_revoke_role_unknown_returns_false(engine):
    assert engine.revoke_role("nobody", "viewer", "org1") is False


def test_revoke_role_removes_role(engine):
    engine.assign_role("user5", "viewer", "org1")
    engine.revoke_role("user5", "viewer", "org1")
    assert engine.get_user_roles("user5", "org1") == []


# ---------------------------------------------------------------------------
# get_user_scopes / get_effective_scopes
# ---------------------------------------------------------------------------


def test_get_user_scopes_analyst_has_read_findings(engine):
    engine.assign_role("user6", "analyst", "org1")
    scopes = engine.get_user_scopes("user6", "org1")
    assert "read:findings" in scopes


def test_get_user_scopes_org_admin_inherits_write_findings(engine):
    """org_admin inherits security_engineer which has write:findings."""
    engine.assign_role("user7", "org_admin", "org1")
    scopes = engine.get_user_scopes("user7", "org1")
    assert "write:findings" in scopes


def test_get_effective_scopes_org_admin_includes_viewer_scopes(engine):
    """org_admin chain: org_admin → security_engineer → analyst → viewer."""
    scopes = engine.get_effective_scopes(["org_admin"])
    # viewer scopes must be present
    assert "read:findings" in scopes
    assert "read:feeds" in scopes
    # security_engineer scope
    assert "write:findings" in scopes
    # org_admin own scope
    assert "admin:org" in scopes


def test_get_effective_scopes_empty_roles(engine):
    scopes = engine.get_effective_scopes([])
    assert scopes == []


# ---------------------------------------------------------------------------
# check_permission
# ---------------------------------------------------------------------------


def test_check_permission_analyst_read_findings_true(engine):
    engine.assign_role("user8", "analyst", "org1")
    assert engine.check_permission("user8", "org1", "read:findings") is True


def test_check_permission_viewer_write_findings_false(engine):
    engine.assign_role("user9", "viewer", "org1")
    assert engine.check_permission("user9", "org1", "write:findings") is False


def test_check_permission_super_admin_anything_true(engine):
    """super_admin has admin:all which satisfies any scope."""
    engine.assign_role("user10", "super_admin", "org1")
    assert engine.check_permission("user10", "org1", "write:findings") is True
    assert engine.check_permission("user10", "org1", "attack:execute") is True
    assert engine.check_permission("user10", "org1", "read:evidence") is True


def test_check_permission_no_role_false(engine):
    assert engine.check_permission("nobody", "org1", "read:findings") is False


def test_check_permission_auditor_read_audit_true(engine):
    engine.assign_role("user11", "auditor", "org1")
    assert engine.check_permission("user11", "org1", "read:audit") is True


def test_check_permission_auditor_write_findings_false(engine):
    engine.assign_role("user12", "auditor", "org1")
    assert engine.check_permission("user12", "org1", "write:findings") is False


# ---------------------------------------------------------------------------
# check_tenant_access
# ---------------------------------------------------------------------------


def test_check_tenant_access_same_org_always_allowed(engine):
    engine.assign_role("user13", "viewer", "org1")
    assert engine.check_tenant_access("user13", "org1", "org1") is True


def test_check_tenant_access_cross_org_regular_user_denied(engine):
    engine.assign_role("user14", "analyst", "org1")
    assert engine.check_tenant_access("user14", "org1", "org2") is False


def test_check_tenant_access_super_admin_cross_org_allowed(engine):
    engine.assign_role("user15", "super_admin", "org1")
    assert engine.check_tenant_access("user15", "org1", "org2") is True


def test_check_tenant_access_org_admin_cross_org_denied(engine):
    """org_admin has admin:org not admin:all — cannot cross tenants."""
    engine.assign_role("user16", "org_admin", "org1")
    assert engine.check_tenant_access("user16", "org1", "org2") is False


# ---------------------------------------------------------------------------
# get_role_hierarchy
# ---------------------------------------------------------------------------


def test_get_role_hierarchy_security_engineer(engine):
    hierarchy = engine.get_role_hierarchy("security_engineer")
    assert "security_engineer" in hierarchy
    assert "analyst" in hierarchy
    assert "viewer" in hierarchy


def test_get_role_hierarchy_viewer_is_leaf(engine):
    hierarchy = engine.get_role_hierarchy("viewer")
    assert hierarchy == ["viewer"]


def test_get_role_hierarchy_org_admin(engine):
    hierarchy = engine.get_role_hierarchy("org_admin")
    assert "org_admin" in hierarchy
    assert "security_engineer" in hierarchy
    assert "analyst" in hierarchy
    assert "viewer" in hierarchy


# ---------------------------------------------------------------------------
# list_users_in_org
# ---------------------------------------------------------------------------


def test_list_users_in_org_returns_assigned(engine):
    engine.assign_role("userA", "viewer", "org99")
    engine.assign_role("userB", "analyst", "org99")
    users = engine.list_users_in_org("org99")
    user_ids = [u["user_id"] for u in users]
    assert "userA" in user_ids
    assert "userB" in user_ids


def test_list_users_in_org_no_cross_tenant_leak(engine):
    engine.assign_role("userA", "viewer", "org1")
    users = engine.list_users_in_org("org2")
    user_ids = [u["user_id"] for u in users]
    assert "userA" not in user_ids


def test_list_users_in_org_empty(engine):
    assert engine.list_users_in_org("org_empty") == []


# ---------------------------------------------------------------------------
# audit_log
# ---------------------------------------------------------------------------


def test_audit_log_called_after_check_permission(engine):
    engine.assign_role("userZ", "viewer", "org1")
    engine.check_permission("userZ", "org1", "read:findings")
    log = engine.get_audit_log(user_id="userZ", org_id="org1")
    assert len(log) >= 1
    assert log[0]["user_id"] == "userZ"


def test_get_audit_log_returns_list(engine):
    log = engine.get_audit_log()
    assert isinstance(log, list)


def test_get_audit_log_filter_by_user(engine):
    engine.assign_role("userX", "viewer", "org1")
    engine.assign_role("userY", "viewer", "org1")
    engine.check_permission("userX", "org1", "read:findings")
    engine.check_permission("userY", "org1", "read:feeds")
    log = engine.get_audit_log(user_id="userX")
    for entry in log:
        assert entry["user_id"] == "userX"


def test_get_audit_log_filter_by_org(engine):
    engine.assign_role("userX", "viewer", "org_a")
    engine.assign_role("userX", "viewer", "org_b")
    engine.check_permission("userX", "org_a", "read:findings")
    engine.check_permission("userX", "org_b", "read:feeds")
    log = engine.get_audit_log(org_id="org_a")
    for entry in log:
        assert entry["org_id"] == "org_a"


def test_audit_log_direct_write(engine):
    engine.audit_log("u1", "manual_action", "some:resource", "org1", allowed=True)
    log = engine.get_audit_log(user_id="u1")
    assert len(log) >= 1
    entry = log[0]
    assert entry["action"] == "manual_action"
    assert entry["allowed"] == 1  # stored as integer


# ---------------------------------------------------------------------------
# ROLES constant
# ---------------------------------------------------------------------------


def test_roles_constant_has_six_roles():
    assert len(ROLES) == 6
    expected = {"super_admin", "org_admin", "security_engineer", "analyst", "viewer", "auditor"}
    assert set(ROLES.keys()) == expected


def test_roles_constant_structure():
    for name, defn in ROLES.items():
        assert "inherits" in defn, f"{name} missing 'inherits'"
        assert "scopes" in defn, f"{name} missing 'scopes'"
        assert isinstance(defn["scopes"], list)
