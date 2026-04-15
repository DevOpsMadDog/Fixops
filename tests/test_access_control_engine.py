"""Tests for AccessControlEngine — Access Control.

Covers: init, policy CRUD, grant lifecycle, check_access, stats, org isolation.
"""

from __future__ import annotations

import pytest

from core.access_control_engine import (
    AccessControlEngine,
    AccessPolicyCreate,
    GrantCreate,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return AccessControlEngine(db_path=str(tmp_path / "test_ac.db"))


def _policy(name="ReadFiles", resource_type="file", action="read", effect="allow", **kw) -> AccessPolicyCreate:
    return AccessPolicyCreate(
        name=name,
        resource_type=resource_type,
        action=action,
        effect=effect,
        **kw,
    )


def _create_policy(engine, org_id="org1", **kw) -> dict:
    return engine.create_access_policy(org_id, _policy(**kw))


def _create_grant(engine, org_id, policy_id, subject_id="user-1", resource_id="res-1", **kw) -> dict:
    return engine.grant_access(
        org_id,
        GrantCreate(
            subject_id=subject_id,
            resource_id=resource_id,
            policy_id=policy_id,
            granted_by="admin",
            **kw,
        ),
    )


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = tmp_path / "ac.db"
    AccessControlEngine(db_path=str(db))
    assert db.exists()


def test_init_twice_idempotent(tmp_path):
    db = str(tmp_path / "ac.db")
    AccessControlEngine(db_path=db)
    AccessControlEngine(db_path=db)  # should not raise


# ---------------------------------------------------------------------------
# 2. Policy creation
# ---------------------------------------------------------------------------


def test_create_policy_returns_record(engine):
    p = _create_policy(engine)
    assert p["name"] == "ReadFiles"
    assert p["resource_type"] == "file"
    assert p["action"] == "read"
    assert p["effect"] == "allow"
    assert p["status"] == "active"
    assert "id" in p


def test_create_policy_generates_uuid(engine):
    p1 = _create_policy(engine, name="P1")
    p2 = _create_policy(engine, name="P2")
    assert p1["id"] != p2["id"]


def test_create_policy_all_resource_types(engine):
    for rt in ("file", "api", "database", "network", "application", "service"):
        p = _create_policy(engine, name=rt, resource_type=rt)
        assert p["resource_type"] == rt


def test_create_policy_all_actions(engine):
    for action in ("read", "write", "execute", "delete", "admin"):
        p = _create_policy(engine, name=action, action=action)
        assert p["action"] == action


def test_create_policy_deny_effect(engine):
    p = _create_policy(engine, effect="deny")
    assert p["effect"] == "deny"


def test_create_policy_invalid_resource_type_raises(engine):
    with pytest.raises(ValueError, match="resource_type"):
        _create_policy(engine, resource_type="spreadsheet")


def test_create_policy_invalid_action_raises(engine):
    with pytest.raises(ValueError, match="action"):
        _create_policy(engine, action="fly")


def test_create_policy_invalid_effect_raises(engine):
    with pytest.raises(ValueError, match="effect"):
        _create_policy(engine, effect="maybe")


def test_create_policy_with_conditions(engine):
    p = engine.create_access_policy(
        "org1",
        AccessPolicyCreate(
            name="CondPolicy",
            resource_type="api",
            action="read",
            conditions={"ip_range": "10.0.0.0/8"},
        ),
    )
    assert isinstance(p["conditions"], dict)
    assert p["conditions"]["ip_range"] == "10.0.0.0/8"


# ---------------------------------------------------------------------------
# 3. List and get policies
# ---------------------------------------------------------------------------


def test_list_policies_empty(engine):
    assert engine.list_access_policies("org1") == []


def test_list_policies_returns_all(engine):
    _create_policy(engine, name="P1")
    _create_policy(engine, name="P2")
    assert len(engine.list_access_policies("org1")) == 2


def test_list_policies_filter_by_resource_type(engine):
    _create_policy(engine, name="F", resource_type="file")
    _create_policy(engine, name="A", resource_type="api")
    result = engine.list_access_policies("org1", resource_type="api")
    assert len(result) == 1
    assert result[0]["name"] == "A"


def test_list_policies_filter_by_effect(engine):
    _create_policy(engine, name="Allow", effect="allow")
    _create_policy(engine, name="Deny", effect="deny")
    result = engine.list_access_policies("org1", effect="deny")
    assert len(result) == 1
    assert result[0]["name"] == "Deny"


def test_get_policy_returns_record(engine):
    p = _create_policy(engine)
    fetched = engine.get_access_policy("org1", p["id"])
    assert fetched["id"] == p["id"]


def test_get_policy_wrong_org_raises(engine):
    p = _create_policy(engine, org_id="org1")
    with pytest.raises(ValueError):
        engine.get_access_policy("org2", p["id"])


def test_get_policy_not_found_raises(engine):
    with pytest.raises(ValueError):
        engine.get_access_policy("org1", "nonexistent-id")


# ---------------------------------------------------------------------------
# 4. Grant management
# ---------------------------------------------------------------------------


def test_grant_access_returns_record(engine):
    p = _create_policy(engine)
    g = _create_grant(engine, "org1", p["id"])
    assert g["subject_id"] == "user-1"
    assert g["resource_id"] == "res-1"
    assert g["policy_id"] == p["id"]
    assert g["status"] == "active"
    assert "id" in g
    assert "granted_at" in g


def test_grant_access_wrong_policy_org_raises(engine):
    p = _create_policy(engine, org_id="org1")
    with pytest.raises(ValueError):
        _create_grant(engine, "org2", p["id"])


def test_grant_access_with_expiry(engine):
    p = _create_policy(engine)
    g = _create_grant(engine, "org1", p["id"], expires_at="2099-12-31T00:00:00+00:00")
    assert g["expires_at"] == "2099-12-31T00:00:00+00:00"


def test_list_grants_empty(engine):
    assert engine.list_grants("org1") == []


def test_list_grants_filter_by_subject(engine):
    p = _create_policy(engine)
    _create_grant(engine, "org1", p["id"], subject_id="alice", resource_id="r1")
    _create_grant(engine, "org1", p["id"], subject_id="bob", resource_id="r2")
    result = engine.list_grants("org1", subject_id="alice")
    assert len(result) == 1
    assert result[0]["subject_id"] == "alice"


def test_list_grants_filter_by_resource(engine):
    p = _create_policy(engine)
    _create_grant(engine, "org1", p["id"], subject_id="alice", resource_id="r1")
    _create_grant(engine, "org1", p["id"], subject_id="bob", resource_id="r2")
    result = engine.list_grants("org1", resource_id="r2")
    assert len(result) == 1
    assert result[0]["subject_id"] == "bob"


def test_revoke_access(engine):
    p = _create_policy(engine)
    g = _create_grant(engine, "org1", p["id"])
    revoked = engine.revoke_access("org1", g["id"], revoked_by="admin", reason="No longer needed")
    assert revoked["status"] == "revoked"
    assert revoked["revoked_by"] == "admin"
    assert revoked["revoke_reason"] == "No longer needed"
    assert revoked["revoked_at"] is not None


def test_revoke_access_wrong_org_raises(engine):
    p = _create_policy(engine, org_id="org1")
    g = _create_grant(engine, "org1", p["id"])
    with pytest.raises(ValueError):
        engine.revoke_access("org2", g["id"], revoked_by="admin")


# ---------------------------------------------------------------------------
# 5. Check access
# ---------------------------------------------------------------------------


def test_check_access_returns_active_grants(engine):
    p = _create_policy(engine)
    _create_grant(engine, "org1", p["id"], subject_id="alice", resource_id="docs")
    result = engine.check_access("org1", "alice", "docs")
    assert len(result) == 1
    assert result[0]["subject_id"] == "alice"
    assert result[0]["resource_id"] == "docs"
    assert "policy_name" in result[0]
    assert "effect" in result[0]


def test_check_access_excludes_revoked(engine):
    p = _create_policy(engine)
    g = _create_grant(engine, "org1", p["id"], subject_id="alice", resource_id="docs")
    engine.revoke_access("org1", g["id"], revoked_by="admin")
    result = engine.check_access("org1", "alice", "docs")
    assert result == []


def test_check_access_excludes_expired(engine):
    p = _create_policy(engine)
    _create_grant(
        engine, "org1", p["id"],
        subject_id="alice", resource_id="docs",
        expires_at="2000-01-01T00:00:00+00:00",
    )
    result = engine.check_access("org1", "alice", "docs")
    assert result == []


def test_check_access_includes_non_expired(engine):
    p = _create_policy(engine)
    _create_grant(
        engine, "org1", p["id"],
        subject_id="alice", resource_id="docs",
        expires_at="2099-01-01T00:00:00+00:00",
    )
    result = engine.check_access("org1", "alice", "docs")
    assert len(result) == 1


def test_check_access_no_match_returns_empty(engine):
    result = engine.check_access("org1", "nobody", "nothing")
    assert result == []


# ---------------------------------------------------------------------------
# 6. Stats
# ---------------------------------------------------------------------------


def test_get_access_stats_empty(engine):
    stats = engine.get_access_stats("org1")
    assert stats["total_policies"] == 0
    assert stats["by_resource_type"] == {}
    assert stats["by_effect"] == {}
    assert stats["total_grants"] == 0
    assert stats["active_grants"] == 0
    assert stats["revoked_grants"] == 0
    assert stats["expired_grants"] == 0


def test_get_access_stats_counts(engine):
    p1 = _create_policy(engine, name="P1", resource_type="file", effect="allow")
    p2 = _create_policy(engine, name="P2", resource_type="api", effect="deny")
    g = _create_grant(engine, "org1", p1["id"])
    _create_grant(engine, "org1", p1["id"], subject_id="user-2", resource_id="res-2")
    engine.revoke_access("org1", g["id"], revoked_by="admin")

    stats = engine.get_access_stats("org1")
    assert stats["total_policies"] == 2
    assert stats["by_resource_type"]["file"] == 1
    assert stats["by_resource_type"]["api"] == 1
    assert stats["by_effect"]["allow"] == 1
    assert stats["by_effect"]["deny"] == 1
    assert stats["total_grants"] == 2
    assert stats["active_grants"] == 1
    assert stats["revoked_grants"] == 1


def test_get_access_stats_expired_count(engine):
    p = _create_policy(engine)
    _create_grant(
        engine, "org1", p["id"],
        expires_at="2000-01-01T00:00:00+00:00",
    )
    stats = engine.get_access_stats("org1")
    assert stats["expired_grants"] == 1
    assert stats["active_grants"] == 1  # status is still 'active'


# ---------------------------------------------------------------------------
# 7. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_policies(engine):
    _create_policy(engine, org_id="orgA", name="A-Policy")
    _create_policy(engine, org_id="orgB", name="B-Policy")
    a_policies = engine.list_access_policies("orgA")
    b_policies = engine.list_access_policies("orgB")
    assert len(a_policies) == 1
    assert len(b_policies) == 1
    assert a_policies[0]["name"] == "A-Policy"
    assert b_policies[0]["name"] == "B-Policy"


def test_org_isolation_grants(engine):
    pA = _create_policy(engine, org_id="orgA")
    pB = _create_policy(engine, org_id="orgB")
    _create_grant(engine, "orgA", pA["id"])
    _create_grant(engine, "orgB", pB["id"])
    assert len(engine.list_grants("orgA")) == 1
    assert len(engine.list_grants("orgB")) == 1


def test_org_isolation_check_access(engine):
    pA = _create_policy(engine, org_id="orgA")
    _create_grant(engine, "orgA", pA["id"], subject_id="alice", resource_id="docs")
    # orgB should not see orgA's grants
    result = engine.check_access("orgB", "alice", "docs")
    assert result == []


def test_org_isolation_stats(engine):
    pA = _create_policy(engine, org_id="orgA")
    _create_policy(engine, org_id="orgB")
    _create_grant(engine, "orgA", pA["id"])

    statsA = engine.get_access_stats("orgA")
    statsB = engine.get_access_stats("orgB")
    assert statsA["total_grants"] == 1
    assert statsB["total_grants"] == 0
