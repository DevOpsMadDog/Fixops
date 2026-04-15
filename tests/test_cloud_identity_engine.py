"""Tests for CloudIdentityEngine — 35 tests.

Covers:
- register_identity: valid types/providers, invalid raises ValueError
- list_identities with filters
- get_identity: found, not found, wrong org
- update_permissions: recalculates privilege_level correctly
- record_access_review: valid types/outcomes, invalid raises ValueError
- list_access_reviews with filters
- record_permission_change and list_permission_changes filters
- get_cloud_identity_stats: admin_count, mfa_disabled_count, federated_count
- Org isolation
"""

import sys
sys.path.insert(0, "suite-core")

import pytest

from core.cloud_identity_engine import CloudIdentityEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return CloudIdentityEngine(db_path=str(tmp_path / "cloud_id.db"))


# ---------------------------------------------------------------------------
# 1. register_identity — basics
# ---------------------------------------------------------------------------

def test_register_identity_returns_dict(engine):
    ident = engine.register_identity("org1", {
        "identity_name": "alice",
        "identity_type": "user",
        "cloud_provider": "aws",
        "privilege_level": "read",
    })
    assert isinstance(ident, dict)
    assert "id" in ident
    assert ident["org_id"] == "org1"
    assert ident["identity_name"] == "alice"


def test_register_identity_requires_name(engine):
    with pytest.raises(ValueError, match="identity_name"):
        engine.register_identity("org1", {"identity_type": "user"})


def test_register_identity_defaults(engine):
    ident = engine.register_identity("org1", {"identity_name": "svc"})
    assert ident["identity_type"] == "user"
    assert ident["cloud_provider"] == "aws"
    assert ident["privilege_level"] == "none"
    assert ident["mfa_enabled"] is False
    assert ident["is_federated"] is False


# ---------------------------------------------------------------------------
# 2. Valid identity_types (all 5)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("itype", ["user", "service_account", "role", "group", "machine"])
def test_register_identity_all_valid_types(engine, itype):
    ident = engine.register_identity("org1", {"identity_name": f"id-{itype}", "identity_type": itype})
    assert ident["identity_type"] == itype


def test_register_identity_invalid_type_raises(engine):
    with pytest.raises(ValueError):
        engine.register_identity("org1", {"identity_name": "x", "identity_type": "bot"})


# ---------------------------------------------------------------------------
# 3. Valid cloud_providers (all 4)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "multi_cloud"])
def test_register_identity_all_valid_providers(engine, provider):
    ident = engine.register_identity("org1", {
        "identity_name": f"id-{provider}",
        "cloud_provider": provider,
    })
    assert ident["cloud_provider"] == provider


def test_register_identity_invalid_provider_raises(engine):
    with pytest.raises(ValueError):
        engine.register_identity("org1", {"identity_name": "x", "cloud_provider": "alibaba"})


# ---------------------------------------------------------------------------
# 4. list_identities with filters
# ---------------------------------------------------------------------------

def test_list_identities_returns_created(engine):
    engine.register_identity("org2", {"identity_name": "a", "identity_type": "user"})
    engine.register_identity("org2", {"identity_name": "b", "identity_type": "role"})
    idents = engine.list_identities("org2")
    assert len(idents) == 2


def test_list_identities_filter_by_type(engine):
    engine.register_identity("org3", {"identity_name": "a", "identity_type": "user"})
    engine.register_identity("org3", {"identity_name": "b", "identity_type": "service_account"})
    users = engine.list_identities("org3", identity_type="user")
    assert len(users) == 1 and users[0]["identity_type"] == "user"


def test_list_identities_filter_by_provider(engine):
    engine.register_identity("org4", {"identity_name": "a", "cloud_provider": "aws"})
    engine.register_identity("org4", {"identity_name": "b", "cloud_provider": "gcp"})
    aws = engine.list_identities("org4", cloud_provider="aws")
    assert len(aws) == 1 and aws[0]["cloud_provider"] == "aws"


def test_list_identities_filter_by_privilege(engine):
    engine.register_identity("org5", {"identity_name": "a", "privilege_level": "admin"})
    engine.register_identity("org5", {"identity_name": "b", "privilege_level": "read"})
    admins = engine.list_identities("org5", privilege_level="admin")
    assert len(admins) == 1 and admins[0]["privilege_level"] == "admin"


# ---------------------------------------------------------------------------
# 5. get_identity
# ---------------------------------------------------------------------------

def test_get_identity_found(engine):
    ident = engine.register_identity("org6", {"identity_name": "svc"})
    found = engine.get_identity("org6", ident["id"])
    assert found is not None and found["id"] == ident["id"]


def test_get_identity_not_found_returns_none(engine):
    assert engine.get_identity("org6", "nonexistent") is None


def test_get_identity_wrong_org_returns_none(engine):
    ident = engine.register_identity("org7", {"identity_name": "svc"})
    assert engine.get_identity("other-org", ident["id"]) is None


# ---------------------------------------------------------------------------
# 6. update_permissions → recalculates privilege_level
# ---------------------------------------------------------------------------

def test_update_permissions_admin(engine):
    ident = engine.register_identity("org8", {"identity_name": "svc"})
    updated = engine.update_permissions("org8", ident["id"], ["AdminFullAccess", "AdminBilling"])
    assert updated["privilege_level"] == "admin"
    assert "AdminFullAccess" in updated["permissions"]


def test_update_permissions_write(engine):
    ident = engine.register_identity("org8", {"identity_name": "svc2"})
    updated = engine.update_permissions("org8", ident["id"], ["WriteS3", "ReadEC2"])
    assert updated["privilege_level"] == "write"


def test_update_permissions_read(engine):
    ident = engine.register_identity("org8", {"identity_name": "svc3"})
    updated = engine.update_permissions("org8", ident["id"], ["ReadOnly"])
    assert updated["privilege_level"] == "read"


def test_update_permissions_none_when_empty(engine):
    ident = engine.register_identity("org8", {"identity_name": "svc4", "privilege_level": "admin"})
    updated = engine.update_permissions("org8", ident["id"], [])
    assert updated["privilege_level"] == "none"


def test_update_permissions_not_found_returns_none(engine):
    result = engine.update_permissions("org8", "nonexistent", ["ReadOnly"])
    assert result is None


def test_update_permissions_updates_last_activity(engine):
    ident = engine.register_identity("org9", {"identity_name": "svc"})
    updated = engine.update_permissions("org9", ident["id"], ["ReadOnly"])
    assert updated["last_activity"] is not None


# ---------------------------------------------------------------------------
# 7. record_access_review
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("review_type", ["periodic", "triggered", "certification"])
def test_record_access_review_all_types(engine, review_type):
    ident = engine.register_identity("org10", {"identity_name": "svc"})
    review = engine.record_access_review("org10", {
        "identity_id": ident["id"],
        "review_type": review_type,
        "outcome": "approved",
    })
    assert review["review_type"] == review_type


@pytest.mark.parametrize("outcome", ["approved", "revoked", "modified", "no_action"])
def test_record_access_review_all_outcomes(engine, outcome):
    ident = engine.register_identity("org11", {"identity_name": "svc"})
    review = engine.record_access_review("org11", {
        "identity_id": ident["id"],
        "outcome": outcome,
    })
    assert review["outcome"] == outcome


def test_record_access_review_invalid_type_raises(engine):
    ident = engine.register_identity("org12", {"identity_name": "svc"})
    with pytest.raises(ValueError):
        engine.record_access_review("org12", {
            "identity_id": ident["id"],
            "review_type": "quarterly",
        })


def test_record_access_review_nonexistent_identity_raises(engine):
    with pytest.raises(ValueError):
        engine.record_access_review("org12", {"identity_id": "nonexistent"})


# ---------------------------------------------------------------------------
# 8. list_access_reviews filters
# ---------------------------------------------------------------------------

def test_list_access_reviews_filter_by_outcome(engine):
    ident = engine.register_identity("org13", {"identity_name": "svc"})
    engine.record_access_review("org13", {"identity_id": ident["id"], "outcome": "approved"})
    engine.record_access_review("org13", {"identity_id": ident["id"], "outcome": "revoked"})
    revoked = engine.list_access_reviews("org13", outcome="revoked")
    assert len(revoked) == 1 and revoked[0]["outcome"] == "revoked"


def test_list_access_reviews_filter_by_identity_id(engine):
    ident_a = engine.register_identity("org14", {"identity_name": "a"})
    ident_b = engine.register_identity("org14", {"identity_name": "b"})
    engine.record_access_review("org14", {"identity_id": ident_a["id"]})
    engine.record_access_review("org14", {"identity_id": ident_b["id"]})
    a_reviews = engine.list_access_reviews("org14", identity_id=ident_a["id"])
    assert len(a_reviews) == 1 and a_reviews[0]["identity_id"] == ident_a["id"]


# ---------------------------------------------------------------------------
# 9. record_permission_change and list filters
# ---------------------------------------------------------------------------

def test_record_permission_change_returns_dict(engine):
    ident = engine.register_identity("org15", {"identity_name": "svc"})
    change = engine.record_permission_change("org15", {
        "identity_id": ident["id"],
        "change_type": "grant",
        "permission_name": "AdminS3",
        "changed_by": "terraform",
        "approved": True,
    })
    assert isinstance(change, dict)
    assert change["change_type"] == "grant"
    assert change["permission_name"] == "AdminS3"
    assert change["approved"] is True


def test_record_permission_change_invalid_type_raises(engine):
    ident = engine.register_identity("org15", {"identity_name": "svc2"})
    with pytest.raises(ValueError):
        engine.record_permission_change("org15", {
            "identity_id": ident["id"],
            "change_type": "delete",
            "permission_name": "ReadS3",
        })


def test_record_permission_change_requires_permission_name(engine):
    ident = engine.register_identity("org15", {"identity_name": "svc3"})
    with pytest.raises(ValueError):
        engine.record_permission_change("org15", {
            "identity_id": ident["id"],
            "change_type": "grant",
        })


def test_list_permission_changes_filter_approved(engine):
    ident = engine.register_identity("org16", {"identity_name": "svc"})
    engine.record_permission_change("org16", {
        "identity_id": ident["id"], "change_type": "grant",
        "permission_name": "ReadS3", "approved": True,
    })
    engine.record_permission_change("org16", {
        "identity_id": ident["id"], "change_type": "revoke",
        "permission_name": "WriteEC2", "approved": False,
    })
    approved = engine.list_permission_changes("org16", approved=True)
    assert len(approved) == 1 and approved[0]["approved"] is True


def test_list_permission_changes_filter_by_identity_id(engine):
    ident_a = engine.register_identity("org17", {"identity_name": "a"})
    ident_b = engine.register_identity("org17", {"identity_name": "b"})
    engine.record_permission_change("org17", {
        "identity_id": ident_a["id"], "change_type": "grant", "permission_name": "ReadS3"
    })
    engine.record_permission_change("org17", {
        "identity_id": ident_b["id"], "change_type": "grant", "permission_name": "ReadEC2"
    })
    a_changes = engine.list_permission_changes("org17", identity_id=ident_a["id"])
    assert len(a_changes) == 1 and a_changes[0]["identity_id"] == ident_a["id"]


# ---------------------------------------------------------------------------
# 10. get_cloud_identity_stats
# ---------------------------------------------------------------------------

def test_get_cloud_identity_stats_returns_dict(engine):
    stats = engine.get_cloud_identity_stats("orgX")
    assert isinstance(stats, dict)
    for key in ("total_identities", "by_type", "by_provider", "admin_count",
                "mfa_disabled_count", "federated_count", "total_reviews", "revoked_in_reviews"):
        assert key in stats


def test_get_cloud_identity_stats_admin_count(engine):
    engine.register_identity("orgS", {"identity_name": "a", "privilege_level": "admin"})
    engine.register_identity("orgS", {"identity_name": "b", "privilege_level": "read"})
    engine.register_identity("orgS", {"identity_name": "c", "privilege_level": "admin"})
    stats = engine.get_cloud_identity_stats("orgS")
    assert stats["admin_count"] == 2
    assert stats["total_identities"] == 3


def test_get_cloud_identity_stats_mfa_disabled_count(engine):
    engine.register_identity("orgM", {"identity_name": "a", "mfa_enabled": True})
    engine.register_identity("orgM", {"identity_name": "b", "mfa_enabled": False})
    engine.register_identity("orgM", {"identity_name": "c", "mfa_enabled": False})
    stats = engine.get_cloud_identity_stats("orgM")
    assert stats["mfa_disabled_count"] == 2


def test_get_cloud_identity_stats_federated_count(engine):
    engine.register_identity("orgF", {"identity_name": "a", "is_federated": True})
    engine.register_identity("orgF", {"identity_name": "b", "is_federated": False})
    stats = engine.get_cloud_identity_stats("orgF")
    assert stats["federated_count"] == 1


def test_get_cloud_identity_stats_revoked_in_reviews(engine):
    ident = engine.register_identity("orgR", {"identity_name": "svc"})
    engine.record_access_review("orgR", {"identity_id": ident["id"], "outcome": "revoked"})
    engine.record_access_review("orgR", {"identity_id": ident["id"], "outcome": "approved"})
    stats = engine.get_cloud_identity_stats("orgR")
    assert stats["revoked_in_reviews"] == 1
    assert stats["total_reviews"] == 2


# ---------------------------------------------------------------------------
# 11. Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_identities(engine):
    engine.register_identity("orgA", {"identity_name": "a"})
    engine.register_identity("orgB", {"identity_name": "b"})
    assert len(engine.list_identities("orgA")) == 1
    assert len(engine.list_identities("orgB")) == 1


def test_org_isolation_reviews(engine):
    ident_a = engine.register_identity("orgA", {"identity_name": "a"})
    ident_b = engine.register_identity("orgB", {"identity_name": "b"})
    engine.record_access_review("orgA", {"identity_id": ident_a["id"]})
    engine.record_access_review("orgB", {"identity_id": ident_b["id"]})
    assert len(engine.list_access_reviews("orgA")) == 1
    assert len(engine.list_access_reviews("orgB")) == 1


def test_org_isolation_permission_changes(engine):
    ident_a = engine.register_identity("orgA", {"identity_name": "a"})
    ident_b = engine.register_identity("orgB", {"identity_name": "b"})
    engine.record_permission_change("orgA", {
        "identity_id": ident_a["id"], "change_type": "grant", "permission_name": "ReadS3"
    })
    engine.record_permission_change("orgB", {
        "identity_id": ident_b["id"], "change_type": "grant", "permission_name": "WriteEC2"
    })
    assert len(engine.list_permission_changes("orgA")) == 1
    assert len(engine.list_permission_changes("orgB")) == 1
