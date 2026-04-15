"""Tests for IdentityGovernanceEngine — 30+ tests covering all methods."""

import pytest
from core.identity_governance_engine import IdentityGovernanceEngine


@pytest.fixture
def engine(tmp_path, monkeypatch):
    """Fresh engine pointed at tmp_path."""
    import core.identity_governance_engine as mod
    monkeypatch.setattr(mod, "_DEFAULT_DATA_DIR", tmp_path)
    e = IdentityGovernanceEngine()
    return e


ORG = "org-iga-test"
ORG2 = "org-iga-test-2"


# ---------------------------------------------------------------------------
# create_review
# ---------------------------------------------------------------------------

def test_create_review_basic(engine):
    review = engine.create_review(ORG, {
        "name": "Q1 2026 Access Review",
        "review_type": "quarterly",
        "reviewer_id": "reviewer-1",
    })
    assert review["id"]
    assert review["org_id"] == ORG
    assert review["name"] == "Q1 2026 Access Review"
    assert review["status"] == "draft"
    assert review["total_identities"] == 0


def test_create_review_requires_name(engine):
    with pytest.raises(ValueError, match="name"):
        engine.create_review(ORG, {"name": ""})


def test_create_review_invalid_type(engine):
    with pytest.raises(ValueError, match="review_type"):
        engine.create_review(ORG, {"name": "Test", "review_type": "monthly_bad"})


def test_create_review_all_types(engine):
    for rtype in ("quarterly", "annual", "triggered", "ad_hoc"):
        r = engine.create_review(ORG, {"name": f"Review {rtype}", "review_type": rtype})
        assert r["review_type"] == rtype


# ---------------------------------------------------------------------------
# list_reviews / get_review
# ---------------------------------------------------------------------------

def test_list_reviews_all(engine):
    engine.create_review(ORG, {"name": "Review A"})
    engine.create_review(ORG, {"name": "Review B"})
    reviews = engine.list_reviews(ORG)
    assert len(reviews) >= 2


def test_list_reviews_status_filter(engine):
    engine.create_review(ORG, {"name": "Draft Review"})
    drafts = engine.list_reviews(ORG, status="draft")
    assert all(r["status"] == "draft" for r in drafts)
    completed = engine.list_reviews(ORG, status="completed")
    assert len(completed) == 0


def test_get_review_found(engine):
    review = engine.create_review(ORG, {"name": "Get Me"})
    result = engine.get_review(ORG, review["id"])
    assert result is not None
    assert result["id"] == review["id"]
    assert "items_total" in result
    assert "items_decided" in result


def test_get_review_not_found(engine):
    assert engine.get_review(ORG, "no-such-id") is None


def test_get_review_org_isolation(engine):
    review = engine.create_review(ORG, {"name": "Org1 Review"})
    assert engine.get_review(ORG2, review["id"]) is None


# ---------------------------------------------------------------------------
# add_review_item
# ---------------------------------------------------------------------------

def test_add_review_item_basic(engine):
    review = engine.create_review(ORG, {"name": "Review X"})
    item = engine.add_review_item(ORG, review["id"], {
        "identity_id": "user-42",
        "identity_name": "Alice",
        "identity_type": "user",
        "entitlement": "admin_panel",
        "entitlement_level": "admin",
        "risk_score": 0.75,
    })
    assert item["id"]
    assert item["identity_id"] == "user-42"
    assert item["reviewer_decision"] is None
    # review total_identities should increment
    r = engine.get_review(ORG, review["id"])
    assert r["total_identities"] == 1


def test_add_review_item_increments_count(engine):
    review = engine.create_review(ORG, {"name": "Review Y"})
    engine.add_review_item(ORG, review["id"], {"identity_id": "u1"})
    engine.add_review_item(ORG, review["id"], {"identity_id": "u2"})
    r = engine.get_review(ORG, review["id"])
    assert r["total_identities"] == 2


def test_add_review_item_requires_identity_id(engine):
    review = engine.create_review(ORG, {"name": "Review Z"})
    with pytest.raises(ValueError, match="identity_id"):
        engine.add_review_item(ORG, review["id"], {"identity_id": ""})


def test_add_review_item_invalid_identity_type(engine):
    review = engine.create_review(ORG, {"name": "Review T"})
    with pytest.raises(ValueError, match="identity_type"):
        engine.add_review_item(ORG, review["id"], {"identity_id": "u1", "identity_type": "machine"})


def test_add_review_item_invalid_entitlement_level(engine):
    review = engine.create_review(ORG, {"name": "Review L"})
    with pytest.raises(ValueError, match="entitlement_level"):
        engine.add_review_item(ORG, review["id"], {"identity_id": "u1", "entitlement_level": "superuser"})


# ---------------------------------------------------------------------------
# submit_decision
# ---------------------------------------------------------------------------

def test_submit_decision_approved(engine):
    review = engine.create_review(ORG, {"name": "Decision Review"})
    item = engine.add_review_item(ORG, review["id"], {"identity_id": "u1"})
    found = engine.submit_decision(ORG, item["id"], "approved", "reviewer-1", "Looks good")
    assert found is True
    r = engine.get_review(ORG, review["id"])
    assert r["approved_count"] == 1
    assert r["reviewed_count"] == 1


def test_submit_decision_revoked(engine):
    review = engine.create_review(ORG, {"name": "Revoke Review"})
    item = engine.add_review_item(ORG, review["id"], {"identity_id": "u2"})
    engine.submit_decision(ORG, item["id"], "revoked", "reviewer-1", "No longer needed")
    r = engine.get_review(ORG, review["id"])
    assert r["revoked_count"] == 1


def test_submit_decision_invalid(engine):
    review = engine.create_review(ORG, {"name": "Bad Decision"})
    item = engine.add_review_item(ORG, review["id"], {"identity_id": "u3"})
    with pytest.raises(ValueError, match="decision"):
        engine.submit_decision(ORG, item["id"], "ignored", "rev", "")


def test_submit_decision_not_found(engine):
    found = engine.submit_decision(ORG, "no-such-item", "approved", "rev", "")
    assert found is False


# ---------------------------------------------------------------------------
# complete_review
# ---------------------------------------------------------------------------

def test_complete_review(engine):
    review = engine.create_review(ORG, {"name": "Complete Me"})
    item1 = engine.add_review_item(ORG, review["id"], {"identity_id": "u1"})
    item2 = engine.add_review_item(ORG, review["id"], {"identity_id": "u2"})
    engine.submit_decision(ORG, item1["id"], "approved", "rev", "")
    engine.submit_decision(ORG, item2["id"], "revoked", "rev", "Excessive")
    result = engine.complete_review(ORG, review["id"])
    assert result["status"] == "completed"
    assert result["approved_count"] == 1
    assert result["revoked_count"] == 1
    assert result["reviewed_count"] == 2
    assert result["completed_date"] is not None


def test_complete_review_not_found(engine):
    assert engine.complete_review(ORG, "no-such-review") is None


# ---------------------------------------------------------------------------
# add_entitlement / list_entitlements
# ---------------------------------------------------------------------------

def test_add_entitlement_basic(engine):
    ent = engine.add_entitlement(ORG, {
        "identity_id": "svc-account-1",
        "identity_name": "ServiceBot",
        "identity_type": "service_account",
        "entitlement": "read_db",
        "system": "postgres",
        "risk_score": 0.3,
    })
    assert ent["id"]
    assert ent["identity_id"] == "svc-account-1"
    assert ent["is_orphaned"] == 0


def test_add_entitlement_requires_identity_id(engine):
    with pytest.raises(ValueError, match="identity_id"):
        engine.add_entitlement(ORG, {"identity_id": ""})


def test_list_entitlements_all(engine):
    engine.add_entitlement(ORG, {"identity_id": "u1", "entitlement": "read"})
    engine.add_entitlement(ORG, {"identity_id": "u2", "entitlement": "write"})
    ents = engine.list_entitlements(ORG)
    assert len(ents) >= 2


def test_list_entitlements_by_identity(engine):
    engine.add_entitlement(ORG, {"identity_id": "u1", "entitlement": "read"})
    engine.add_entitlement(ORG, {"identity_id": "u1", "entitlement": "write"})
    engine.add_entitlement(ORG, {"identity_id": "u2", "entitlement": "admin"})
    ents = engine.list_entitlements(ORG, identity_id="u1")
    assert all(e["identity_id"] == "u1" for e in ents)
    assert len(ents) == 2


def test_list_entitlements_orphaned_filter(engine):
    engine.add_entitlement(ORG, {"identity_id": "u1", "is_orphaned": True})
    engine.add_entitlement(ORG, {"identity_id": "u2", "is_orphaned": False})
    orphaned = engine.list_entitlements(ORG, is_orphaned=True)
    assert all(e["is_orphaned"] == 1 for e in orphaned)


def test_list_entitlements_excessive_filter(engine):
    engine.add_entitlement(ORG, {"identity_id": "u1", "is_excessive": True})
    engine.add_entitlement(ORG, {"identity_id": "u2", "is_excessive": False})
    excessive = engine.list_entitlements(ORG, is_excessive=True)
    assert all(e["is_excessive"] == 1 for e in excessive)


# ---------------------------------------------------------------------------
# flag_orphaned
# ---------------------------------------------------------------------------

def test_flag_orphaned(engine):
    engine.add_entitlement(ORG, {"identity_id": "depart-user", "entitlement": "read"})
    engine.add_entitlement(ORG, {"identity_id": "depart-user", "entitlement": "write"})
    count = engine.flag_orphaned(ORG, "depart-user")
    assert count == 2
    ents = engine.list_entitlements(ORG, identity_id="depart-user", is_orphaned=True)
    assert len(ents) == 2


def test_flag_orphaned_no_match(engine):
    count = engine.flag_orphaned(ORG, "ghost-user")
    assert count == 0


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

def test_create_policy_basic(engine):
    policy = engine.create_policy(ORG, {
        "policy_name": "Least Privilege Policy",
        "policy_type": "least_privilege",
        "conditions": {"max_roles": 3},
        "auto_remediate": False,
    })
    assert policy["id"]
    assert policy["policy_name"] == "Least Privilege Policy"
    assert policy["violation_count"] == 0


def test_create_policy_requires_name(engine):
    with pytest.raises(ValueError, match="policy_name"):
        engine.create_policy(ORG, {"policy_name": ""})


def test_create_policy_invalid_type(engine):
    with pytest.raises(ValueError, match="policy_type"):
        engine.create_policy(ORG, {"policy_name": "Bad", "policy_type": "unlimited_access"})


def test_create_policy_all_types(engine):
    for ptype in ("separation_of_duties", "least_privilege", "recertification", "max_entitlements"):
        p = engine.create_policy(ORG, {"policy_name": f"P {ptype}", "policy_type": ptype})
        assert p["policy_type"] == ptype


def test_list_policies(engine):
    engine.create_policy(ORG, {"policy_name": "Policy 1"})
    engine.create_policy(ORG, {"policy_name": "Policy 2"})
    policies = engine.list_policies(ORG)
    assert len(policies) >= 2


# ---------------------------------------------------------------------------
# get_governance_stats
# ---------------------------------------------------------------------------

def test_governance_stats_empty(engine):
    stats = engine.get_governance_stats(ORG)
    assert stats["total_reviews"] == 0
    assert stats["total_entitlements"] == 0
    assert stats["orphaned_count"] == 0
    assert stats["revocation_rate"] == 0.0


def test_governance_stats_with_data(engine):
    # Create and complete a review
    review = engine.create_review(ORG, {"name": "Stats Review"})
    item = engine.add_review_item(ORG, review["id"], {"identity_id": "u1"})
    engine.submit_decision(ORG, item["id"], "revoked", "rev", "")
    engine.complete_review(ORG, review["id"])

    # Add entitlements
    engine.add_entitlement(ORG, {"identity_id": "old-user", "is_orphaned": True})
    engine.add_entitlement(ORG, {"identity_id": "power-user", "is_excessive": True})

    stats = engine.get_governance_stats(ORG)
    assert stats["total_reviews"] == 1
    assert stats["total_entitlements"] == 2
    assert stats["orphaned_count"] == 1
    assert stats["excessive_count"] == 1
    assert stats["revocation_rate"] > 0
    assert "completed" in stats["by_status"]


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_reviews(engine):
    engine.create_review(ORG, {"name": "Org1 Review"})
    reviews = engine.list_reviews(ORG2)
    assert len(reviews) == 0


def test_org_isolation_entitlements(engine):
    engine.add_entitlement(ORG, {"identity_id": "u1"})
    ents = engine.list_entitlements(ORG2)
    assert len(ents) == 0


def test_org_isolation_policies(engine):
    engine.create_policy(ORG, {"policy_name": "Org1 Policy"})
    policies = engine.list_policies(ORG2)
    assert len(policies) == 0


def test_org_isolation_stats(engine):
    engine.create_review(ORG, {"name": "Org1 Review"})
    stats = engine.get_governance_stats(ORG2)
    assert stats["total_reviews"] == 0
