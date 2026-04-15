"""Tests for PolicyEnforcementEngine — policy lifecycle and exception workflows.

Coverage:
  - Policy CRUD with valid/invalid domains, types
  - Version creation and version increment logic
  - Exception lifecycle (pending → approved)
  - Expired exceptions detection
  - Enforcement stats aggregation
  - Org isolation
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine(tmp_path):
    from core.policy_enforcement_engine import PolicyEnforcementEngine
    db = str(tmp_path / "test_policy_enforcement.db")
    return PolicyEnforcementEngine(db_path=db)


ORG = "org_pe_test"
ORG2 = "org_pe_other"


# ---------------------------------------------------------------------------
# Policy creation — valid cases
# ---------------------------------------------------------------------------

def test_create_policy_basic(engine):
    p = engine.create_policy(ORG, {
        "name": "Network Segmentation Policy",
        "policy_domain": "network",
        "policy_type": "mandatory",
        "enforcement_mechanism": "automated",
    })
    assert p["id"]
    assert p["name"] == "Network Segmentation Policy"
    assert p["policy_domain"] == "network"
    assert p["policy_type"] == "mandatory"
    assert p["enforcement_mechanism"] == "automated"
    assert p["status"] == "active"
    assert p["version"] == "1.0"
    assert p["org_id"] == ORG


def test_create_policy_defaults(engine):
    p = engine.create_policy(ORG, {
        "name": "Identity Policy",
        "policy_domain": "identity",
    })
    assert p["policy_type"] == "mandatory"
    assert p["enforcement_mechanism"] == "manual"


def test_create_policy_all_valid_domains(engine):
    for domain in ("network", "identity", "data", "endpoint", "cloud", "application", "physical"):
        p = engine.create_policy(ORG, {"name": f"D {domain}", "policy_domain": domain})
        assert p["policy_domain"] == domain


def test_create_policy_all_valid_types(engine):
    for ptype in ("mandatory", "recommended", "prohibited"):
        p = engine.create_policy(ORG, {
            "name": f"T {ptype}",
            "policy_domain": "network",
            "policy_type": ptype,
        })
        assert p["policy_type"] == ptype


def test_create_policy_all_valid_mechanisms(engine):
    for mech in ("automated", "manual", "hybrid"):
        p = engine.create_policy(ORG, {
            "name": f"M {mech}",
            "policy_domain": "cloud",
            "enforcement_mechanism": mech,
        })
        assert p["enforcement_mechanism"] == mech


def test_create_policy_initial_version_history(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "data", "content": "initial content"})
    assert isinstance(p["version_history"], list)
    assert len(p["version_history"]) == 1
    assert p["version_history"][0]["version"] == "1.0"
    assert p["version_history"][0]["content"] == "initial content"


# ---------------------------------------------------------------------------
# Policy creation — invalid cases
# ---------------------------------------------------------------------------

def test_create_policy_missing_name(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.create_policy(ORG, {"policy_domain": "network"})


def test_create_policy_invalid_domain(engine):
    with pytest.raises(ValueError, match="Invalid policy_domain"):
        engine.create_policy(ORG, {"name": "P", "policy_domain": "invalid_domain"})


def test_create_policy_invalid_type_falls_back(engine):
    p = engine.create_policy(ORG, {
        "name": "P",
        "policy_domain": "network",
        "policy_type": "strict",
    })
    assert p["policy_type"] == "mandatory"


def test_create_policy_invalid_mechanism_falls_back(engine):
    p = engine.create_policy(ORG, {
        "name": "P",
        "policy_domain": "network",
        "enforcement_mechanism": "magic",
    })
    assert p["enforcement_mechanism"] == "manual"


# ---------------------------------------------------------------------------
# List and get policies
# ---------------------------------------------------------------------------

def test_list_policies_empty(engine):
    assert engine.list_policies(ORG) == []


def test_list_policies_returns_all(engine):
    engine.create_policy(ORG, {"name": "P1", "policy_domain": "network"})
    engine.create_policy(ORG, {"name": "P2", "policy_domain": "identity"})
    assert len(engine.list_policies(ORG)) == 2


def test_list_policies_filter_by_domain(engine):
    engine.create_policy(ORG, {"name": "A", "policy_domain": "network"})
    engine.create_policy(ORG, {"name": "B", "policy_domain": "cloud"})
    result = engine.list_policies(ORG, policy_domain="network")
    assert len(result) == 1
    assert result[0]["name"] == "A"


def test_list_policies_filter_by_type(engine):
    engine.create_policy(ORG, {"name": "A", "policy_domain": "data", "policy_type": "mandatory"})
    engine.create_policy(ORG, {"name": "B", "policy_domain": "data", "policy_type": "prohibited"})
    result = engine.list_policies(ORG, policy_type="prohibited")
    assert len(result) == 1
    assert result[0]["name"] == "B"


def test_get_policy_found(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "endpoint"})
    fetched = engine.get_policy(ORG, p["id"])
    assert fetched is not None
    assert fetched["id"] == p["id"]
    assert fetched["name"] == "P"
    assert isinstance(fetched["version_history"], list)


def test_get_policy_not_found(engine):
    assert engine.get_policy(ORG, "nonexistent-id") is None


# ---------------------------------------------------------------------------
# Version creation
# ---------------------------------------------------------------------------

def test_create_policy_version_increments(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "network", "content": "v1 content"})
    assert p["version"] == "1.0"

    updated = engine.create_policy_version(ORG, p["id"], "v1.1 content", "Minor update")
    assert updated["version"] == "1.1"
    assert updated["content"] == "v1.1 content"


def test_create_policy_version_increments_again(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "identity"})
    engine.create_policy_version(ORG, p["id"], "content v1.1", "First update")
    updated = engine.create_policy_version(ORG, p["id"], "content v1.2", "Second update")
    assert updated["version"] == "1.2"


def test_create_policy_version_history_grows(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "cloud", "content": "initial"})
    engine.create_policy_version(ORG, p["id"], "v2 content", "Major update")
    updated = engine.get_policy(ORG, p["id"])
    assert len(updated["version_history"]) == 2
    assert updated["version_history"][0]["version"] == "1.0"
    assert updated["version_history"][1]["version"] == "1.1"


def test_create_policy_version_not_found(engine):
    result = engine.create_policy_version(ORG, "bad-id", "content", "summary")
    assert result is None


def test_create_policy_version_change_summary_stored(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "data"})
    engine.create_policy_version(ORG, p["id"], "new content", "Added compliance clause")
    updated = engine.get_policy(ORG, p["id"])
    assert updated["version_history"][-1]["change_summary"] == "Added compliance clause"


# ---------------------------------------------------------------------------
# Exception lifecycle
# ---------------------------------------------------------------------------

def test_record_exception_basic(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "network"})
    exc = engine.record_exception(ORG, {
        "policy_id": p["id"],
        "exception_type": "temporary",
        "justification": "Legacy system compatibility",
        "requested_by": "alice",
        "expiry_date": "2026-12-31",
    })
    assert exc["id"]
    assert exc["status"] == "pending"
    assert exc["policy_id"] == p["id"]
    assert exc["exception_type"] == "temporary"
    assert exc["requested_by"] == "alice"
    assert exc["approved_by"] is None
    assert exc["approved_at"] is None


def test_record_exception_all_types(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "cloud"})
    for etype in ("permanent", "temporary", "conditional"):
        exc = engine.record_exception(ORG, {
            "policy_id": p["id"],
            "exception_type": etype,
            "justification": "reason",
            "requested_by": "user",
        })
        assert exc["exception_type"] == etype


def test_record_exception_missing_policy_id(engine):
    with pytest.raises(ValueError, match="policy_id is required"):
        engine.record_exception(ORG, {"justification": "r", "requested_by": "u"})


def test_record_exception_missing_justification(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "data"})
    with pytest.raises(ValueError, match="justification is required"):
        engine.record_exception(ORG, {"policy_id": p["id"], "requested_by": "u"})


def test_record_exception_missing_requested_by(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "data"})
    with pytest.raises(ValueError, match="requested_by is required"):
        engine.record_exception(ORG, {"policy_id": p["id"], "justification": "j"})


def test_approve_exception(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "endpoint"})
    exc = engine.record_exception(ORG, {
        "policy_id": p["id"],
        "exception_type": "temporary",
        "justification": "Needed for migration",
        "requested_by": "bob",
    })
    approved = engine.approve_exception(ORG, exc["id"], "manager", "Approved for 30 days")
    assert approved["status"] == "approved"
    assert approved["approved_by"] == "manager"
    assert approved["approved_at"]
    assert approved["notes"] == "Approved for 30 days"


def test_approve_exception_not_found(engine):
    result = engine.approve_exception(ORG, "bad-id", "manager")
    assert result is None


def test_list_exceptions_empty(engine):
    assert engine.list_exceptions(ORG) == []


def test_list_exceptions_filter_by_status(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "identity"})
    exc = engine.record_exception(ORG, {
        "policy_id": p["id"],
        "exception_type": "temporary",
        "justification": "j",
        "requested_by": "u",
    })
    engine.approve_exception(ORG, exc["id"], "mgr")
    pending = engine.list_exceptions(ORG, status="pending")
    assert len(pending) == 0
    approved = engine.list_exceptions(ORG, status="approved")
    assert len(approved) == 1


def test_list_exceptions_filter_by_policy_id(engine):
    p1 = engine.create_policy(ORG, {"name": "P1", "policy_domain": "network"})
    p2 = engine.create_policy(ORG, {"name": "P2", "policy_domain": "cloud"})
    engine.record_exception(ORG, {"policy_id": p1["id"], "exception_type": "temporary", "justification": "j", "requested_by": "u"})
    engine.record_exception(ORG, {"policy_id": p2["id"], "exception_type": "temporary", "justification": "j", "requested_by": "u"})
    result = engine.list_exceptions(ORG, policy_id=p1["id"])
    assert len(result) == 1
    assert result[0]["policy_id"] == p1["id"]


# ---------------------------------------------------------------------------
# Expired exceptions detection
# ---------------------------------------------------------------------------

def test_expired_exceptions_in_stats(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "data"})
    # Exception with past expiry date
    exc = engine.record_exception(ORG, {
        "policy_id": p["id"],
        "exception_type": "temporary",
        "justification": "old",
        "requested_by": "alice",
        "expiry_date": "2020-01-01T00:00:00+00:00",
    })
    engine.approve_exception(ORG, exc["id"], "manager")

    stats = engine.get_enforcement_stats(ORG)
    assert stats["expired_exceptions"] == 1
    assert stats["approved_exceptions"] == 1


def test_future_expiry_not_counted_as_expired(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "cloud"})
    exc = engine.record_exception(ORG, {
        "policy_id": p["id"],
        "exception_type": "temporary",
        "justification": "ongoing",
        "requested_by": "bob",
        "expiry_date": "2099-12-31T00:00:00+00:00",
    })
    engine.approve_exception(ORG, exc["id"], "manager")
    stats = engine.get_enforcement_stats(ORG)
    assert stats["expired_exceptions"] == 0


def test_no_expiry_date_not_counted_as_expired(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "identity"})
    exc = engine.record_exception(ORG, {
        "policy_id": p["id"],
        "exception_type": "permanent",
        "justification": "permanent exception",
        "requested_by": "carol",
    })
    engine.approve_exception(ORG, exc["id"], "manager")
    stats = engine.get_enforcement_stats(ORG)
    assert stats["expired_exceptions"] == 0


# ---------------------------------------------------------------------------
# Enforcement stats
# ---------------------------------------------------------------------------

def test_stats_empty(engine):
    stats = engine.get_enforcement_stats(ORG)
    assert stats["total_policies"] == 0
    assert stats["active_policies"] == 0
    assert stats["total_exceptions"] == 0
    assert stats["pending_exceptions"] == 0


def test_stats_by_domain(engine):
    engine.create_policy(ORG, {"name": "A", "policy_domain": "network"})
    engine.create_policy(ORG, {"name": "B", "policy_domain": "cloud"})
    engine.create_policy(ORG, {"name": "C", "policy_domain": "network"})
    stats = engine.get_enforcement_stats(ORG)
    assert stats["by_domain"]["network"] == 2
    assert stats["by_domain"]["cloud"] == 1


def test_stats_by_type(engine):
    engine.create_policy(ORG, {"name": "A", "policy_domain": "data", "policy_type": "mandatory"})
    engine.create_policy(ORG, {"name": "B", "policy_domain": "data", "policy_type": "recommended"})
    engine.create_policy(ORG, {"name": "C", "policy_domain": "endpoint", "policy_type": "mandatory"})
    stats = engine.get_enforcement_stats(ORG)
    assert stats["by_type"]["mandatory"] == 2
    assert stats["by_type"]["recommended"] == 1


def test_stats_exception_counts(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "network"})
    exc1 = engine.record_exception(ORG, {"policy_id": p["id"], "exception_type": "temporary", "justification": "j", "requested_by": "u"})
    exc2 = engine.record_exception(ORG, {"policy_id": p["id"], "exception_type": "permanent", "justification": "j2", "requested_by": "u2"})
    engine.approve_exception(ORG, exc1["id"], "manager")

    stats = engine.get_enforcement_stats(ORG)
    assert stats["total_exceptions"] == 2
    assert stats["pending_exceptions"] == 1
    assert stats["approved_exceptions"] == 1


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_policies(engine):
    engine.create_policy(ORG, {"name": "P1", "policy_domain": "network"})
    engine.create_policy(ORG2, {"name": "P2", "policy_domain": "cloud"})
    assert len(engine.list_policies(ORG)) == 1
    assert len(engine.list_policies(ORG2)) == 1
    assert engine.list_policies(ORG)[0]["name"] == "P1"


def test_org_isolation_exceptions(engine):
    p1 = engine.create_policy(ORG, {"name": "P", "policy_domain": "data"})
    p2 = engine.create_policy(ORG2, {"name": "P", "policy_domain": "data"})
    engine.record_exception(ORG, {"policy_id": p1["id"], "exception_type": "temporary", "justification": "j", "requested_by": "u"})
    engine.record_exception(ORG2, {"policy_id": p2["id"], "exception_type": "temporary", "justification": "j", "requested_by": "u"})
    assert len(engine.list_exceptions(ORG)) == 1
    assert len(engine.list_exceptions(ORG2)) == 1


def test_get_policy_org_isolation(engine):
    p = engine.create_policy(ORG, {"name": "P", "policy_domain": "identity"})
    assert engine.get_policy(ORG2, p["id"]) is None


def test_org_isolation_stats(engine):
    engine.create_policy(ORG, {"name": "P", "policy_domain": "network"})
    stats2 = engine.get_enforcement_stats(ORG2)
    assert stats2["total_policies"] == 0
