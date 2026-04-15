"""Tests for ThreatDeceptionManagementEngine.

Covers decoy lifecycle, interaction recording, interaction_count increment,
campaign creation, org isolation, validation errors, and statistics.

Total: 35 tests.
"""

from __future__ import annotations

import os
import pytest
from core.threat_deception_management_engine import ThreatDeceptionManagementEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "tdm_test.db")
    return ThreatDeceptionManagementEngine(db_path=db)


@pytest.fixture()
def decoy(engine):
    return engine.create_decoy("org1", {
        "name": "Fake SSH Server",
        "decoy_type": "honeypot",
        "ip_address": "10.0.0.50",
        "port": 22,
        "description": "SSH honeypot",
    })


@pytest.fixture()
def interaction(engine, decoy):
    return engine.record_interaction("org1", decoy["id"], {
        "interaction_type": "login_attempt",
        "source_ip": "192.168.1.100",
        "user_agent": "masscan/1.0",
        "payload_preview": "root:password123",
        "attacker_fingerprint": "fp-abc123",
    })


@pytest.fixture()
def campaign(engine):
    return engine.create_campaign("org1", {
        "name": "Q1 Deception Campaign",
        "description": "Catch lateral movers",
        "objective": "early_detection",
    })


# ===========================================================================
# 1. Initialisation
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "tdm_init.db")
    ThreatDeceptionManagementEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "tdm_idem.db")
    ThreatDeceptionManagementEngine(db_path=db)
    ThreatDeceptionManagementEngine(db_path=db)  # second init is safe


# ===========================================================================
# 2. create_decoy
# ===========================================================================

def test_create_decoy_returns_dict(engine, decoy):
    assert decoy["id"]
    assert decoy["name"] == "Fake SSH Server"
    assert decoy["decoy_type"] == "honeypot"
    assert decoy["ip_address"] == "10.0.0.50"
    assert decoy["port"] == 22
    assert decoy["active"] is True
    assert decoy["interaction_count"] == 0
    assert decoy["org_id"] == "org1"


def test_create_decoy_missing_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.create_decoy("org1", {"decoy_type": "honeypot"})


def test_create_decoy_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="decoy_type"):
        engine.create_decoy("org1", {"name": "Bad", "decoy_type": "invalid_type"})


def test_create_decoy_all_valid_types(engine):
    for dtype in ("honeypot", "honeytoken", "honeydoc", "fake_service", "canary_endpoint"):
        d = engine.create_decoy("org1", {"name": f"Decoy-{dtype}", "decoy_type": dtype})
        assert d["decoy_type"] == dtype


def test_create_decoy_inactive(engine):
    d = engine.create_decoy("org1", {"name": "Inactive Decoy", "active": False})
    assert d["active"] is False


def test_create_decoy_assigns_unique_ids(engine):
    d1 = engine.create_decoy("org1", {"name": "D1"})
    d2 = engine.create_decoy("org1", {"name": "D2"})
    assert d1["id"] != d2["id"]


# ===========================================================================
# 3. list_decoys / get_decoy
# ===========================================================================

def test_list_decoys_returns_all(engine, decoy):
    engine.create_decoy("org1", {"name": "Second Decoy", "decoy_type": "honeytoken"})
    results = engine.list_decoys("org1")
    assert len(results) == 2


def test_list_decoys_filter_by_type(engine, decoy):
    engine.create_decoy("org1", {"name": "Token", "decoy_type": "honeytoken"})
    results = engine.list_decoys("org1", decoy_type="honeypot")
    assert all(d["decoy_type"] == "honeypot" for d in results)
    assert len(results) == 1


def test_list_decoys_filter_by_active(engine):
    engine.create_decoy("org1", {"name": "Active", "active": True})
    engine.create_decoy("org1", {"name": "Inactive", "active": False})
    active = engine.list_decoys("org1", active=True)
    inactive = engine.list_decoys("org1", active=False)
    assert all(d["active"] is True for d in active)
    assert all(d["active"] is False for d in inactive)


def test_list_decoys_org_isolation(engine, decoy):
    results = engine.list_decoys("org2")
    assert results == []


def test_get_decoy_returns_correct(engine, decoy):
    result = engine.get_decoy("org1", decoy["id"])
    assert result["id"] == decoy["id"]
    assert result["name"] == "Fake SSH Server"


def test_get_decoy_wrong_org_returns_none(engine, decoy):
    result = engine.get_decoy("org2", decoy["id"])
    assert result is None


def test_get_decoy_nonexistent_returns_none(engine):
    result = engine.get_decoy("org1", "nonexistent-id")
    assert result is None


# ===========================================================================
# 4. record_interaction / interaction_count
# ===========================================================================

def test_record_interaction_returns_dict(engine, interaction):
    assert interaction["id"]
    assert interaction["interaction_type"] == "login_attempt"
    assert interaction["source_ip"] == "192.168.1.100"
    assert interaction["user_agent"] == "masscan/1.0"
    assert interaction["payload_preview"] == "root:password123"
    assert interaction["attacker_fingerprint"] == "fp-abc123"


def test_record_interaction_increments_count(engine, decoy, interaction):
    updated = engine.get_decoy("org1", decoy["id"])
    assert updated["interaction_count"] == 1


def test_record_interaction_multiple_increments(engine, decoy):
    for _ in range(5):
        engine.record_interaction("org1", decoy["id"], {"interaction_type": "scan"})
    updated = engine.get_decoy("org1", decoy["id"])
    assert updated["interaction_count"] == 5


def test_record_interaction_invalid_type_raises(engine, decoy):
    with pytest.raises(ValueError, match="interaction_type"):
        engine.record_interaction("org1", decoy["id"], {"interaction_type": "teleport"})


def test_record_interaction_all_valid_types(engine, decoy):
    for itype in ("scan", "login_attempt", "file_access", "network_probe", "data_exfil"):
        r = engine.record_interaction("org1", decoy["id"], {"interaction_type": itype})
        assert r["interaction_type"] == itype


# ===========================================================================
# 5. list_interactions
# ===========================================================================

def test_list_interactions_returns_all(engine, decoy):
    engine.record_interaction("org1", decoy["id"], {"interaction_type": "scan"})
    engine.record_interaction("org1", decoy["id"], {"interaction_type": "file_access"})
    results = engine.list_interactions("org1")
    assert len(results) == 2


def test_list_interactions_filter_by_decoy_id(engine):
    d1 = engine.create_decoy("org1", {"name": "D1"})
    d2 = engine.create_decoy("org1", {"name": "D2"})
    engine.record_interaction("org1", d1["id"], {"interaction_type": "scan"})
    engine.record_interaction("org1", d2["id"], {"interaction_type": "scan"})
    results = engine.list_interactions("org1", decoy_id=d1["id"])
    assert len(results) == 1
    assert results[0]["decoy_id"] == d1["id"]


def test_list_interactions_filter_by_type(engine, decoy):
    engine.record_interaction("org1", decoy["id"], {"interaction_type": "scan"})
    engine.record_interaction("org1", decoy["id"], {"interaction_type": "file_access"})
    results = engine.list_interactions("org1", interaction_type="scan")
    assert all(r["interaction_type"] == "scan" for r in results)


def test_list_interactions_org_isolation(engine, decoy, interaction):
    results = engine.list_interactions("org2")
    assert results == []


def test_list_interactions_ordered_desc(engine, decoy):
    engine.record_interaction("org1", decoy["id"], {"interaction_type": "scan"})
    engine.record_interaction("org1", decoy["id"], {"interaction_type": "file_access"})
    results = engine.list_interactions("org1")
    # occurred_at DESC — most recent first
    assert results[0]["occurred_at"] >= results[-1]["occurred_at"]


# ===========================================================================
# 6. Campaigns
# ===========================================================================

def test_create_campaign_returns_dict(engine, campaign):
    assert campaign["id"]
    assert campaign["name"] == "Q1 Deception Campaign"
    assert campaign["status"] == "active"
    assert campaign["org_id"] == "org1"


def test_create_campaign_invalid_status_raises(engine):
    with pytest.raises(ValueError, match="status"):
        engine.create_campaign("org1", {"name": "Bad", "status": "unknown_status"})


def test_list_campaigns_filter_by_status(engine, campaign):
    engine.create_campaign("org1", {"name": "Completed", "status": "completed"})
    active = engine.list_campaigns("org1", status="active")
    assert all(c["status"] == "active" for c in active)
    completed = engine.list_campaigns("org1", status="completed")
    assert all(c["status"] == "completed" for c in completed)


def test_list_campaigns_org_isolation(engine, campaign):
    results = engine.list_campaigns("org2")
    assert results == []


# ===========================================================================
# 7. get_deception_stats
# ===========================================================================

def test_get_deception_stats_empty(engine):
    stats = engine.get_deception_stats("org1")
    assert stats["total_decoys"] == 0
    assert stats["active_decoys"] == 0
    assert stats["total_interactions"] == 0
    assert stats["unique_attackers"] == 0
    assert stats["hottest_decoy"] is None
    assert stats["by_interaction_type"] == {}


def test_get_deception_stats_counts(engine, decoy, interaction):
    # Add another interaction from a different IP
    engine.record_interaction("org1", decoy["id"], {
        "interaction_type": "scan",
        "source_ip": "10.10.10.10",
    })
    stats = engine.get_deception_stats("org1")
    assert stats["total_decoys"] == 1
    assert stats["active_decoys"] == 1
    assert stats["total_interactions"] == 2
    assert stats["unique_attackers"] == 2
    assert stats["hottest_decoy"] == decoy["id"]


def test_get_deception_stats_by_interaction_type(engine, decoy):
    engine.record_interaction("org1", decoy["id"], {"interaction_type": "scan"})
    engine.record_interaction("org1", decoy["id"], {"interaction_type": "scan"})
    engine.record_interaction("org1", decoy["id"], {"interaction_type": "file_access"})
    stats = engine.get_deception_stats("org1")
    assert stats["by_interaction_type"]["scan"] == 2
    assert stats["by_interaction_type"]["file_access"] == 1


def test_get_deception_stats_org_isolation(engine, decoy, interaction):
    stats = engine.get_deception_stats("org2")
    assert stats["total_decoys"] == 0
    assert stats["total_interactions"] == 0
