"""Tests for DeceptionAnalyticsEngine.

Covers asset lifecycle, interaction count increments, campaign stats,
org isolation, deactivate lifecycle, and statistics.

Total: 35 tests.
"""

from __future__ import annotations

import os
import pytest
from core.deception_analytics_engine import DeceptionAnalyticsEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "deception_analytics_test.db")
    return DeceptionAnalyticsEngine(db_path=db)


@pytest.fixture()
def asset(engine):
    return engine.register_asset("org1", {
        "asset_name": "Fake SSH Server",
        "asset_type": "honeypot",
        "location": "10.0.0.50",
        "decoy_category": "network",
        "active": True,
    })


@pytest.fixture()
def interaction(engine, asset):
    return engine.record_interaction("org1", {
        "asset_id": asset["id"],
        "source_ip": "192.168.1.100",
        "attacker_technique": "recon",
        "confidence_score": 75.0,
        "threat_actor_signature": "APT-42",
        "severity": "high",
        "details": "SSH brute force detected",
    })


@pytest.fixture()
def campaign(engine):
    return engine.create_campaign("org1", {
        "campaign_name": "Q1 Early Detection",
        "objective": "early_detection",
    })


# ===========================================================================
# 1. Initialisation
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "da_init.db")
    DeceptionAnalyticsEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "da_idem.db")
    DeceptionAnalyticsEngine(db_path=db)
    DeceptionAnalyticsEngine(db_path=db)


# ===========================================================================
# 2. Register Asset
# ===========================================================================

def test_register_asset_returns_dict(engine, asset):
    assert asset["id"]
    assert asset["asset_name"] == "Fake SSH Server"
    assert asset["asset_type"] == "honeypot"
    assert asset["location"] == "10.0.0.50"
    assert asset["decoy_category"] == "network"
    assert asset["active"] is True
    assert asset["interaction_count"] == 0


def test_register_asset_defaults(engine):
    a = engine.register_asset("org1", {"asset_name": "Minimal"})
    assert a["asset_type"] == "honeypot"
    assert a["decoy_category"] == "network"
    assert a["active"] is True


def test_register_asset_invalid_type(engine):
    with pytest.raises(ValueError, match="asset_type"):
        engine.register_asset("org1", {"asset_name": "X", "asset_type": "trap"})


def test_register_asset_invalid_decoy_category(engine):
    with pytest.raises(ValueError, match="decoy_category"):
        engine.register_asset("org1", {"asset_name": "X", "decoy_category": "physical"})


def test_register_asset_inactive(engine):
    a = engine.register_asset("org1", {"asset_name": "Inactive", "active": False})
    assert a["active"] is False


# ===========================================================================
# 3. List & Get Assets
# ===========================================================================

def test_list_assets_empty(engine):
    assert engine.list_assets("org1") == []


def test_list_assets_returns_all(engine, asset):
    engine.register_asset("org1", {"asset_name": "Second"})
    result = engine.list_assets("org1")
    assert len(result) == 2


def test_list_assets_filter_type(engine, asset):
    engine.register_asset("org1", {"asset_name": "Token", "asset_type": "honeytoken"})
    result = engine.list_assets("org1", asset_type="honeypot")
    assert all(a["asset_type"] == "honeypot" for a in result)


def test_list_assets_filter_active(engine, asset):
    engine.register_asset("org1", {"asset_name": "Inactive", "active": False})
    active = engine.list_assets("org1", active=True)
    assert all(a["active"] is True for a in active)
    inactive = engine.list_assets("org1", active=False)
    assert all(a["active"] is False for a in inactive)


def test_list_assets_org_isolation(engine, asset):
    assert engine.list_assets("org2") == []


def test_get_asset_returns_dict(engine, asset):
    result = engine.get_asset("org1", asset["id"])
    assert result is not None
    assert result["id"] == asset["id"]


def test_get_asset_wrong_org_returns_none(engine, asset):
    result = engine.get_asset("org2", asset["id"])
    assert result is None


def test_get_asset_not_found_returns_none(engine):
    assert engine.get_asset("org1", "nonexistent") is None


# ===========================================================================
# 4. Deactivate Asset
# ===========================================================================

def test_deactivate_asset_sets_active_false(engine, asset):
    result = engine.deactivate_asset("org1", asset["id"])
    assert result["active"] is False


def test_deactivate_asset_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.deactivate_asset("org1", "nonexistent-id")


def test_deactivate_asset_org_isolation(engine, asset):
    with pytest.raises(KeyError):
        engine.deactivate_asset("org2", asset["id"])


# ===========================================================================
# 5. Record Interaction
# ===========================================================================

def test_record_interaction_returns_dict(engine, interaction, asset):
    assert interaction["id"]
    assert interaction["asset_id"] == asset["id"]
    assert interaction["source_ip"] == "192.168.1.100"
    assert interaction["attacker_technique"] == "recon"
    assert interaction["confidence_score"] == 75.0
    assert interaction["threat_actor_signature"] == "APT-42"
    assert interaction["severity"] == "high"


def test_record_interaction_increments_asset_count(engine, asset, interaction):
    updated = engine.get_asset("org1", asset["id"])
    assert updated["interaction_count"] == 1


def test_record_interaction_multiple_increments(engine, asset):
    for i in range(5):
        engine.record_interaction("org1", {
            "asset_id": asset["id"],
            "source_ip": f"10.0.0.{i}",
        })
    updated = engine.get_asset("org1", asset["id"])
    assert updated["interaction_count"] == 5


def test_record_interaction_updates_last_interaction(engine, asset):
    assert asset["last_interaction"] is None
    engine.record_interaction("org1", {"asset_id": asset["id"], "source_ip": "1.2.3.4"})
    updated = engine.get_asset("org1", asset["id"])
    assert updated["last_interaction"] is not None


def test_record_interaction_confidence_clamped_high(engine, asset):
    r = engine.record_interaction("org1", {
        "asset_id": asset["id"], "source_ip": "1.1.1.1", "confidence_score": 200.0
    })
    assert r["confidence_score"] == 100.0


def test_record_interaction_confidence_clamped_low(engine, asset):
    r = engine.record_interaction("org1", {
        "asset_id": asset["id"], "source_ip": "1.1.1.1", "confidence_score": -50.0
    })
    assert r["confidence_score"] == 0.0


def test_record_interaction_invalid_technique(engine, asset):
    with pytest.raises(ValueError, match="attacker_technique"):
        engine.record_interaction("org1", {
            "asset_id": asset["id"], "source_ip": "1.1.1.1", "attacker_technique": "hacking"
        })


def test_record_interaction_invalid_severity(engine, asset):
    with pytest.raises(ValueError, match="severity"):
        engine.record_interaction("org1", {
            "asset_id": asset["id"], "source_ip": "1.1.1.1", "severity": "unknown"
        })


# ===========================================================================
# 6. List Interactions
# ===========================================================================

def test_list_interactions_empty(engine):
    assert engine.list_interactions("org1") == []


def test_list_interactions_filter_asset_id(engine, asset, interaction):
    other_asset = engine.register_asset("org1", {"asset_name": "Other"})
    engine.record_interaction("org1", {"asset_id": other_asset["id"], "source_ip": "9.9.9.9"})
    result = engine.list_interactions("org1", asset_id=asset["id"])
    assert all(i["asset_id"] == asset["id"] for i in result)


def test_list_interactions_filter_severity(engine, asset):
    engine.record_interaction("org1", {"asset_id": asset["id"], "source_ip": "1.1.1.1", "severity": "critical"})
    engine.record_interaction("org1", {"asset_id": asset["id"], "source_ip": "2.2.2.2", "severity": "low"})
    critical = engine.list_interactions("org1", severity="critical")
    assert all(i["severity"] == "critical" for i in critical)


def test_list_interactions_filter_technique(engine, asset):
    engine.record_interaction("org1", {
        "asset_id": asset["id"], "source_ip": "1.1.1.1",
        "attacker_technique": "exfiltration"
    })
    engine.record_interaction("org1", {
        "asset_id": asset["id"], "source_ip": "2.2.2.2",
        "attacker_technique": "recon"
    })
    result = engine.list_interactions("org1", attacker_technique="exfiltration")
    assert all(i["attacker_technique"] == "exfiltration" for i in result)


def test_list_interactions_org_isolation(engine, interaction):
    assert engine.list_interactions("org2") == []


# ===========================================================================
# 7. Campaigns
# ===========================================================================

def test_create_campaign_returns_dict(engine, campaign):
    assert campaign["id"]
    assert campaign["campaign_name"] == "Q1 Early Detection"
    assert campaign["objective"] == "early_detection"
    assert campaign["status"] == "active"
    assert campaign["asset_count"] == 0
    assert campaign["interaction_count"] == 0
    assert campaign["unique_attacker_ips"] == 0


def test_create_campaign_invalid_objective(engine):
    with pytest.raises(ValueError, match="objective"):
        engine.create_campaign("org1", {"campaign_name": "X", "objective": "revenge"})


def test_update_campaign_stats(engine, campaign):
    updated = engine.update_campaign_stats(
        "org1", campaign["id"],
        asset_count=5, interaction_count=12, unique_attacker_ips=3
    )
    assert updated["asset_count"] == 5
    assert updated["interaction_count"] == 12
    assert updated["unique_attacker_ips"] == 3


def test_update_campaign_stats_partial(engine, campaign):
    updated = engine.update_campaign_stats("org1", campaign["id"], asset_count=7)
    assert updated["asset_count"] == 7
    assert updated["interaction_count"] == 0  # unchanged


def test_update_campaign_stats_not_found(engine):
    with pytest.raises(KeyError):
        engine.update_campaign_stats("org1", "nonexistent-id", asset_count=1)


def test_update_campaign_stats_org_isolation(engine, campaign):
    with pytest.raises(KeyError):
        engine.update_campaign_stats("org2", campaign["id"], asset_count=1)


def test_list_campaigns_filter_status(engine, campaign):
    engine.create_campaign("org1", {"campaign_name": "C2", "objective": "attacker_profiling"})
    active = engine.list_campaigns("org1", status="active")
    assert len(active) == 2
    completed = engine.list_campaigns("org1", status="completed")
    assert len(completed) == 0


def test_list_campaigns_org_isolation(engine, campaign):
    assert engine.list_campaigns("org2") == []


# ===========================================================================
# 8. Statistics
# ===========================================================================

def test_get_deception_stats_empty(engine):
    stats = engine.get_deception_stats("org1")
    assert stats["total_assets"] == 0
    assert stats["active_assets"] == 0
    assert stats["total_interactions"] == 0
    assert stats["unique_attacker_ips"] == 0
    assert stats["critical_interactions"] == 0
    assert stats["total_campaigns"] == 0
    assert stats["by_asset_type"] == {}
    assert stats["by_attacker_technique"] == {}
    assert stats["by_severity"] == {}


def test_get_deception_stats_with_data(engine, asset, interaction, campaign):
    stats = engine.get_deception_stats("org1")
    assert stats["total_assets"] == 1
    assert stats["active_assets"] == 1
    assert stats["total_interactions"] == 1
    assert stats["unique_attacker_ips"] == 1
    assert stats["total_campaigns"] == 1
    assert "honeypot" in stats["by_asset_type"]
    assert "recon" in stats["by_attacker_technique"]
    assert "high" in stats["by_severity"]


def test_get_deception_stats_unique_ips(engine, asset):
    engine.record_interaction("org1", {"asset_id": asset["id"], "source_ip": "1.1.1.1"})
    engine.record_interaction("org1", {"asset_id": asset["id"], "source_ip": "1.1.1.1"})
    engine.record_interaction("org1", {"asset_id": asset["id"], "source_ip": "2.2.2.2"})
    stats = engine.get_deception_stats("org1")
    assert stats["unique_attacker_ips"] == 2


def test_get_deception_stats_critical_interactions(engine, asset):
    engine.record_interaction("org1", {
        "asset_id": asset["id"], "source_ip": "1.1.1.1", "severity": "critical"
    })
    engine.record_interaction("org1", {
        "asset_id": asset["id"], "source_ip": "2.2.2.2", "severity": "low"
    })
    stats = engine.get_deception_stats("org1")
    assert stats["critical_interactions"] == 1


def test_get_deception_stats_active_assets(engine):
    engine.register_asset("org1", {"asset_name": "Active1"})
    a2 = engine.register_asset("org1", {"asset_name": "ToDeactivate"})
    engine.deactivate_asset("org1", a2["id"])
    stats = engine.get_deception_stats("org1")
    assert stats["total_assets"] == 2
    assert stats["active_assets"] == 1


def test_get_deception_stats_org_isolation(engine, asset, interaction):
    stats = engine.get_deception_stats("org2")
    assert stats["total_assets"] == 0
    assert stats["total_interactions"] == 0
