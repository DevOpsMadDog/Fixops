"""Tests for suite-core/core/threat_actor_engine.py — ThreatActorEngine.

Tests cover:
- add_actor, list_actors, get_actor
- add_campaign, list_campaigns
- add_ioc, list_iocs
- add_to_watchlist, get_watchlist
- get_stats
- Validation errors (invalid enum values, missing required fields)
- Multi-tenant org isolation

Usage:
    pytest tests/test_threat_actor_engine.py -v --timeout=10
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_suite_core = str(Path(__file__).parent.parent / "suite-core")
if _suite_core not in sys.path:
    sys.path.insert(0, _suite_core)

from core.threat_actor_engine import ThreatActorEngine

ORG_A = "org-alpha"
ORG_B = "org-beta"


@pytest.fixture
def engine(tmp_path):
    return ThreatActorEngine(data_dir=str(tmp_path))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _actor(name="APT28", **kwargs):
    return {
        "name": name,
        "actor_type": "apt",
        "motivation": "espionage",
        "sophistication": "advanced",
        **kwargs,
    }


def _campaign(campaign_name="Operation Bear", **kwargs):
    return {
        "campaign_name": campaign_name,
        "status": "active",
        "impact_level": "high",
        "target_sectors": ["government", "defense"],
        "ttps_used": ["T1059", "T1078"],
        **kwargs,
    }


def _ioc(value="192.168.1.100", **kwargs):
    return {
        "ioc_type": "ip",
        "value": value,
        "confidence": 0.9,
        **kwargs,
    }


def _watchlist_entry(**kwargs):
    return {
        "added_by": "analyst-1",
        "reason": "Active threat to sector",
        "priority": "critical",
        "alert_on_ioc_match": True,
        **kwargs,
    }


# ---------------------------------------------------------------------------
# add_actor
# ---------------------------------------------------------------------------

def test_add_actor_returns_record(engine):
    rec = engine.add_actor(ORG_A, _actor())
    assert rec["id"]
    assert rec["name"] == "APT28"
    assert rec["org_id"] == ORG_A
    assert rec["actor_type"] == "apt"


def test_add_actor_defaults(engine):
    rec = engine.add_actor(ORG_A, _actor())
    assert rec["active"] is True
    assert rec["threat_score"] == 0.0
    assert rec["aliases"] == []


def test_add_actor_all_types(engine):
    for atype in ["nation_state", "cybercriminal", "hacktivist", "insider", "apt", "ransomware_group"]:
        rec = engine.add_actor(ORG_A, _actor(name=f"Group-{atype}", actor_type=atype))
        assert rec["actor_type"] == atype


def test_add_actor_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="Invalid actor_type"):
        engine.add_actor(ORG_A, _actor(actor_type="script_kiddie"))


def test_add_actor_invalid_motivation_raises(engine):
    with pytest.raises(ValueError, match="Invalid motivation"):
        engine.add_actor(ORG_A, _actor(motivation="fun"))


def test_add_actor_invalid_sophistication_raises(engine):
    with pytest.raises(ValueError, match="Invalid sophistication"):
        engine.add_actor(ORG_A, _actor(sophistication="elite"))


def test_add_actor_missing_name_raises(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.add_actor(ORG_A, {"actor_type": "apt", "motivation": "espionage", "sophistication": "high"})


def test_add_actor_with_aliases(engine):
    rec = engine.add_actor(ORG_A, _actor(aliases=["Fancy Bear", "Sofacy"]))
    assert "Fancy Bear" in rec["aliases"]


# ---------------------------------------------------------------------------
# list_actors / get_actor
# ---------------------------------------------------------------------------

def test_list_actors_empty(engine):
    assert engine.list_actors(ORG_A) == []


def test_list_actors_returns_all(engine):
    engine.add_actor(ORG_A, _actor("A"))
    engine.add_actor(ORG_A, _actor("B"))
    assert len(engine.list_actors(ORG_A)) == 2


def test_list_actors_filter_by_type(engine):
    engine.add_actor(ORG_A, _actor("APT28", actor_type="apt"))
    engine.add_actor(ORG_A, _actor("Lazarus", actor_type="nation_state"))
    apt_actors = engine.list_actors(ORG_A, actor_type="apt")
    assert len(apt_actors) == 1
    assert apt_actors[0]["name"] == "APT28"


def test_list_actors_filter_by_active(engine):
    engine.add_actor(ORG_A, _actor("Active", active=True))
    engine.add_actor(ORG_A, _actor("Dormant", active=False))
    active = engine.list_actors(ORG_A, active=True)
    assert all(a["active"] for a in active)


def test_list_actors_org_isolation(engine):
    engine.add_actor(ORG_A, _actor())
    assert engine.list_actors(ORG_B) == []


def test_get_actor_found(engine):
    rec = engine.add_actor(ORG_A, _actor())
    fetched = engine.get_actor(ORG_A, rec["id"])
    assert fetched is not None
    assert fetched["id"] == rec["id"]
    assert "campaigns" in fetched
    assert "ioc_count" in fetched


def test_get_actor_not_found(engine):
    assert engine.get_actor(ORG_A, "nonexistent") is None


def test_get_actor_wrong_org(engine):
    rec = engine.add_actor(ORG_A, _actor())
    assert engine.get_actor(ORG_B, rec["id"]) is None


def test_get_actor_includes_campaigns(engine):
    actor = engine.add_actor(ORG_A, _actor())
    engine.add_campaign(ORG_A, actor["id"], _campaign())
    fetched = engine.get_actor(ORG_A, actor["id"])
    assert len(fetched["campaigns"]) == 1


def test_get_actor_ioc_count(engine):
    actor = engine.add_actor(ORG_A, _actor())
    engine.add_ioc(ORG_A, actor["id"], _ioc())
    engine.add_ioc(ORG_A, actor["id"], _ioc("10.0.0.1"))
    fetched = engine.get_actor(ORG_A, actor["id"])
    assert fetched["ioc_count"] == 2


# ---------------------------------------------------------------------------
# add_campaign / list_campaigns
# ---------------------------------------------------------------------------

def test_add_campaign_returns_record(engine):
    actor = engine.add_actor(ORG_A, _actor())
    camp = engine.add_campaign(ORG_A, actor["id"], _campaign())
    assert camp["id"]
    assert camp["campaign_name"] == "Operation Bear"
    assert camp["actor_id"] == actor["id"]


def test_add_campaign_invalid_status_raises(engine):
    actor = engine.add_actor(ORG_A, _actor())
    with pytest.raises(ValueError, match="Invalid status"):
        engine.add_campaign(ORG_A, actor["id"], _campaign(status="paused"))


def test_add_campaign_invalid_impact_raises(engine):
    actor = engine.add_actor(ORG_A, _actor())
    with pytest.raises(ValueError, match="Invalid impact_level"):
        engine.add_campaign(ORG_A, actor["id"], _campaign(impact_level="catastrophic"))


def test_add_campaign_missing_name_raises(engine):
    actor = engine.add_actor(ORG_A, _actor())
    with pytest.raises(ValueError, match="campaign_name is required"):
        engine.add_campaign(ORG_A, actor["id"], {"status": "active"})


def test_list_campaigns_empty(engine):
    assert engine.list_campaigns(ORG_A) == []


def test_list_campaigns_filter_by_actor(engine):
    a1 = engine.add_actor(ORG_A, _actor("A1"))
    a2 = engine.add_actor(ORG_A, _actor("A2"))
    engine.add_campaign(ORG_A, a1["id"], _campaign("Camp1"))
    engine.add_campaign(ORG_A, a2["id"], _campaign("Camp2"))
    camps = engine.list_campaigns(ORG_A, actor_id=a1["id"])
    assert len(camps) == 1
    assert camps[0]["campaign_name"] == "Camp1"


def test_list_campaigns_filter_by_status(engine):
    actor = engine.add_actor(ORG_A, _actor())
    engine.add_campaign(ORG_A, actor["id"], _campaign("Active", status="active"))
    engine.add_campaign(ORG_A, actor["id"], _campaign("Done", status="concluded"))
    active = engine.list_campaigns(ORG_A, status="active")
    assert all(c["status"] == "active" for c in active)


def test_list_campaigns_org_isolation(engine):
    actor = engine.add_actor(ORG_A, _actor())
    engine.add_campaign(ORG_A, actor["id"], _campaign())
    assert engine.list_campaigns(ORG_B) == []


# ---------------------------------------------------------------------------
# add_ioc / list_iocs
# ---------------------------------------------------------------------------

def test_add_ioc_returns_record(engine):
    actor = engine.add_actor(ORG_A, _actor())
    ioc = engine.add_ioc(ORG_A, actor["id"], _ioc())
    assert ioc["id"]
    assert ioc["ioc_type"] == "ip"
    assert ioc["value"] == "192.168.1.100"


def test_add_ioc_all_types(engine):
    actor = engine.add_actor(ORG_A, _actor())
    for itype in ["ip", "domain", "hash", "email", "url", "mutex", "registry"]:
        ioc = engine.add_ioc(ORG_A, actor["id"], _ioc(f"test-{itype}", ioc_type=itype))
        assert ioc["ioc_type"] == itype


def test_add_ioc_invalid_type_raises(engine):
    actor = engine.add_actor(ORG_A, _actor())
    with pytest.raises(ValueError, match="Invalid ioc_type"):
        engine.add_ioc(ORG_A, actor["id"], _ioc(ioc_type="certificate"))


def test_add_ioc_missing_value_raises(engine):
    actor = engine.add_actor(ORG_A, _actor())
    with pytest.raises(ValueError, match="value is required"):
        engine.add_ioc(ORG_A, actor["id"], {"ioc_type": "ip", "value": ""})


def test_list_iocs_empty(engine):
    assert engine.list_iocs(ORG_A) == []


def test_list_iocs_filter_by_actor(engine):
    a1 = engine.add_actor(ORG_A, _actor("A1"))
    a2 = engine.add_actor(ORG_A, _actor("A2"))
    engine.add_ioc(ORG_A, a1["id"], _ioc("1.1.1.1"))
    engine.add_ioc(ORG_A, a2["id"], _ioc("2.2.2.2"))
    iocs = engine.list_iocs(ORG_A, actor_id=a1["id"])
    assert len(iocs) == 1
    assert iocs[0]["value"] == "1.1.1.1"


def test_list_iocs_filter_by_type(engine):
    actor = engine.add_actor(ORG_A, _actor())
    engine.add_ioc(ORG_A, actor["id"], _ioc("1.1.1.1", ioc_type="ip"))
    engine.add_ioc(ORG_A, actor["id"], _ioc("evil.com", ioc_type="domain"))
    domains = engine.list_iocs(ORG_A, ioc_type="domain")
    assert all(i["ioc_type"] == "domain" for i in domains)


def test_list_iocs_filter_by_active(engine):
    actor = engine.add_actor(ORG_A, _actor())
    engine.add_ioc(ORG_A, actor["id"], _ioc("1.1.1.1", active=True))
    engine.add_ioc(ORG_A, actor["id"], _ioc("2.2.2.2", active=False))
    active = engine.list_iocs(ORG_A, active=True)
    assert all(i["active"] for i in active)


def test_list_iocs_org_isolation(engine):
    actor = engine.add_actor(ORG_A, _actor())
    engine.add_ioc(ORG_A, actor["id"], _ioc())
    assert engine.list_iocs(ORG_B) == []


# ---------------------------------------------------------------------------
# add_to_watchlist / get_watchlist
# ---------------------------------------------------------------------------

def test_add_to_watchlist_returns_record(engine):
    actor = engine.add_actor(ORG_A, _actor())
    entry = engine.add_to_watchlist(ORG_A, actor["id"], _watchlist_entry())
    assert entry["id"]
    assert entry["actor_id"] == actor["id"]
    assert entry["priority"] == "critical"
    assert entry["alert_on_ioc_match"] is True


def test_add_to_watchlist_invalid_priority_raises(engine):
    actor = engine.add_actor(ORG_A, _actor())
    with pytest.raises(ValueError, match="Invalid priority"):
        engine.add_to_watchlist(ORG_A, actor["id"], _watchlist_entry(priority="urgent"))


def test_get_watchlist_empty(engine):
    assert engine.get_watchlist(ORG_A) == []


def test_get_watchlist_returns_entries(engine):
    a1 = engine.add_actor(ORG_A, _actor("A1"))
    a2 = engine.add_actor(ORG_A, _actor("A2"))
    engine.add_to_watchlist(ORG_A, a1["id"], _watchlist_entry(priority="high"))
    engine.add_to_watchlist(ORG_A, a2["id"], _watchlist_entry(priority="critical"))
    wl = engine.get_watchlist(ORG_A)
    assert len(wl) == 2
    # critical comes first
    assert wl[0]["priority"] == "critical"


def test_get_watchlist_org_isolation(engine):
    actor = engine.add_actor(ORG_A, _actor())
    engine.add_to_watchlist(ORG_A, actor["id"], _watchlist_entry())
    assert engine.get_watchlist(ORG_B) == []


# ---------------------------------------------------------------------------
# get_stats
# ---------------------------------------------------------------------------

def test_get_stats_empty(engine):
    stats = engine.get_stats(ORG_A)
    assert stats["actor_count"] == 0
    assert stats["active_campaigns"] == 0
    assert stats["total_iocs"] == 0
    assert stats["watchlist_size"] == 0


def test_get_stats_counts_actors(engine):
    engine.add_actor(ORG_A, _actor("A"))
    engine.add_actor(ORG_A, _actor("B"))
    stats = engine.get_stats(ORG_A)
    assert stats["actor_count"] == 2


def test_get_stats_counts_campaigns(engine):
    actor = engine.add_actor(ORG_A, _actor())
    engine.add_campaign(ORG_A, actor["id"], _campaign(status="active"))
    engine.add_campaign(ORG_A, actor["id"], _campaign("Done", status="concluded"))
    stats = engine.get_stats(ORG_A)
    assert stats["active_campaigns"] == 1


def test_get_stats_counts_iocs(engine):
    actor = engine.add_actor(ORG_A, _actor())
    engine.add_ioc(ORG_A, actor["id"], _ioc("1.1.1.1"))
    engine.add_ioc(ORG_A, actor["id"], _ioc("2.2.2.2"))
    stats = engine.get_stats(ORG_A)
    assert stats["total_iocs"] == 2


def test_get_stats_by_sophistication(engine):
    engine.add_actor(ORG_A, _actor("A", sophistication="advanced"))
    engine.add_actor(ORG_A, _actor("B", sophistication="high"))
    stats = engine.get_stats(ORG_A)
    assert stats["by_sophistication"].get("advanced", 0) >= 1


def test_get_stats_top_targeted_sectors(engine):
    actor = engine.add_actor(ORG_A, _actor())
    engine.add_campaign(ORG_A, actor["id"], _campaign(target_sectors=["finance", "energy"]))
    engine.add_campaign(ORG_A, actor["id"], _campaign("C2", target_sectors=["finance"]))
    stats = engine.get_stats(ORG_A)
    sectors = {s["sector"]: s["count"] for s in stats["top_targeted_sectors"]}
    assert sectors.get("finance", 0) == 2


def test_get_stats_org_isolation(engine):
    engine.add_actor(ORG_A, _actor())
    stats_b = engine.get_stats(ORG_B)
    assert stats_b["actor_count"] == 0
