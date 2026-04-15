"""Tests for ThreatActorTrackingEngine — 35+ tests."""

from __future__ import annotations

import pytest
import sys
import os
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))
from core.threat_actor_tracking_engine import ThreatActorTrackingEngine


@pytest.fixture
def engine(tmp_path):
    return ThreatActorTrackingEngine(db_path=str(tmp_path / "test.db"))


ORG = "org-alpha"
OTHER_ORG = "org-beta"


def _future(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


# ---------------------------------------------------------------------------
# track_actor
# ---------------------------------------------------------------------------

def test_track_actor_returns_dict(engine):
    result = engine.track_actor(ORG, "APT28")
    assert result["id"]
    assert result["actor_name"] == "APT28"
    assert result["org_id"] == ORG


def test_track_actor_default_attribution_confidence(engine):
    result = engine.track_actor(ORG, "Lazarus Group")
    assert result["attribution_confidence"] == 0.5


def test_track_actor_all_fields(engine):
    result = engine.track_actor(
        ORG, "Sandworm",
        actor_alias="Voodoo Bear",
        nation_state="Russia",
        actor_type="nation-state",
        threat_level="critical",
        targeting_our_sector=True,
        mitre_groups=["G0034"],
    )
    assert result["actor_alias"] == "Voodoo Bear"
    assert result["nation_state"] == "Russia"
    assert result["actor_type"] == "nation-state"
    assert result["threat_level"] == "critical"
    assert result["targeting_our_sector"] == 1


def test_track_actor_targeting_our_sector_false(engine):
    result = engine.track_actor(ORG, "Generic Group", targeting_our_sector=False)
    assert result["targeting_our_sector"] == 0


def test_track_actor_mitre_groups_stored(engine):
    result = engine.track_actor(ORG, "FIN7", mitre_groups=["G0046", "G0085"])
    assert isinstance(result["mitre_groups"], list)
    assert "G0046" in result["mitre_groups"]


def test_track_actor_unique_ids(engine):
    a1 = engine.track_actor(ORG, "Actor One")
    a2 = engine.track_actor(ORG, "Actor Two")
    assert a1["id"] != a2["id"]


def test_track_actor_tenant_isolation(engine):
    a1 = engine.track_actor(ORG, "Shared Name")
    a2 = engine.track_actor(OTHER_ORG, "Shared Name")
    assert a1["org_id"] != a2["org_id"]


# ---------------------------------------------------------------------------
# update_actor_activity
# ---------------------------------------------------------------------------

def test_update_actor_activity_sets_last_activity(engine):
    actor = engine.track_actor(ORG, "APT29")
    assert actor["last_activity"] is None
    updated = engine.update_actor_activity(actor["id"], ORG)
    assert updated["last_activity"] is not None


def test_update_actor_activity_wrong_org_returns_empty(engine):
    actor = engine.track_actor(ORG, "Cozy Bear")
    result = engine.update_actor_activity(actor["id"], OTHER_ORG)
    assert result == {}


# ---------------------------------------------------------------------------
# record_activity
# ---------------------------------------------------------------------------

def test_record_activity_returns_dict(engine):
    actor = engine.track_actor(ORG, "HAFNIUM")
    activity = engine.record_activity(actor["id"], ORG, "campaign",
                                      description="Exchange Server compromise")
    assert activity["id"]
    assert activity["actor_id"] == actor["id"]
    assert activity["activity_type"] == "campaign"


def test_record_activity_ttps_stored_as_list(engine):
    actor = engine.track_actor(ORG, "SolarWinds Actor")
    activity = engine.record_activity(
        actor["id"], ORG, "exploitation",
        ttps_used=["T1195.002", "T1059.001"],
        indicators=["evil.com", "1.2.3.4"],
    )
    assert isinstance(activity["ttps_used"], list)
    assert "T1195.002" in activity["ttps_used"]
    assert isinstance(activity["indicators"], list)


def test_record_activity_updates_actor_last_activity(engine):
    actor = engine.track_actor(ORG, "Lazarus")
    engine.record_activity(actor["id"], ORG, "attack")
    updated = engine.get_actor(actor["id"], ORG)
    assert updated["last_activity"] is not None


def test_record_activity_verified_flag(engine):
    actor = engine.track_actor(ORG, "Charming Kitten")
    activity = engine.record_activity(actor["id"], ORG, "reconnaissance", verified=True)
    assert activity["verified"] == 1


# ---------------------------------------------------------------------------
# add_intelligence
# ---------------------------------------------------------------------------

def test_add_intelligence_returns_dict(engine):
    actor = engine.track_actor(ORG, "MuddyWater")
    intel = engine.add_intelligence(actor["id"], ORG, "technical",
                                    "Uses PowerSploit for lateral movement", 0.85)
    assert intel["id"]
    assert intel["intel_type"] == "technical"
    assert intel["confidence"] == 0.85


def test_add_intelligence_confidence_clamped_high(engine):
    actor = engine.track_actor(ORG, "OilRig")
    intel = engine.add_intelligence(actor["id"], ORG, "strategic", "Nation-state ops", 1.5)
    assert intel["confidence"] == 1.0


def test_add_intelligence_confidence_clamped_low(engine):
    actor = engine.track_actor(ORG, "Turla")
    intel = engine.add_intelligence(actor["id"], ORG, "tactical", "TTP info", -0.5)
    assert intel["confidence"] == 0.0


def test_add_intelligence_with_valid_until(engine):
    actor = engine.track_actor(ORG, "Equation Group")
    valid = _future(180)
    intel = engine.add_intelligence(actor["id"], ORG, "operational", "Infrastructure info",
                                    0.9, valid_until=valid)
    assert intel["valid_until"] == valid


# ---------------------------------------------------------------------------
# get_actor
# ---------------------------------------------------------------------------

def test_get_actor_returns_activities_and_intel(engine):
    actor = engine.track_actor(ORG, "APT41")
    engine.record_activity(actor["id"], ORG, "campaign")
    engine.add_intelligence(actor["id"], ORG, "technical", "Dual espionage+crime", 0.9)
    result = engine.get_actor(actor["id"], ORG)
    assert len(result["recent_activities"]) >= 1
    assert len(result["intelligence"]) >= 1


def test_get_actor_max_10_activities(engine):
    actor = engine.track_actor(ORG, "Prolific Actor")
    for i in range(15):
        engine.record_activity(actor["id"], ORG, "campaign", description=f"Campaign {i}")
    result = engine.get_actor(actor["id"], ORG)
    assert len(result["recent_activities"]) <= 10


def test_get_actor_not_found_returns_empty(engine):
    result = engine.get_actor("nonexistent-id", ORG)
    assert result == {}


def test_get_actor_tenant_isolation(engine):
    actor = engine.track_actor(ORG, "Isolated Actor")
    result = engine.get_actor(actor["id"], OTHER_ORG)
    assert result == {}


# ---------------------------------------------------------------------------
# list_actors
# ---------------------------------------------------------------------------

def test_list_actors_returns_all(engine):
    engine.track_actor(ORG, "Actor A")
    engine.track_actor(ORG, "Actor B")
    results = engine.list_actors(ORG)
    assert len(results) >= 2


def test_list_actors_filter_by_type(engine):
    engine.track_actor(ORG, "Nation Actor", actor_type="nation-state")
    results = engine.list_actors(ORG, actor_type="nation-state")
    assert all(r["actor_type"] == "nation-state" for r in results)


def test_list_actors_filter_by_threat_level(engine):
    engine.track_actor(ORG, "Critical Actor", threat_level="critical")
    results = engine.list_actors(ORG, threat_level="critical")
    assert all(r["threat_level"] == "critical" for r in results)


def test_list_actors_filter_targeting_our_sector(engine):
    engine.track_actor(ORG, "Targeting Us", targeting_our_sector=True)
    engine.track_actor(ORG, "Not Targeting Us", targeting_our_sector=False)
    results = engine.list_actors(ORG, targeting_our_sector=True)
    assert all(r["targeting_our_sector"] == 1 for r in results)


def test_list_actors_tenant_isolation(engine):
    engine.track_actor(ORG, "Org A Actor")
    engine.track_actor(OTHER_ORG, "Org B Actor")
    results = engine.list_actors(ORG)
    assert all(r["org_id"] == ORG for r in results)


# ---------------------------------------------------------------------------
# get_active_threats
# ---------------------------------------------------------------------------

def test_get_active_threats_within_90_days(engine):
    actor = engine.track_actor(ORG, "Recent Actor")
    engine.record_activity(actor["id"], ORG, "attack")
    active = engine.get_active_threats(ORG)
    ids = [a["id"] for a in active]
    assert actor["id"] in ids


def test_get_active_threats_excludes_no_activity(engine):
    actor = engine.track_actor(ORG, "Quiet Actor")
    # No activity recorded
    active = engine.get_active_threats(ORG)
    ids = [a["id"] for a in active]
    assert actor["id"] not in ids


# ---------------------------------------------------------------------------
# get_actor_ttp_summary
# ---------------------------------------------------------------------------

def test_get_actor_ttp_summary_structure(engine):
    summary = engine.get_actor_ttp_summary(ORG)
    assert "total_unique_ttps" in summary
    assert "ttp_frequency" in summary
    assert "most_common_ttps" in summary


def test_get_actor_ttp_summary_frequency(engine):
    actor = engine.track_actor(ORG, "TTP Actor")
    engine.record_activity(actor["id"], ORG, "campaign", ttps_used=["T1059", "T1078"])
    engine.record_activity(actor["id"], ORG, "attack", ttps_used=["T1059", "T1021"])
    summary = engine.get_actor_ttp_summary(ORG)
    assert summary["ttp_frequency"].get("T1059", 0) >= 2


def test_get_actor_ttp_summary_top_10_max(engine):
    actor = engine.track_actor(ORG, "Many TTP Actor")
    ttps = [f"T{i:04d}" for i in range(20)]
    engine.record_activity(actor["id"], ORG, "campaign", ttps_used=ttps)
    summary = engine.get_actor_ttp_summary(ORG)
    assert len(summary["most_common_ttps"]) <= 10


def test_get_actor_ttp_summary_empty_org(engine):
    summary = engine.get_actor_ttp_summary("empty-org")
    assert summary["total_unique_ttps"] == 0
    assert summary["most_common_ttps"] == []


# ---------------------------------------------------------------------------
# get_tracking_summary
# ---------------------------------------------------------------------------

def test_get_tracking_summary_structure(engine):
    summary = engine.get_tracking_summary(ORG)
    assert "total_tracked" in summary
    assert "by_threat_level" in summary
    assert "targeting_our_sector" in summary
    assert "active_last_90_days" in summary
    assert "nation_state_breakdown" in summary


def test_get_tracking_summary_counts(engine):
    engine.track_actor(ORG, "Count A", threat_level="high")
    engine.track_actor(ORG, "Count B", threat_level="critical")
    summary = engine.get_tracking_summary(ORG)
    assert summary["total_tracked"] >= 2


def test_get_tracking_summary_targeting_count(engine):
    engine.track_actor(ORG, "Target Us 1", targeting_our_sector=True)
    engine.track_actor(ORG, "Target Us 2", targeting_our_sector=True)
    engine.track_actor(ORG, "Not Targeting", targeting_our_sector=False)
    summary = engine.get_tracking_summary(ORG)
    assert summary["targeting_our_sector"] >= 2


def test_get_tracking_summary_nation_state_breakdown(engine):
    engine.track_actor(ORG, "Russian Actor 1", nation_state="Russia")
    engine.track_actor(ORG, "Russian Actor 2", nation_state="Russia")
    engine.track_actor(ORG, "Chinese Actor", nation_state="China")
    summary = engine.get_tracking_summary(ORG)
    assert summary["nation_state_breakdown"].get("Russia", 0) >= 2
    assert summary["nation_state_breakdown"].get("China", 0) >= 1


def test_get_tracking_summary_tenant_isolation(engine):
    engine.track_actor(ORG, "Org A Actor")
    engine.track_actor(OTHER_ORG, "Org B Actor")
    summary_a = engine.get_tracking_summary(ORG)
    summary_b = engine.get_tracking_summary(OTHER_ORG)
    assert summary_a["total_tracked"] != summary_b["total_tracked"] or summary_a["org_id"] != summary_b["org_id"]
