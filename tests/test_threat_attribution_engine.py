"""Tests for ThreatAttributionEngine — ALDECI.

Coverage: threat actor CRUD, attribution lifecycle, indicators, stats, validation, org isolation.
"""

from __future__ import annotations

import pytest

from core.threat_attribution_engine import ThreatAttributionEngine


@pytest.fixture
def engine(tmp_path):
    return ThreatAttributionEngine(db_path=str(tmp_path / "ta.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_actor(engine, org_id="org1", name="APT28", actor_type="nation_state"):
    return engine.create_threat_actor(org_id, {
        "name": name,
        "actor_type": actor_type,
        "origin_country": "RU",
        "motivation": "espionage",
        "sophistication": "advanced",
    })


def _make_attribution(engine, org_id="org1", incident_id="INC-001", confidence="likely", actor_id=""):
    return engine.create_attribution(org_id, {
        "incident_id": incident_id,
        "actor_id": actor_id,
        "confidence": confidence,
        "analyst": "alice",
        "notes": "Initial assessment",
    })


# ---------------------------------------------------------------------------
# create_threat_actor — valid types
# ---------------------------------------------------------------------------

VALID_ACTOR_TYPES = [
    "nation_state", "criminal_group", "hacktivist", "insider", "competitor", "unknown"
]


@pytest.mark.parametrize("actor_type", VALID_ACTOR_TYPES)
def test_create_actor_all_types(engine, actor_type):
    actor = engine.create_threat_actor("org1", {
        "name": f"Actor-{actor_type}",
        "actor_type": actor_type,
    })
    assert actor["actor_type"] == actor_type
    assert actor["org_id"] == "org1"
    assert "id" in actor
    assert "created_at" in actor


def test_create_actor_name_required_raises(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.create_threat_actor("org1", {"actor_type": "nation_state"})


def test_create_actor_empty_name_raises(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.create_threat_actor("org1", {"name": "   ", "actor_type": "nation_state"})


def test_create_actor_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="actor_type"):
        engine.create_threat_actor("org1", {"name": "BadActor", "actor_type": "alien"})


def test_create_actor_defaults(engine):
    actor = engine.create_threat_actor("org1", {"name": "Unknown Actor"})
    assert actor["actor_type"] == "unknown"
    assert actor["sophistication"] == "basic"
    assert actor["active"] == 1
    assert actor["aliases_json"] == "[]"
    assert actor["origin_country"] == ""
    assert actor["motivation"] == ""


def test_create_actor_with_aliases(engine):
    import json
    actor = engine.create_threat_actor("org1", {
        "name": "Fancy Bear",
        "actor_type": "nation_state",
        "aliases": ["APT28", "STRONTIUM", "Sofacy"],
    })
    aliases = json.loads(actor["aliases_json"])
    assert "APT28" in aliases
    assert "STRONTIUM" in aliases


def test_create_actor_inactive(engine):
    actor = engine.create_threat_actor("org1", {"name": "Retired Group", "active": False})
    assert actor["active"] == 0


# ---------------------------------------------------------------------------
# list_threat_actors
# ---------------------------------------------------------------------------

def test_list_actors_empty(engine):
    assert engine.list_threat_actors("org1") == []


def test_list_actors_returns_all(engine):
    _make_actor(engine, name="APT28")
    _make_actor(engine, name="Lazarus", actor_type="criminal_group")
    assert len(engine.list_threat_actors("org1")) == 2


def test_list_actors_filter_type(engine):
    _make_actor(engine, name="APT28", actor_type="nation_state")
    _make_actor(engine, name="Lazarus", actor_type="criminal_group")
    ns = engine.list_threat_actors("org1", actor_type="nation_state")
    assert len(ns) == 1
    assert ns[0]["name"] == "APT28"


def test_list_actors_filter_active(engine):
    engine.create_threat_actor("org1", {"name": "Active", "active": True})
    engine.create_threat_actor("org1", {"name": "Retired", "active": False})
    active = engine.list_threat_actors("org1", active=True)
    assert len(active) == 1
    assert active[0]["name"] == "Active"
    retired = engine.list_threat_actors("org1", active=False)
    assert len(retired) == 1


def test_list_actors_org_isolation(engine):
    _make_actor(engine, org_id="org1", name="APT28")
    _make_actor(engine, org_id="org2", name="Lazarus")
    assert len(engine.list_threat_actors("org1")) == 1
    assert len(engine.list_threat_actors("org2")) == 1


# ---------------------------------------------------------------------------
# get_threat_actor
# ---------------------------------------------------------------------------

def test_get_actor_returns_correct(engine):
    actor = _make_actor(engine, name="APT29")
    fetched = engine.get_threat_actor("org1", actor["id"])
    assert fetched is not None
    assert fetched["name"] == "APT29"
    assert fetched["id"] == actor["id"]


def test_get_actor_not_found_returns_none(engine):
    assert engine.get_threat_actor("org1", "does-not-exist") is None


def test_get_actor_org_isolation(engine):
    actor = _make_actor(engine, org_id="org1")
    assert engine.get_threat_actor("org2", actor["id"]) is None


# ---------------------------------------------------------------------------
# create_attribution
# ---------------------------------------------------------------------------

VALID_CONFIDENCES = ["confirmed", "likely", "possible", "unlikely"]


@pytest.mark.parametrize("confidence", VALID_CONFIDENCES)
def test_create_attribution_all_confidences(engine, confidence):
    attr = _make_attribution(engine, confidence=confidence)
    assert attr["confidence"] == confidence
    assert attr["status"] == "investigating"
    assert attr["org_id"] == "org1"
    assert "id" in attr
    assert "created_at" in attr


def test_create_attribution_incident_id_required_raises(engine):
    with pytest.raises(ValueError, match="incident_id"):
        engine.create_attribution("org1", {"confidence": "likely"})


def test_create_attribution_empty_incident_id_raises(engine):
    with pytest.raises(ValueError, match="incident_id"):
        engine.create_attribution("org1", {"incident_id": ""})


def test_create_attribution_invalid_confidence_raises(engine):
    with pytest.raises(ValueError, match="confidence"):
        engine.create_attribution("org1", {"incident_id": "INC-1", "confidence": "very_sure"})


def test_create_attribution_with_actor(engine):
    actor = _make_actor(engine)
    attr = engine.create_attribution("org1", {
        "incident_id": "INC-100",
        "actor_id": actor["id"],
        "confidence": "confirmed",
    })
    assert attr["actor_id"] == actor["id"]


def test_create_attribution_defaults(engine):
    attr = engine.create_attribution("org1", {"incident_id": "INC-X"})
    assert attr["status"] == "investigating"
    assert attr["confidence"] == "possible"
    assert attr["actor_id"] == ""
    assert attr["analyst"] == ""


# ---------------------------------------------------------------------------
# update_attribution_status
# ---------------------------------------------------------------------------

VALID_STATUSES = ["investigating", "attributed", "disputed", "closed"]


@pytest.mark.parametrize("new_status", VALID_STATUSES)
def test_update_status_all_valid(engine, new_status):
    attr = _make_attribution(engine)
    updated = engine.update_attribution_status("org1", attr["id"], new_status)
    assert updated["status"] == new_status


def test_update_status_with_notes(engine):
    attr = _make_attribution(engine)
    updated = engine.update_attribution_status("org1", attr["id"], "attributed", "Confirmed via TTPs")
    assert updated["status"] == "attributed"
    assert updated["notes"] == "Confirmed via TTPs"


def test_update_status_invalid_raises(engine):
    attr = _make_attribution(engine)
    with pytest.raises(ValueError, match="status"):
        engine.update_attribution_status("org1", attr["id"], "approved")


def test_update_status_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.update_attribution_status("org1", "bad-id", "closed")


def test_update_status_org_isolation(engine):
    attr = _make_attribution(engine, org_id="org1")
    with pytest.raises(ValueError):
        engine.update_attribution_status("org2", attr["id"], "closed")


# ---------------------------------------------------------------------------
# add_indicator
# ---------------------------------------------------------------------------

VALID_INDICATOR_TYPES = ["ttps", "iocs", "infrastructure", "malware", "victimology"]


@pytest.mark.parametrize("ind_type", VALID_INDICATOR_TYPES)
def test_add_indicator_all_types(engine, ind_type):
    attr = _make_attribution(engine)
    ind = engine.add_indicator("org1", attr["id"], {
        "indicator_type": ind_type,
        "value": f"sample-{ind_type}",
        "description": f"Test {ind_type} indicator",
    })
    assert ind["indicator_type"] == ind_type
    assert ind["org_id"] == "org1"
    assert ind["attribution_id"] == attr["id"]
    assert "id" in ind
    assert "created_at" in ind


def test_add_indicator_invalid_type_raises(engine):
    attr = _make_attribution(engine)
    with pytest.raises(ValueError, match="indicator_type"):
        engine.add_indicator("org1", attr["id"], {"indicator_type": "bad_type"})


def test_add_indicator_defaults(engine):
    attr = _make_attribution(engine)
    ind = engine.add_indicator("org1", attr["id"], {})
    assert ind["indicator_type"] == "iocs"
    assert ind["value"] == ""
    assert ind["description"] == ""
    assert ind["first_seen"] is None
    assert ind["last_seen"] is None


def test_add_multiple_indicators(engine):
    attr = _make_attribution(engine)
    engine.add_indicator("org1", attr["id"], {"indicator_type": "iocs", "value": "1.2.3.4"})
    engine.add_indicator("org1", attr["id"], {"indicator_type": "malware", "value": "trojan.exe"})
    engine.add_indicator("org1", attr["id"], {"indicator_type": "ttps", "value": "T1059"})
    # Verify by listing attributions (indicator count not directly in attr, just verify no error)
    attrs = engine.list_attributions("org1")
    assert len(attrs) == 1


# ---------------------------------------------------------------------------
# list_attributions
# ---------------------------------------------------------------------------

def test_list_attributions_empty(engine):
    assert engine.list_attributions("org1") == []


def test_list_attributions_returns_all(engine):
    _make_attribution(engine, incident_id="INC-1")
    _make_attribution(engine, incident_id="INC-2")
    assert len(engine.list_attributions("org1")) == 2


def test_list_attributions_filter_status(engine):
    attr = _make_attribution(engine, incident_id="INC-1")
    _make_attribution(engine, incident_id="INC-2")
    engine.update_attribution_status("org1", attr["id"], "closed")
    closed = engine.list_attributions("org1", status="closed")
    assert len(closed) == 1
    investigating = engine.list_attributions("org1", status="investigating")
    assert len(investigating) == 1


def test_list_attributions_filter_confidence(engine):
    _make_attribution(engine, incident_id="INC-1", confidence="confirmed")
    _make_attribution(engine, incident_id="INC-2", confidence="unlikely")
    confirmed = engine.list_attributions("org1", confidence="confirmed")
    assert len(confirmed) == 1
    assert confirmed[0]["confidence"] == "confirmed"


def test_list_attributions_org_isolation(engine):
    _make_attribution(engine, org_id="org1", incident_id="INC-1")
    _make_attribution(engine, org_id="org2", incident_id="INC-2")
    assert len(engine.list_attributions("org1")) == 1
    assert len(engine.list_attributions("org2")) == 1


# ---------------------------------------------------------------------------
# get_attribution_stats
# ---------------------------------------------------------------------------

def test_get_stats_empty(engine):
    stats = engine.get_attribution_stats("org1")
    assert stats["total_actors"] == 0
    assert stats["active_actors"] == 0
    assert stats["total_attributions"] == 0
    assert stats["confirmed_attributions"] == 0
    assert stats["by_actor_type"] == {}
    assert stats["nation_state_count"] == 0


def test_get_stats_with_actors(engine):
    _make_actor(engine, name="APT28", actor_type="nation_state")
    _make_actor(engine, name="APT29", actor_type="nation_state")
    _make_actor(engine, name="Lazarus", actor_type="criminal_group")
    engine.create_threat_actor("org1", {"name": "Retired", "actor_type": "hacktivist", "active": False})

    stats = engine.get_attribution_stats("org1")
    assert stats["total_actors"] == 4
    assert stats["active_actors"] == 3
    assert stats["nation_state_count"] == 2
    assert stats["by_actor_type"]["nation_state"] == 2
    assert stats["by_actor_type"]["criminal_group"] == 1
    assert stats["by_actor_type"]["hacktivist"] == 1


def test_get_stats_confirmed_attributions(engine):
    _make_attribution(engine, incident_id="INC-1", confidence="confirmed")
    _make_attribution(engine, incident_id="INC-2", confidence="confirmed")
    _make_attribution(engine, incident_id="INC-3", confidence="likely")

    stats = engine.get_attribution_stats("org1")
    assert stats["total_attributions"] == 3
    assert stats["confirmed_attributions"] == 2


def test_get_stats_org_isolation(engine):
    _make_actor(engine, org_id="org1", name="APT28")
    _make_actor(engine, org_id="org2", name="APT29")
    _make_attribution(engine, org_id="org1", incident_id="INC-1")

    s1 = engine.get_attribution_stats("org1")
    s2 = engine.get_attribution_stats("org2")
    assert s1["total_actors"] == 1
    assert s2["total_actors"] == 1
    assert s1["total_attributions"] == 1
    assert s2["total_attributions"] == 0
