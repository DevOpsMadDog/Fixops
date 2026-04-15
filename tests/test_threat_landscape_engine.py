"""Tests for ThreatLandscapeEngine — 35+ tests covering full lifecycle."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.threat_landscape_engine import ThreatLandscapeEngine

ORG = "test-org"


@pytest.fixture
def engine(tmp_path):
    return ThreatLandscapeEngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_actor(engine, actor_name="APT-X", actor_type="nation-state", motivation="espionage",
                sophistication="advanced", ttps=None, target_sectors=None, confidence=0.9):
    return engine.add_threat_actor(
        org_id=ORG,
        actor_name=actor_name,
        actor_type=actor_type,
        motivation=motivation,
        sophistication=sophistication,
        ttps=ttps or ["T1059", "T1486"],
        target_sectors=target_sectors or ["finance", "healthcare"],
        confidence=confidence,
    )


def _make_threat(engine, threat_name="RansomX", severity="high", category="ransomware"):
    return engine.add_emerging_threat(
        org_id=ORG,
        threat_name=threat_name,
        threat_category=category,
        severity=severity,
        description="Emerging ransomware threat",
        affected_sectors=["retail", "energy"],
        indicators=["hash:abc123"],
        mitigations=["Patch systems", "Backup data"],
    )


# ---------------------------------------------------------------------------
# add_threat_actor
# ---------------------------------------------------------------------------

class TestAddThreatActor:
    def test_basic_creation(self, engine):
        actor = _make_actor(engine)
        assert actor["id"]
        assert actor["org_id"] == ORG
        assert actor["actor_name"] == "APT-X"
        assert actor["active"] == 1
        assert actor["confidence"] == 0.9

    def test_all_actor_types(self, engine):
        types = ["nation-state", "criminal", "hacktivist", "insider", "competitor", "unknown"]
        for at in types:
            a = _make_actor(engine, actor_name=f"Actor-{at}", actor_type=at)
            assert a["actor_type"] == at

    def test_all_motivations(self, engine):
        motivations = ["financial", "espionage", "disruption", "ideology", "revenge", "unknown"]
        for m in motivations:
            a = _make_actor(engine, actor_name=f"Actor-{m}", motivation=m)
            assert a["motivation"] == m

    def test_all_sophistications(self, engine):
        for s in ["advanced", "intermediate", "basic", "unknown"]:
            a = _make_actor(engine, actor_name=f"Actor-{s}", sophistication=s)
            assert a["sophistication"] == s

    def test_confidence_clamped_above_1(self, engine):
        actor = _make_actor(engine, confidence=1.5)
        assert actor["confidence"] == 1.0

    def test_confidence_clamped_below_0(self, engine):
        actor = _make_actor(engine, confidence=-0.5)
        assert actor["confidence"] == 0.0

    def test_confidence_boundary_0(self, engine):
        actor = _make_actor(engine, confidence=0.0)
        assert actor["confidence"] == 0.0

    def test_confidence_boundary_1(self, engine):
        actor = _make_actor(engine, confidence=1.0)
        assert actor["confidence"] == 1.0

    def test_ttps_stored(self, engine):
        actor = _make_actor(engine, ttps=["T1059", "T1486", "T1003"])
        assert isinstance(actor["ttps"], list)
        assert "T1059" in actor["ttps"]

    def test_target_sectors_stored(self, engine):
        actor = _make_actor(engine, target_sectors=["finance", "energy"])
        assert "finance" in actor["target_sectors"]

    def test_invalid_actor_type_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid actor_type"):
            engine.add_threat_actor(ORG, "Bad", "alien", "financial", "advanced", [], [], 0.5)

    def test_invalid_motivation_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid motivation"):
            engine.add_threat_actor(ORG, "Bad", "criminal", "profit", "advanced", [], [], 0.5)

    def test_invalid_sophistication_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid sophistication"):
            engine.add_threat_actor(ORG, "Bad", "criminal", "financial", "expert", [], [], 0.5)

    def test_unique_ids(self, engine):
        a1 = _make_actor(engine, actor_name="A1")
        a2 = _make_actor(engine, actor_name="A2")
        assert a1["id"] != a2["id"]


# ---------------------------------------------------------------------------
# update_actor_activity
# ---------------------------------------------------------------------------

class TestUpdateActorActivity:
    def test_deactivate_actor(self, engine):
        actor = _make_actor(engine)
        updated = engine.update_actor_activity(actor["id"], ORG, active=0, last_seen="2026-04-01T00:00:00+00:00")
        assert updated["active"] == 0
        assert updated["last_seen"] == "2026-04-01T00:00:00+00:00"

    def test_reactivate_actor(self, engine):
        actor = _make_actor(engine)
        engine.update_actor_activity(actor["id"], ORG, active=0, last_seen="2026-04-01T00:00:00+00:00")
        updated = engine.update_actor_activity(actor["id"], ORG, active=1, last_seen="2026-04-15T00:00:00+00:00")
        assert updated["active"] == 1

    def test_org_isolation(self, engine):
        actor = _make_actor(engine)
        result = engine.update_actor_activity(actor["id"], "other-org", active=0, last_seen="2026-04-01T00:00:00+00:00")
        assert result is None


# ---------------------------------------------------------------------------
# get_active_actors
# ---------------------------------------------------------------------------

class TestGetActiveActors:
    def test_returns_active_only(self, engine):
        a1 = _make_actor(engine, actor_name="Active")
        a2 = _make_actor(engine, actor_name="Inactive")
        engine.update_actor_activity(a2["id"], ORG, active=0, last_seen="2026-04-01T00:00:00+00:00")
        actors = engine.get_active_actors(ORG)
        ids = [a["id"] for a in actors]
        assert a1["id"] in ids
        assert a2["id"] not in ids

    def test_filter_by_actor_type(self, engine):
        _make_actor(engine, actor_name="NS", actor_type="nation-state")
        _make_actor(engine, actor_name="CR", actor_type="criminal")
        ns_actors = engine.get_active_actors(ORG, actor_type="nation-state")
        assert all(a["actor_type"] == "nation-state" for a in ns_actors)

    def test_org_isolation(self, engine):
        _make_actor(engine)
        assert engine.get_active_actors("other-org") == []


# ---------------------------------------------------------------------------
# add_emerging_threat
# ---------------------------------------------------------------------------

class TestAddEmergingThreat:
    def test_basic_creation(self, engine):
        threat = _make_threat(engine)
        assert threat["id"]
        assert threat["org_id"] == ORG
        assert threat["status"] == "active"
        assert threat["threat_name"] == "RansomX"

    def test_all_threat_categories(self, engine):
        categories = ["ransomware", "phishing", "supply-chain", "zero-day", "insider", "ddos", "data-breach", "malware"]
        for cat in categories:
            t = _make_threat(engine, threat_name=f"Threat-{cat}", category=cat)
            assert t["threat_category"] == cat

    def test_all_severities(self, engine):
        for sev in ["critical", "high", "medium", "low"]:
            t = _make_threat(engine, threat_name=f"T-{sev}", severity=sev)
            assert t["severity"] == sev

    def test_invalid_category_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid threat_category"):
            engine.add_emerging_threat(ORG, "Bad", "worm", "high", "", [], [], [])

    def test_invalid_severity_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid severity"):
            engine.add_emerging_threat(ORG, "Bad", "malware", "extreme", "", [], [], [])

    def test_indicators_and_mitigations_stored(self, engine):
        t = engine.add_emerging_threat(
            ORG, "T", "phishing", "medium", "desc",
            ["healthcare"], ["ip:1.2.3.4"], ["Block IP"]
        )
        assert "ip:1.2.3.4" in t["indicators"]
        assert "Block IP" in t["mitigations"]


# ---------------------------------------------------------------------------
# resolve_threat
# ---------------------------------------------------------------------------

class TestResolveThreat:
    def test_resolve_sets_status(self, engine):
        threat = _make_threat(engine)
        resolved = engine.resolve_threat(threat["id"], ORG)
        assert resolved["status"] == "resolved"

    def test_org_isolation(self, engine):
        threat = _make_threat(engine)
        result = engine.resolve_threat(threat["id"], "other-org")
        assert result is None

    def test_resolved_not_in_active_threats(self, engine):
        threat = _make_threat(engine)
        engine.resolve_threat(threat["id"], ORG)
        active = engine.get_active_threats(ORG)
        ids = [t["id"] for t in active]
        assert threat["id"] not in ids


# ---------------------------------------------------------------------------
# create_assessment + overall_risk
# ---------------------------------------------------------------------------

class TestCreateAssessment:
    def test_no_threats_gives_low_risk(self, engine):
        assessment = engine.create_assessment(ORG, "finance", ["Finding 1"], ["Rec 1"])
        assert assessment["overall_risk"] == "low"

    def test_one_critical_threat_gives_high_risk(self, engine):
        _make_threat(engine, severity="critical")
        assessment = engine.create_assessment(ORG, "finance", [], [])
        assert assessment["overall_risk"] == "high"

    def test_three_critical_threats_gives_critical_risk(self, engine):
        for i in range(3):
            _make_threat(engine, threat_name=f"T{i}", severity="critical")
        assessment = engine.create_assessment(ORG, "finance", [], [])
        assert assessment["overall_risk"] == "critical"

    def test_medium_threats_give_medium_risk(self, engine):
        _make_threat(engine, severity="medium")
        assessment = engine.create_assessment(ORG, "finance", [], [])
        assert assessment["overall_risk"] == "medium"

    def test_threat_count_auto_populated(self, engine):
        _make_threat(engine, threat_name="T1")
        _make_threat(engine, threat_name="T2")
        assessment = engine.create_assessment(ORG, "finance", [], [])
        assert assessment["threat_count"] == 2

    def test_actor_count_auto_populated(self, engine):
        _make_actor(engine, actor_name="A1")
        _make_actor(engine, actor_name="A2")
        assessment = engine.create_assessment(ORG, "finance", [], [])
        assert assessment["actor_count"] == 2

    def test_resolved_threats_not_counted(self, engine):
        t = _make_threat(engine, severity="critical")
        engine.resolve_threat(t["id"], ORG)
        assessment = engine.create_assessment(ORG, "finance", [], [])
        assert assessment["overall_risk"] == "low"
        assert assessment["threat_count"] == 0

    def test_assessment_fields(self, engine):
        assessment = engine.create_assessment(ORG, "healthcare", ["Finding"], ["Recommendation"])
        assert assessment["sector"] == "healthcare"
        assert assessment["assessment_date"]
        assert assessment["created_at"]


# ---------------------------------------------------------------------------
# list_assessments / get_assessment
# ---------------------------------------------------------------------------

class TestAssessmentCRUD:
    def test_list_all(self, engine):
        engine.create_assessment(ORG, "finance", [], [])
        engine.create_assessment(ORG, "energy", [], [])
        assessments = engine.list_assessments(ORG)
        assert len(assessments) == 2

    def test_filter_by_sector(self, engine):
        engine.create_assessment(ORG, "finance", [], [])
        engine.create_assessment(ORG, "energy", [], [])
        finance = engine.list_assessments(ORG, sector="finance")
        assert len(finance) == 1
        assert finance[0]["sector"] == "finance"

    def test_get_assessment_by_id(self, engine):
        a = engine.create_assessment(ORG, "telecom", ["F1"], ["R1"])
        fetched = engine.get_assessment(a["id"], ORG)
        assert fetched["id"] == a["id"]
        assert fetched["sector"] == "telecom"

    def test_get_missing_returns_none(self, engine):
        assert engine.get_assessment("no-such-id", ORG) is None

    def test_org_isolation(self, engine):
        a = engine.create_assessment(ORG, "finance", [], [])
        assert engine.get_assessment(a["id"], "other-org") is None


# ---------------------------------------------------------------------------
# get_landscape_summary
# ---------------------------------------------------------------------------

class TestGetLandscapeSummary:
    def test_empty_summary(self, engine):
        summary = engine.get_landscape_summary(ORG)
        assert summary["total_actors"] == 0
        assert summary["active_actors"] == 0
        assert summary["total_threats"] == 0
        assert summary["active_threats"] == 0
        assert summary["by_severity"] == {}
        assert summary["top_target_sectors"] == []

    def test_counts(self, engine):
        _make_actor(engine, actor_name="A1")
        a2 = _make_actor(engine, actor_name="A2")
        engine.update_actor_activity(a2["id"], ORG, active=0, last_seen="2026-04-01T00:00:00+00:00")
        _make_threat(engine, threat_name="T1", severity="critical")
        _make_threat(engine, threat_name="T2", severity="high")
        summary = engine.get_landscape_summary(ORG)
        assert summary["total_actors"] == 2
        assert summary["active_actors"] == 1
        assert summary["total_threats"] == 2
        assert summary["active_threats"] == 2

    def test_by_severity_breakdown(self, engine):
        _make_threat(engine, threat_name="C1", severity="critical")
        _make_threat(engine, threat_name="C2", severity="critical")
        _make_threat(engine, threat_name="H1", severity="high")
        summary = engine.get_landscape_summary(ORG)
        assert summary["by_severity"]["critical"] == 2
        assert summary["by_severity"]["high"] == 1

    def test_top_target_sectors(self, engine):
        _make_actor(engine, actor_name="A1", target_sectors=["finance", "healthcare"])
        _make_actor(engine, actor_name="A2", target_sectors=["finance", "energy"])
        summary = engine.get_landscape_summary(ORG)
        assert "finance" in summary["top_target_sectors"]

    def test_org_isolation(self, engine):
        _make_actor(engine)
        _make_threat(engine)
        summary = engine.get_landscape_summary("other-org")
        assert summary["total_actors"] == 0
        assert summary["total_threats"] == 0
