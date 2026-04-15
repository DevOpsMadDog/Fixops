"""Tests for IncidentTriageEngine — 30+ tests covering all methods and stats."""

from __future__ import annotations

import pytest

from core.incident_triage_engine import IncidentTriageEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_incident_triage.db")


@pytest.fixture
def engine(db_path):
    return IncidentTriageEngine(db_path=db_path)


ORG = "org-triage-test"
ORG2 = "org-triage-other"


# ---------------------------------------------------------------------------
# submit_for_triage
# ---------------------------------------------------------------------------

def test_submit_minimal(engine):
    inc = engine.submit_for_triage(ORG, {
        "title": "Suspicious Login",
        "source": "siem",
        "severity": "high",
    })
    assert inc["title"] == "Suspicious Login"
    assert inc["source"] == "siem"
    assert inc["severity"] == "high"
    assert inc["status"] == "pending"
    assert inc["triage_score"] == 0
    assert "id" in inc
    assert "submitted_at" in inc


def test_submit_missing_title(engine):
    with pytest.raises(ValueError, match="title is required"):
        engine.submit_for_triage(ORG, {"source": "siem", "severity": "high"})


def test_submit_invalid_source(engine):
    with pytest.raises(ValueError, match="Invalid source"):
        engine.submit_for_triage(ORG, {"title": "X", "source": "unknown_src", "severity": "high"})


def test_submit_invalid_severity(engine):
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.submit_for_triage(ORG, {"title": "X", "source": "siem", "severity": "catastrophic"})


def test_submit_all_valid_sources(engine):
    for source in ("siem", "edr", "user_report", "threat_feed", "manual"):
        inc = engine.submit_for_triage(ORG, {"title": f"Src {source}", "source": source, "severity": "low"})
        assert inc["source"] == source


def test_submit_all_valid_severities(engine):
    for severity in ("low", "medium", "high", "critical"):
        inc = engine.submit_for_triage(ORG, {"title": f"Sev {severity}", "source": "siem", "severity": severity})
        assert inc["severity"] == severity


def test_submit_with_raw_data(engine):
    raw = {"alert_id": "a-999", "count": 5}
    inc = engine.submit_for_triage(ORG, {
        "title": "Raw Data Inc",
        "source": "edr",
        "severity": "medium",
        "raw_data": raw,
    })
    assert inc["raw_data"]["alert_id"] == "a-999"


def test_submit_unique_ids(engine):
    i1 = engine.submit_for_triage(ORG, {"title": "I1", "source": "siem", "severity": "low"})
    i2 = engine.submit_for_triage(ORG, {"title": "I2", "source": "siem", "severity": "low"})
    assert i1["id"] != i2["id"]


# ---------------------------------------------------------------------------
# triage_incident (scoring)
# ---------------------------------------------------------------------------

def _submit(engine, org, title="Test", source="siem", severity="high"):
    return engine.submit_for_triage(org, {"title": title, "source": source, "severity": severity})


def test_triage_confirmed_critical(engine):
    inc = _submit(engine, ORG, severity="critical")
    result = engine.triage_incident(ORG, inc["id"], {
        "confirmed": True,
        "classification": "true_positive",
    })
    # confirmed=40 + critical=40 = 80
    assert result["triage_score"] == 80
    assert result["status"] == "triaged"
    assert result["classification"] == "true_positive"
    assert result["triaged_at"] is not None


def test_triage_confirmed_high(engine):
    inc = _submit(engine, ORG, severity="high")
    result = engine.triage_incident(ORG, inc["id"], {
        "confirmed": True,
        "classification": "true_positive",
    })
    # confirmed=40 + high=30 = 70
    assert result["triage_score"] == 70


def test_triage_confirmed_medium(engine):
    inc = _submit(engine, ORG, severity="medium")
    result = engine.triage_incident(ORG, inc["id"], {
        "confirmed": True,
        "classification": "true_positive",
    })
    # confirmed=40 + medium=20 = 60
    assert result["triage_score"] == 60


def test_triage_confirmed_low(engine):
    inc = _submit(engine, ORG, severity="low")
    result = engine.triage_incident(ORG, inc["id"], {
        "confirmed": True,
        "classification": "true_positive",
    })
    # confirmed=40 + low=10 = 50
    assert result["triage_score"] == 50


def test_triage_not_confirmed_critical(engine):
    inc = _submit(engine, ORG, severity="critical")
    result = engine.triage_incident(ORG, inc["id"], {
        "confirmed": False,
        "classification": "false_positive",
    })
    # confirmed=0 + critical=40 = 40
    assert result["triage_score"] == 40


def test_triage_not_confirmed_low(engine):
    inc = _submit(engine, ORG, severity="low")
    result = engine.triage_incident(ORG, inc["id"], {
        "confirmed": False,
        "classification": "benign",
    })
    # confirmed=0 + low=10 = 10
    assert result["triage_score"] == 10


def test_triage_severity_override(engine):
    inc = _submit(engine, ORG, severity="low")
    result = engine.triage_incident(ORG, inc["id"], {
        "confirmed": True,
        "severity_override": "critical",
        "classification": "true_positive",
    })
    # confirmed=40 + critical=40 = 80
    assert result["triage_score"] == 80
    assert result["severity"] == "critical"


def test_triage_with_assignee_and_notes(engine):
    inc = _submit(engine, ORG)
    result = engine.triage_incident(ORG, inc["id"], {
        "confirmed": True,
        "classification": "true_positive",
        "assignee": "analyst@corp.com",
        "notes": "Verified via logs",
    })
    assert result["assignee"] == "analyst@corp.com"
    assert result["notes"] == "Verified via logs"


def test_triage_invalid_classification(engine):
    inc = _submit(engine, ORG)
    with pytest.raises(ValueError, match="Invalid classification"):
        engine.triage_incident(ORG, inc["id"], {
            "confirmed": True,
            "classification": "maybe",
        })


def test_triage_not_found(engine):
    result = engine.triage_incident(ORG, "ghost-id", {
        "confirmed": True,
        "classification": "true_positive",
    })
    assert result is None


def test_triage_all_classifications(engine):
    for cls in ("true_positive", "false_positive", "benign", "escalated"):
        inc = _submit(engine, ORG)
        result = engine.triage_incident(ORG, inc["id"], {
            "confirmed": False,
            "classification": cls,
        })
        assert result["classification"] == cls


# ---------------------------------------------------------------------------
# list_incidents / get_incident
# ---------------------------------------------------------------------------

def test_list_incidents_empty(engine):
    assert engine.list_incidents(ORG) == []


def test_list_incidents_returns_all(engine):
    _submit(engine, ORG, "Inc A")
    _submit(engine, ORG, "Inc B")
    assert len(engine.list_incidents(ORG)) == 2


def test_list_incidents_filter_status(engine):
    inc = _submit(engine, ORG)
    engine.triage_incident(ORG, inc["id"], {"confirmed": True, "classification": "true_positive"})
    pending = engine.list_incidents(ORG, status="pending")
    triaged = engine.list_incidents(ORG, status="triaged")
    assert len(pending) == 0
    assert len(triaged) == 1


def test_list_incidents_filter_severity(engine):
    _submit(engine, ORG, "High Inc", severity="high")
    _submit(engine, ORG, "Low Inc", severity="low")
    highs = engine.list_incidents(ORG, severity="high")
    assert len(highs) == 1
    assert highs[0]["severity"] == "high"


def test_list_incidents_filter_classification(engine):
    inc = _submit(engine, ORG)
    engine.triage_incident(ORG, inc["id"], {"confirmed": False, "classification": "false_positive"})
    fps = engine.list_incidents(ORG, classification="false_positive")
    assert len(fps) == 1


def test_list_incidents_org_isolation(engine):
    _submit(engine, ORG, "Org1 Inc")
    _submit(engine, ORG2, "Org2 Inc")
    assert len(engine.list_incidents(ORG)) == 1
    assert len(engine.list_incidents(ORG2)) == 1


def test_get_incident_found(engine):
    inc = _submit(engine, ORG, "Findable")
    fetched = engine.get_incident(ORG, inc["id"])
    assert fetched is not None
    assert fetched["title"] == "Findable"


def test_get_incident_not_found(engine):
    assert engine.get_incident(ORG, "ghost-id") is None


def test_get_incident_wrong_org(engine):
    inc = _submit(engine, ORG)
    assert engine.get_incident(ORG2, inc["id"]) is None


# ---------------------------------------------------------------------------
# escalate_incident
# ---------------------------------------------------------------------------

def test_escalate_incident(engine):
    inc = _submit(engine, ORG)
    result = engine.escalate_incident(ORG, inc["id"], "tier2@corp.com", "Requires senior analyst")
    assert result["status"] == "escalated"
    assert result["escalated_to"] == "tier2@corp.com"
    assert result["escalation_reason"] == "Requires senior analyst"
    assert result["escalated_at"] is not None


def test_escalate_incident_not_found(engine):
    result = engine.escalate_incident(ORG, "ghost-id", "tier2", "reason")
    assert result is None


# ---------------------------------------------------------------------------
# resolve_triage
# ---------------------------------------------------------------------------

def test_resolve_triage(engine):
    inc = _submit(engine, ORG)
    result = engine.resolve_triage(ORG, inc["id"], "Confirmed false alarm, closed")
    assert result["status"] == "resolved"
    assert result["resolution"] == "Confirmed false alarm, closed"
    assert result["resolved_at"] is not None


def test_resolve_triage_not_found(engine):
    result = engine.resolve_triage(ORG, "ghost-id", "resolution")
    assert result is None


# ---------------------------------------------------------------------------
# get_triage_stats
# ---------------------------------------------------------------------------

def test_stats_empty_org(engine):
    stats = engine.get_triage_stats(ORG)
    assert stats["total_incidents"] == 0
    assert stats["by_status"] == {}
    assert stats["by_severity"] == {}
    assert stats["by_classification"] == {}
    assert stats["pending_count"] == 0
    assert stats["avg_triage_score"] == 0.0
    assert stats["false_positive_rate"] == 0.0


def test_stats_total_and_pending(engine):
    _submit(engine, ORG, "P1")
    _submit(engine, ORG, "P2")
    inc = _submit(engine, ORG, "Triaged")
    engine.triage_incident(ORG, inc["id"], {"confirmed": True, "classification": "true_positive"})
    stats = engine.get_triage_stats(ORG)
    assert stats["total_incidents"] == 3
    assert stats["pending_count"] == 2


def test_stats_by_severity(engine):
    _submit(engine, ORG, "C1", severity="critical")
    _submit(engine, ORG, "H1", severity="high")
    _submit(engine, ORG, "H2", severity="high")
    stats = engine.get_triage_stats(ORG)
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["high"] == 2


def test_stats_avg_triage_score(engine):
    # two triaged: confirmed+critical=80, not_confirmed+low=10 → avg=45
    inc1 = _submit(engine, ORG, severity="critical")
    inc2 = _submit(engine, ORG, severity="low")
    engine.triage_incident(ORG, inc1["id"], {"confirmed": True, "classification": "true_positive"})
    engine.triage_incident(ORG, inc2["id"], {"confirmed": False, "classification": "benign"})
    stats = engine.get_triage_stats(ORG)
    assert stats["avg_triage_score"] == 45.0


def test_stats_false_positive_rate(engine):
    # 3 triaged: 1 FP → rate=33.33%
    inc1 = _submit(engine, ORG)
    inc2 = _submit(engine, ORG)
    inc3 = _submit(engine, ORG)
    engine.triage_incident(ORG, inc1["id"], {"confirmed": True, "classification": "true_positive"})
    engine.triage_incident(ORG, inc2["id"], {"confirmed": True, "classification": "true_positive"})
    engine.triage_incident(ORG, inc3["id"], {"confirmed": False, "classification": "false_positive"})
    stats = engine.get_triage_stats(ORG)
    assert abs(stats["false_positive_rate"] - 33.33) < 0.1


def test_stats_by_classification(engine):
    inc1 = _submit(engine, ORG)
    inc2 = _submit(engine, ORG)
    engine.triage_incident(ORG, inc1["id"], {"confirmed": True, "classification": "true_positive"})
    engine.triage_incident(ORG, inc2["id"], {"confirmed": False, "classification": "false_positive"})
    stats = engine.get_triage_stats(ORG)
    assert stats["by_classification"]["true_positive"] == 1
    assert stats["by_classification"]["false_positive"] == 1


def test_stats_org_isolation(engine):
    _submit(engine, ORG, "Org1 Inc")
    _submit(engine, ORG2, "Org2 Inc")
    stats1 = engine.get_triage_stats(ORG)
    stats2 = engine.get_triage_stats(ORG2)
    assert stats1["total_incidents"] == 1
    assert stats2["total_incidents"] == 1


def test_stats_escalated_counts_in_triaged_for_score(engine):
    inc = _submit(engine, ORG, severity="high")
    engine.triage_incident(ORG, inc["id"], {"confirmed": True, "classification": "escalated"})
    engine.escalate_incident(ORG, inc["id"], "tier2", "needs escalation")
    stats = engine.get_triage_stats(ORG)
    # escalated incidents (status=escalated) should still have triage_score in avg
    assert stats["avg_triage_score"] > 0
