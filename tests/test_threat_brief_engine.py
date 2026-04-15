"""Tests for ThreatBriefEngine.

Covers brief creation, listing, distribution, recipient tracking,
threat records, and statistics aggregation.

Total: 37 tests.
"""

from __future__ import annotations

import os
import pytest
from core.threat_brief_engine import ThreatBriefEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "threat_brief_test.db")
    return ThreatBriefEngine(db_path=db)


@pytest.fixture()
def daily_brief(engine):
    return engine.create_brief("org1", {
        "title": "Daily Threat Brief 2026-04-16",
        "brief_type": "daily",
        "threat_level": "high",
        "summary": "Elevated activity observed",
        "author": "analyst1",
    })


@pytest.fixture()
def exec_brief(engine):
    return engine.create_brief("org1", {
        "title": "Executive Weekly Summary",
        "brief_type": "executive",
        "threat_level": "medium",
        "author": "ciso_team",
    })


# ===========================================================================
# 1. Initialization
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "tb_init.db")
    ThreatBriefEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "tb_idem.db")
    ThreatBriefEngine(db_path=db)
    ThreatBriefEngine(db_path=db)


# ===========================================================================
# 2. create_brief — validation
# ===========================================================================

def test_create_brief_returns_record(engine, daily_brief):
    assert daily_brief["id"]
    assert daily_brief["title"] == "Daily Threat Brief 2026-04-16"
    assert daily_brief["brief_type"] == "daily"
    assert daily_brief["threat_level"] == "high"
    assert daily_brief["distribution_status"] == "draft"
    assert daily_brief["recipient_count"] == 0


def test_create_brief_requires_title(engine):
    with pytest.raises(ValueError, match="title"):
        engine.create_brief("org1", {"brief_type": "daily"})


def test_create_brief_empty_title_rejected(engine):
    with pytest.raises(ValueError):
        engine.create_brief("org1", {"title": "   "})


def test_create_brief_invalid_brief_type(engine):
    with pytest.raises(ValueError, match="brief_type"):
        engine.create_brief("org1", {"title": "X", "brief_type": "bogus"})


def test_create_brief_invalid_threat_level(engine):
    with pytest.raises(ValueError, match="threat_level"):
        engine.create_brief("org1", {"title": "X", "threat_level": "extreme"})


def test_create_brief_invalid_distribution_status(engine):
    with pytest.raises(ValueError, match="distribution_status"):
        engine.create_brief("org1", {"title": "X", "distribution_status": "archived"})


def test_create_brief_default_draft_status(engine):
    b = engine.create_brief("org1", {"title": "Test"})
    assert b["distribution_status"] == "draft"


def test_create_brief_key_findings_list(engine):
    b = engine.create_brief("org1", {
        "title": "T",
        "key_findings": ["Finding A", "Finding B"],
    })
    assert isinstance(b["key_findings"], list)
    assert "Finding A" in b["key_findings"]


def test_create_brief_recommendations_list(engine):
    b = engine.create_brief("org1", {
        "title": "T",
        "recommendations": ["Patch immediately"],
    })
    assert isinstance(b["recommendations"], list)
    assert len(b["recommendations"]) == 1


# ===========================================================================
# 3. list_briefs / get_brief
# ===========================================================================

def test_list_briefs_returns_all(engine, daily_brief, exec_brief):
    briefs = engine.list_briefs("org1")
    assert len(briefs) == 2


def test_list_briefs_filter_by_type(engine, daily_brief, exec_brief):
    briefs = engine.list_briefs("org1", brief_type="daily")
    assert len(briefs) == 1
    assert briefs[0]["brief_type"] == "daily"


def test_list_briefs_filter_by_status(engine, daily_brief):
    briefs = engine.list_briefs("org1", distribution_status="draft")
    assert len(briefs) >= 1


def test_list_briefs_org_isolation(engine, daily_brief):
    other = engine.list_briefs("org_other")
    assert len(other) == 0


def test_get_brief_returns_record(engine, daily_brief):
    result = engine.get_brief("org1", daily_brief["id"])
    assert result is not None
    assert result["id"] == daily_brief["id"]


def test_get_brief_wrong_org_returns_none(engine, daily_brief):
    assert engine.get_brief("org_x", daily_brief["id"]) is None


def test_get_brief_missing_id_returns_none(engine):
    assert engine.get_brief("org1", "nonexistent") is None


# ===========================================================================
# 4. distribute_brief
# ===========================================================================

def test_distribute_brief_sets_status(engine, daily_brief):
    result = engine.distribute_brief("org1", daily_brief["id"], [
        {"recipient_type": "ciso", "recipient_email": "ciso@acme.com"},
        {"recipient_type": "soc", "recipient_email": "soc@acme.com"},
    ])
    assert result["distribution_status"] == "distributed"
    assert result["distributed_at"] is not None
    assert result["recipient_count"] == 2


def test_distribute_brief_increments_recipient_count(engine, daily_brief):
    engine.distribute_brief("org1", daily_brief["id"], [
        {"recipient_type": "individual", "recipient_email": "a@b.com"},
    ])
    engine.distribute_brief("org1", daily_brief["id"], [
        {"recipient_type": "individual", "recipient_email": "c@d.com"},
    ])
    updated = engine.get_brief("org1", daily_brief["id"])
    assert updated["recipient_count"] == 2


def test_distribute_brief_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.distribute_brief("org1", "bad-id", [])


def test_distribute_brief_invalid_recipient_type_raises(engine, daily_brief):
    with pytest.raises(ValueError, match="recipient_type"):
        engine.distribute_brief("org1", daily_brief["id"], [
            {"recipient_type": "unknown"},
        ])


# ===========================================================================
# 5. list_recipients
# ===========================================================================

def test_list_recipients_after_distribute(engine, daily_brief):
    engine.distribute_brief("org1", daily_brief["id"], [
        {"recipient_type": "ciso", "recipient_email": "ciso@acme.com"},
        {"recipient_type": "soc", "recipient_email": "soc@acme.com"},
    ])
    recipients = engine.list_recipients("org1", brief_id=daily_brief["id"])
    assert len(recipients) == 2


def test_list_recipients_filter_by_type(engine, daily_brief):
    engine.distribute_brief("org1", daily_brief["id"], [
        {"recipient_type": "ciso", "recipient_email": "ciso@acme.com"},
        {"recipient_type": "executive", "recipient_email": "exec@acme.com"},
    ])
    ciso_only = engine.list_recipients("org1", recipient_type="ciso")
    assert all(r["recipient_type"] == "ciso" for r in ciso_only)


# ===========================================================================
# 6. add_threat / list_threats
# ===========================================================================

def test_add_threat_returns_record(engine, daily_brief):
    threat = engine.add_threat("org1", daily_brief["id"], {
        "threat_name": "APT29 Spearphishing",
        "threat_actor": "APT29",
        "severity": "critical",
        "ioc_count": 42,
        "mitre_tactics": ["TA0001", "TA0002"],
    })
    assert threat["id"]
    assert threat["threat_name"] == "APT29 Spearphishing"
    assert threat["severity"] == "critical"
    assert threat["ioc_count"] == 42
    assert isinstance(threat["mitre_tactics"], list)


def test_add_threat_requires_threat_name(engine, daily_brief):
    with pytest.raises(ValueError, match="threat_name"):
        engine.add_threat("org1", daily_brief["id"], {"severity": "high"})


def test_add_threat_invalid_severity(engine, daily_brief):
    with pytest.raises(ValueError, match="severity"):
        engine.add_threat("org1", daily_brief["id"], {
            "threat_name": "X",
            "severity": "unknown",
        })


def test_list_threats_filter_by_brief(engine, daily_brief, exec_brief):
    engine.add_threat("org1", daily_brief["id"], {"threat_name": "T1", "severity": "high"})
    engine.add_threat("org1", exec_brief["id"], {"threat_name": "T2", "severity": "low"})
    threats = engine.list_threats("org1", brief_id=daily_brief["id"])
    assert len(threats) == 1
    assert threats[0]["threat_name"] == "T1"


def test_list_threats_all_org(engine, daily_brief, exec_brief):
    engine.add_threat("org1", daily_brief["id"], {"threat_name": "T1", "severity": "high"})
    engine.add_threat("org1", exec_brief["id"], {"threat_name": "T2", "severity": "low"})
    all_threats = engine.list_threats("org1")
    assert len(all_threats) == 2


# ===========================================================================
# 7. get_brief_stats
# ===========================================================================

def test_stats_empty_org(engine):
    stats = engine.get_brief_stats("empty_org")
    assert stats["total_briefs"] == 0
    assert stats["distributed_briefs"] == 0
    assert stats["total_threats"] == 0
    assert stats["avg_recipient_count"] == 0


def test_stats_total_briefs(engine, daily_brief, exec_brief):
    stats = engine.get_brief_stats("org1")
    assert stats["total_briefs"] == 2


def test_stats_distributed_briefs(engine, daily_brief, exec_brief):
    engine.distribute_brief("org1", daily_brief["id"], [
        {"recipient_type": "ciso", "recipient_email": "c@c.com"},
    ])
    stats = engine.get_brief_stats("org1")
    assert stats["distributed_briefs"] == 1


def test_stats_total_threats(engine, daily_brief):
    engine.add_threat("org1", daily_brief["id"], {"threat_name": "T1", "severity": "high"})
    engine.add_threat("org1", daily_brief["id"], {"threat_name": "T2", "severity": "critical"})
    stats = engine.get_brief_stats("org1")
    assert stats["total_threats"] == 2


def test_stats_by_type(engine, daily_brief, exec_brief):
    stats = engine.get_brief_stats("org1")
    assert "daily" in stats["by_type"]
    assert "executive" in stats["by_type"]


def test_stats_by_threat_level(engine, daily_brief):
    stats = engine.get_brief_stats("org1")
    assert "high" in stats["by_threat_level"]


def test_stats_critical_briefs_this_month(engine):
    engine.create_brief("org1", {"title": "Crit", "threat_level": "critical"})
    stats = engine.get_brief_stats("org1")
    assert stats["critical_briefs_this_month"] >= 1


def test_stats_avg_recipient_count(engine, daily_brief):
    engine.distribute_brief("org1", daily_brief["id"], [
        {"recipient_type": "soc", "recipient_email": "a@b.com"},
        {"recipient_type": "ciso", "recipient_email": "c@d.com"},
    ])
    stats = engine.get_brief_stats("org1")
    assert stats["avg_recipient_count"] > 0
