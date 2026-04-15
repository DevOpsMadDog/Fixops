"""Tests for SecurityChampionsEngine — 30+ tests covering all methods,
level auto-promotion, and program stats."""

from __future__ import annotations

import os
import tempfile
import pytest

from core.security_champions_engine import SecurityChampionsEngine, _compute_level


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_security_champions.db")


@pytest.fixture
def engine(db_path):
    return SecurityChampionsEngine(db_path=db_path)


ORG = "org-test"


# ---------------------------------------------------------------------------
# _compute_level helper
# ---------------------------------------------------------------------------

def test_compute_level_bronze():
    assert _compute_level(0) == "bronze"
    assert _compute_level(50) == "bronze"
    assert _compute_level(99) == "bronze"


def test_compute_level_silver():
    assert _compute_level(100) == "silver"
    assert _compute_level(499) == "silver"


def test_compute_level_gold():
    assert _compute_level(500) == "gold"
    assert _compute_level(1499) == "gold"


def test_compute_level_platinum():
    assert _compute_level(1500) == "platinum"
    assert _compute_level(9999) == "platinum"


# ---------------------------------------------------------------------------
# add_champion
# ---------------------------------------------------------------------------

def test_add_champion_basic(engine):
    c = engine.add_champion(ORG, {"name": "Alice", "email": "alice@example.com", "department": "Engineering"})
    assert c["name"] == "Alice"
    assert c["email"] == "alice@example.com"
    assert c["level"] == "bronze"
    assert c["points"] == 0
    assert c["status"] == "active"
    assert c["role"] == "champion"
    assert "id" in c


def test_add_champion_all_fields(engine):
    c = engine.add_champion(ORG, {
        "name": "Bob", "email": "bob@example.com",
        "department": "Security", "team": "AppSec",
        "role": "lead", "status": "active",
    })
    assert c["role"] == "lead"
    assert c["team"] == "AppSec"


def test_add_champion_missing_name(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.add_champion(ORG, {})


def test_add_champion_invalid_role(engine):
    with pytest.raises(ValueError, match="Invalid role"):
        engine.add_champion(ORG, {"name": "X", "role": "superuser"})


def test_add_champion_invalid_status(engine):
    with pytest.raises(ValueError, match="Invalid status"):
        engine.add_champion(ORG, {"name": "X", "status": "retired"})


# ---------------------------------------------------------------------------
# list_champions / get_champion
# ---------------------------------------------------------------------------

def test_list_champions_empty(engine):
    assert engine.list_champions(ORG) == []


def test_list_champions_multiple(engine):
    engine.add_champion(ORG, {"name": "Alice"})
    engine.add_champion(ORG, {"name": "Bob"})
    result = engine.list_champions(ORG)
    assert len(result) == 2


def test_list_champions_filter_status(engine):
    engine.add_champion(ORG, {"name": "Alice", "status": "active"})
    engine.add_champion(ORG, {"name": "Bob", "status": "inactive"})
    active = engine.list_champions(ORG, status="active")
    assert len(active) == 1
    assert active[0]["name"] == "Alice"


def test_list_champions_filter_department(engine):
    engine.add_champion(ORG, {"name": "Alice", "department": "Eng"})
    engine.add_champion(ORG, {"name": "Bob", "department": "Ops"})
    result = engine.list_champions(ORG, department="Eng")
    assert len(result) == 1
    assert result[0]["name"] == "Alice"


def test_get_champion(engine):
    c = engine.add_champion(ORG, {"name": "Alice"})
    fetched = engine.get_champion(ORG, c["id"])
    assert fetched is not None
    assert fetched["name"] == "Alice"


def test_get_champion_not_found(engine):
    assert engine.get_champion(ORG, "nonexistent-id") is None


def test_get_champion_org_isolation(engine):
    c = engine.add_champion(ORG, {"name": "Alice"})
    assert engine.get_champion("other-org", c["id"]) is None


# ---------------------------------------------------------------------------
# log_activity + level auto-promotion
# ---------------------------------------------------------------------------

def test_log_activity_basic(engine):
    c = engine.add_champion(ORG, {"name": "Alice"})
    act = engine.log_activity(ORG, c["id"], {"activity_type": "training"})
    assert act["activity_type"] == "training"
    assert act["points_awarded"] == 20
    assert act["_total_points"] == 20
    assert act["_new_level"] == "bronze"


def test_log_activity_invalid_type(engine):
    c = engine.add_champion(ORG, {"name": "Alice"})
    with pytest.raises(ValueError, match="Invalid activity_type"):
        engine.log_activity(ORG, c["id"], {"activity_type": "hacking"})


def test_log_activity_points_map(engine):
    c = engine.add_champion(ORG, {"name": "Alice"})
    expected = {
        "mentoring": 30, "code_review": 15, "incident_response": 50,
        "awareness_campaign": 25, "vulnerability_report": 40, "tool_contribution": 35,
    }
    for activity_type, expected_pts in expected.items():
        act = engine.log_activity(ORG, c["id"], {"activity_type": activity_type})
        assert act["points_awarded"] == expected_pts


def test_log_activity_auto_promote_silver(engine):
    c = engine.add_champion(ORG, {"name": "Alice"})
    # 3 incident_response = 150 points -> silver
    for _ in range(3):
        act = engine.log_activity(ORG, c["id"], {"activity_type": "incident_response"})
    assert act["_new_level"] == "silver"
    assert act["_total_points"] == 150


def test_log_activity_auto_promote_gold(engine):
    c = engine.add_champion(ORG, {"name": "Alice"})
    # 11 incident_response = 550 points -> gold
    for _ in range(11):
        act = engine.log_activity(ORG, c["id"], {"activity_type": "incident_response"})
    assert act["_new_level"] == "gold"


def test_log_activity_auto_promote_platinum(engine):
    c = engine.add_champion(ORG, {"name": "Alice"})
    # 30 incident_response = 1500 points -> platinum
    for _ in range(30):
        act = engine.log_activity(ORG, c["id"], {"activity_type": "incident_response"})
    assert act["_new_level"] == "platinum"


def test_log_activity_custom_points(engine):
    c = engine.add_champion(ORG, {"name": "Alice"})
    act = engine.log_activity(ORG, c["id"], {"activity_type": "training", "points_awarded": 99})
    assert act["points_awarded"] == 99
    assert act["_total_points"] == 99


# ---------------------------------------------------------------------------
# Certifications
# ---------------------------------------------------------------------------

def test_add_certification_basic(engine):
    c = engine.add_champion(ORG, {"name": "Alice"})
    cert = engine.add_certification(ORG, c["id"], {
        "cert_name": "OSCP", "cert_provider": "Offensive Security"
    })
    assert cert["cert_name"] == "OSCP"
    assert cert["status"] == "valid"
    assert cert["champion_id"] == c["id"]


def test_add_certification_missing_name(engine):
    c = engine.add_champion(ORG, {"name": "Alice"})
    with pytest.raises(ValueError, match="cert_name is required"):
        engine.add_certification(ORG, c["id"], {})


def test_add_certification_invalid_status(engine):
    c = engine.add_champion(ORG, {"name": "Alice"})
    with pytest.raises(ValueError, match="Invalid status"):
        engine.add_certification(ORG, c["id"], {"cert_name": "OSCP", "status": "pending"})


def test_list_certifications_by_champion(engine):
    c1 = engine.add_champion(ORG, {"name": "Alice"})
    c2 = engine.add_champion(ORG, {"name": "Bob"})
    engine.add_certification(ORG, c1["id"], {"cert_name": "OSCP"})
    engine.add_certification(ORG, c2["id"], {"cert_name": "CEH"})
    result = engine.list_certifications(ORG, champion_id=c1["id"])
    assert len(result) == 1
    assert result[0]["cert_name"] == "OSCP"


def test_list_certifications_all_org(engine):
    c1 = engine.add_champion(ORG, {"name": "Alice"})
    c2 = engine.add_champion(ORG, {"name": "Bob"})
    engine.add_certification(ORG, c1["id"], {"cert_name": "OSCP"})
    engine.add_certification(ORG, c2["id"], {"cert_name": "CEH"})
    result = engine.list_certifications(ORG)
    assert len(result) == 2


# ---------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------

def test_create_campaign_basic(engine):
    camp = engine.create_campaign(ORG, {
        "title": "Q1 Phishing Sim", "campaign_type": "phishing_simulation",
        "start_date": "2026-01-01", "end_date": "2026-01-31",
    })
    assert camp["title"] == "Q1 Phishing Sim"
    assert camp["status"] == "planned"
    assert "id" in camp


def test_create_campaign_missing_title(engine):
    with pytest.raises(ValueError, match="title is required"):
        engine.create_campaign(ORG, {})


def test_create_campaign_invalid_type(engine):
    with pytest.raises(ValueError, match="Invalid campaign_type"):
        engine.create_campaign(ORG, {"title": "X", "campaign_type": "hackathon"})


def test_list_campaigns_empty(engine):
    assert engine.list_campaigns(ORG) == []


def test_list_campaigns_filter_status(engine):
    engine.create_campaign(ORG, {"title": "C1", "status": "active"})
    engine.create_campaign(ORG, {"title": "C2", "status": "completed"})
    active = engine.list_campaigns(ORG, status="active")
    assert len(active) == 1
    assert active[0]["title"] == "C1"


# ---------------------------------------------------------------------------
# get_program_stats
# ---------------------------------------------------------------------------

def test_get_program_stats_empty(engine):
    stats = engine.get_program_stats(ORG)
    assert stats["champion_count"] == 0
    assert stats["total_activities"] == 0
    assert stats["certifications_expiring_soon"] == 0
    assert stats["active_campaigns"] == 0
    assert stats["top_champions"] == []
    assert isinstance(stats["level_distribution"], dict)


def test_get_program_stats_with_data(engine):
    c1 = engine.add_champion(ORG, {"name": "Alice"})
    c2 = engine.add_champion(ORG, {"name": "Bob"})
    engine.log_activity(ORG, c1["id"], {"activity_type": "training"})
    engine.log_activity(ORG, c1["id"], {"activity_type": "mentoring"})
    engine.add_certification(ORG, c1["id"], {"cert_name": "OSCP", "status": "expiring_soon"})
    engine.create_campaign(ORG, {"title": "Phish", "status": "active"})

    stats = engine.get_program_stats(ORG)
    assert stats["champion_count"] == 2
    assert stats["total_activities"] == 2
    assert stats["certifications_expiring_soon"] == 1
    assert stats["active_campaigns"] == 1
    assert len(stats["top_champions"]) <= 5


def test_get_program_stats_level_distribution(engine):
    c1 = engine.add_champion(ORG, {"name": "Alice"})
    c2 = engine.add_champion(ORG, {"name": "Bob"})
    # Promote c1 to silver (3 x incident_response = 150 pts)
    for _ in range(3):
        engine.log_activity(ORG, c1["id"], {"activity_type": "incident_response"})
    stats = engine.get_program_stats(ORG)
    dist = stats["level_distribution"]
    assert "silver" in dist
    assert dist["silver"] >= 1
    assert "bronze" in dist
