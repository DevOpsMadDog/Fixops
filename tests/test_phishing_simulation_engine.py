"""Tests for PhishingSimulationEngine (suite-core/core/phishing_simulation_engine.py).

Covers: campaign CRUD, target management, result recording, template CRUD, stats.
All tests use an in-memory (tmp_path) SQLite DB so they are fully isolated.
"""

from __future__ import annotations

import pytest

from core.phishing_simulation_engine import PhishingSimulationEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "phishing_test.db")
    return PhishingSimulationEngine(db_path=db)


ORG = "org-abc"
ORG2 = "org-xyz"


# ---------------------------------------------------------------------------
# Campaign CRUD
# ---------------------------------------------------------------------------


def test_create_campaign_returns_record(engine):
    c = engine.create_campaign(ORG, {"name": "Test Campaign"})
    assert c["campaign_id"]
    assert c["name"] == "Test Campaign"
    assert c["org_id"] == ORG
    assert c["status"] == "draft"
    assert c["campaign_type"] == "email"


def test_create_campaign_custom_type(engine):
    c = engine.create_campaign(ORG, {"name": "SMS Run", "campaign_type": "sms"})
    assert c["campaign_type"] == "sms"


def test_create_campaign_invalid_type_falls_back_to_email(engine):
    c = engine.create_campaign(ORG, {"name": "Bad", "campaign_type": "fax"})
    assert c["campaign_type"] == "email"


def test_create_campaign_invalid_status_falls_back_to_draft(engine):
    c = engine.create_campaign(ORG, {"name": "Bad", "status": "flying"})
    assert c["status"] == "draft"


def test_list_campaigns_empty(engine):
    assert engine.list_campaigns(ORG) == []


def test_list_campaigns_returns_own_org_only(engine):
    engine.create_campaign(ORG, {"name": "A"})
    engine.create_campaign(ORG2, {"name": "B"})
    results = engine.list_campaigns(ORG)
    assert len(results) == 1
    assert results[0]["name"] == "A"


def test_list_campaigns_status_filter(engine):
    engine.create_campaign(ORG, {"name": "Draft", "status": "draft"})
    engine.create_campaign(ORG, {"name": "Active", "status": "active"})
    actives = engine.list_campaigns(ORG, status="active")
    assert len(actives) == 1
    assert actives[0]["name"] == "Active"


def test_list_campaigns_no_filter_returns_all(engine):
    engine.create_campaign(ORG, {"name": "D", "status": "draft"})
    engine.create_campaign(ORG, {"name": "A", "status": "active"})
    assert len(engine.list_campaigns(ORG)) == 2


def test_create_campaign_with_optional_fields(engine):
    c = engine.create_campaign(ORG, {
        "name": "Full",
        "campaign_type": "spear_phishing",
        "template_id": "tmpl-1",
        "target_group": "engineering",
        "status": "active",
        "launch_date": "2026-04-16T00:00:00Z",
        "end_date": "2026-04-30T00:00:00Z",
        "targets_count": 50,
    })
    assert c["template_id"] == "tmpl-1"
    assert c["target_group"] == "engineering"
    assert c["targets_count"] == 50


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


def test_add_target_returns_record(engine):
    c = engine.create_campaign(ORG, {"name": "C"})
    t = engine.add_target(ORG, c["campaign_id"], {"email": "alice@acme.com", "department": "Eng"})
    assert t["email"] == "alice@acme.com"
    assert t["department"] == "Eng"
    assert t["clicked"] is False
    assert t["opened"] is False


def test_add_target_increments_campaign_count(engine):
    c = engine.create_campaign(ORG, {"name": "C"})
    cid = c["campaign_id"]
    engine.add_target(ORG, cid, {"email": "a@x.com"})
    engine.add_target(ORG, cid, {"email": "b@x.com"})
    campaigns = engine.list_campaigns(ORG)
    assert campaigns[0]["targets_count"] == 2


def test_list_targets_empty(engine):
    c = engine.create_campaign(ORG, {"name": "C"})
    assert engine.list_targets(ORG, c["campaign_id"]) == []


def test_list_targets_scoped_by_org(engine):
    c1 = engine.create_campaign(ORG, {"name": "C"})
    c2 = engine.create_campaign(ORG2, {"name": "D"})
    engine.add_target(ORG, c1["campaign_id"], {"email": "a@x.com"})
    engine.add_target(ORG2, c2["campaign_id"], {"email": "b@x.com"})
    assert len(engine.list_targets(ORG, c1["campaign_id"])) == 1
    assert len(engine.list_targets(ORG2, c2["campaign_id"])) == 1


def test_list_targets_returns_multiple(engine):
    c = engine.create_campaign(ORG, {"name": "C"})
    cid = c["campaign_id"]
    for i in range(5):
        engine.add_target(ORG, cid, {"email": f"user{i}@x.com"})
    assert len(engine.list_targets(ORG, cid)) == 5


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


def test_record_result_opened(engine):
    c = engine.create_campaign(ORG, {"name": "C"})
    t = engine.add_target(ORG, c["campaign_id"], {"email": "a@x.com"})
    ok = engine.record_result(ORG, t["target_id"], "opened")
    assert ok is True
    targets = engine.list_targets(ORG, c["campaign_id"])
    assert targets[0]["opened"] is True


def test_record_result_clicked_sets_click_time(engine):
    c = engine.create_campaign(ORG, {"name": "C"})
    t = engine.add_target(ORG, c["campaign_id"], {"email": "a@x.com"})
    engine.record_result(ORG, t["target_id"], "clicked")
    targets = engine.list_targets(ORG, c["campaign_id"])
    assert targets[0]["clicked"] is True
    assert targets[0]["click_time"] is not None


def test_record_result_reported(engine):
    c = engine.create_campaign(ORG, {"name": "C"})
    t = engine.add_target(ORG, c["campaign_id"], {"email": "a@x.com"})
    engine.record_result(ORG, t["target_id"], "reported")
    targets = engine.list_targets(ORG, c["campaign_id"])
    assert targets[0]["reported"] is True


def test_record_result_data_submitted(engine):
    c = engine.create_campaign(ORG, {"name": "C"})
    t = engine.add_target(ORG, c["campaign_id"], {"email": "a@x.com"})
    engine.record_result(ORG, t["target_id"], "data_submitted")
    targets = engine.list_targets(ORG, c["campaign_id"])
    assert targets[0]["data_submitted"] is True


def test_record_result_invalid_action(engine):
    c = engine.create_campaign(ORG, {"name": "C"})
    t = engine.add_target(ORG, c["campaign_id"], {"email": "a@x.com"})
    ok = engine.record_result(ORG, t["target_id"], "exploded")
    assert ok is False


def test_record_result_wrong_org_returns_false(engine):
    c = engine.create_campaign(ORG, {"name": "C"})
    t = engine.add_target(ORG, c["campaign_id"], {"email": "a@x.com"})
    ok = engine.record_result(ORG2, t["target_id"], "clicked")
    assert ok is False


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


def test_create_template_returns_record(engine):
    tmpl = engine.create_template(ORG, {
        "name": "Bank Phish",
        "template_type": "email",
        "subject": "Your account has been suspended",
        "sender_name": "Security Team",
        "difficulty": "high",
        "click_rate_avg": 0.35,
    })
    assert tmpl["template_id"]
    assert tmpl["name"] == "Bank Phish"
    assert tmpl["difficulty"] == "high"
    assert tmpl["click_rate_avg"] == pytest.approx(0.35)


def test_create_template_invalid_difficulty_falls_back(engine):
    tmpl = engine.create_template(ORG, {"name": "T", "difficulty": "impossible"})
    assert tmpl["difficulty"] == "medium"


def test_list_templates_empty(engine):
    assert engine.list_templates(ORG) == []


def test_list_templates_scoped_by_org(engine):
    engine.create_template(ORG, {"name": "A"})
    engine.create_template(ORG2, {"name": "B"})
    assert len(engine.list_templates(ORG)) == 1
    assert engine.list_templates(ORG)[0]["name"] == "A"


def test_list_templates_returns_multiple(engine):
    for i in range(4):
        engine.create_template(ORG, {"name": f"T{i}"})
    assert len(engine.list_templates(ORG)) == 4


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_get_campaign_stats_empty(engine):
    c = engine.create_campaign(ORG, {"name": "C"})
    stats = engine.get_campaign_stats(ORG, c["campaign_id"])
    assert stats["total_targets"] == 0
    assert stats["click_rate"] == 0.0


def test_get_campaign_stats_with_data(engine):
    c = engine.create_campaign(ORG, {"name": "C"})
    cid = c["campaign_id"]
    t1 = engine.add_target(ORG, cid, {"email": "a@x.com", "department": "Eng"})
    t2 = engine.add_target(ORG, cid, {"email": "b@x.com", "department": "Eng"})
    t3 = engine.add_target(ORG, cid, {"email": "c@x.com", "department": "HR"})
    engine.record_result(ORG, t1["target_id"], "clicked")
    engine.record_result(ORG, t2["target_id"], "reported")
    engine.record_result(ORG, t3["target_id"], "opened")
    stats = engine.get_campaign_stats(ORG, cid)
    assert stats["total_targets"] == 3
    assert stats["clicked_count"] == 1
    assert stats["reported_count"] == 1
    assert stats["opened_count"] == 1
    assert stats["click_rate"] == pytest.approx(33.33)
    assert "Eng" in stats["by_department"]
    assert "HR" in stats["by_department"]


def test_get_campaign_stats_all_campaigns(engine):
    c1 = engine.create_campaign(ORG, {"name": "C1"})
    c2 = engine.create_campaign(ORG, {"name": "C2"})
    t1 = engine.add_target(ORG, c1["campaign_id"], {"email": "a@x.com"})
    t2 = engine.add_target(ORG, c2["campaign_id"], {"email": "b@x.com"})
    engine.record_result(ORG, t1["target_id"], "clicked")
    stats = engine.get_campaign_stats(ORG)  # no campaign_id = all campaigns
    assert stats["total_targets"] == 2
    assert stats["clicked_count"] == 1


def test_get_org_stats(engine):
    c = engine.create_campaign(ORG, {"name": "C"})
    cid = c["campaign_id"]
    t1 = engine.add_target(ORG, cid, {"email": "a@x.com", "department": "Sales"})
    t2 = engine.add_target(ORG, cid, {"email": "b@x.com", "department": "Eng"})
    engine.record_result(ORG, t1["target_id"], "clicked")
    stats = engine.get_org_stats(ORG)
    assert stats["total_campaigns"] == 1
    assert stats["avg_click_rate"] == pytest.approx(50.0)
    assert stats["most_vulnerable_department"] == "Sales"


def test_get_org_stats_no_data(engine):
    stats = engine.get_org_stats(ORG)
    assert stats["total_campaigns"] == 0
    assert stats["avg_click_rate"] == 0.0
    assert stats["most_vulnerable_department"] is None
