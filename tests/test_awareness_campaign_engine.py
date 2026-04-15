"""Tests for AwarenessCampaignEngine.

Covers campaign creation, status updates, participation recording,
counter increments, pass_rate computation, org isolation, and stats.

Total: 35 tests.
"""

from __future__ import annotations

import os
import pytest
from core.awareness_campaign_engine import AwarenessCampaignEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "awareness_campaign_test.db")
    return AwarenessCampaignEngine(db_path=db)


@pytest.fixture()
def phishing_campaign(engine):
    return engine.create_campaign("org1", {
        "title": "Q2 Phishing Simulation",
        "campaign_type": "phishing_sim",
        "campaign_status": "active",
        "target_department": "Finance",
        "target_count": 50,
    })


@pytest.fixture()
def training_campaign(engine):
    return engine.create_campaign("org1", {
        "title": "Security Fundamentals Training",
        "campaign_type": "training",
        "campaign_status": "draft",
    })


# ===========================================================================
# 1. Initialization
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "ac_init.db")
    AwarenessCampaignEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "ac_idem.db")
    AwarenessCampaignEngine(db_path=db)
    AwarenessCampaignEngine(db_path=db)  # no error on second init


# ===========================================================================
# 2. create_campaign — happy path
# ===========================================================================

def test_create_campaign_returns_record(phishing_campaign):
    assert phishing_campaign["id"]
    assert phishing_campaign["title"] == "Q2 Phishing Simulation"
    assert phishing_campaign["campaign_type"] == "phishing_sim"
    assert phishing_campaign["campaign_status"] == "active"


def test_create_campaign_initial_counters_zero(phishing_campaign):
    assert phishing_campaign["participant_count"] == 0
    assert phishing_campaign["pass_count"] == 0
    assert phishing_campaign["fail_count"] == 0
    assert phishing_campaign["pass_rate"] == pytest.approx(0.0)


def test_create_campaign_defaults_status_draft(engine):
    c = engine.create_campaign("org1", {
        "title": "My Campaign",
        "campaign_type": "quiz",
    })
    assert c["campaign_status"] == "draft"


def test_create_campaign_all_types(engine):
    for ctype in ["phishing_sim", "training", "quiz", "newsletter", "video", "tabletop"]:
        c = engine.create_campaign("org1", {"title": f"C_{ctype}", "campaign_type": ctype})
        assert c["campaign_type"] == ctype


# ===========================================================================
# 3. create_campaign — validation
# ===========================================================================

def test_create_campaign_missing_title_raises(engine):
    with pytest.raises(ValueError, match="title"):
        engine.create_campaign("org1", {"campaign_type": "training"})


def test_create_campaign_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="campaign_type"):
        engine.create_campaign("org1", {"title": "X", "campaign_type": "webinar"})


def test_create_campaign_invalid_status_raises(engine):
    with pytest.raises(ValueError, match="campaign_status"):
        engine.create_campaign("org1", {"title": "X", "campaign_type": "quiz", "campaign_status": "archived"})


# ===========================================================================
# 4. list_campaigns / get_campaign
# ===========================================================================

def test_list_campaigns_returns_all(engine, phishing_campaign, training_campaign):
    campaigns = engine.list_campaigns("org1")
    assert len(campaigns) == 2


def test_list_campaigns_filter_by_type(engine, phishing_campaign, training_campaign):
    result = engine.list_campaigns("org1", campaign_type="phishing_sim")
    assert len(result) == 1
    assert result[0]["campaign_type"] == "phishing_sim"


def test_list_campaigns_filter_by_status(engine, phishing_campaign, training_campaign):
    result = engine.list_campaigns("org1", campaign_status="draft")
    assert len(result) == 1
    assert result[0]["campaign_status"] == "draft"


def test_get_campaign_returns_record(engine, phishing_campaign):
    fetched = engine.get_campaign("org1", phishing_campaign["id"])
    assert fetched["id"] == phishing_campaign["id"]


def test_get_campaign_returns_none_for_missing(engine):
    assert engine.get_campaign("org1", "no-such-id") is None


# ===========================================================================
# 5. update_campaign_status
# ===========================================================================

def test_update_campaign_status_success(engine, training_campaign):
    updated = engine.update_campaign_status("org1", training_campaign["id"], "active")
    assert updated["campaign_status"] == "active"


def test_update_campaign_status_all_valid(engine, training_campaign):
    for status in ["active", "paused", "completed", "cancelled", "draft"]:
        updated = engine.update_campaign_status("org1", training_campaign["id"], status)
        assert updated["campaign_status"] == status


def test_update_campaign_status_invalid_raises(engine, training_campaign):
    with pytest.raises(ValueError, match="campaign_status"):
        engine.update_campaign_status("org1", training_campaign["id"], "expired")


def test_update_campaign_status_missing_campaign_raises(engine):
    with pytest.raises(KeyError):
        engine.update_campaign_status("org1", "bad-id", "active")


# ===========================================================================
# 6. Org isolation
# ===========================================================================

def test_org_isolation_campaigns(engine, phishing_campaign):
    assert engine.list_campaigns("org2") == []
    assert engine.get_campaign("org2", phishing_campaign["id"]) is None


def test_org_isolation_participations(engine, phishing_campaign):
    engine.record_participation("org1", phishing_campaign["id"], {
        "user_id": "user1", "result": "pass"
    })
    assert engine.list_participations("org2") == []


def test_org_isolation_status_update(engine, phishing_campaign):
    with pytest.raises(KeyError):
        engine.update_campaign_status("org2", phishing_campaign["id"], "active")


# ===========================================================================
# 7. record_participation
# ===========================================================================

def test_record_participation_returns_record(engine, phishing_campaign):
    part = engine.record_participation("org1", phishing_campaign["id"], {
        "user_id": "alice",
        "result": "pass",
        "department": "Finance",
        "score": 90,
        "time_spent_minutes": 15,
    })
    assert part["id"]
    assert part["user_id"] == "alice"
    assert part["result"] == "pass"
    assert part["score"] == pytest.approx(90.0)


def test_record_participation_increments_participant_count(engine, phishing_campaign):
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u1", "result": "pass"})
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u2", "result": "fail"})
    updated = engine.get_campaign("org1", phishing_campaign["id"])
    assert updated["participant_count"] == 2


def test_record_participation_pass_increments_pass_count(engine, phishing_campaign):
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u1", "result": "pass"})
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u2", "result": "pass"})
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u3", "result": "fail"})
    updated = engine.get_campaign("org1", phishing_campaign["id"])
    assert updated["pass_count"] == 2
    assert updated["fail_count"] == 1


def test_record_participation_pass_rate_computed(engine, phishing_campaign):
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u1", "result": "pass"})
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u2", "result": "pass"})
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u3", "result": "fail"})
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u4", "result": "fail"})
    updated = engine.get_campaign("org1", phishing_campaign["id"])
    # 2 pass / 4 total * 100 = 50.0
    assert updated["pass_rate"] == pytest.approx(50.0)


def test_record_participation_non_pass_fail_no_count_change(engine, phishing_campaign):
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u1", "result": "click"})
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u2", "result": "report"})
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u3", "result": "incomplete"})
    updated = engine.get_campaign("org1", phishing_campaign["id"])
    assert updated["pass_count"] == 0
    assert updated["fail_count"] == 0
    assert updated["participant_count"] == 3


def test_record_participation_missing_user_id_raises(engine, phishing_campaign):
    with pytest.raises(ValueError, match="user_id"):
        engine.record_participation("org1", phishing_campaign["id"], {"result": "pass"})


def test_record_participation_invalid_result_raises(engine, phishing_campaign):
    with pytest.raises(ValueError, match="result"):
        engine.record_participation("org1", phishing_campaign["id"], {
            "user_id": "u1", "result": "skipped"
        })


def test_record_participation_all_valid_results(engine, phishing_campaign):
    for i, result in enumerate(["pass", "fail", "incomplete", "click", "report"]):
        part = engine.record_participation("org1", phishing_campaign["id"], {
            "user_id": f"user_{i}",
            "result": result,
        })
        assert part["result"] == result


# ===========================================================================
# 8. list_participations
# ===========================================================================

def test_list_participations_filter_by_campaign(engine, phishing_campaign, training_campaign):
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u1", "result": "pass"})
    engine.record_participation("org1", training_campaign["id"], {"user_id": "u2", "result": "fail"})
    result = engine.list_participations("org1", campaign_id=phishing_campaign["id"])
    assert len(result) == 1
    assert result[0]["user_id"] == "u1"


def test_list_participations_filter_by_result(engine, phishing_campaign):
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u1", "result": "pass"})
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u2", "result": "fail"})
    result = engine.list_participations("org1", result="pass")
    assert all(r["result"] == "pass" for r in result)


def test_list_participations_filter_by_department(engine, phishing_campaign):
    engine.record_participation("org1", phishing_campaign["id"], {
        "user_id": "u1", "result": "pass", "department": "Engineering"
    })
    engine.record_participation("org1", phishing_campaign["id"], {
        "user_id": "u2", "result": "fail", "department": "HR"
    })
    result = engine.list_participations("org1", department="Engineering")
    assert len(result) == 1
    assert result[0]["department"] == "Engineering"


# ===========================================================================
# 9. get_campaign_stats
# ===========================================================================

def test_get_campaign_stats_empty(engine):
    stats = engine.get_campaign_stats("org1")
    assert stats["total_campaigns"] == 0
    assert stats["active_campaigns"] == 0
    assert stats["total_participations"] == 0
    assert stats["overall_pass_rate"] == pytest.approx(0.0)
    assert stats["by_type"] == {}
    assert stats["best_campaign"] is None
    assert stats["worst_campaign"] is None


def test_get_campaign_stats_counts(engine, phishing_campaign, training_campaign):
    # Mark training as active too
    engine.update_campaign_status("org1", training_campaign["id"], "active")
    engine.record_participation("org1", phishing_campaign["id"], {"user_id": "u1", "result": "pass"})
    engine.record_participation("org1", training_campaign["id"], {"user_id": "u2", "result": "fail"})

    stats = engine.get_campaign_stats("org1")
    assert stats["total_campaigns"] == 2
    assert stats["active_campaigns"] == 2
    assert stats["total_participations"] == 2
    assert stats["by_type"]["phishing_sim"] == 1
    assert stats["by_type"]["training"] == 1


def test_get_campaign_stats_overall_pass_rate(engine):
    # Create two completed campaigns with known pass_rates
    c1 = engine.create_campaign("org1", {"title": "C1", "campaign_type": "quiz", "campaign_status": "active"})
    c2 = engine.create_campaign("org1", {"title": "C2", "campaign_type": "quiz", "campaign_status": "active"})

    # C1: 2 pass, 0 fail → 100% pass rate
    engine.record_participation("org1", c1["id"], {"user_id": "u1", "result": "pass"})
    engine.record_participation("org1", c1["id"], {"user_id": "u2", "result": "pass"})
    engine.update_campaign_status("org1", c1["id"], "completed")

    # C2: 0 pass, 2 fail → 0% pass rate
    engine.record_participation("org1", c2["id"], {"user_id": "u3", "result": "fail"})
    engine.record_participation("org1", c2["id"], {"user_id": "u4", "result": "fail"})
    engine.update_campaign_status("org1", c2["id"], "completed")

    stats = engine.get_campaign_stats("org1")
    # overall = avg(100, 0) = 50
    assert stats["overall_pass_rate"] == pytest.approx(50.0)


def test_get_campaign_stats_best_worst(engine):
    c1 = engine.create_campaign("org1", {"title": "Best", "campaign_type": "training", "campaign_status": "active"})
    c2 = engine.create_campaign("org1", {"title": "Worst", "campaign_type": "training", "campaign_status": "active"})

    engine.record_participation("org1", c1["id"], {"user_id": "u1", "result": "pass"})
    engine.record_participation("org1", c2["id"], {"user_id": "u2", "result": "fail"})

    stats = engine.get_campaign_stats("org1")
    assert stats["best_campaign"]["title"] == "Best"
    assert stats["worst_campaign"]["title"] == "Worst"


def test_get_campaign_stats_org_isolation(engine, phishing_campaign):
    stats = engine.get_campaign_stats("org2")
    assert stats["total_campaigns"] == 0
