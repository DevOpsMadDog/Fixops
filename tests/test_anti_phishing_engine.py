"""Tests for AntiPhishingEngine — URL analysis, simulations, stats."""

from __future__ import annotations

import pytest

from core.anti_phishing_engine import AntiPhishingEngine


@pytest.fixture
def engine(tmp_path):
    return AntiPhishingEngine(db_path=str(tmp_path / "test_anti_phishing.db"))


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = tmp_path / "anti_phishing.db"
    AntiPhishingEngine(db_path=str(db))
    assert db.exists()


def test_init_idempotent(tmp_path):
    db = tmp_path / "anti_phishing.db"
    AntiPhishingEngine(db_path=str(db))
    AntiPhishingEngine(db_path=str(db))


# ---------------------------------------------------------------------------
# URL Submission
# ---------------------------------------------------------------------------

def test_submit_url_basic(engine):
    url_obj = engine.submit_url("org1", {"url": "http://evil.com/phish"})
    assert url_obj["id"]
    assert url_obj["url"] == "http://evil.com/phish"
    assert url_obj["submission_source"] == "automated"
    assert url_obj["status"] == "pending"
    assert url_obj["verdict"] == ""
    assert url_obj["confidence"] == 0
    assert url_obj["indicators"] == []
    assert url_obj["org_id"] == "org1"


def test_submit_url_all_sources(engine):
    for source in ["user_report", "automated", "feed", "manual"]:
        url_obj = engine.submit_url("org1", {"url": f"http://x.com/{source}", "submission_source": source})
        assert url_obj["submission_source"] == source


def test_submit_url_missing_url(engine):
    with pytest.raises(ValueError, match="url"):
        engine.submit_url("org1", {})


def test_submit_url_invalid_source(engine):
    with pytest.raises(ValueError, match="submission_source"):
        engine.submit_url("org1", {"url": "http://x.com", "submission_source": "unknown"})


# ---------------------------------------------------------------------------
# URL Analysis
# ---------------------------------------------------------------------------

def test_analyze_url_basic(engine):
    url_obj = engine.submit_url("org1", {"url": "http://evil.com"})
    result = engine.analyze_url("org1", url_obj["id"], {
        "verdict": "phishing",
        "confidence": 90,
        "indicators": ["suspicious_domain", "lookalike_brand"],
    })
    assert result["verdict"] == "phishing"
    assert result["confidence"] == 90
    assert result["status"] == "analyzed"
    assert "suspicious_domain" in result["indicators"]
    assert result["analyzed_at"] != ""


def test_analyze_url_all_verdicts(engine):
    for verdict in ["clean", "phishing", "suspicious", "malware"]:
        url_obj = engine.submit_url("org1", {"url": f"http://x.com/{verdict}"})
        result = engine.analyze_url("org1", url_obj["id"], {"verdict": verdict, "confidence": 50})
        assert result["verdict"] == verdict


def test_analyze_url_confidence_clamp_high(engine):
    url_obj = engine.submit_url("org1", {"url": "http://evil.com"})
    result = engine.analyze_url("org1", url_obj["id"], {"verdict": "phishing", "confidence": 999})
    assert result["confidence"] == 100


def test_analyze_url_confidence_clamp_low(engine):
    url_obj = engine.submit_url("org1", {"url": "http://evil.com"})
    result = engine.analyze_url("org1", url_obj["id"], {"verdict": "clean", "confidence": -10})
    assert result["confidence"] == 0


def test_analyze_url_invalid_verdict(engine):
    url_obj = engine.submit_url("org1", {"url": "http://evil.com"})
    with pytest.raises(ValueError, match="verdict"):
        engine.analyze_url("org1", url_obj["id"], {"verdict": "bad_verdict", "confidence": 50})


def test_analyze_url_not_found(engine):
    result = engine.analyze_url("org1", "nonexistent-id", {"verdict": "phishing", "confidence": 80})
    assert result is None


def test_analyze_url_org_isolation(engine):
    url_obj = engine.submit_url("org1", {"url": "http://evil.com"})
    result = engine.analyze_url("org2", url_obj["id"], {"verdict": "phishing", "confidence": 80})
    assert result is None


# ---------------------------------------------------------------------------
# URL List and Get
# ---------------------------------------------------------------------------

def test_list_urls_empty(engine):
    urls = engine.list_urls("org1")
    assert urls == []


def test_list_urls_filter_by_verdict(engine):
    url1 = engine.submit_url("org1", {"url": "http://a.com"})
    url2 = engine.submit_url("org1", {"url": "http://b.com"})
    engine.analyze_url("org1", url1["id"], {"verdict": "phishing", "confidence": 90})
    engine.analyze_url("org1", url2["id"], {"verdict": "clean", "confidence": 10})
    urls = engine.list_urls("org1", verdict="phishing")
    assert len(urls) == 1
    assert urls[0]["verdict"] == "phishing"


def test_list_urls_filter_by_status(engine):
    engine.submit_url("org1", {"url": "http://pending.com"})
    url2 = engine.submit_url("org1", {"url": "http://analyzed.com"})
    engine.analyze_url("org1", url2["id"], {"verdict": "clean", "confidence": 5})
    pending = engine.list_urls("org1", status="pending")
    analyzed = engine.list_urls("org1", status="analyzed")
    assert len(pending) == 1
    assert len(analyzed) == 1


def test_get_url_found(engine):
    created = engine.submit_url("org1", {"url": "http://evil.com"})
    fetched = engine.get_url("org1", created["id"])
    assert fetched["id"] == created["id"]
    assert fetched["url"] == "http://evil.com"


def test_get_url_not_found(engine):
    result = engine.get_url("org1", "nonexistent-id")
    assert result is None


def test_get_url_org_isolation(engine):
    created = engine.submit_url("org1", {"url": "http://evil.com"})
    result = engine.get_url("org2", created["id"])
    assert result is None


# ---------------------------------------------------------------------------
# Simulations
# ---------------------------------------------------------------------------

def test_record_simulation_basic(engine):
    sim = engine.record_simulation("org1", {
        "campaign_name": "Q1 Phishing Test",
        "simulation_type": "credential_harvest",
        "sent_count": 100,
    })
    assert sim["id"]
    assert sim["campaign_name"] == "Q1 Phishing Test"
    assert sim["simulation_type"] == "credential_harvest"
    assert sim["sent_count"] == 100
    assert sim["opened"] == 0
    assert sim["clicked"] == 0
    assert sim["reported"] == 0
    assert sim["click_rate"] == 0.0
    assert sim["status"] == "running"
    assert sim["org_id"] == "org1"


def test_record_simulation_all_types(engine):
    for sim_type in ["credential_harvest", "malware_link", "attachment", "voice", "sms"]:
        sim = engine.record_simulation("org1", {
            "campaign_name": f"Test {sim_type}",
            "simulation_type": sim_type,
            "sent_count": 10,
        })
        assert sim["simulation_type"] == sim_type


def test_record_simulation_missing_campaign_name(engine):
    with pytest.raises(ValueError, match="campaign_name"):
        engine.record_simulation("org1", {"simulation_type": "credential_harvest", "sent_count": 10})


def test_record_simulation_missing_sent_count(engine):
    with pytest.raises(ValueError, match="sent_count"):
        engine.record_simulation("org1", {"campaign_name": "Test", "simulation_type": "credential_harvest"})


def test_record_simulation_invalid_type(engine):
    with pytest.raises(ValueError, match="simulation_type"):
        engine.record_simulation("org1", {
            "campaign_name": "Test", "simulation_type": "bad_type", "sent_count": 10
        })


# ---------------------------------------------------------------------------
# Simulation Results Update
# ---------------------------------------------------------------------------

def test_update_simulation_results_basic(engine):
    sim = engine.record_simulation("org1", {
        "campaign_name": "Test", "simulation_type": "credential_harvest", "sent_count": 100
    })
    result = engine.update_simulation_results("org1", sim["id"], opened=50, clicked=20, reported=10)
    assert result["opened"] == 50
    assert result["clicked"] == 20
    assert result["reported"] == 10
    assert result["status"] == "completed"
    assert result["completed_at"] != ""


def test_update_simulation_click_rate_calculation(engine):
    sim = engine.record_simulation("org1", {
        "campaign_name": "Test", "simulation_type": "credential_harvest", "sent_count": 200
    })
    result = engine.update_simulation_results("org1", sim["id"], opened=100, clicked=50, reported=5)
    assert result["click_rate"] == 25.0


def test_update_simulation_zero_sent_count_no_division_error(engine):
    sim = engine.record_simulation("org1", {
        "campaign_name": "Empty", "simulation_type": "sms", "sent_count": 0
    })
    result = engine.update_simulation_results("org1", sim["id"], opened=0, clicked=0, reported=0)
    assert result["click_rate"] == 0.0


def test_update_simulation_not_found(engine):
    result = engine.update_simulation_results("org1", "nonexistent-id", opened=0, clicked=0, reported=0)
    assert result is None


def test_update_simulation_org_isolation(engine):
    sim = engine.record_simulation("org1", {
        "campaign_name": "Test", "simulation_type": "credential_harvest", "sent_count": 100
    })
    result = engine.update_simulation_results("org2", sim["id"], opened=10, clicked=5, reported=1)
    assert result is None


def test_list_simulations_filter_by_status(engine):
    sim = engine.record_simulation("org1", {
        "campaign_name": "Running", "simulation_type": "credential_harvest", "sent_count": 50
    })
    engine.record_simulation("org1", {
        "campaign_name": "Another", "simulation_type": "malware_link", "sent_count": 30
    })
    engine.update_simulation_results("org1", sim["id"], opened=10, clicked=5, reported=1)
    running = engine.list_simulations("org1", status="running")
    completed = engine.list_simulations("org1", status="completed")
    assert len(running) == 1
    assert len(completed) == 1


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_anti_phishing_stats_empty(engine):
    stats = engine.get_anti_phishing_stats("org1")
    assert stats["total_urls"] == 0
    assert stats["by_verdict"] == {}
    assert stats["phishing_urls"] == 0
    assert stats["avg_confidence"] == 0.0
    assert stats["total_simulations"] == 0
    assert stats["avg_click_rate"] == 0.0


def test_get_anti_phishing_stats_urls(engine):
    url1 = engine.submit_url("org1", {"url": "http://a.com"})
    url2 = engine.submit_url("org1", {"url": "http://b.com"})
    url3 = engine.submit_url("org1", {"url": "http://c.com"})
    engine.analyze_url("org1", url1["id"], {"verdict": "phishing", "confidence": 90})
    engine.analyze_url("org1", url2["id"], {"verdict": "phishing", "confidence": 80})
    engine.analyze_url("org1", url3["id"], {"verdict": "clean", "confidence": 10})
    stats = engine.get_anti_phishing_stats("org1")
    assert stats["total_urls"] == 3
    assert stats["phishing_urls"] == 2
    assert stats["by_verdict"]["phishing"] == 2
    assert stats["by_verdict"]["clean"] == 1


def test_get_anti_phishing_stats_avg_confidence_only_analyzed(engine):
    url1 = engine.submit_url("org1", {"url": "http://a.com"})
    url2 = engine.submit_url("org1", {"url": "http://b.com"})
    # Only analyze url1 — url2 stays pending
    engine.analyze_url("org1", url1["id"], {"verdict": "phishing", "confidence": 80})
    stats = engine.get_anti_phishing_stats("org1")
    # avg_confidence should only include analyzed urls
    assert stats["avg_confidence"] == 80.0


def test_get_anti_phishing_stats_avg_click_rate_only_completed(engine):
    sim1 = engine.record_simulation("org1", {
        "campaign_name": "C1", "simulation_type": "credential_harvest", "sent_count": 100
    })
    sim2 = engine.record_simulation("org1", {
        "campaign_name": "C2", "simulation_type": "malware_link", "sent_count": 200
    })
    engine.update_simulation_results("org1", sim1["id"], opened=50, clicked=20, reported=5)
    # sim2 stays running
    stats = engine.get_anti_phishing_stats("org1")
    # avg_click_rate should only include completed simulations
    assert stats["avg_click_rate"] == 20.0
    assert stats["total_simulations"] == 2


def test_get_anti_phishing_stats_org_isolation(engine):
    engine.submit_url("org1", {"url": "http://a.com"})
    engine.record_simulation("org1", {
        "campaign_name": "C1", "simulation_type": "credential_harvest", "sent_count": 100
    })
    stats = engine.get_anti_phishing_stats("org2")
    assert stats["total_urls"] == 0
    assert stats["total_simulations"] == 0
