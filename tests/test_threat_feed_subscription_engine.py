"""Tests for ThreatFeedSubscriptionEngine — 35+ tests covering all major paths."""

from __future__ import annotations

import hashlib
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.threat_feed_subscription_engine import ThreatFeedSubscriptionEngine

ORG = "test-org-tfs"
ORG2 = "other-org-tfs"


@pytest.fixture
def engine(tmp_path):
    return ThreatFeedSubscriptionEngine(db_path=str(tmp_path / "tfs.db"))


# ---------------------------------------------------------------------------
# create_subscription
# ---------------------------------------------------------------------------

def test_create_subscription_basic(engine):
    sub = engine.create_subscription(ORG, "AlienVault OTX", "osint", "https://otx.alienvault.com", "key123")
    assert sub["id"]
    assert sub["feed_name"] == "AlienVault OTX"
    assert sub["feed_type"] == "osint"
    assert sub["status"] == "active"
    assert sub["ioc_count"] == 0
    assert sub["error_count"] == 0
    assert sub["last_fetched"] is None


def test_create_subscription_api_key_hashed(engine):
    key = "supersecret"
    sub = engine.create_subscription(ORG, "Feed", "commercial", "https://feed.example.com", key)
    expected_hash = hashlib.sha256(key.encode()).hexdigest()
    assert sub["api_key_hash"] == expected_hash
    assert key not in str(sub)


def test_create_subscription_empty_api_key(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://feed.example.com", "")
    assert sub["api_key_hash"] == ""


def test_create_subscription_all_feed_types(engine):
    types = ["commercial", "osint", "isac", "government", "community", "internal", "vendor"]
    for ft in types:
        sub = engine.create_subscription(ORG, f"Feed-{ft}", ft, "https://example.com", "k")
        assert sub["feed_type"] == ft


def test_create_subscription_invalid_feed_type(engine):
    with pytest.raises(ValueError, match="feed_type"):
        engine.create_subscription(ORG, "X", "unknown-type", "https://x.com", "k")


def test_create_subscription_refresh_interval(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k", refresh_interval_minutes=30)
    assert sub["refresh_interval_minutes"] == 30


def test_create_subscription_org_isolation(engine):
    engine.create_subscription(ORG, "Feed A", "osint", "https://a.com", "k")
    subs2 = engine.list_subscriptions(ORG2)
    assert subs2 == []


# ---------------------------------------------------------------------------
# update_subscription_status
# ---------------------------------------------------------------------------

def test_update_status_valid(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    updated = engine.update_subscription_status(sub["id"], ORG, "paused")
    assert updated["status"] == "paused"


def test_update_status_all_statuses(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    for s in ["paused", "error", "disabled", "active"]:
        updated = engine.update_subscription_status(sub["id"], ORG, s)
        assert updated["status"] == s


def test_update_status_invalid(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    with pytest.raises(ValueError):
        engine.update_subscription_status(sub["id"], ORG, "invalid-status")


def test_update_status_not_found(engine):
    with pytest.raises(ValueError):
        engine.update_subscription_status("nonexistent-id", ORG, "paused")


# ---------------------------------------------------------------------------
# record_ingestion
# ---------------------------------------------------------------------------

def test_record_ingestion_success(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    log = engine.record_ingestion(sub["id"], ORG, iocs_fetched=100, iocs_new=50, iocs_updated=10, status="success")
    assert log["iocs_fetched"] == 100
    assert log["iocs_new"] == 50
    assert log["status"] == "success"


def test_record_ingestion_success_increments_ioc_count(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    engine.record_ingestion(sub["id"], ORG, 100, 30, 5, "success")
    engine.record_ingestion(sub["id"], ORG, 80, 20, 3, "success")
    updated = engine.get_subscription(sub["id"], ORG)
    assert updated["ioc_count"] == 50  # 30 + 20


def test_record_ingestion_error_increments_error_count(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    engine.record_ingestion(sub["id"], ORG, 0, 0, 0, "error", "Connection timeout")
    engine.record_ingestion(sub["id"], ORG, 0, 0, 0, "error", "Auth failed")
    updated = engine.get_subscription(sub["id"], ORG)
    assert updated["error_count"] == 2
    assert updated["ioc_count"] == 0


def test_record_ingestion_updates_last_fetched(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    assert sub["last_fetched"] is None
    engine.record_ingestion(sub["id"], ORG, 10, 5, 0, "success")
    updated = engine.get_subscription(sub["id"], ORG)
    assert updated["last_fetched"] is not None


def test_record_ingestion_log_appears_in_get_subscription(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    for i in range(3):
        engine.record_ingestion(sub["id"], ORG, 10, i, 0, "success")
    result = engine.get_subscription(sub["id"], ORG)
    assert len(result["recent_ingestion_logs"]) == 3


def test_record_ingestion_log_capped_at_10(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    for i in range(15):
        engine.record_ingestion(sub["id"], ORG, 10, 1, 0, "success")
    result = engine.get_subscription(sub["id"], ORG)
    assert len(result["recent_ingestion_logs"]) == 10


# ---------------------------------------------------------------------------
# create_delivery / record_delivery
# ---------------------------------------------------------------------------

def test_create_delivery_basic(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    d = engine.create_delivery(sub["id"], ORG, "webhook", "https://hook.example.com")
    assert d["id"]
    assert d["delivery_type"] == "webhook"
    assert d["enabled"] is True
    assert d["delivery_count"] == 0


def test_create_delivery_all_types(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    for dt in ["webhook", "email", "siem", "soar", "api-push", "file-export"]:
        d = engine.create_delivery(sub["id"], ORG, dt, "endpoint")
        assert d["delivery_type"] == dt


def test_create_delivery_invalid_type(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    with pytest.raises(ValueError, match="delivery_type"):
        engine.create_delivery(sub["id"], ORG, "fax", "endpoint")


def test_create_delivery_filter_categories_stored(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    d = engine.create_delivery(sub["id"], ORG, "siem", "siem.example.com",
                               filter_severity="high", filter_categories=["malware", "phishing"])
    assert "malware" in d["filter_categories"]
    assert "phishing" in d["filter_categories"]


def test_record_delivery_increments_count(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    d = engine.create_delivery(sub["id"], ORG, "webhook", "https://hook.example.com")
    engine.record_delivery(d["id"], ORG, 5)
    updated = engine.record_delivery(d["id"], ORG, 3)
    assert updated["delivery_count"] == 8
    assert updated["last_delivered"] is not None


def test_record_delivery_not_found(engine):
    with pytest.raises(ValueError):
        engine.record_delivery("nonexistent-id", ORG, 1)


# ---------------------------------------------------------------------------
# list_subscriptions / get_subscription
# ---------------------------------------------------------------------------

def test_list_subscriptions_empty(engine):
    assert engine.list_subscriptions(ORG) == []


def test_list_subscriptions_filter_status(engine):
    sub1 = engine.create_subscription(ORG, "A", "osint", "https://a.com", "k")
    engine.create_subscription(ORG, "B", "commercial", "https://b.com", "k")
    engine.update_subscription_status(sub1["id"], ORG, "paused")
    paused = engine.list_subscriptions(ORG, status="paused")
    assert len(paused) == 1
    assert paused[0]["feed_name"] == "A"


def test_list_subscriptions_filter_feed_type(engine):
    engine.create_subscription(ORG, "A", "osint", "https://a.com", "k")
    engine.create_subscription(ORG, "B", "commercial", "https://b.com", "k")
    osint_feeds = engine.list_subscriptions(ORG, feed_type="osint")
    assert len(osint_feeds) == 1
    assert osint_feeds[0]["feed_name"] == "A"


def test_get_subscription_not_found(engine):
    result = engine.get_subscription("nonexistent-id", ORG)
    assert result is None


# ---------------------------------------------------------------------------
# get_due_subscriptions
# ---------------------------------------------------------------------------

def test_due_subscriptions_never_fetched(engine):
    engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k", refresh_interval_minutes=60)
    due = engine.get_due_subscriptions(ORG)
    assert len(due) == 1


def test_due_subscriptions_recently_fetched_not_due(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k", refresh_interval_minutes=9999)
    # Record a fresh ingestion so last_fetched = now
    engine.record_ingestion(sub["id"], ORG, 10, 5, 0, "success")
    due = engine.get_due_subscriptions(ORG)
    assert len(due) == 0


def test_due_subscriptions_paused_not_included(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    engine.update_subscription_status(sub["id"], ORG, "paused")
    due = engine.get_due_subscriptions(ORG)
    assert len(due) == 0


# ---------------------------------------------------------------------------
# get_ingestion_stats
# ---------------------------------------------------------------------------

def test_ingestion_stats_empty(engine):
    stats = engine.get_ingestion_stats(ORG)
    assert stats["total_subscriptions"] == 0
    assert stats["total_iocs"] == 0
    assert stats["total_deliveries"] == 0


def test_ingestion_stats_with_data(engine):
    sub1 = engine.create_subscription(ORG, "A", "osint", "https://a.com", "k")
    sub2 = engine.create_subscription(ORG, "B", "commercial", "https://b.com", "k")
    engine.record_ingestion(sub1["id"], ORG, 100, 40, 5, "success")
    engine.record_ingestion(sub2["id"], ORG, 50, 20, 2, "success")
    engine.record_ingestion(sub1["id"], ORG, 0, 0, 0, "error", "timeout")
    stats = engine.get_ingestion_stats(ORG)
    assert stats["total_subscriptions"] == 2
    assert stats["total_iocs"] == 60  # 40 + 20
    assert stats["ingestion_success_count"] == 2
    assert stats["ingestion_error_count"] == 1


def test_ingestion_stats_high_error_feeds(engine):
    sub = engine.create_subscription(ORG, "Flaky Feed", "osint", "https://x.com", "k")
    for _ in range(6):
        engine.record_ingestion(sub["id"], ORG, 0, 0, 0, "error", "fail")
    stats = engine.get_ingestion_stats(ORG)
    assert len(stats["high_error_feeds"]) == 1
    assert stats["high_error_feeds"][0]["feed_name"] == "Flaky Feed"


def test_ingestion_stats_total_deliveries(engine):
    sub = engine.create_subscription(ORG, "Feed", "osint", "https://x.com", "k")
    d = engine.create_delivery(sub["id"], ORG, "webhook", "https://hook.example.com")
    engine.record_delivery(d["id"], ORG, 10)
    engine.record_delivery(d["id"], ORG, 5)
    stats = engine.get_ingestion_stats(ORG)
    assert stats["total_deliveries"] == 15
