"""Tests for FeedManager — feed lifecycle, health, IOC management.

Tests cover:
- Feed CRUD (register, get, list, update, delete)
- Refresh recording and health calculation
- Reliability scoring
- IOC ingestion, search, deduplication
- Stale feed detection
- Feed statistics
"""

from __future__ import annotations

import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from typing import List

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")

from core.feed_manager import (
    FeedConfig,
    FeedHealth,
    FeedManager,
    FeedStatus,
    FeedType,
    IOC,
    IOCType,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "test_feed_manager.db")


@pytest.fixture
def manager(tmp_db):
    return FeedManager(db_path=tmp_db)


@pytest.fixture
def sample_feed(manager) -> FeedConfig:
    config = FeedConfig(
        name="Test CVE Feed",
        url="https://example.com/cve-feed",
        type=FeedType.CVE,
        enabled=True,
        refresh_interval_minutes=60,
        org_id="org-test",
    )
    return manager.register_feed(config)


@pytest.fixture
def sample_iocs(sample_feed) -> List[IOC]:
    now = datetime.now(timezone.utc)
    return [
        IOC(
            type=IOCType.IP,
            value="1.2.3.4",
            source_feed=sample_feed.name,
            confidence=0.9,
            first_seen=now,
            last_seen=now,
            tags=["malware", "c2"],
        ),
        IOC(
            type=IOCType.DOMAIN,
            value="evil.example.com",
            source_feed=sample_feed.name,
            confidence=0.7,
            first_seen=now,
            last_seen=now,
            tags=["phishing"],
        ),
        IOC(
            type=IOCType.HASH_SHA256,
            value="abc123def456" * 4 + "abcd",
            source_feed=sample_feed.name,
            confidence=0.95,
            first_seen=now,
            last_seen=now,
            tags=["malware"],
        ),
    ]


# ---------------------------------------------------------------------------
# Feed CRUD
# ---------------------------------------------------------------------------


class TestFeedCRUD:
    def test_register_feed_returns_config(self, manager):
        config = FeedConfig(
            name="MISP Feed",
            url="https://misp.example.com/feed",
            type=FeedType.IOC,
            org_id="org-1",
        )
        result = manager.register_feed(config)
        assert result.id == config.id
        assert result.name == "MISP Feed"
        assert result.type == FeedType.IOC

    def test_register_feed_persists(self, manager):
        config = FeedConfig(
            name="Exploit Feed",
            url="https://exploit.example.com",
            type=FeedType.EXPLOIT,
            org_id="org-1",
        )
        manager.register_feed(config)
        retrieved = manager.get_feed(config.id)
        assert retrieved.name == "Exploit Feed"
        assert retrieved.url == "https://exploit.example.com"

    def test_get_feed_not_found_raises(self, manager):
        with pytest.raises(ValueError, match="not found"):
            manager.get_feed("nonexistent-id")

    def test_list_feeds_returns_all_for_org(self, manager):
        for i in range(3):
            manager.register_feed(FeedConfig(
                name=f"Feed {i}",
                url=f"https://example.com/feed{i}",
                type=FeedType.MALWARE,
                org_id="org-list",
            ))
        feeds = manager.list_feeds(org_id="org-list")
        assert len(feeds) == 3

    def test_list_feeds_isolates_by_org(self, manager):
        manager.register_feed(FeedConfig(
            name="Org A Feed",
            url="https://a.example.com",
            type=FeedType.CVE,
            org_id="org-a",
        ))
        manager.register_feed(FeedConfig(
            name="Org B Feed",
            url="https://b.example.com",
            type=FeedType.CVE,
            org_id="org-b",
        ))
        assert len(manager.list_feeds("org-a")) == 1
        assert len(manager.list_feeds("org-b")) == 1

    def test_update_feed_name(self, manager, sample_feed):
        updated = manager.update_feed(sample_feed.id, {"name": "Updated Name"})
        assert updated.name == "Updated Name"

    def test_update_feed_enabled_flag(self, manager, sample_feed):
        updated = manager.update_feed(sample_feed.id, {"enabled": False})
        assert updated.enabled is False

    def test_update_feed_ignores_unknown_fields(self, manager, sample_feed):
        # Should not raise, just ignore unknown fields
        updated = manager.update_feed(sample_feed.id, {"bogus_field": "value", "name": "New Name"})
        assert updated.name == "New Name"

    def test_update_feed_not_found_raises(self, manager):
        with pytest.raises(ValueError, match="not found"):
            manager.update_feed("no-such-id", {"name": "X"})

    def test_delete_feed_removes_record(self, manager, sample_feed):
        manager.delete_feed(sample_feed.id)
        with pytest.raises(ValueError):
            manager.get_feed(sample_feed.id)

    def test_delete_feed_not_in_list(self, manager, sample_feed):
        manager.delete_feed(sample_feed.id)
        feeds = manager.list_feeds(org_id=sample_feed.org_id)
        assert all(f.id != sample_feed.id for f in feeds)


# ---------------------------------------------------------------------------
# Refresh recording and health
# ---------------------------------------------------------------------------


class TestRefreshAndHealth:
    def test_record_refresh_success_updates_last_success(self, manager, sample_feed):
        manager.record_refresh(sample_feed.id, success=True, ioc_count=10, response_ms=150)
        feed = manager.get_feed(sample_feed.id)
        assert feed.last_success is not None
        assert feed.error_count == 0

    def test_record_refresh_failure_increments_error_count(self, manager, sample_feed):
        manager.record_refresh(sample_feed.id, success=False, error="Timeout")
        feed = manager.get_feed(sample_feed.id)
        assert feed.error_count == 1

    def test_multiple_failures_increment_correctly(self, manager, sample_feed):
        for _ in range(3):
            manager.record_refresh(sample_feed.id, success=False, error="Connection refused")
        feed = manager.get_feed(sample_feed.id)
        assert feed.error_count == 3

    def test_success_resets_error_count(self, manager, sample_feed):
        manager.record_refresh(sample_feed.id, success=False, error="err")
        manager.record_refresh(sample_feed.id, success=True, ioc_count=5)
        feed = manager.get_feed(sample_feed.id)
        assert feed.error_count == 0

    def test_get_feed_health_returns_feedhealth(self, manager, sample_feed):
        manager.record_refresh(sample_feed.id, success=True, ioc_count=5)
        health = manager.get_feed_health(sample_feed.id)
        assert isinstance(health, FeedHealth)
        assert health.feed_id == sample_feed.id

    def test_health_active_after_success(self, manager, sample_feed):
        manager.record_refresh(sample_feed.id, success=True, ioc_count=5)
        health = manager.get_feed_health(sample_feed.id)
        assert health.status == FeedStatus.ACTIVE

    def test_health_error_after_five_failures(self, manager, sample_feed):
        for _ in range(5):
            manager.record_refresh(sample_feed.id, success=False, error="err")
        health = manager.get_feed_health(sample_feed.id)
        assert health.status == FeedStatus.ERROR

    def test_health_degraded_after_two_failures(self, manager, sample_feed):
        # First succeed so last_success is set, then fail twice
        manager.record_refresh(sample_feed.id, success=True, ioc_count=1)
        manager.record_refresh(sample_feed.id, success=False, error="err")
        manager.record_refresh(sample_feed.id, success=False, error="err")
        health = manager.get_feed_health(sample_feed.id)
        assert health.status == FeedStatus.DEGRADED

    def test_health_disabled_when_feed_disabled(self, manager, sample_feed):
        manager.update_feed(sample_feed.id, {"enabled": False})
        health = manager.get_feed_health(sample_feed.id)
        assert health.status == FeedStatus.DISABLED

    def test_health_uptime_pct_calculation(self, manager, sample_feed):
        manager.record_refresh(sample_feed.id, success=True, ioc_count=1)
        manager.record_refresh(sample_feed.id, success=True, ioc_count=1)
        manager.record_refresh(sample_feed.id, success=False, error="err")
        manager.record_refresh(sample_feed.id, success=False, error="err")
        health = manager.get_feed_health(sample_feed.id)
        assert health.uptime_pct == pytest.approx(50.0)

    def test_health_consecutive_failures(self, manager, sample_feed):
        manager.record_refresh(sample_feed.id, success=True, ioc_count=1)
        manager.record_refresh(sample_feed.id, success=False, error="e1")
        manager.record_refresh(sample_feed.id, success=False, error="e2")
        health = manager.get_feed_health(sample_feed.id)
        assert health.consecutive_failures == 2

    def test_get_all_health_returns_list(self, manager):
        for i in range(3):
            f = manager.register_feed(FeedConfig(
                name=f"Health Feed {i}",
                url=f"https://h{i}.example.com",
                type=FeedType.IOC,
                org_id="org-health",
            ))
            manager.record_refresh(f.id, success=True, ioc_count=i)
        health_list = manager.get_all_health(org_id="org-health")
        assert len(health_list) == 3

    def test_refresh_feed_returns_stats(self, manager, sample_feed):
        result = manager.refresh_feed(sample_feed.id)
        assert result["feed_id"] == sample_feed.id
        assert "refreshed_at" in result
        assert "response_ms" in result

    def test_refresh_feed_not_found_raises(self, manager):
        with pytest.raises(ValueError):
            manager.refresh_feed("no-such-feed")


# ---------------------------------------------------------------------------
# Reliability scoring
# ---------------------------------------------------------------------------


class TestReliability:
    def test_reliability_default_no_history(self, manager, sample_feed):
        score = manager.calculate_reliability(sample_feed.id)
        assert score == 1.0  # No history → default perfect

    def test_reliability_decreases_on_failures(self, manager, sample_feed):
        # Establish baseline with successes first
        manager.record_refresh(sample_feed.id, success=True, ioc_count=5)
        score_before = manager.calculate_reliability(sample_feed.id)
        manager.record_refresh(sample_feed.id, success=False, error="err")
        manager.record_refresh(sample_feed.id, success=False, error="err")
        manager.record_refresh(sample_feed.id, success=False, error="err")
        score_after = manager.calculate_reliability(sample_feed.id)
        assert score_after < score_before

    def test_reliability_score_in_range(self, manager, sample_feed):
        for i in range(10):
            manager.record_refresh(
                sample_feed.id,
                success=(i % 3 != 0),
                ioc_count=i * 2,
                response_ms=100 + i * 10,
            )
        score = manager.calculate_reliability(sample_feed.id)
        assert 0.0 <= score <= 1.0

    def test_reliability_stored_on_record_refresh(self, manager, sample_feed):
        manager.record_refresh(sample_feed.id, success=True, ioc_count=10)
        feed = manager.get_feed(sample_feed.id)
        assert feed.reliability_score is not None
        assert 0.0 <= feed.reliability_score <= 1.0


# ---------------------------------------------------------------------------
# IOC ingestion, search, deduplication
# ---------------------------------------------------------------------------


class TestIOCManagement:
    def test_ingest_iocs_stores_records(self, manager, sample_feed, sample_iocs):
        manager.ingest_iocs(sample_feed.id, sample_iocs)
        results = manager.search_iocs()
        assert len(results) == 3

    def test_search_iocs_by_type(self, manager, sample_feed, sample_iocs):
        manager.ingest_iocs(sample_feed.id, sample_iocs)
        ips = manager.search_iocs(ioc_type=IOCType.IP)
        assert len(ips) == 1
        assert ips[0].value == "1.2.3.4"

    def test_search_iocs_by_query(self, manager, sample_feed, sample_iocs):
        manager.ingest_iocs(sample_feed.id, sample_iocs)
        results = manager.search_iocs(query="evil")
        assert len(results) == 1
        assert results[0].type == IOCType.DOMAIN

    def test_search_iocs_by_source_feed(self, manager, sample_feed, sample_iocs):
        manager.ingest_iocs(sample_feed.id, sample_iocs)
        results = manager.search_iocs(source_feed=sample_feed.name)
        assert len(results) == 3

    def test_search_iocs_min_confidence(self, manager, sample_feed, sample_iocs):
        manager.ingest_iocs(sample_feed.id, sample_iocs)
        high_conf = manager.search_iocs(min_confidence=0.9)
        # Only IP (0.9) and SHA256 (0.95) qualify
        assert len(high_conf) == 2

    def test_ingest_iocs_no_duplicates(self, manager, sample_feed, sample_iocs):
        manager.ingest_iocs(sample_feed.id, sample_iocs)
        manager.ingest_iocs(sample_feed.id, sample_iocs)  # Second ingest same IOCs
        results = manager.search_iocs()
        assert len(results) == 3  # Still 3, not 6

    def test_dedup_iocs_removes_cross_feed_dupes(self, manager):
        now = datetime.now(timezone.utc)
        org_id = "org-dedup"

        feed1 = manager.register_feed(FeedConfig(
            name="Feed Alpha",
            url="https://alpha.example.com",
            type=FeedType.IOC,
            org_id=org_id,
        ))
        feed2 = manager.register_feed(FeedConfig(
            name="Feed Beta",
            url="https://beta.example.com",
            type=FeedType.IOC,
            org_id=org_id,
        ))

        # Same IP in both feeds (different dedup_hash because different feed_id)
        # dedup_iocs finds same (type, value) across feeds
        ioc1 = IOC(type=IOCType.IP, value="5.5.5.5", source_feed="alpha",
                   confidence=0.8, first_seen=now, last_seen=now)
        ioc2 = IOC(type=IOCType.IP, value="5.5.5.5", source_feed="beta",
                   confidence=0.6, first_seen=now, last_seen=now)

        manager.ingest_iocs(feed1.id, [ioc1])
        manager.ingest_iocs(feed2.id, [ioc2])

        # Verify 2 records exist before dedup
        results_before = manager.search_iocs(ioc_type=IOCType.IP, query="5.5.5.5")
        assert len(results_before) == 2

        removed = manager.dedup_iocs(org_id=org_id)
        assert removed == 1

        results_after = manager.search_iocs(ioc_type=IOCType.IP, query="5.5.5.5")
        assert len(results_after) == 1

    def test_dedup_returns_zero_when_no_dupes(self, manager, sample_feed, sample_iocs):
        manager.ingest_iocs(sample_feed.id, sample_iocs)
        removed = manager.dedup_iocs(org_id=sample_feed.org_id)
        assert removed == 0


# ---------------------------------------------------------------------------
# Stale feed detection
# ---------------------------------------------------------------------------


class TestStaleFeedDetection:
    def test_stale_feed_never_refreshed(self, manager):
        feed = manager.register_feed(FeedConfig(
            name="Never Refreshed",
            url="https://stale.example.com",
            type=FeedType.CVE,
            org_id="org-stale",
        ))
        stale = manager.get_stale_feeds(threshold_hours=1)
        assert any(f.id == feed.id for f in stale)

    def test_stale_feed_refreshed_recently_not_stale(self, manager):
        feed = manager.register_feed(FeedConfig(
            name="Fresh Feed",
            url="https://fresh.example.com",
            type=FeedType.CVE,
            org_id="org-fresh",
        ))
        manager.record_refresh(feed.id, success=True, ioc_count=5)
        stale = manager.get_stale_feeds(threshold_hours=24)
        assert not any(f.id == feed.id for f in stale)

    def test_disabled_feed_excluded_from_stale(self, manager):
        feed = manager.register_feed(FeedConfig(
            name="Disabled Feed",
            url="https://disabled.example.com",
            type=FeedType.CVE,
            org_id="org-dis",
            enabled=False,
        ))
        stale = manager.get_stale_feeds(threshold_hours=1)
        assert not any(f.id == feed.id for f in stale)

    def test_list_feeds_filtered_by_status(self, manager):
        org_id = "org-status-filter"
        feed = manager.register_feed(FeedConfig(
            name="Status Feed",
            url="https://status.example.com",
            type=FeedType.IOC,
            org_id=org_id,
            enabled=False,
        ))
        disabled_feeds = manager.list_feeds(org_id=org_id, status_filter=FeedStatus.DISABLED)
        assert any(f.id == feed.id for f in disabled_feeds)
        active_feeds = manager.list_feeds(org_id=org_id, status_filter=FeedStatus.ACTIVE)
        assert not any(f.id == feed.id for f in active_feeds)


# ---------------------------------------------------------------------------
# Feed statistics
# ---------------------------------------------------------------------------


class TestFeedStats:
    def test_stats_returns_correct_total(self, manager):
        org_id = "org-stats"
        for i in range(4):
            manager.register_feed(FeedConfig(
                name=f"Stats Feed {i}",
                url=f"https://s{i}.example.com",
                type=FeedType.IOC,
                org_id=org_id,
            ))
        stats = manager.get_feed_stats(org_id=org_id)
        assert stats["total_feeds"] == 4

    def test_stats_keys_present(self, manager):
        stats = manager.get_feed_stats(org_id="org-empty")
        assert "total_feeds" in stats
        assert "active" in stats
        assert "stale" in stats
        assert "total_iocs" in stats
        assert "top_feeds" in stats
        assert "org_id" in stats

    def test_stats_empty_org(self, manager):
        stats = manager.get_feed_stats(org_id="org-nonexistent")
        assert stats["total_feeds"] == 0
        assert stats["total_iocs"] == 0

    def test_stats_ioc_count_aggregated(self, manager):
        org_id = "org-ioc-stats"
        feed = manager.register_feed(FeedConfig(
            name="IOC Stats Feed",
            url="https://ioc-stats.example.com",
            type=FeedType.IOC,
            org_id=org_id,
        ))
        manager.record_refresh(feed.id, success=True, ioc_count=50)
        stats = manager.get_feed_stats(org_id=org_id)
        assert stats["total_iocs"] == 50

    def test_stats_top_feeds_limited_to_five(self, manager):
        org_id = "org-top"
        for i in range(8):
            f = manager.register_feed(FeedConfig(
                name=f"Top Feed {i}",
                url=f"https://top{i}.example.com",
                type=FeedType.IOC,
                org_id=org_id,
            ))
            manager.record_refresh(f.id, success=True, ioc_count=i * 10)
        stats = manager.get_feed_stats(org_id=org_id)
        assert len(stats["top_feeds"]) <= 5
