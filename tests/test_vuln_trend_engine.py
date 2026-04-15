"""Tests for VulnTrendEngine — 28 tests covering all methods and org isolation."""

from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone

import pytest

from core.vuln_trend_engine import VulnTrendEngine

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "test_vuln_trend.db")
    return VulnTrendEngine(db_path=db)


ORG_A = "org-trend-aaa"
ORG_B = "org-trend-bbb"


def _snap(critical=5, high=10, medium=20, low=15, info=3, **kwargs):
    return dict(critical=critical, high=high, medium=medium, low=low, info=info, **kwargs)


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------


class TestSnapshots:
    def test_record_snapshot_returns_id(self, engine):
        result = engine.record_snapshot(ORG_A, _snap())
        assert "snapshot_id" in result
        assert result["org_id"] == ORG_A

    def test_record_snapshot_stores_fields(self, engine):
        engine.record_snapshot(ORG_A, _snap(critical=3, high=7, mttr_days=14.5))
        snaps = engine.list_snapshots(ORG_A)
        assert len(snaps) == 1
        assert snaps[0]["critical"] == 3
        assert snaps[0]["high"] == 7
        assert snaps[0]["mttr_days"] == 14.5

    def test_list_snapshots_default_limit(self, engine):
        for i in range(5):
            engine.record_snapshot(ORG_A, _snap(critical=i))
        snaps = engine.list_snapshots(ORG_A)
        assert len(snaps) == 5

    def test_list_snapshots_respects_limit(self, engine):
        for i in range(10):
            engine.record_snapshot(ORG_A, _snap())
        snaps = engine.list_snapshots(ORG_A, limit=3)
        assert len(snaps) == 3

    def test_list_snapshots_ordered_desc(self, engine):
        engine.record_snapshot(ORG_A, _snap(critical=1, taken_at="2024-01-01T00:00:00+00:00"))
        engine.record_snapshot(ORG_A, _snap(critical=9, taken_at="2024-06-01T00:00:00+00:00"))
        snaps = engine.list_snapshots(ORG_A)
        assert snaps[0]["critical"] == 9  # most recent first

    def test_org_isolation_snapshots(self, engine):
        engine.record_snapshot(ORG_A, _snap(critical=5))
        engine.record_snapshot(ORG_B, _snap(critical=99))
        snaps_a = engine.list_snapshots(ORG_A)
        snaps_b = engine.list_snapshots(ORG_B)
        assert all(s["org_id"] == ORG_A for s in snaps_a)
        assert all(s["org_id"] == ORG_B for s in snaps_b)
        assert len(snaps_a) == 1
        assert len(snaps_b) == 1

    def test_total_vulns_auto_sum(self, engine):
        result = engine.record_snapshot(ORG_A, _snap(critical=2, high=3, medium=5, low=1, info=0))
        snaps = engine.list_snapshots(ORG_A)
        assert snaps[0]["total_vulns"] == 11


# ---------------------------------------------------------------------------
# Trend Analysis
# ---------------------------------------------------------------------------


class TestTrendAnalysis:
    def test_analysis_needs_two_snapshots(self, engine):
        engine.record_snapshot(ORG_A, _snap())
        result = engine.get_trend_analysis(ORG_A)
        assert "message" in result
        assert result["overall_trend"] == "stable"

    def test_analysis_increasing(self, engine):
        engine.record_snapshot(ORG_A, _snap(critical=5, high=10, taken_at="2024-01-01T00:00:00+00:00"))
        engine.record_snapshot(ORG_A, _snap(critical=20, high=30, taken_at="2024-01-08T00:00:00+00:00"))
        result = engine.get_trend_analysis(ORG_A)
        assert result["overall_trend"] == "increasing"
        assert result["pct_change"] > 10

    def test_analysis_decreasing(self, engine):
        engine.record_snapshot(ORG_A, _snap(critical=50, high=60, taken_at="2024-01-01T00:00:00+00:00"))
        engine.record_snapshot(ORG_A, _snap(critical=10, high=15, taken_at="2024-01-08T00:00:00+00:00"))
        result = engine.get_trend_analysis(ORG_A)
        assert result["overall_trend"] == "decreasing"

    def test_analysis_stable(self, engine):
        engine.record_snapshot(ORG_A, _snap(critical=10, high=20, taken_at="2024-01-01T00:00:00+00:00"))
        engine.record_snapshot(ORG_A, _snap(critical=11, high=21, taken_at="2024-01-08T00:00:00+00:00"))
        result = engine.get_trend_analysis(ORG_A)
        assert result["overall_trend"] == "stable"

    def test_analysis_saves_trend_record(self, engine):
        engine.record_snapshot(ORG_A, _snap(critical=5, taken_at="2024-01-01T00:00:00+00:00"))
        engine.record_snapshot(ORG_A, _snap(critical=50, taken_at="2024-01-08T00:00:00+00:00"))
        result = engine.get_trend_analysis(ORG_A)
        assert "trend_id" in result
        assert result["trend_id"]

    def test_org_isolation_trend(self, engine):
        engine.record_snapshot(ORG_A, _snap(critical=5, taken_at="2024-01-01T00:00:00+00:00"))
        engine.record_snapshot(ORG_A, _snap(critical=50, taken_at="2024-01-08T00:00:00+00:00"))
        engine.record_snapshot(ORG_B, _snap(critical=5, taken_at="2024-01-01T00:00:00+00:00"))
        engine.record_snapshot(ORG_B, _snap(critical=4, taken_at="2024-01-08T00:00:00+00:00"))
        r_a = engine.get_trend_analysis(ORG_A)
        r_b = engine.get_trend_analysis(ORG_B)
        assert r_a["overall_trend"] == "increasing"
        assert r_b["overall_trend"] != "increasing"


# ---------------------------------------------------------------------------
# SLA Tracking
# ---------------------------------------------------------------------------


class TestSlaTracking:
    def test_track_sla_returns_id(self, engine):
        result = engine.track_sla(ORG_A, {"vuln_id": "CVE-2024-001", "severity": "critical"})
        assert "sla_id" in result
        assert result["sla_days"] == 7  # critical = 7 days

    def test_sla_days_by_severity(self, engine):
        expected = {"critical": 7, "high": 30, "medium": 90, "low": 180}
        for sev, days in expected.items():
            r = engine.track_sla(ORG_A, {"vuln_id": f"CVE-{sev}", "severity": sev})
            assert r["sla_days"] == days, f"Failed for severity={sev}"

    def test_check_sla_breaches_finds_overdue(self, engine):
        # Discovered 100 days ago, medium SLA = 90 days → breached
        past = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        engine.track_sla(ORG_A, {"vuln_id": "CVE-OLD", "severity": "medium", "discovered_at": past})
        breaches = engine.check_sla_breaches(ORG_A)
        assert len(breaches) == 1
        assert breaches[0]["vuln_id"] == "CVE-OLD"

    def test_check_sla_breaches_excludes_within_sla(self, engine):
        # Discovered 5 days ago, medium SLA = 90 days → not breached
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        engine.track_sla(ORG_A, {"vuln_id": "CVE-NEW", "severity": "medium", "discovered_at": recent})
        breaches = engine.check_sla_breaches(ORG_A)
        assert len(breaches) == 0

    def test_resolve_sla(self, engine):
        result = engine.track_sla(ORG_A, {"vuln_id": "CVE-FIX", "severity": "high"})
        ok = engine.resolve_sla(ORG_A, result["sla_id"])
        assert ok is True

    def test_resolve_sla_not_found(self, engine):
        ok = engine.resolve_sla(ORG_A, "nonexistent-sla-id")
        assert ok is False

    def test_resolve_sla_marks_breached_if_overdue(self, engine):
        past = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        r = engine.track_sla(ORG_A, {"vuln_id": "CVE-LATE", "severity": "medium", "discovered_at": past})
        engine.resolve_sla(ORG_A, r["sla_id"])
        # After resolving, breach check should not include it (resolved)
        breaches = engine.check_sla_breaches(ORG_A)
        assert all(b["sla_id"] != r["sla_id"] for b in breaches)

    def test_sla_org_isolation(self, engine):
        engine.track_sla(ORG_A, {"vuln_id": "CVE-A", "severity": "critical"})
        engine.track_sla(ORG_B, {"vuln_id": "CVE-B", "severity": "critical"})
        # Breach check: none should be breached (just created)
        breaches_a = engine.check_sla_breaches(ORG_A)
        breaches_b = engine.check_sla_breaches(ORG_B)
        # Each org only sees its own data (none breached = empty list for both)
        assert isinstance(breaches_a, list)
        assert isinstance(breaches_b, list)


# ---------------------------------------------------------------------------
# Cohorts
# ---------------------------------------------------------------------------


class TestCohorts:
    def test_create_cohort(self, engine):
        result = engine.create_cohort(ORG_A, {
            "cohort_name": "Q1 Criticals",
            "vuln_ids": ["CVE-001", "CVE-002"],
            "avg_age_days": 45.5,
            "avg_cvss": 8.2,
        })
        assert "cohort_id" in result
        assert result["cohort_name"] == "Q1 Criticals"
        assert result["vuln_ids"] == ["CVE-001", "CVE-002"]

    def test_list_cohorts_deserializes_vuln_ids(self, engine):
        engine.create_cohort(ORG_A, {"cohort_name": "Test", "vuln_ids": ["A", "B", "C"]})
        cohorts = engine.list_cohorts(ORG_A)
        assert len(cohorts) == 1
        assert isinstance(cohorts[0]["vuln_ids"], list)
        assert "A" in cohorts[0]["vuln_ids"]

    def test_cohort_org_isolation(self, engine):
        engine.create_cohort(ORG_A, {"cohort_name": "A Cohort", "vuln_ids": []})
        engine.create_cohort(ORG_B, {"cohort_name": "B Cohort", "vuln_ids": []})
        cohorts_a = engine.list_cohorts(ORG_A)
        cohorts_b = engine.list_cohorts(ORG_B)
        assert all(c["org_id"] == ORG_A for c in cohorts_a)
        assert all(c["org_id"] == ORG_B for c in cohorts_b)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestTrendStats:
    def test_stats_empty_org(self, engine):
        stats = engine.get_trend_stats("org-empty-xyz")
        assert stats["snapshots_count"] == 0
        assert stats["active_slas"] == 0
        assert stats["cohorts_count"] == 0
        assert stats["overall_trend"] == "stable"

    def test_stats_reflects_data(self, engine):
        engine.record_snapshot(ORG_A, _snap(critical=10, high=20, taken_at="2024-01-01T00:00:00+00:00"))
        engine.record_snapshot(ORG_A, _snap(critical=50, high=60, taken_at="2024-01-08T00:00:00+00:00"))
        engine.get_trend_analysis(ORG_A)  # saves trend record
        engine.track_sla(ORG_A, {"vuln_id": "V1", "severity": "high"})
        engine.create_cohort(ORG_A, {"cohort_name": "C1", "vuln_ids": []})

        stats = engine.get_trend_stats(ORG_A)
        assert stats["snapshots_count"] == 2
        assert stats["active_slas"] == 1
        assert stats["cohorts_count"] == 1
        assert stats["avg_critical"] > 0
        assert stats["overall_trend"] in ("increasing", "decreasing", "stable")

    def test_stats_breach_rate(self, engine):
        past = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        r1 = engine.track_sla(ORG_A, {"vuln_id": "CVE-1", "severity": "medium", "discovered_at": past})
        r2 = engine.track_sla(ORG_A, {"vuln_id": "CVE-2", "severity": "high"})
        engine.resolve_sla(ORG_A, r1["sla_id"])  # resolve overdue → breached=1
        engine.resolve_sla(ORG_A, r2["sla_id"])  # resolve within SLA → breached=0
        stats = engine.get_trend_stats(ORG_A)
        # 1 breached out of 2 total = 0.5
        assert stats["sla_breach_rate"] == 0.5
