"""
Tests for suite-core/core/vuln_risk_scoring.py — VulnRiskScorer.

Covers:
- _compute(): pure scoring formula, all priority tiers, criticality multipliers,
  KEV bonus, exploit bonus, exposure bonus, cap at 100
- score_vulnerability(): wraps _compute with cve_id / org_id
- batch_score(): sorted DESC by composite_score, unknown cve_id default
- save_score() + get_score_trend(): persistence and ordering
- get_priority_queue(): P1→P4 ordering, org isolation
- get_scoring_stats(): distribution counts, empty org
- get_scorer() singleton

25 tests — all self-contained with tmp SQLite DBs.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.vuln_risk_scoring import VulnRiskScorer, get_scorer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scorer(tmp_path):
    return VulnRiskScorer(db_path=str(tmp_path / "test_vrs.db"))


# ---------------------------------------------------------------------------
# Pure scoring — _compute
# ---------------------------------------------------------------------------

class TestCompute:
    def test_zero_context_is_p4(self):
        result = VulnRiskScorer._compute({})
        assert result["priority"] == "P4"
        assert result["composite_score"] == 0.0

    def test_max_cvss_alone_gives_p2(self):
        # cvss=10 → cvss_weight=100; * medium(1.0) = 100 → capped at 100 → P1
        result = VulnRiskScorer._compute({"cvss_base": 10.0})
        assert result["composite_score"] == 100.0
        assert result["priority"] == "P1"

    def test_kev_bonus_adds_20(self):
        r_no_kev = VulnRiskScorer._compute({"cvss_base": 2.0})
        r_kev    = VulnRiskScorer._compute({"cvss_base": 2.0, "kev": True})
        assert r_kev["composite_score"] - r_no_kev["composite_score"] == pytest.approx(20.0)

    def test_exploit_bonus_adds_5_when_no_kev(self):
        r_base    = VulnRiskScorer._compute({"cvss_base": 2.0})
        r_exploit = VulnRiskScorer._compute({"cvss_base": 2.0, "has_known_exploit": True})
        assert r_exploit["composite_score"] - r_base["composite_score"] == pytest.approx(5.0)

    def test_exploit_bonus_suppressed_when_kev(self):
        # kev and has_known_exploit → only kev_bonus (20), not exploit_bonus (5)
        r_kev_only    = VulnRiskScorer._compute({"cvss_base": 2.0, "kev": True})
        r_kev_exploit = VulnRiskScorer._compute({"cvss_base": 2.0, "kev": True, "has_known_exploit": True})
        assert r_kev_only["composite_score"] == r_kev_exploit["composite_score"]

    def test_exposure_bonus_adds_10(self):
        r_no_exp = VulnRiskScorer._compute({"cvss_base": 2.0})
        r_exp    = VulnRiskScorer._compute({"cvss_base": 2.0, "internet_exposed": True})
        assert r_exp["composite_score"] - r_no_exp["composite_score"] == pytest.approx(10.0)

    def test_critical_criticality_multiplier(self):
        r_med = VulnRiskScorer._compute({"cvss_base": 4.0})
        r_cri = VulnRiskScorer._compute({"cvss_base": 4.0, "asset_criticality": "critical"})
        assert r_cri["composite_score"] == pytest.approx(
            min(40.0 * 1.5, 100.0), abs=0.01
        )

    def test_low_criticality_multiplier_reduces_score(self):
        r_med = VulnRiskScorer._compute({"cvss_base": 4.0})
        r_low = VulnRiskScorer._compute({"cvss_base": 4.0, "asset_criticality": "low"})
        assert r_low["composite_score"] < r_med["composite_score"]

    def test_unknown_criticality_defaults_to_medium(self):
        r_unknown = VulnRiskScorer._compute({"cvss_base": 4.0, "asset_criticality": "mega"})
        r_medium  = VulnRiskScorer._compute({"cvss_base": 4.0})
        assert r_unknown["composite_score"] == r_medium["composite_score"]

    def test_score_capped_at_100(self):
        result = VulnRiskScorer._compute({
            "cvss_base": 10.0, "epss_score": 1.0, "kev": True,
            "internet_exposed": True, "has_known_exploit": True,
            "asset_criticality": "critical",
        })
        assert result["composite_score"] == 100.0

    def test_priority_p1_threshold(self):
        # composite >= 80 → P1; cvss=8 → cvss_weight=80 → composite=80.0 → P1
        result = VulnRiskScorer._compute({"cvss_base": 8.0})
        assert result["priority"] == "P1"
        assert result["sla_hours"] == 24

    def test_priority_p2_threshold(self):
        # cvss=6 → 60.0 → P2
        result = VulnRiskScorer._compute({"cvss_base": 6.0})
        assert result["priority"] == "P2"
        assert result["sla_hours"] == 72

    def test_priority_p3_threshold(self):
        # cvss=4 → 40.0 → P3
        result = VulnRiskScorer._compute({"cvss_base": 4.0})
        assert result["priority"] == "P3"
        assert result["sla_hours"] == 168

    def test_priority_p4_threshold(self):
        # cvss=1 → 10.0 → P4
        result = VulnRiskScorer._compute({"cvss_base": 1.0})
        assert result["priority"] == "P4"
        assert result["sla_hours"] == 720

    def test_factors_keys_present(self):
        result = VulnRiskScorer._compute({"cvss_base": 5.0})
        for key in ("cvss_weight", "epss_weight", "kev_bonus", "exploit_bonus",
                    "exposure_bonus", "criticality_multiplier", "raw_before_cap"):
            assert key in result["factors"]

    def test_recommendation_non_empty(self):
        result = VulnRiskScorer._compute({"cvss_base": 8.0})
        assert result["recommendation"]


# ---------------------------------------------------------------------------
# score_vulnerability
# ---------------------------------------------------------------------------

class TestScoreVulnerability:
    def test_returns_cve_and_org(self, scorer):
        result = scorer.score_vulnerability("CVE-2024-0001", "org-a", {"cvss_base": 7.0})
        assert result["cve_id"] == "CVE-2024-0001"
        assert result["org_id"] == "org-a"
        assert "composite_score" in result

    def test_score_matches_compute(self, scorer):
        ctx = {"cvss_base": 5.5, "kev": True}
        direct = VulnRiskScorer._compute(ctx)
        via_method = scorer.score_vulnerability("CVE-X", "org-a", ctx)
        assert via_method["composite_score"] == direct["composite_score"]


# ---------------------------------------------------------------------------
# batch_score
# ---------------------------------------------------------------------------

class TestBatchScore:
    def test_sorted_desc(self, scorer):
        vulns = [
            {"cve_id": "CVE-A", "cvss_base": 3.0},
            {"cve_id": "CVE-B", "cvss_base": 8.0},
            {"cve_id": "CVE-C", "cvss_base": 5.5},
        ]
        results = scorer.batch_score(vulns, "org-b")
        scores = [r["composite_score"] for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_missing_cve_id_uses_unknown(self, scorer):
        vulns = [{"cvss_base": 4.0}]
        results = scorer.batch_score(vulns, "org-b")
        assert results[0]["cve_id"] == "UNKNOWN"

    def test_empty_list_returns_empty(self, scorer):
        assert scorer.batch_score([], "org-b") == []


# ---------------------------------------------------------------------------
# save_score + get_score_trend
# ---------------------------------------------------------------------------

class TestSaveAndTrend:
    def test_save_returns_uuid(self, scorer):
        score_data = scorer.score_vulnerability("CVE-2024-0002", "org-c", {"cvss_base": 6.0})
        record_id = scorer.save_score("org-c", "CVE-2024-0002", "asset-1", score_data)
        assert len(record_id) == 36

    def test_trend_returns_saved_record(self, scorer):
        ctx = {"cvss_base": 7.0}
        score_data = scorer.score_vulnerability("CVE-T", "org-t", ctx)
        scorer.save_score("org-t", "CVE-T", None, score_data)
        trend = scorer.get_score_trend("org-t", "CVE-T")
        assert len(trend) == 1
        assert trend[0]["composite_score"] == score_data["composite_score"]

    def test_trend_empty_when_no_records(self, scorer):
        assert scorer.get_score_trend("org-empty", "CVE-NONE") == []

    def test_org_isolation_in_trend(self, scorer):
        ctx = {"cvss_base": 5.0}
        sd = scorer.score_vulnerability("CVE-ISO", "org-1", ctx)
        scorer.save_score("org-1", "CVE-ISO", None, sd)
        trend = scorer.get_score_trend("org-2", "CVE-ISO")
        assert trend == []


# ---------------------------------------------------------------------------
# get_priority_queue
# ---------------------------------------------------------------------------

class TestPriorityQueue:
    def test_empty_org_returns_empty(self, scorer):
        assert scorer.get_priority_queue("no-org") == []

    def test_p1_before_p4_in_queue(self, scorer):
        for cve, cvss in [("CVE-P4", 1.0), ("CVE-P1", 8.0)]:
            sd = scorer.score_vulnerability(cve, "org-q", {"cvss_base": cvss})
            scorer.save_score("org-q", cve, None, sd)
        queue = scorer.get_priority_queue("org-q")
        priorities = [r["priority"] for r in queue]
        assert priorities.index("P1") < priorities.index("P4")


# ---------------------------------------------------------------------------
# get_scoring_stats
# ---------------------------------------------------------------------------

class TestScoringStats:
    def test_empty_org_zero_total(self, scorer):
        stats = scorer.get_scoring_stats("org-s")
        assert stats["total"] == 0
        assert stats["distribution"] == {"P1": 0, "P2": 0, "P3": 0, "P4": 0}

    def test_counts_by_priority(self, scorer):
        for i, cvss in enumerate([8.0, 8.0, 6.0]):
            sd = scorer.score_vulnerability(f"CVE-S{i}", "org-cnt", {"cvss_base": cvss})
            scorer.save_score("org-cnt", f"CVE-S{i}", None, sd)
        stats = scorer.get_scoring_stats("org-cnt")
        assert stats["distribution"]["P1"] == 2
        assert stats["distribution"]["P2"] == 1
        assert stats["total"] == 3


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

class TestSingleton:
    def test_get_scorer_returns_instance(self, tmp_path):
        import core.vuln_risk_scoring as vrs_mod
        # Reset singleton for test isolation
        vrs_mod._scorer = None
        s = get_scorer(db_path=str(tmp_path / "singleton.db"))
        assert isinstance(s, VulnRiskScorer)

    def test_get_scorer_same_instance(self, tmp_path):
        import core.vuln_risk_scoring as vrs_mod
        vrs_mod._scorer = None
        db = str(tmp_path / "singleton2.db")
        s1 = get_scorer(db_path=db)
        s2 = get_scorer(db_path=db)
        assert s1 is s2
