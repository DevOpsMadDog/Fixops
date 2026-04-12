"""
Tests for VulnPrioritizer — ML-based vulnerability prioritization.

Covers:
- Feature extraction from various finding shapes
- Risk score calculation with known inputs
- Categorization boundaries
- Ranking order (higher risk = lower rank number)
- Explanation generation
- Weight updates affect scores
- Top-N selection
- Factor comparison
- Feedback recording
- Stats aggregation

Run with:
    python -m pytest tests/test_vuln_prioritizer.py -x --tb=short --timeout=10 -q
"""

import sys
import math
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Ensure suite-core is importable
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.vuln_prioritizer import (
    RiskFactor,
    PrioritizedFinding,
    VulnPrioritizer,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(**kwargs):
    """Build a minimal finding dict with sensible defaults."""
    defaults = {
        "id": "FIND-001",
        "cvss_score": 7.5,
        "epss_score": 0.05,
        "asset_criticality": 0.5,
        "exposure_level": "internal",
        "exploit_available": False,
        "age_days": 30,
        "cwe_id": "CWE-89",
        "has_patch": False,
        "in_attack_path": False,
    }
    defaults.update(kwargs)
    return defaults


def make_prioritizer(**kwargs):
    """Return a VulnPrioritizer with a tmp db path so tests don't touch production data."""
    import tempfile, os
    tmp_dir = Path(tempfile.mkdtemp())
    return VulnPrioritizer(db_path=tmp_dir / "test_feedback.db", **kwargs)


# ---------------------------------------------------------------------------
# RiskFactor model tests
# ---------------------------------------------------------------------------

class TestRiskFactor:
    def test_risk_factor_fields(self):
        rf = RiskFactor(name="cvss_score", value=0.75, weight=0.25, source="NVD")
        assert rf.name == "cvss_score"
        assert rf.value == 0.75
        assert rf.weight == 0.25
        assert rf.source == "NVD"

    def test_risk_factor_value_bounds(self):
        with pytest.raises(Exception):
            RiskFactor(name="x", value=1.5, weight=0.1, source="src")

    def test_risk_factor_value_lower_bound(self):
        with pytest.raises(Exception):
            RiskFactor(name="x", value=-0.1, weight=0.1, source="src")


# ---------------------------------------------------------------------------
# PrioritizedFinding model tests
# ---------------------------------------------------------------------------

class TestPrioritizedFinding:
    def test_prioritized_finding_fields(self):
        pf = PrioritizedFinding(
            finding_id="F-1",
            risk_score=85.0,
            rank=1,
            factors=[],
            explanation="High risk",
            category="critical_now",
        )
        assert pf.finding_id == "F-1"
        assert pf.risk_score == 85.0
        assert pf.rank == 1
        assert pf.category == "critical_now"

    def test_risk_score_bounds(self):
        with pytest.raises(Exception):
            PrioritizedFinding(
                finding_id="x", risk_score=101.0, rank=1,
                factors=[], explanation="", category="defer",
            )


# ---------------------------------------------------------------------------
# Feature extraction tests
# ---------------------------------------------------------------------------

class TestExtractFeatures:
    def setup_method(self):
        self.p = make_prioritizer()

    def test_cvss_normalised(self):
        f = self.p.extract_features(make_finding(cvss_score=10.0))
        assert f["cvss_score"] == 1.0

    def test_cvss_zero(self):
        f = self.p.extract_features(make_finding(cvss_score=0.0))
        assert f["cvss_score"] == 0.0

    def test_cvss_clamped(self):
        # cvss_score > 10 should clamp to 1.0
        f = self.p.extract_features(make_finding(cvss_score=15.0))
        assert f["cvss_score"] == 1.0

    def test_epss_passthrough(self):
        f = self.p.extract_features(make_finding(epss_score=0.42))
        assert abs(f["epss_score"] - 0.42) < 1e-6

    def test_exposure_external(self):
        f = self.p.extract_features(make_finding(exposure_level="external"))
        assert f["exposure_level"] == 1.0

    def test_exposure_internal(self):
        f = self.p.extract_features(make_finding(exposure_level="internal"))
        assert f["exposure_level"] == 0.3

    def test_exposure_numeric(self):
        f = self.p.extract_features(make_finding(exposure_level=0.7))
        assert abs(f["exposure_level"] - 0.7) < 1e-6

    def test_exploit_available_true(self):
        f = self.p.extract_features(make_finding(exploit_available=True))
        assert f["exploit_available"] == 1.0

    def test_exploit_available_false(self):
        f = self.p.extract_features(make_finding(exploit_available=False))
        assert f["exploit_available"] == 0.0

    def test_exploit_available_string(self):
        f = self.p.extract_features(make_finding(exploit_available="yes"))
        assert f["exploit_available"] == 1.0

    def test_has_patch_true_means_lower_risk(self):
        # has_patch=True → patch available → lower risk → value=0.0
        f = self.p.extract_features(make_finding(has_patch=True))
        assert f["has_patch"] == 0.0

    def test_has_patch_false_means_higher_risk(self):
        # has_patch=False → no patch → higher risk → value=1.0
        f = self.p.extract_features(make_finding(has_patch=False))
        assert f["has_patch"] == 1.0

    def test_in_attack_path_true(self):
        f = self.p.extract_features(make_finding(in_attack_path=True))
        assert f["in_attack_path"] == 1.0

    def test_age_days_raw(self):
        f = self.p.extract_features(make_finding(age_days=90))
        assert f["age_days"] == 90.0

    def test_asset_criticality_string_mapping(self):
        f = self.p.extract_features(make_finding(asset_criticality="critical"))
        assert f["asset_criticality"] == 1.0

    def test_cwe_known(self):
        f = self.p.extract_features(make_finding(cwe_id="CWE-89"))
        assert f["cwe_severity_weight"] == 0.9

    def test_cwe_unknown_defaults(self):
        f = self.p.extract_features(make_finding(cwe_id="CWE-9999"))
        assert f["cwe_severity_weight"] == 0.5

    def test_missing_fields_use_defaults(self):
        f = self.p.extract_features({"id": "bare"})
        assert 0.0 <= f["cvss_score"] <= 1.0
        assert 0.0 <= f["epss_score"] <= 1.0
        assert f["age_days"] == 0.0


# ---------------------------------------------------------------------------
# Risk score calculation tests
# ---------------------------------------------------------------------------

class TestCalculateRiskScore:
    def setup_method(self):
        self.p = make_prioritizer()

    def test_all_zeros_score_near_zero(self):
        features = {
            "cvss_score": 0.0, "epss_score": 0.0, "asset_criticality": 0.0,
            "exposure_level": 0.0, "exploit_available": 0.0, "age_days": 0.0,
            "cwe_severity_weight": 0.0, "has_patch": 0.0, "in_attack_path": 0.0,
        }
        score = self.p.calculate_risk_score(features)
        assert score < 15.0  # close to zero with low CWE modifier

    def test_all_max_score_near_100(self):
        features = {
            "cvss_score": 1.0, "epss_score": 1.0, "asset_criticality": 1.0,
            "exposure_level": 1.0, "exploit_available": 1.0, "age_days": 365.0,
            "cwe_severity_weight": 1.0, "has_patch": 1.0, "in_attack_path": 1.0,
        }
        score = self.p.calculate_risk_score(features)
        assert score >= 80.0

    def test_score_in_range(self):
        features = self.p.extract_features(make_finding())
        score = self.p.calculate_risk_score(features)
        assert 0.0 <= score <= 100.0

    def test_higher_cvss_higher_score(self):
        f_low = self.p.extract_features(make_finding(cvss_score=2.0))
        f_high = self.p.extract_features(make_finding(cvss_score=9.5))
        assert self.p.calculate_risk_score(f_high) > self.p.calculate_risk_score(f_low)


# ---------------------------------------------------------------------------
# Categorisation tests
# ---------------------------------------------------------------------------

class TestCategorize:
    def setup_method(self):
        self.p = make_prioritizer()

    def test_critical_now(self):
        assert self.p.categorize(81.0) == "critical_now"
        assert self.p.categorize(100.0) == "critical_now"

    def test_act_soon_lower_bound(self):
        assert self.p.categorize(60.0) == "act_soon"

    def test_act_soon_upper_bound(self):
        assert self.p.categorize(80.0) == "act_soon"

    def test_monitor_lower_bound(self):
        assert self.p.categorize(30.0) == "monitor"

    def test_monitor_upper_bound(self):
        assert self.p.categorize(59.9) == "monitor"

    def test_defer(self):
        assert self.p.categorize(0.0) == "defer"
        assert self.p.categorize(29.9) == "defer"


# ---------------------------------------------------------------------------
# Ranking order tests
# ---------------------------------------------------------------------------

class TestPrioritizeFindings:
    def setup_method(self):
        self.p = make_prioritizer()

    def test_higher_risk_lower_rank(self):
        findings = [
            make_finding(id="LOW", cvss_score=2.0, epss_score=0.01),
            make_finding(id="HIGH", cvss_score=9.8, epss_score=0.9, exploit_available=True),
        ]
        results = self.p.prioritize_findings(findings)
        rank_map = {pf.finding_id: pf.rank for pf in results}
        assert rank_map["HIGH"] < rank_map["LOW"]

    def test_ranks_are_sequential(self):
        findings = [make_finding(id=f"F{i}", cvss_score=float(i)) for i in range(5)]
        results = self.p.prioritize_findings(findings)
        ranks = sorted(pf.rank for pf in results)
        assert ranks == list(range(1, 6))

    def test_empty_findings(self):
        assert self.p.prioritize_findings([]) == []

    def test_single_finding_rank_one(self):
        results = self.p.prioritize_findings([make_finding()])
        assert len(results) == 1
        assert results[0].rank == 1

    def test_all_fields_populated(self):
        results = self.p.prioritize_findings([make_finding()])
        pf = results[0]
        assert pf.finding_id
        assert isinstance(pf.risk_score, float)
        assert isinstance(pf.rank, int)
        assert len(pf.factors) > 0
        assert pf.explanation
        assert pf.category in ("critical_now", "act_soon", "monitor", "defer")


# ---------------------------------------------------------------------------
# Explanation tests
# ---------------------------------------------------------------------------

class TestExplainRanking:
    def setup_method(self):
        self.p = make_prioritizer()

    def test_explanation_contains_finding_id(self):
        results = self.p.prioritize_findings([make_finding(id="EXPLAIN-ME")])
        assert "EXPLAIN-ME" in results[0].explanation

    def test_explanation_contains_rank(self):
        results = self.p.prioritize_findings([make_finding()])
        assert "#1" in results[0].explanation

    def test_explanation_contains_category(self):
        results = self.p.prioritize_findings([make_finding(cvss_score=9.9, epss_score=0.9)])
        assert results[0].category in results[0].explanation


# ---------------------------------------------------------------------------
# Weight update tests
# ---------------------------------------------------------------------------

class TestWeightUpdates:
    def test_update_weights_affects_score(self):
        p = make_prioritizer()
        finding = make_finding(cvss_score=9.0, epss_score=0.01)
        features = p.extract_features(finding)
        score_before = p.calculate_risk_score(features)

        # Boost EPSS weight, reduce CVSS weight
        p.update_weights({"epss_score": 0.01, "cvss_score": 0.60})
        score_after = p.calculate_risk_score(features)

        # Score should change (cvss dominates more now)
        assert score_before != score_after

    def test_get_factor_weights_returns_dict(self):
        p = make_prioritizer()
        weights = p.get_factor_weights()
        assert isinstance(weights, dict)
        assert "cvss_score" in weights
        assert "epss_score" in weights

    def test_update_unknown_key_ignored(self):
        p = make_prioritizer()
        original = dict(p.get_factor_weights())
        p.update_weights({"nonexistent_factor": 0.99})
        assert p.get_factor_weights() == original


# ---------------------------------------------------------------------------
# Top-N tests
# ---------------------------------------------------------------------------

class TestGetTopN:
    def setup_method(self):
        self.p = make_prioritizer()

    def test_top_n_returns_n_items(self):
        findings = [make_finding(id=f"F{i}", cvss_score=float(i % 10)) for i in range(20)]
        top5 = self.p.get_top_n(findings, 5)
        assert len(top5) == 5

    def test_top_n_are_highest_ranked(self):
        findings = [make_finding(id=f"F{i}", cvss_score=float(i % 10)) for i in range(10)]
        top3 = self.p.get_top_n(findings, 3)
        all_results = self.p.prioritize_findings(findings)
        top3_ids = {pf.finding_id for pf in top3}
        top3_full_ids = {pf.finding_id for pf in all_results[:3]}
        assert top3_ids == top3_full_ids

    def test_top_n_larger_than_findings(self):
        findings = [make_finding(id=f"F{i}") for i in range(3)]
        result = self.p.get_top_n(findings, 10)
        assert len(result) == 3


# ---------------------------------------------------------------------------
# Factor comparison tests
# ---------------------------------------------------------------------------

class TestCompareFindings:
    def setup_method(self):
        self.p = make_prioritizer()

    def test_compare_returns_both_ids(self):
        a = make_finding(id="A", cvss_score=9.0)
        b = make_finding(id="B", cvss_score=3.0)
        result = self.p.compare_findings(a, b)
        assert result["finding_a"]["id"] == "A"
        assert result["finding_b"]["id"] == "B"

    def test_compare_winner_is_higher_score(self):
        a = make_finding(id="A", cvss_score=9.5, epss_score=0.8, exploit_available=True)
        b = make_finding(id="B", cvss_score=2.0, epss_score=0.01)
        result = self.p.compare_findings(a, b)
        assert result["winner"] == "A"

    def test_compare_has_factors(self):
        a = make_finding(id="A")
        b = make_finding(id="B")
        result = self.p.compare_findings(a, b)
        assert "factors" in result
        assert "cvss_score" in result["factors"]

    def test_compare_delta_non_negative(self):
        a = make_finding(id="A", cvss_score=8.0)
        b = make_finding(id="B", cvss_score=4.0)
        result = self.p.compare_findings(a, b)
        assert result["score_delta"] >= 0


# ---------------------------------------------------------------------------
# Feedback recording tests
# ---------------------------------------------------------------------------

class TestFeedbackRecording:
    def test_feedback_recorded_without_error(self, tmp_path):
        p = VulnPrioritizer(db_path=tmp_path / "fb.db")
        # Should not raise
        p.train_from_feedback("FIND-001", "critical_now")

    def test_multiple_feedback_entries(self, tmp_path):
        p = VulnPrioritizer(db_path=tmp_path / "fb.db")
        p.train_from_feedback("F-1", "act_soon")
        p.train_from_feedback("F-2", "monitor")
        p.train_from_feedback("F-3", "defer")
        stats = p.get_prioritization_stats()
        assert stats["total_feedback_records"] == 3

    def test_stats_distribution_keys(self, tmp_path):
        p = VulnPrioritizer(db_path=tmp_path / "fb.db")
        p.train_from_feedback("F-1", "critical_now")
        stats = p.get_prioritization_stats("org-123")
        dist = stats["distribution"]
        assert "critical_now" in dist
        assert "act_soon" in dist
        assert "monitor" in dist
        assert "defer" in dist

    def test_stats_includes_weights(self, tmp_path):
        p = VulnPrioritizer(db_path=tmp_path / "fb.db")
        stats = p.get_prioritization_stats()
        assert "weights" in stats
