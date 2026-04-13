"""
Tests for CompositeRiskScorer — ML-powered multi-signal risk scoring.

Covers:
- Formula correctness (weighted sum, component isolation)
- Grade boundary conditions (CRITICAL>=80, HIGH>=60, MEDIUM>=40, LOW>=20, MINIMAL<20)
- Batch scoring with empty org
- top_risks ordering
- Persistence and retrieval
- Asset aggregation
- Graceful fallback when source DBs are missing
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import uuid
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import pytest

# Ensure suite paths are importable
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Configure environment before importing anything
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")

from core.composite_risk_scorer import (
    CompositeRiskScore,
    CompositeRiskScorer,
    RiskFactor,
    _W_ASSET,
    _W_CVSS,
    _W_EPSS,
    _W_KEV,
    _W_LATERAL,
    _W_SLA,
    _GRADE_CRITICAL,
    _GRADE_HIGH,
    _GRADE_MEDIUM,
    _GRADE_LOW,
    _get_cvss_component,
    _get_epss_component,
    _get_kev_component,
    _get_asset_criticality,
    _get_sla_breach_risk,
    _get_lateral_movement_risk,
    get_composite_risk_scorer,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path) -> str:
    """Return a fresh temporary DB path for each test."""
    return str(tmp_path / "composite_risk.db")


@pytest.fixture
def scorer(tmp_db) -> CompositeRiskScorer:
    """Fresh CompositeRiskScorer backed by a temp DB."""
    return CompositeRiskScorer(db_path=tmp_db)


# ---------------------------------------------------------------------------
# 1. Grade boundary tests
# ---------------------------------------------------------------------------


class TestGradeScore:
    def test_critical_at_boundary(self):
        assert CompositeRiskScorer.grade_score(80.0) == "CRITICAL"

    def test_critical_above_boundary(self):
        assert CompositeRiskScorer.grade_score(95.0) == "CRITICAL"

    def test_critical_at_100(self):
        assert CompositeRiskScorer.grade_score(100.0) == "CRITICAL"

    def test_high_at_boundary(self):
        assert CompositeRiskScorer.grade_score(60.0) == "HIGH"

    def test_high_just_below_critical(self):
        assert CompositeRiskScorer.grade_score(79.9) == "HIGH"

    def test_medium_at_boundary(self):
        assert CompositeRiskScorer.grade_score(40.0) == "MEDIUM"

    def test_medium_just_below_high(self):
        assert CompositeRiskScorer.grade_score(59.9) == "MEDIUM"

    def test_low_at_boundary(self):
        assert CompositeRiskScorer.grade_score(20.0) == "LOW"

    def test_low_just_below_medium(self):
        assert CompositeRiskScorer.grade_score(39.9) == "LOW"

    def test_minimal_just_below_low(self):
        assert CompositeRiskScorer.grade_score(19.9) == "MINIMAL"

    def test_minimal_at_zero(self):
        assert CompositeRiskScorer.grade_score(0.0) == "MINIMAL"


# ---------------------------------------------------------------------------
# 2. RiskFactor model
# ---------------------------------------------------------------------------


class TestRiskFactor:
    def test_weighted_value(self):
        f = RiskFactor(name="cvss", value=80.0, weight=0.25, explanation="test")
        assert abs(f.weighted_value - 20.0) < 0.001

    def test_weighted_value_zero_weight(self):
        f = RiskFactor(name="x", value=100.0, weight=0.0, explanation="")
        assert f.weighted_value == 0.0

    def test_weighted_value_full_weight(self):
        f = RiskFactor(name="x", value=50.0, weight=1.0, explanation="")
        assert f.weighted_value == 50.0


# ---------------------------------------------------------------------------
# 3. Formula correctness — all defaults (no real DBs)
# ---------------------------------------------------------------------------


class TestFormulaCorrectness:
    def test_score_in_valid_range(self, scorer):
        result = scorer.score_finding("f1", cve_id=None, asset_id=None)
        assert 0.0 <= result.score <= 100.0

    def test_score_returns_composite_risk_score(self, scorer):
        result = scorer.score_finding("f2")
        assert isinstance(result, CompositeRiskScore)

    def test_score_has_six_factors(self, scorer):
        result = scorer.score_finding("f3")
        assert len(result.factors) == 6

    def test_factor_names_present(self, scorer):
        result = scorer.score_finding("f4")
        names = {f.name for f in result.factors}
        assert "cvss" in names
        assert "epss" in names
        assert "kev" in names
        assert "asset_criticality" in names
        assert "sla_breach_risk" in names
        assert "lateral_movement" in names

    def test_weights_sum_to_one(self, scorer):
        result = scorer.score_finding("f5")
        total_weight = sum(f.weight for f in result.factors)
        assert abs(total_weight - 1.0) < 0.001

    def test_formula_manual_calculation(self, scorer):
        """Verify composite = sum(value * weight) for all factors."""
        result = scorer.score_finding("f6")
        manual = sum(f.value * f.weight for f in result.factors)
        assert abs(result.score - manual) < 0.01

    def test_default_score_uses_defaults(self, scorer):
        """With no DBs, defaults produce a deterministic score."""
        r1 = scorer.score_finding("x1")
        r2 = scorer.score_finding("x2")
        # Both should use same defaults → same score
        assert r1.score == r2.score

    def test_grade_consistent_with_score(self, scorer):
        result = scorer.score_finding("f7")
        expected = CompositeRiskScorer.grade_score(result.score)
        assert result.grade == expected


# ---------------------------------------------------------------------------
# 4. Signal extractor unit tests
# ---------------------------------------------------------------------------


class TestSignalExtractors:
    def test_cvss_fallback_no_cve(self):
        val, expl = _get_cvss_component(None, None)
        assert val == 50.0
        assert "unavailable" in expl.lower()

    def test_epss_fallback_no_cve(self):
        val, expl = _get_epss_component(None)
        assert val == 10.0

    def test_kev_fallback_no_cve(self):
        val, expl = _get_kev_component(None)
        assert val == 0.0

    def test_asset_criticality_fallback_no_asset(self):
        val, expl = _get_asset_criticality(None)
        assert val == 50.0

    def test_sla_fallback_no_finding(self):
        val, expl = _get_sla_breach_risk(None, "default")
        assert val == 30.0

    def test_lateral_fallback_no_posture(self):
        val, expl = _get_lateral_movement_risk(None, "default")
        assert val == 30.0

    def test_cvss_from_vuln_db(self, tmp_path):
        """CVSS extraction from a real SQLite DB."""
        db = str(tmp_path / "vuln.db")
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE enriched_vulns (cve_id TEXT, cvss_score REAL, epss_score REAL, in_kev INTEGER, finding_id TEXT)"
            )
            conn.execute(
                "INSERT INTO enriched_vulns VALUES ('CVE-2024-1234', 9.8, 0.75, 1, 'f-abc')"
            )
            conn.commit()
        with patch("core.composite_risk_scorer._VULN_DB", db):
            val, expl = _get_cvss_component("CVE-2024-1234", None)
            assert abs(val - 98.0) < 0.1
            assert "9.8" in expl

    def test_epss_from_vuln_db(self, tmp_path):
        db = str(tmp_path / "vuln.db")
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE enriched_vulns (cve_id TEXT, cvss_score REAL, epss_score REAL, in_kev INTEGER, finding_id TEXT)"
            )
            conn.execute(
                "INSERT INTO enriched_vulns VALUES ('CVE-2024-5678', 7.5, 0.50, 0, NULL)"
            )
            conn.commit()
        with patch("core.composite_risk_scorer._VULN_DB", db):
            val, expl = _get_epss_component("CVE-2024-5678")
            assert abs(val - 50.0) < 0.1

    def test_kev_in_kev_true(self, tmp_path):
        db = str(tmp_path / "vuln.db")
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE enriched_vulns (cve_id TEXT, cvss_score REAL, epss_score REAL, in_kev INTEGER, finding_id TEXT)"
            )
            conn.execute("INSERT INTO enriched_vulns VALUES ('CVE-2024-KEV', 9.0, 0.9, 1, NULL)")
            conn.commit()
        with patch("core.composite_risk_scorer._VULN_DB", db):
            val, expl = _get_kev_component("CVE-2024-KEV")
            assert val == 100.0
            assert "KEV" in expl

    def test_kev_not_in_kev(self, tmp_path):
        db = str(tmp_path / "vuln.db")
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE enriched_vulns (cve_id TEXT, cvss_score REAL, epss_score REAL, in_kev INTEGER, finding_id TEXT)"
            )
            conn.execute("INSERT INTO enriched_vulns VALUES ('CVE-2024-NOKEV', 5.0, 0.1, 0, NULL)")
            conn.commit()
        with patch("core.composite_risk_scorer._VULN_DB", db):
            val, expl = _get_kev_component("CVE-2024-NOKEV")
            assert val == 0.0

    def test_asset_criticality_critical(self, tmp_path):
        db = str(tmp_path / "assets.db")
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE assets (asset_id TEXT, criticality TEXT)")
            conn.execute("INSERT INTO assets VALUES ('asset-crit', 'critical')")
            conn.commit()
        with patch("core.composite_risk_scorer._ASSET_INVENTORY_DB", db):
            val, expl = _get_asset_criticality("asset-crit")
            assert val == 100.0

    def test_asset_criticality_low(self, tmp_path):
        db = str(tmp_path / "assets.db")
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE assets (asset_id TEXT, criticality TEXT)")
            conn.execute("INSERT INTO assets VALUES ('asset-low', 'low')")
            conn.commit()
        with patch("core.composite_risk_scorer._ASSET_INVENTORY_DB", db):
            val, expl = _get_asset_criticality("asset-low")
            assert val == 25.0

    def test_sla_breached(self, tmp_path):
        db = str(tmp_path / "sla.db")
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE sla_tracking (finding_id TEXT, org_id TEXT, status TEXT, deadline TEXT, created_at TEXT)"
            )
            conn.execute("INSERT INTO sla_tracking VALUES ('f-sla', 'org1', 'BREACHED', '2024-01-01', '2024-01-02')")
            conn.commit()
        with patch("core.composite_risk_scorer._SLA_DB", db):
            val, expl = _get_sla_breach_risk("f-sla", "org1")
            assert val == 100.0
            assert "BREACHED" in expl

    def test_sla_on_track(self, tmp_path):
        db = str(tmp_path / "sla.db")
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE sla_tracking (finding_id TEXT, org_id TEXT, status TEXT, deadline TEXT, created_at TEXT)"
            )
            conn.execute("INSERT INTO sla_tracking VALUES ('f-ok', 'org1', 'ON_TRACK', '2025-01-01', '2024-12-01')")
            conn.commit()
        with patch("core.composite_risk_scorer._SLA_DB", db):
            val, expl = _get_sla_breach_risk("f-ok", "org1")
            assert val == 10.0


# ---------------------------------------------------------------------------
# 5. Batch scoring with empty org
# ---------------------------------------------------------------------------


class TestBatchScoring:
    def test_batch_empty_org_returns_empty(self, scorer):
        results = scorer.batch_score(org_id="empty-org-xyz", limit=10)
        assert isinstance(results, list)
        # No findings in vuln or sla DBs → empty
        assert results == []

    def test_batch_respects_limit(self, scorer, tmp_path):
        """Create 5 findings in a vuln DB, batch with limit=3 → 3 results."""
        db = str(tmp_path / "vuln.db")
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE enriched_vulns (cve_id TEXT, cvss_score REAL, epss_score REAL, in_kev INTEGER, finding_id TEXT)"
            )
            for i in range(5):
                conn.execute(
                    "INSERT INTO enriched_vulns VALUES (?, 7.0, 0.1, 0, ?)",
                    (f"CVE-2024-{i}", f"f-batch-{i}"),
                )
            conn.commit()
        with patch("core.composite_risk_scorer._VULN_DB", db):
            results = scorer.batch_score(org_id="test-org", limit=3)
        assert len(results) == 3

    def test_batch_returns_composite_risk_scores(self, scorer, tmp_path):
        db = str(tmp_path / "vuln.db")
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE enriched_vulns (cve_id TEXT, cvss_score REAL, epss_score REAL, in_kev INTEGER, finding_id TEXT)"
            )
            conn.execute("INSERT INTO enriched_vulns VALUES ('CVE-X', 8.0, 0.5, 0, 'f-r')")
            conn.commit()
        with patch("core.composite_risk_scorer._VULN_DB", db):
            results = scorer.batch_score(org_id="test-org", limit=10)
        assert all(isinstance(r, CompositeRiskScore) for r in results)


# ---------------------------------------------------------------------------
# 6. top_risks ordering
# ---------------------------------------------------------------------------


class TestTopRisks:
    def test_top_risks_empty(self, scorer):
        results = scorer.top_risks(org_id="no-data", n=5)
        assert results == []

    def test_top_risks_sorted_descending(self, scorer):
        # Score multiple findings and check ordering
        scorer.score_finding("high-f", cve_id=None, asset_id=None)
        results = scorer.top_risks(org_id="default", n=10)
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_top_risks_respects_n(self, scorer):
        for i in range(5):
            scorer.score_finding(f"f-top-{i}", org_id="org-top")
        results = scorer.top_risks(org_id="org-top", n=3)
        assert len(results) <= 3

    def test_top_risks_returns_correct_type(self, scorer):
        scorer.score_finding("tf1", org_id="org-type")
        results = scorer.top_risks(org_id="org-type", n=5)
        assert all(isinstance(r, CompositeRiskScore) for r in results)

    def test_top_risks_grade_consistent(self, scorer):
        scorer.score_finding("tf2", org_id="org-grade")
        results = scorer.top_risks(org_id="org-grade", n=5)
        for r in results:
            assert r.grade == CompositeRiskScorer.grade_score(r.score)


# ---------------------------------------------------------------------------
# 7. Persistence and retrieval
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_scored_finding_persisted(self, tmp_db):
        scorer = CompositeRiskScorer(db_path=tmp_db)
        result = scorer.score_finding("persist-f1", org_id="org-p")
        # Reload scorer from same DB
        scorer2 = CompositeRiskScorer(db_path=tmp_db)
        top = scorer2.top_risks(org_id="org-p", n=10)
        ids = [r.finding_id for r in top]
        assert "persist-f1" in ids

    def test_get_latest_asset_score_none_when_missing(self, scorer):
        result = scorer.get_latest_asset_score("nonexistent-asset", "default")
        assert result is None

    def test_score_asset_persisted_and_retrievable(self, tmp_db):
        scorer = CompositeRiskScorer(db_path=tmp_db)
        scored = scorer.score_asset("asset-persist", org_id="org-ap")
        retrieved = scorer.get_latest_asset_score("asset-persist", "org-ap")
        assert retrieved is not None
        assert abs(retrieved.score - scored.score) < 0.001

    def test_multiple_findings_persisted(self, tmp_db):
        scorer = CompositeRiskScorer(db_path=tmp_db)
        for i in range(5):
            scorer.score_finding(f"pf-{i}", org_id="org-multi")
        top = scorer.top_risks(org_id="org-multi", n=10)
        assert len(top) == 5

    def test_factors_round_trip(self, tmp_db):
        scorer = CompositeRiskScorer(db_path=tmp_db)
        original = scorer.score_finding("rt-f1", org_id="org-rt")
        retrieved = scorer.top_risks(org_id="org-rt", n=1)
        assert len(retrieved) == 1
        assert len(retrieved[0].factors) == len(original.factors)

    def test_score_org_isolation(self, tmp_db):
        scorer = CompositeRiskScorer(db_path=tmp_db)
        scorer.score_finding("iso-f1", org_id="org-a")
        scorer.score_finding("iso-f2", org_id="org-b")
        top_a = scorer.top_risks(org_id="org-a", n=10)
        top_b = scorer.top_risks(org_id="org-b", n=10)
        assert all(r.org_id == "org-a" for r in top_a)
        assert all(r.org_id == "org-b" for r in top_b)


# ---------------------------------------------------------------------------
# 8. score_asset aggregation
# ---------------------------------------------------------------------------


class TestScoreAsset:
    def test_score_asset_no_findings(self, scorer):
        result = scorer.score_asset("new-asset", org_id="default")
        assert isinstance(result, CompositeRiskScore)
        assert result.asset_id == "new-asset"
        assert 0.0 <= result.score <= 100.0

    def test_score_asset_aggregates_findings(self, tmp_db):
        scorer = CompositeRiskScorer(db_path=tmp_db)
        # Score some findings for this asset
        for i in range(3):
            scorer.score_finding(f"af-{i}", asset_id="agg-asset", org_id="agg-org")
        result = scorer.score_asset("agg-asset", org_id="agg-org")
        assert result.asset_id == "agg-asset"
        assert 0.0 <= result.score <= 100.0

    def test_score_asset_grade_consistent(self, scorer):
        result = scorer.score_asset("grade-asset", org_id="default")
        assert result.grade == CompositeRiskScorer.grade_score(result.score)


# ---------------------------------------------------------------------------
# 9. Singleton
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_get_composite_risk_scorer_returns_instance(self, tmp_db):
        scorer = get_composite_risk_scorer(db_path=tmp_db)
        assert isinstance(scorer, CompositeRiskScorer)

    def test_singleton_same_instance(self, tmp_db):
        # Module-level singleton — same call returns same object
        import core.composite_risk_scorer as _mod
        old = _mod._singleton
        try:
            _mod._singleton = None
            s1 = get_composite_risk_scorer(tmp_db)
            s2 = get_composite_risk_scorer(tmp_db)
            assert s1 is s2
        finally:
            _mod._singleton = old
