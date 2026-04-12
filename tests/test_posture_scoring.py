"""
Tests for Security Posture Scoring Engine.

Covers:
- PostureComponent and PostureScore Pydantic models
- Individual component scoring (all 6 components)
- Weighted aggregate calculation
- Grade assignment (A through F boundaries)
- Score persistence and history
- Trend data generation
- Multi-org comparison
- Edge cases: no data = baseline score
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Generator

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.posture_scoring import (
    PostureComponent,
    PostureScore,
    PostureScorer,
    _BASELINE_SCORE,
    _WEIGHTS,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_dirs() -> Generator[dict, None, None]:
    """Provide isolated temporary directories for all three databases."""
    with tempfile.TemporaryDirectory() as tmpdir:
        posture_db = os.path.join(tmpdir, "posture.db")
        analytics_db = os.path.join(tmpdir, "analytics.db")
        surface_db = os.path.join(tmpdir, "surface.db")
        yield {
            "posture_db": posture_db,
            "analytics_db": analytics_db,
            "surface_db": surface_db,
            "tmpdir": tmpdir,
        }


@pytest.fixture
def scorer(tmp_dirs: dict) -> PostureScorer:
    """PostureScorer with fresh isolated databases."""
    return PostureScorer(
        db_path=tmp_dirs["posture_db"],
        analytics_db=tmp_dirs["analytics_db"],
        attack_surface_db=tmp_dirs["surface_db"],
    )


@pytest.fixture
def analytics_db(tmp_dirs: dict) -> str:
    """Initialised analytics SQLite database path."""
    db_path = tmp_dirs["analytics_db"]
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS finding_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id      TEXT    NOT NULL,
            finding_id  TEXT    NOT NULL,
            event_type  TEXT    NOT NULL,
            severity    TEXT    NOT NULL DEFAULT 'medium',
            scanner     TEXT    NOT NULL DEFAULT 'unknown',
            cve_id      TEXT,
            risk_score  REAL    NOT NULL DEFAULT 5.0,
            ts          TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_fe_org_ts ON finding_events (org_id, ts);
        CREATE INDEX IF NOT EXISTS idx_fe_finding ON finding_events (finding_id, event_type);
        """
    )
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def surface_db(tmp_dirs: dict) -> str:
    """Initialised attack surface SQLite database path."""
    db_path = tmp_dirs["surface_db"]
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            exposure_level TEXT NOT NULL,
            attributes TEXT DEFAULT '{}',
            tags TEXT DEFAULT '[]',
            discovered_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            org_id TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(org_id);
        """
    )
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def scorer_with_data(tmp_dirs: dict, analytics_db: str, surface_db: str) -> PostureScorer:
    """PostureScorer whose analytics + surface databases have representative data."""
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=45)

    # Insert finding events
    conn = sqlite3.connect(analytics_db)
    events = [
        # 3 open findings (not resolved)
        ("org1", "f001", "opened", "high", "bandit", now.isoformat()),
        ("org1", "f002", "opened", "medium", "trivy", now.isoformat()),
        ("org1", "f003", "opened", "low", "semgrep", now.isoformat()),
        # 2 resolved findings
        ("org1", "f004", "opened", "high", "bandit", old.isoformat()),
        ("org1", "f004", "resolved", "high", "bandit", now.isoformat()),
        ("org1", "f005", "opened", "medium", "trivy", old.isoformat()),
        ("org1", "f005", "resolved", "medium", "trivy", now.isoformat()),
        # 1 old unresolved finding (>30 days old)
        ("org1", "f006", "opened", "critical", "snyk", old.isoformat()),
    ]
    conn.executemany(
        "INSERT INTO finding_events (org_id, finding_id, event_type, severity, scanner, ts) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        events,
    )
    conn.commit()
    conn.close()

    # Insert assets
    conn = sqlite3.connect(surface_db)
    assets = [
        ("a1", "web-server", "service", "external", now.isoformat(), now.isoformat(), "org1"),
        ("a2", "db-server", "service", "internal", now.isoformat(), now.isoformat(), "org1"),
        ("a3", "api-gateway", "api_endpoint", "internal", now.isoformat(), now.isoformat(), "org1"),
        ("a4", "cdn-node", "domain", "external", now.isoformat(), now.isoformat(), "org1"),
    ]
    conn.executemany(
        "INSERT INTO assets (id, name, type, exposure_level, discovered_at, last_seen, org_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        assets,
    )
    conn.commit()
    conn.close()

    return PostureScorer(
        db_path=tmp_dirs["posture_db"],
        analytics_db=analytics_db,
        attack_surface_db=surface_db,
    )


# ============================================================================
# PYDANTIC MODEL TESTS
# ============================================================================


class TestPostureComponent:
    def test_valid_construction(self) -> None:
        c = PostureComponent(name="vuln_density", score=75.0, weight=0.25, details={})
        assert c.name == "vuln_density"
        assert c.score == 75.0
        assert c.weight == 0.25

    def test_score_bounds_enforced(self) -> None:
        with pytest.raises(Exception):
            PostureComponent(name="x", score=101.0, weight=0.1, details={})

    def test_score_lower_bound_enforced(self) -> None:
        with pytest.raises(Exception):
            PostureComponent(name="x", score=-1.0, weight=0.1, details={})

    def test_details_defaults_to_empty_dict(self) -> None:
        c = PostureComponent(name="x", score=50.0, weight=0.1)
        assert c.details == {}


class TestPostureScore:
    def test_valid_construction(self) -> None:
        ps = PostureScore(
            org_id="test-org",
            overall_score=82.5,
            grade="B",
            components=[],
        )
        assert ps.org_id == "test-org"
        assert ps.overall_score == 82.5
        assert ps.grade == "B"
        assert ps.id.startswith("ps-")

    def test_auto_generated_id(self) -> None:
        a = PostureScore(org_id="o1", overall_score=50.0, grade="F")
        b = PostureScore(org_id="o1", overall_score=50.0, grade="F")
        assert a.id != b.id

    def test_calculated_at_is_iso(self) -> None:
        ps = PostureScore(org_id="o1", overall_score=70.0, grade="C")
        datetime.fromisoformat(ps.calculated_at)  # must not raise


# ============================================================================
# GRADE CALCULATION TESTS
# ============================================================================


class TestGradeCalculation:
    def test_grade_a(self, scorer: PostureScorer) -> None:
        assert scorer._calculate_grade(90.0) == "A"
        assert scorer._calculate_grade(100.0) == "A"
        assert scorer._calculate_grade(95.5) == "A"

    def test_grade_b(self, scorer: PostureScorer) -> None:
        assert scorer._calculate_grade(80.0) == "B"
        assert scorer._calculate_grade(89.9) == "B"

    def test_grade_c(self, scorer: PostureScorer) -> None:
        assert scorer._calculate_grade(70.0) == "C"
        assert scorer._calculate_grade(79.9) == "C"

    def test_grade_d(self, scorer: PostureScorer) -> None:
        assert scorer._calculate_grade(60.0) == "D"
        assert scorer._calculate_grade(69.9) == "D"

    def test_grade_f(self, scorer: PostureScorer) -> None:
        assert scorer._calculate_grade(59.9) == "F"
        assert scorer._calculate_grade(0.0) == "F"

    def test_boundary_90_is_a(self, scorer: PostureScorer) -> None:
        assert scorer._calculate_grade(90.0) == "A"

    def test_boundary_80_is_b(self, scorer: PostureScorer) -> None:
        assert scorer._calculate_grade(80.0) == "B"

    def test_boundary_70_is_c(self, scorer: PostureScorer) -> None:
        assert scorer._calculate_grade(70.0) == "C"

    def test_boundary_60_is_d(self, scorer: PostureScorer) -> None:
        assert scorer._calculate_grade(60.0) == "D"


# ============================================================================
# COMPONENT SCORER TESTS (no data = baseline)
# ============================================================================


class TestComponentScorersNoData:
    """All component scorers must return _BASELINE_SCORE when databases are absent."""

    def test_vuln_density_baseline_no_data(self, scorer: PostureScorer) -> None:
        score, details = scorer._score_vulnerability_density("org1")
        assert score == _BASELINE_SCORE

    def test_mttr_baseline_no_data(self, scorer: PostureScorer) -> None:
        score, details = scorer._score_mttr("org1")
        assert score == _BASELINE_SCORE

    def test_compliance_baseline_no_data(self, scorer: PostureScorer) -> None:
        score, details = scorer._score_compliance("org1")
        assert score == _BASELINE_SCORE

    def test_attack_surface_baseline_no_data(self, scorer: PostureScorer) -> None:
        score, details = scorer._score_attack_surface("org1")
        assert score == _BASELINE_SCORE

    def test_finding_age_baseline_no_data(self, scorer: PostureScorer) -> None:
        score, details = scorer._score_finding_age("org1")
        assert score == _BASELINE_SCORE

    def test_scanner_coverage_baseline_no_data(self, scorer: PostureScorer) -> None:
        score, details = scorer._score_scanner_coverage("org1")
        assert score == _BASELINE_SCORE


# ============================================================================
# COMPONENT SCORER TESTS (with data)
# ============================================================================


class TestComponentScorersWithData:
    def test_vuln_density_score_range(self, scorer_with_data: PostureScorer) -> None:
        score, details = scorer_with_data._score_vulnerability_density("org1")
        assert 0.0 <= score <= 100.0
        assert "open_vulns" in details
        assert details["open_vulns"] >= 0

    def test_vuln_density_perfect_score_no_vulns(self, tmp_dirs: dict, analytics_db: str, surface_db: str) -> None:
        """Zero open vulns should yield 100."""
        scorer = PostureScorer(
            db_path=tmp_dirs["posture_db"],
            analytics_db=analytics_db,
            attack_surface_db=surface_db,
        )
        score, _ = scorer._score_vulnerability_density("empty-org")
        assert score == 100.0

    def test_mttr_score_range(self, scorer_with_data: PostureScorer) -> None:
        score, details = scorer_with_data._score_mttr("org1")
        assert 0.0 <= score <= 100.0

    def test_mttr_details_populated(self, scorer_with_data: PostureScorer) -> None:
        score, details = scorer_with_data._score_mttr("org1")
        # Should have computed actual MTTR from resolved findings
        assert "avg_mttr_hours" in details
        if details["avg_mttr_hours"] is not None:
            assert details["avg_mttr_hours"] >= 0

    def test_attack_surface_score_range(self, scorer_with_data: PostureScorer) -> None:
        score, details = scorer_with_data._score_attack_surface("org1")
        assert 0.0 <= score <= 100.0

    def test_attack_surface_external_ratio(self, scorer_with_data: PostureScorer) -> None:
        score, details = scorer_with_data._score_attack_surface("org1")
        # 2 external of 4 total → 50% exposure → score = 50
        assert details["external_assets"] == 2
        assert details["total_assets"] == 4
        assert abs(score - 50.0) < 0.01

    def test_finding_age_score_range(self, scorer_with_data: PostureScorer) -> None:
        score, details = scorer_with_data._score_finding_age("org1")
        assert 0.0 <= score <= 100.0

    def test_finding_age_old_findings_penalised(self, scorer_with_data: PostureScorer) -> None:
        score, details = scorer_with_data._score_finding_age("org1")
        # f006 is >30 days old and unresolved → old_findings_pct > 0 → score < 100
        assert score < 100.0
        assert details["old_findings_pct"] > 0

    def test_scanner_coverage_score_range(self, scorer_with_data: PostureScorer) -> None:
        score, details = scorer_with_data._score_scanner_coverage("org1")
        assert 0.0 <= score <= 100.0

    def test_scanner_coverage_counts_distinct(self, scorer_with_data: PostureScorer) -> None:
        score, details = scorer_with_data._score_scanner_coverage("org1")
        # bandit, trivy, semgrep, snyk = 4 distinct scanners used recently
        assert details["distinct_scanners"] >= 1

    def test_scanner_coverage_five_equals_100(self, tmp_dirs: dict, analytics_db: str, surface_db: str) -> None:
        """5 distinct scanners should yield score = 100."""
        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(analytics_db)
        for i, scanner in enumerate(["alpha", "beta", "gamma", "delta", "epsilon"]):
            conn.execute(
                "INSERT INTO finding_events (org_id, finding_id, event_type, severity, scanner, ts) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("scanner-org", f"f{i}", "opened", "low", scanner, now),
            )
        conn.commit()
        conn.close()

        scorer = PostureScorer(
            db_path=tmp_dirs["posture_db"],
            analytics_db=analytics_db,
            attack_surface_db=surface_db,
        )
        score, details = scorer._score_scanner_coverage("scanner-org")
        assert score == 100.0


# ============================================================================
# WEIGHTED AGGREGATE TESTS
# ============================================================================


class TestWeightedAggregate:
    def test_weights_sum_to_one(self) -> None:
        total = sum(_WEIGHTS.values())
        assert abs(total - 1.0) < 1e-9

    def test_calculate_score_returns_posture_score(self, scorer: PostureScorer) -> None:
        result = scorer.calculate_score("org1")
        assert isinstance(result, PostureScore)
        assert result.org_id == "org1"

    def test_calculate_score_overall_in_range(self, scorer: PostureScorer) -> None:
        result = scorer.calculate_score("org1")
        assert 0.0 <= result.overall_score <= 100.0

    def test_calculate_score_has_six_components(self, scorer: PostureScorer) -> None:
        result = scorer.calculate_score("org1")
        assert len(result.components) == 6

    def test_calculate_score_grade_set(self, scorer: PostureScorer) -> None:
        result = scorer.calculate_score("org1")
        assert result.grade in {"A", "B", "C", "D", "F"}

    def test_no_data_yields_baseline_aggregate(self, scorer: PostureScorer) -> None:
        result = scorer.calculate_score("empty-org")
        # All components at baseline → overall ≈ 50
        assert abs(result.overall_score - _BASELINE_SCORE) < 0.01

    def test_component_weights_match_constants(self, scorer: PostureScorer) -> None:
        result = scorer.calculate_score("org1")
        component_weights = {c.name: c.weight for c in result.components}
        for name, expected_weight in _WEIGHTS.items():
            assert abs(component_weights[name] - expected_weight) < 1e-9


# ============================================================================
# PERSISTENCE AND HISTORY TESTS
# ============================================================================


class TestPersistenceAndHistory:
    def test_calculate_persists_score(self, scorer: PostureScorer) -> None:
        scorer.calculate_score("org1")
        history = scorer.get_score_history("org1", days=1)
        assert len(history) == 1

    def test_get_latest_returns_most_recent(self, scorer: PostureScorer) -> None:
        scorer.calculate_score("org1")
        scorer.calculate_score("org1")
        latest = scorer.get_latest_score("org1")
        assert isinstance(latest, PostureScore)

    def test_get_latest_computes_if_none_exists(self, scorer: PostureScorer) -> None:
        result = scorer.get_latest_score("brand-new-org")
        assert isinstance(result, PostureScore)
        assert result.org_id == "brand-new-org"

    def test_history_empty_for_new_org(self, scorer: PostureScorer) -> None:
        history = scorer.get_score_history("never-seen-org", days=30)
        assert history == []

    def test_history_returns_scores_in_window(self, scorer: PostureScorer) -> None:
        scorer.calculate_score("org1")
        scorer.calculate_score("org1")
        history = scorer.get_score_history("org1", days=7)
        assert len(history) == 2

    def test_multiple_orgs_isolated(self, scorer: PostureScorer) -> None:
        scorer.calculate_score("org-a")
        scorer.calculate_score("org-b")
        history_a = scorer.get_score_history("org-a", days=7)
        history_b = scorer.get_score_history("org-b", days=7)
        assert len(history_a) == 1
        assert len(history_b) == 1


# ============================================================================
# TREND DATA TESTS
# ============================================================================


class TestTrendData:
    def test_get_score_trend_returns_list(self, scorer: PostureScorer) -> None:
        scorer.calculate_score("org1")
        trend = scorer.get_score_trend("org1", days=30)
        assert isinstance(trend, list)

    def test_trend_items_have_required_keys(self, scorer: PostureScorer) -> None:
        scorer.calculate_score("org1")
        trend = scorer.get_score_trend("org1", days=30)
        assert len(trend) >= 1
        item = trend[0]
        assert "date" in item
        assert "score" in item
        assert "grade" in item

    def test_trend_date_format(self, scorer: PostureScorer) -> None:
        scorer.calculate_score("org1")
        trend = scorer.get_score_trend("org1", days=30)
        for item in trend:
            # YYYY-MM-DD format
            assert len(item["date"]) == 10
            datetime.strptime(item["date"], "%Y-%m-%d")  # must not raise

    def test_trend_empty_for_new_org(self, scorer: PostureScorer) -> None:
        trend = scorer.get_score_trend("fresh-org", days=30)
        assert trend == []


# ============================================================================
# MULTI-ORG COMPARISON TESTS
# ============================================================================


class TestCompareOrgs:
    def test_compare_returns_list(self, scorer: PostureScorer) -> None:
        result = scorer.compare_orgs(["org-x", "org-y"])
        assert isinstance(result, list)
        assert len(result) == 2

    def test_compare_sorted_descending(self, scorer: PostureScorer) -> None:
        result = scorer.compare_orgs(["org-x", "org-y", "org-z"])
        scores = [r.overall_score for r in result]
        assert scores == sorted(scores, reverse=True)

    def test_compare_single_org(self, scorer: PostureScorer) -> None:
        result = scorer.compare_orgs(["solo-org"])
        assert len(result) == 1
        assert result[0].org_id == "solo-org"
