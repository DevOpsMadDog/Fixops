"""
Tests for risk_prioritizer.py and exposure_scorer.py.

Coverage:
  - RiskScore composite calculation
  - CVSS severity normalisation
  - Asset criticality extraction
  - ExploitWindow heuristics
  - rank_findings ordering
  - get_remediation_priority urgency tiers
  - ExposureScorer.calculate_org_exposure
  - ExposureScorer.calculate_asset_exposure / get_asset_exposure
  - ExposureScorer.get_exposure_trend
  - ExposureScorer.ingest_scores
  - API router: score, rank, org exposure, asset exposure, trend
  - Edge cases: empty findings, unknown severity, missing CVE
"""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# ── env vars must be set before any app imports ──────────────────────────────
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi import FastAPI
from fastapi.testclient import TestClient

# ── path bootstrap ────────────────────────────────────────────────────────────
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

# ── imports under test ────────────────────────────────────────────────────────
from core.risk_prioritizer import (
    ExploitWindow,
    PriorityQueue,
    RemediationUrgency,
    RiskPrioritizer,
    RiskScore,
    _determine_exploit_window,
    _normalise_asset_criticality,
    _normalise_severity,
    _urgency_from_score,
)
from core.exposure_scorer import (
    AssetExposureScore,
    ExposureScorer,
    ExposureTrend,
    OrgExposureScore,
    _exposure_rating,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture()
def tmp_prioritizer(tmp_path):
    """RiskPrioritizer backed by a temp SQLite DB, KEV + EPSS calls mocked."""
    db = str(tmp_path / "rp.db")
    with (
        patch.object(RiskPrioritizer, "_warm_kev_cache", return_value=None),
        patch.object(RiskPrioritizer, "_get_epss", return_value=0.0),
    ):
        rp = RiskPrioritizer(db_path=db)
        rp._kev_cves = set()
    return rp


@pytest.fixture()
def tmp_scorer(tmp_path):
    """ExposureScorer backed by a temp SQLite DB."""
    return ExposureScorer(db_path=str(tmp_path / "es.db"))


@pytest.fixture()
def api_client(tmp_path):
    """TestClient wired to the risk_scoring_router with auth and engines mocked."""
    from apps.api.auth_deps import api_key_auth
    from apps.api.risk_scoring_router import router as risk_router

    db = str(tmp_path / "api_rp.db")
    es_db = str(tmp_path / "api_es.db")
    os.environ["RISK_PRIORITIZER_DB"] = db
    os.environ["EXPOSURE_SCORER_DB"] = es_db

    # Reset singletons so tmp paths are used
    import core.risk_prioritizer as _rp_mod
    import core.exposure_scorer as _es_mod

    _rp_mod._instance = None
    _es_mod._instance = None

    app = FastAPI()
    app.include_router(risk_router)
    # Bypass auth — standard pattern used across all ALDECI test files
    app.dependency_overrides[api_key_auth] = lambda: None

    with (
        patch.object(RiskPrioritizer, "_warm_kev_cache", return_value=None),
        patch.object(RiskPrioritizer, "_get_epss", return_value=0.05),
    ):
        client = TestClient(app, raise_server_exceptions=True)
        yield client

    _rp_mod._instance = None
    _es_mod._instance = None


# ============================================================================
# UNIT — helpers
# ============================================================================


def test_normalise_severity_from_string():
    assert _normalise_severity({"severity": "critical"}) == 10.0
    assert _normalise_severity({"severity": "HIGH"}) == 7.5
    assert _normalise_severity({"severity": "medium"}) == 5.0
    assert _normalise_severity({"severity": "low"}) == 2.5
    assert _normalise_severity({"severity": "info"}) == 0.5


def test_normalise_severity_from_cvss_score():
    assert _normalise_severity({"cvss_score": 9.8}) == 9.8
    assert _normalise_severity({"cvss_base_score": 3.1}) == 3.1


def test_normalise_severity_unknown_defaults_medium():
    assert _normalise_severity({"severity": "unknown"}) == 5.0
    assert _normalise_severity({}) == 5.0


def test_normalise_asset_criticality_from_env():
    assert _normalise_asset_criticality({"environment": "production"}) == 1.0
    assert _normalise_asset_criticality({"asset_environment": "staging"}) == 0.5
    assert _normalise_asset_criticality({"environment": "dev"}) == 0.2
    assert _normalise_asset_criticality({"environment": "sandbox"}) == 0.1


def test_normalise_asset_criticality_explicit_value():
    assert _normalise_asset_criticality({"asset_criticality": 0.8}) == 0.8


def test_normalise_asset_criticality_unknown_defaults_05():
    assert _normalise_asset_criticality({}) == 0.5


def test_exploit_window_days_kev_high_epss():
    assert _determine_exploit_window("critical", 0.7, True) == ExploitWindow.DAYS


def test_exploit_window_weeks_kev_low_epss():
    assert _determine_exploit_window("high", 0.05, True) == ExploitWindow.WEEKS


def test_exploit_window_weeks_no_kev_high_epss():
    assert _determine_exploit_window("high", 0.2, False) == ExploitWindow.WEEKS


def test_exploit_window_months_medium():
    assert _determine_exploit_window("medium", 0.0, False) == ExploitWindow.MONTHS


def test_exploit_window_quarters_low():
    assert _determine_exploit_window("low", 0.0, False) == ExploitWindow.QUARTERS


def test_urgency_from_score():
    assert _urgency_from_score(85.0) == RemediationUrgency.IMMEDIATE
    assert _urgency_from_score(65.0) == RemediationUrgency.URGENT
    assert _urgency_from_score(45.0) == RemediationUrgency.PLANNED
    assert _urgency_from_score(10.0) == RemediationUrgency.BACKLOG


def test_exposure_rating():
    assert _exposure_rating(90.0) == "critical"
    assert _exposure_rating(70.0) == "high"
    assert _exposure_rating(50.0) == "medium"
    assert _exposure_rating(30.0) == "low"
    assert _exposure_rating(10.0) == "minimal"


# ============================================================================
# UNIT — RiskPrioritizer
# ============================================================================


def test_score_finding_returns_risk_score(tmp_prioritizer):
    finding = {
        "id": "f-001",
        "severity": "high",
        "environment": "production",
    }
    result = tmp_prioritizer.score_finding(finding)

    assert isinstance(result, RiskScore)
    assert result.finding_id == "f-001"
    assert 0.0 <= result.composite_score <= 100.0
    assert result.cvss_raw == 7.5
    assert result.asset_criticality_raw == 1.0


def test_score_finding_critical_production_high_score(tmp_prioritizer):
    finding = {
        "id": "f-critical",
        "severity": "critical",
        "environment": "production",
    }
    result = tmp_prioritizer.score_finding(finding)
    # CVSS(40% × 10/10 × 100) + asset(15% × 1.0 × 100) = 40 + 15 = 55 minimum
    assert result.composite_score >= 50.0


def test_score_finding_low_info_dev_low_score(tmp_prioritizer):
    finding = {
        "id": "f-low",
        "severity": "low",
        "environment": "dev",
    }
    result = tmp_prioritizer.score_finding(finding)
    assert result.composite_score < 40.0


def test_score_finding_kev_boost(tmp_path):
    """KEV presence should raise score compared to identical non-KEV finding."""
    db = str(tmp_path / "kev_test.db")
    with (
        patch.object(RiskPrioritizer, "_warm_kev_cache", return_value=None),
        patch.object(RiskPrioritizer, "_get_epss", return_value=0.0),
    ):
        rp = RiskPrioritizer(db_path=db)

    finding = {"id": "f-kev", "severity": "high", "environment": "production", "cve_id": "CVE-2023-1234"}

    rp._kev_cves = set()
    score_no_kev = rp.score_finding(finding).composite_score

    rp._kev_cves = {"CVE-2023-1234"}
    score_with_kev = rp.score_finding(finding).composite_score

    assert score_with_kev > score_no_kev


def test_rank_findings_descending_order(tmp_prioritizer):
    findings = [
        {"id": "low-f", "severity": "low", "environment": "dev"},
        {"id": "critical-f", "severity": "critical", "environment": "production"},
        {"id": "medium-f", "severity": "medium", "environment": "staging"},
    ]
    ranked = tmp_prioritizer.rank_findings(findings)
    assert ranked[0].finding_id == "critical-f"
    assert ranked[-1].finding_id == "low-f"
    scores = [r.composite_score for r in ranked]
    assert scores == sorted(scores, reverse=True)


def test_rank_findings_empty_list(tmp_prioritizer):
    assert tmp_prioritizer.rank_findings([]) == []


def test_get_remediation_priority_structure(tmp_prioritizer):
    findings = [
        {"id": "a", "severity": "high", "environment": "production"},
        {"id": "b", "severity": "low", "environment": "dev"},
    ]
    queue = tmp_prioritizer.get_remediation_priority(findings)
    assert isinstance(queue, PriorityQueue)
    assert queue.total == 2
    assert queue.items[0].rank == 1
    assert queue.items[1].rank == 2
    # Highest risk first
    assert queue.items[0].composite_score >= queue.items[1].composite_score


def test_predict_exploit_window(tmp_prioritizer):
    finding = {"id": "w", "severity": "medium", "environment": "production"}
    window = tmp_prioritizer.predict_exploit_window(finding)
    assert isinstance(window, ExploitWindow)


def test_score_persisted_to_db(tmp_prioritizer):
    """Score is saved to SQLite so it can be retrieved."""
    import sqlite3

    tmp_prioritizer.score_finding({"id": "persist-me", "severity": "high"})
    with sqlite3.connect(tmp_prioritizer._db_path) as conn:
        row = conn.execute(
            "SELECT finding_id FROM risk_scores WHERE finding_id = 'persist-me'"
        ).fetchone()
    assert row is not None


# ============================================================================
# UNIT — ExposureScorer
# ============================================================================


def test_org_exposure_no_findings(tmp_scorer):
    result = tmp_scorer.calculate_org_exposure(snapshot=False)
    assert result.exposure_score == 0.0
    assert result.rating == "minimal"
    assert result.open_findings_count == 0


def test_org_exposure_with_findings(tmp_scorer):
    tmp_scorer.ingest_scores([
        {"finding_id": "f1", "asset_id": "asset-a", "composite_score": 85.0},
        {"finding_id": "f2", "asset_id": "asset-b", "composite_score": 40.0},
    ])
    result = tmp_scorer.calculate_org_exposure(snapshot=False)
    assert result.open_findings_count == 2
    assert result.exposure_score > 0.0
    assert result.critical_count == 1
    assert result.medium_count == 1
    assert result.assets_at_risk == 2


def test_asset_exposure_no_findings(tmp_scorer):
    score = tmp_scorer.calculate_asset_exposure("nonexistent-asset")
    assert score == 0.0


def test_asset_exposure_with_findings(tmp_scorer):
    tmp_scorer.ingest_scores([
        {"finding_id": "f1", "asset_id": "web-server", "composite_score": 80.0},
        {"finding_id": "f2", "asset_id": "web-server", "composite_score": 50.0},
    ])
    score = tmp_scorer.calculate_asset_exposure("web-server")
    # 60% max (80) + 40% avg (65) = 48 + 26 = 74
    assert score == pytest.approx(0.60 * 80.0 + 0.40 * 65.0, abs=0.1)


def test_get_asset_exposure_returns_model(tmp_scorer):
    tmp_scorer.ingest_scores([
        {"finding_id": "fa", "asset_id": "db-prod", "composite_score": 90.0},
    ])
    result = tmp_scorer.get_asset_exposure("db-prod")
    assert isinstance(result, AssetExposureScore)
    assert result.open_findings_count == 1
    assert result.max_finding_score == 90.0


def test_exposure_trend_empty(tmp_scorer):
    trend = tmp_scorer.get_exposure_trend(org_id="default", days=30)
    assert trend == []


def test_exposure_trend_after_snapshot(tmp_scorer):
    tmp_scorer.ingest_scores([
        {"finding_id": "t1", "asset_id": "a", "composite_score": 70.0},
    ])
    tmp_scorer.calculate_org_exposure(org_id="default", snapshot=True)
    trend = tmp_scorer.get_exposure_trend(org_id="default", days=30)
    assert len(trend) >= 1
    assert isinstance(trend[0], ExposureTrend)
    assert 0.0 <= trend[0].exposure_score <= 100.0


def test_ingest_resolved_finding_excluded(tmp_scorer):
    """Resolved findings must not count toward open exposure."""
    tmp_scorer.ingest_scores([
        {"finding_id": "open-1", "asset_id": "srv", "composite_score": 80.0, "status": "open"},
        {"finding_id": "closed-1", "asset_id": "srv", "composite_score": 80.0, "status": "resolved"},
    ])
    result = tmp_scorer.calculate_org_exposure(snapshot=False)
    assert result.open_findings_count == 1


# ============================================================================
# API INTEGRATION
# ============================================================================


def test_api_score_finding(api_client):
    resp = api_client.post(
        "/api/v1/risk/score",
        json={"finding": {"id": "api-f1", "severity": "high", "environment": "production"}},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["finding_id"] == "api-f1"
    assert 0 <= data["composite_score"] <= 100
    assert "rationale" in data
    assert "exploit_window" in data


def test_api_rank_findings(api_client):
    resp = api_client.post(
        "/api/v1/risk/rank",
        json={
            "findings": [
                {"id": "r1", "severity": "low", "environment": "dev"},
                {"id": "r2", "severity": "critical", "environment": "production"},
            ]
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    scores = [s["composite_score"] for s in data["scores"]]
    assert scores == sorted(scores, reverse=True)
    assert "remediation_queue" in data


def test_api_org_exposure(api_client):
    resp = api_client.get("/api/v1/risk/exposure/org")
    assert resp.status_code == 200
    data = resp.json()
    assert "exposure_score" in data
    assert "rating" in data


def test_api_asset_exposure(api_client):
    resp = api_client.get("/api/v1/risk/exposure/my-server")
    assert resp.status_code == 200
    data = resp.json()
    assert data["asset_id"] == "my-server"
    assert "exposure_score" in data


def test_api_exposure_trend(api_client):
    resp = api_client.get("/api/v1/risk/exposure/trend?days=7")
    assert resp.status_code == 200
    data = resp.json()
    assert "trend" in data
    assert data["days"] == 7


def test_api_rank_requires_findings(api_client):
    """Empty findings list should return 422 validation error."""
    resp = api_client.post("/api/v1/risk/rank", json={"findings": []})
    assert resp.status_code == 422
