"""Tests for ThreatScoreEngine — 35 tests covering signals, scoring, history, stats."""

from __future__ import annotations

import pytest
from core.threat_score_engine import ThreatScoreEngine, _risk_level


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return ThreatScoreEngine(db_path=str(tmp_path / "threat_score.db"))


ORG = "org-a"
ORG2 = "org-b"


# ---------------------------------------------------------------------------
# Risk level helper
# ---------------------------------------------------------------------------

def test_risk_level_critical():
    assert _risk_level(80) == "critical"
    assert _risk_level(100) == "critical"


def test_risk_level_high():
    assert _risk_level(60) == "high"
    assert _risk_level(79.9) == "high"


def test_risk_level_medium():
    assert _risk_level(40) == "medium"
    assert _risk_level(59.9) == "medium"


def test_risk_level_low():
    assert _risk_level(20) == "low"
    assert _risk_level(39.9) == "low"


def test_risk_level_info():
    assert _risk_level(0) == "info"
    assert _risk_level(19.9) == "info"


# ---------------------------------------------------------------------------
# Signal ingestion
# ---------------------------------------------------------------------------

def test_ingest_signal_all_sources(engine):
    for source in ("vuln_scanner", "threat_intel", "siem", "uba", "network"):
        sig = engine.ingest_signal(ORG, {
            "asset_id": "asset-1", "signal_source": source,
            "signal_value": 50.0, "signal_weight": 1.0,
        })
        assert sig["signal_source"] == source


def test_ingest_signal_invalid_source_raises(engine):
    with pytest.raises(ValueError, match="signal_source"):
        engine.ingest_signal(ORG, {
            "asset_id": "asset-1", "signal_source": "magic_box", "signal_value": 50.0,
        })


def test_ingest_signal_missing_asset_id_raises(engine):
    with pytest.raises(ValueError, match="asset_id"):
        engine.ingest_signal(ORG, {"signal_source": "siem", "signal_value": 50.0})


def test_ingest_signal_default_weight(engine):
    sig = engine.ingest_signal(ORG, {
        "asset_id": "asset-x", "signal_source": "uba", "signal_value": 30.0,
    })
    assert sig["signal_weight"] == 1.0


def test_ingest_signal_custom_weight(engine):
    sig = engine.ingest_signal(ORG, {
        "asset_id": "asset-x", "signal_source": "siem",
        "signal_value": 70.0, "signal_weight": 2.5,
    })
    assert sig["signal_weight"] == 2.5


# ---------------------------------------------------------------------------
# Score calculation
# ---------------------------------------------------------------------------

def test_get_score_before_calculation_returns_none(engine):
    engine.ingest_signal(ORG, {"asset_id": "asset-new", "signal_source": "siem", "signal_value": 50.0})
    assert engine.get_score(ORG, "asset-new") is None


def test_calculate_score_basic(engine):
    engine.ingest_signal(ORG, {"asset_id": "a1", "signal_source": "siem", "signal_value": 90.0})
    result = engine.calculate_score(ORG, "a1")
    assert result["score"] == 90.0
    assert result["risk_level"] == "critical"


def test_calculate_score_weighted_average(engine):
    # weight 1 * value 100 + weight 3 * value 0 = 100 / 4 = 25 → low
    engine.ingest_signal(ORG, {"asset_id": "a2", "signal_source": "siem", "signal_value": 100.0, "signal_weight": 1.0})
    engine.ingest_signal(ORG, {"asset_id": "a2", "signal_source": "network", "signal_value": 0.0, "signal_weight": 3.0})
    result = engine.calculate_score(ORG, "a2")
    assert result["score"] == 25.0
    assert result["risk_level"] == "low"


def test_calculate_score_risk_level_high(engine):
    engine.ingest_signal(ORG, {"asset_id": "a3", "signal_source": "uba", "signal_value": 65.0})
    result = engine.calculate_score(ORG, "a3")
    assert result["risk_level"] == "high"


def test_calculate_score_risk_level_medium(engine):
    engine.ingest_signal(ORG, {"asset_id": "a4", "signal_source": "vuln_scanner", "signal_value": 45.0})
    result = engine.calculate_score(ORG, "a4")
    assert result["risk_level"] == "medium"


def test_calculate_score_risk_level_info(engine):
    engine.ingest_signal(ORG, {"asset_id": "a5", "signal_source": "threat_intel", "signal_value": 10.0})
    result = engine.calculate_score(ORG, "a5")
    assert result["risk_level"] == "info"


def test_calculate_score_no_signals(engine):
    result = engine.calculate_score(ORG, "ghost-asset")
    assert result["score"] == 0.0
    assert result["risk_level"] == "info"


def test_calculate_score_contributing_factors(engine):
    engine.ingest_signal(ORG, {"asset_id": "a6", "signal_source": "siem", "signal_value": 70.0, "signal_type": "alert"})
    result = engine.calculate_score(ORG, "a6")
    assert len(result["contributing_factors"]) == 1
    assert result["contributing_factors"][0]["value"] == 70.0


def test_calculate_score_uses_last_30_signals(engine):
    # Ingest 35 signals — only last 30 should count
    for i in range(35):
        engine.ingest_signal(ORG, {
            "asset_id": "a7", "signal_source": "network",
            "signal_value": float(i), "signal_weight": 1.0,
        })
    result = engine.calculate_score(ORG, "a7")
    assert len(result["contributing_factors"]) == 30


def test_calculate_score_version_increments(engine):
    engine.ingest_signal(ORG, {"asset_id": "a8", "signal_source": "uba", "signal_value": 50.0})
    r1 = engine.calculate_score(ORG, "a8")
    engine.ingest_signal(ORG, {"asset_id": "a8", "signal_source": "siem", "signal_value": 60.0})
    r2 = engine.calculate_score(ORG, "a8")
    assert r2["score_version"] == r1["score_version"] + 1


# ---------------------------------------------------------------------------
# Get / list scores
# ---------------------------------------------------------------------------

def test_get_score_after_calculation(engine):
    engine.ingest_signal(ORG, {"asset_id": "b1", "signal_source": "siem", "signal_value": 55.0})
    engine.calculate_score(ORG, "b1")
    result = engine.get_score(ORG, "b1")
    assert result is not None
    assert result["asset_id"] == "b1"


def test_list_scores(engine):
    for aid in ("b2", "b3", "b4"):
        engine.ingest_signal(ORG, {"asset_id": aid, "signal_source": "uba", "signal_value": 50.0})
        engine.calculate_score(ORG, aid)
    result = engine.list_scores(ORG)
    assert len(result) == 3


def test_list_scores_filter_asset_type(engine):
    engine.ingest_signal(ORG, {"asset_id": "b5", "signal_source": "siem", "signal_value": 80.0})
    engine.calculate_score(ORG, "b5")
    result = engine.list_scores(ORG, asset_type="host")
    assert all(r["asset_type"] == "host" for r in result)


def test_list_scores_filter_risk_level(engine):
    engine.ingest_signal(ORG, {"asset_id": "b6", "signal_source": "network", "signal_value": 85.0})
    engine.calculate_score(ORG, "b6")
    result = engine.list_scores(ORG, risk_level="critical")
    assert all(r["risk_level"] == "critical" for r in result)


def test_list_scores_org_isolation(engine):
    engine.ingest_signal(ORG, {"asset_id": "b7", "signal_source": "siem", "signal_value": 50.0})
    engine.calculate_score(ORG, "b7")
    assert engine.list_scores(ORG2) == []


# ---------------------------------------------------------------------------
# Score history
# ---------------------------------------------------------------------------

def test_get_score_history_ordering(engine):
    engine.ingest_signal(ORG, {"asset_id": "c1", "signal_source": "siem", "signal_value": 30.0})
    engine.calculate_score(ORG, "c1")
    engine.ingest_signal(ORG, {"asset_id": "c1", "signal_source": "uba", "signal_value": 60.0})
    engine.calculate_score(ORG, "c1")
    history = engine.get_score_history(ORG, "c1")
    assert len(history) == 2
    # Most recent first
    assert history[0]["recorded_at"] >= history[1]["recorded_at"]


def test_get_score_history_limit(engine):
    for _ in range(5):
        engine.ingest_signal(ORG, {"asset_id": "c2", "signal_source": "network", "signal_value": 50.0})
        engine.calculate_score(ORG, "c2")
    history = engine.get_score_history(ORG, "c2", limit=3)
    assert len(history) == 3


def test_get_score_history_org_isolation(engine):
    engine.ingest_signal(ORG, {"asset_id": "c3", "signal_source": "siem", "signal_value": 50.0})
    engine.calculate_score(ORG, "c3")
    assert engine.get_score_history(ORG2, "c3") == []


# ---------------------------------------------------------------------------
# Top threats
# ---------------------------------------------------------------------------

def test_get_top_threats_ordering(engine):
    for aid, val in (("d1", 90.0), ("d2", 50.0), ("d3", 70.0)):
        engine.ingest_signal(ORG, {"asset_id": aid, "signal_source": "siem", "signal_value": val})
        engine.calculate_score(ORG, aid)
    top = engine.get_top_threats(ORG)
    scores = [r["score"] for r in top]
    assert scores == sorted(scores, reverse=True)


def test_get_top_threats_limit(engine):
    for i in range(15):
        aid = f"e{i}"
        engine.ingest_signal(ORG, {"asset_id": aid, "signal_source": "uba", "signal_value": float(i * 6)})
        engine.calculate_score(ORG, aid)
    assert len(engine.get_top_threats(ORG, limit=5)) == 5


def test_get_top_threats_org_isolation(engine):
    engine.ingest_signal(ORG, {"asset_id": "f1", "signal_source": "network", "signal_value": 80.0})
    engine.calculate_score(ORG, "f1")
    assert engine.get_top_threats(ORG2) == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_threat_stats_empty(engine):
    stats = engine.get_threat_stats(ORG)
    assert stats["total_assets"] == 0
    assert stats["avg_score"] == 0.0
    assert stats["critical_count"] == 0


def test_get_threat_stats_counts(engine):
    for aid, val in (("g1", 85.0), ("g2", 65.0), ("g3", 45.0)):
        engine.ingest_signal(ORG, {"asset_id": aid, "signal_source": "siem", "signal_value": val})
        engine.calculate_score(ORG, aid)
    stats = engine.get_threat_stats(ORG)
    assert stats["total_assets"] == 3
    assert stats["critical_count"] == 1
    assert "critical" in stats["by_risk_level"]
    assert "high" in stats["by_risk_level"]
    assert stats["assets_scored_24h"] == 3
    assert round(stats["avg_score"], 1) == round((85.0 + 65.0 + 45.0) / 3, 1)


def test_get_threat_stats_org_isolation(engine):
    engine.ingest_signal(ORG, {"asset_id": "g4", "signal_source": "uba", "signal_value": 90.0})
    engine.calculate_score(ORG, "g4")
    stats = engine.get_threat_stats(ORG2)
    assert stats["total_assets"] == 0
