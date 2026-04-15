"""Tests for RiskAggregatorEngine.

Covers risk score recording, entity lookups, heatmap, top-risks,
composite org score, threshold rules, and statistics.

Total: 35 tests.
"""

from __future__ import annotations

import os
import pytest
from core.risk_aggregator_engine import RiskAggregatorEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "risk_agg_test.db")
    return RiskAggregatorEngine(db_path=db)


def _score(engine, org_id="org1", entity_id="asset-1", risk_score=75.0,
           entity_type="asset", severity=None):
    data = {
        "entity_id": entity_id,
        "entity_name": entity_id,
        "entity_type": entity_type,
        "source_engine": "test_engine",
        "risk_score": risk_score,
        "risk_factors": ["open_ports", "unpatched_cve"],
    }
    if severity:
        data["severity"] = severity
    return engine.record_risk_score(org_id, data)


# ===========================================================================
# 1. Initialisation
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "ra_init.db")
    RiskAggregatorEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "ra_idem.db")
    RiskAggregatorEngine(db_path=db)
    RiskAggregatorEngine(db_path=db)


# ===========================================================================
# 2. Record Risk Score
# ===========================================================================

def test_record_risk_score_returns_dict(engine):
    result = _score(engine)
    assert result["score_id"]
    assert result["entity_id"] == "asset-1"
    assert result["risk_score"] == 75.0
    assert result["severity"] == "high"
    assert result["risk_factors"] == ["open_ports", "unpatched_cve"]


def test_record_risk_score_auto_severity_critical(engine):
    result = _score(engine, risk_score=85.0)
    assert result["severity"] == "critical"


def test_record_risk_score_auto_severity_medium(engine):
    result = _score(engine, risk_score=50.0)
    assert result["severity"] == "medium"


def test_record_risk_score_auto_severity_low(engine):
    result = _score(engine, risk_score=20.0)
    assert result["severity"] == "low"


def test_record_risk_score_override_severity(engine):
    result = _score(engine, risk_score=90.0, severity="low")
    assert result["severity"] == "low"


def test_record_risk_score_invalid_entity_type(engine):
    with pytest.raises(ValueError, match="entity_type"):
        engine.record_risk_score("org1", {
            "entity_id": "x", "risk_score": 50, "entity_type": "robot"
        })


def test_record_risk_score_invalid_score_range(engine):
    with pytest.raises(ValueError, match="risk_score"):
        engine.record_risk_score("org1", {"entity_id": "x", "risk_score": 150})


def test_record_risk_score_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.record_risk_score("org1", {
            "entity_id": "x", "risk_score": 50, "severity": "extreme"
        })


def test_record_risk_score_all_entity_types(engine):
    for etype in ("asset", "user", "network", "application", "vendor"):
        r = engine.record_risk_score("org1", {
            "entity_id": f"{etype}-1",
            "entity_type": etype,
            "risk_score": 50.0,
        })
        assert r["entity_type"] == etype


# ===========================================================================
# 3. List Risk Scores
# ===========================================================================

def test_list_risk_scores_empty(engine):
    assert engine.list_risk_scores("org1") == []


def test_list_risk_scores_returns_all(engine):
    _score(engine, entity_id="a1")
    _score(engine, entity_id="a2")
    result = engine.list_risk_scores("org1")
    assert len(result) == 2


def test_list_risk_scores_filter_entity_type(engine):
    _score(engine, entity_id="a1", entity_type="asset")
    _score(engine, entity_id="u1", entity_type="user")
    assets = engine.list_risk_scores("org1", entity_type="asset")
    assert all(r["entity_type"] == "asset" for r in assets)


def test_list_risk_scores_filter_severity(engine):
    _score(engine, entity_id="h1", risk_score=85)  # critical
    _score(engine, entity_id="l1", risk_score=20)  # low
    critical = engine.list_risk_scores("org1", severity="critical")
    assert all(r["severity"] == "critical" for r in critical)


def test_list_risk_scores_limit(engine):
    for i in range(10):
        _score(engine, entity_id=f"e{i}")
    result = engine.list_risk_scores("org1", limit=5)
    assert len(result) == 5


def test_list_risk_scores_org_isolation(engine):
    _score(engine, org_id="org1")
    assert engine.list_risk_scores("org2") == []


# ===========================================================================
# 4. Get Entity Risk
# ===========================================================================

def test_get_entity_risk_not_found(engine):
    result = engine.get_entity_risk("org1", "nonexistent")
    assert result["latest"] is None
    assert result["history"] == []


def test_get_entity_risk_with_scores(engine):
    _score(engine, entity_id="asset-1", risk_score=60.0)
    _score(engine, entity_id="asset-1", risk_score=70.0)
    result = engine.get_entity_risk("org1", "asset-1")
    assert result["entity_id"] == "asset-1"
    assert result["latest"]["risk_score"] == 70.0
    assert len(result["history"]) == 2


def test_get_entity_risk_org_isolation(engine):
    _score(engine, org_id="org1", entity_id="asset-1")
    result = engine.get_entity_risk("org2", "asset-1")
    assert result["latest"] is None


# ===========================================================================
# 5. Heatmap
# ===========================================================================

def test_get_risk_heatmap_empty(engine):
    hm = engine.get_risk_heatmap("org1")
    assert hm["heatmap"] == {}


def test_get_risk_heatmap_with_data(engine):
    _score(engine, entity_id="a1", entity_type="asset", risk_score=85)   # critical
    _score(engine, entity_id="u1", entity_type="user", risk_score=50)    # medium
    hm = engine.get_risk_heatmap("org1")
    assert "asset" in hm["heatmap"]
    assert hm["heatmap"]["asset"]["critical"] == 1
    assert "user" in hm["heatmap"]
    assert hm["heatmap"]["user"]["medium"] == 1


# ===========================================================================
# 6. Top Risks
# ===========================================================================

def test_get_top_risks_empty(engine):
    assert engine.get_top_risks("org1") == []


def test_get_top_risks_returns_highest(engine):
    _score(engine, entity_id="low", risk_score=20)
    _score(engine, entity_id="high", risk_score=90)
    _score(engine, entity_id="mid", risk_score=55)
    top = engine.get_top_risks("org1", limit=2)
    assert len(top) == 2
    assert top[0]["entity_id"] == "high"
    assert top[1]["entity_id"] == "mid"


def test_get_top_risks_deduplicates_entity(engine):
    # Two scores for same entity — should appear once with latest
    _score(engine, entity_id="asset-1", risk_score=60)
    _score(engine, entity_id="asset-1", risk_score=80)
    top = engine.get_top_risks("org1")
    ids = [r["entity_id"] for r in top]
    assert ids.count("asset-1") == 1


# ===========================================================================
# 7. Org Risk Score
# ===========================================================================

def test_calculate_org_risk_score_empty(engine):
    result = engine.calculate_org_risk_score("org1")
    assert result["org_risk_score"] == 0
    assert result["grade"] == "A"
    assert result["trend"] == "stable"


def test_calculate_org_risk_score_with_data(engine):
    _score(engine, entity_id="a1", risk_score=80)
    _score(engine, entity_id="a2", risk_score=60)
    result = engine.calculate_org_risk_score("org1")
    assert result["org_risk_score"] == 70.0
    assert result["grade"] in ("A", "B", "C", "D", "F")
    assert result["entity_count"] == 2


def test_calculate_org_risk_score_grade_a(engine):
    _score(engine, entity_id="safe", risk_score=10)
    result = engine.calculate_org_risk_score("org1")
    assert result["grade"] == "A"


def test_calculate_org_risk_score_grade_f(engine):
    _score(engine, entity_id="bad", risk_score=100)
    result = engine.calculate_org_risk_score("org1")
    assert result["grade"] == "F"


def test_calculate_org_risk_score_breakdown(engine):
    _score(engine, entity_id="a1", entity_type="asset", risk_score=80)
    _score(engine, entity_id="u1", entity_type="user", risk_score=40)
    result = engine.calculate_org_risk_score("org1")
    assert "asset" in result["breakdown"]
    assert "user" in result["breakdown"]


# ===========================================================================
# 8. Risk Thresholds
# ===========================================================================

def test_create_risk_threshold_returns_dict(engine):
    t = engine.create_risk_threshold("org1", {
        "entity_type": "asset", "threshold": 80.0, "action": "alert"
    })
    assert t["threshold_id"]
    assert t["threshold"] == 80.0
    assert t["action"] == "alert"


def test_create_risk_threshold_invalid_entity_type(engine):
    with pytest.raises(ValueError, match="entity_type"):
        engine.create_risk_threshold("org1", {
            "entity_type": "unknown", "threshold": 70, "action": "alert"
        })


def test_create_risk_threshold_invalid_action(engine):
    with pytest.raises(ValueError, match="action"):
        engine.create_risk_threshold("org1", {
            "entity_type": "asset", "threshold": 70, "action": "ignore"
        })


def test_list_risk_thresholds_empty(engine):
    assert engine.list_risk_thresholds("org1") == []


def test_list_risk_thresholds_returns_all(engine):
    engine.create_risk_threshold("org1", {"entity_type": "asset", "threshold": 70, "action": "alert"})
    engine.create_risk_threshold("org1", {"entity_type": "user", "threshold": 60, "action": "escalate"})
    result = engine.list_risk_thresholds("org1")
    assert len(result) == 2


def test_list_risk_thresholds_org_isolation(engine):
    engine.create_risk_threshold("org1", {"entity_type": "asset", "threshold": 70, "action": "alert"})
    assert engine.list_risk_thresholds("org2") == []


# ===========================================================================
# 9. Aggregator Stats
# ===========================================================================

def test_get_aggregator_stats_empty(engine):
    stats = engine.get_aggregator_stats("org1")
    assert stats["entities_tracked"] == 0
    assert stats["high_risk_count"] == 0
    assert stats["org_risk_score"] == 0


def test_get_aggregator_stats_with_data(engine):
    _score(engine, entity_id="a1", risk_score=85)  # critical
    _score(engine, entity_id="a2", risk_score=20)  # low
    stats = engine.get_aggregator_stats("org1")
    assert stats["entities_tracked"] == 2
    assert stats["high_risk_count"] == 1
    assert stats["org_risk_score"] > 0
    assert stats["grade"] in ("A", "B", "C", "D", "F")


def test_get_aggregator_stats_org_isolation(engine):
    _score(engine, org_id="org1")
    stats = engine.get_aggregator_stats("org2")
    assert stats["entities_tracked"] == 0
