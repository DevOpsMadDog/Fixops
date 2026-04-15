"""Tests for SecurityPostureScoringEngine.

Covers control lifecycle, weighted score calculation, score levels,
posture history snapshots, gap stats, org isolation, and validation errors.

Total: 35 tests.
"""

from __future__ import annotations

import os
import pytest
from core.security_posture_scoring_engine import SecurityPostureScoringEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "sps_test.db")
    return SecurityPostureScoringEngine(db_path=db)


@pytest.fixture()
def control(engine):
    return engine.register_control("org1", {
        "name": "MFA Enforcement",
        "domain": "identity",
        "description": "All privileged accounts require MFA",
        "weight": 2.0,
        "control_status": "implemented",
        "evidence_url": "https://example.com/evidence/mfa",
    })


# ===========================================================================
# 1. Initialisation
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "sps_init.db")
    SecurityPostureScoringEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "sps_idem.db")
    SecurityPostureScoringEngine(db_path=db)
    SecurityPostureScoringEngine(db_path=db)


# ===========================================================================
# 2. register_control
# ===========================================================================

def test_register_control_returns_dict(engine, control):
    assert control["id"]
    assert control["name"] == "MFA Enforcement"
    assert control["domain"] == "identity"
    assert control["weight"] == 2.0
    assert control["control_status"] == "implemented"
    assert control["evidence_url"] == "https://example.com/evidence/mfa"
    assert control["org_id"] == "org1"


def test_register_control_missing_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.register_control("org1", {"domain": "identity"})


def test_register_control_invalid_domain_raises(engine):
    with pytest.raises(ValueError, match="domain"):
        engine.register_control("org1", {"name": "Test", "domain": "invalid_domain"})


def test_register_control_invalid_status_raises(engine):
    with pytest.raises(ValueError, match="control_status"):
        engine.register_control("org1", {"name": "Test", "control_status": "unknown"})


def test_register_control_all_valid_domains(engine):
    for domain in ("identity", "network", "endpoint", "cloud", "application", "data", "governance"):
        c = engine.register_control("org1", {"name": f"Ctrl-{domain}", "domain": domain})
        assert c["domain"] == domain


def test_register_control_all_valid_statuses(engine):
    for status in ("implemented", "partial", "not_implemented", "compensating"):
        c = engine.register_control("org1", {
            "name": f"Ctrl-{status}", "control_status": status
        })
        assert c["control_status"] == status


def test_register_control_default_weight(engine):
    c = engine.register_control("org1", {"name": "Default Weight Control"})
    assert c["weight"] == 1.0


def test_register_control_assigns_unique_ids(engine):
    c1 = engine.register_control("org1", {"name": "C1"})
    c2 = engine.register_control("org1", {"name": "C2"})
    assert c1["id"] != c2["id"]


# ===========================================================================
# 3. list_controls / get_control
# ===========================================================================

def test_list_controls_returns_all(engine, control):
    engine.register_control("org1", {"name": "Network Segmentation", "domain": "network"})
    results = engine.list_controls("org1")
    assert len(results) == 2


def test_list_controls_filter_by_domain(engine, control):
    engine.register_control("org1", {"name": "FW Rule", "domain": "network"})
    results = engine.list_controls("org1", domain="identity")
    assert all(c["domain"] == "identity" for c in results)
    assert len(results) == 1


def test_list_controls_filter_by_status(engine, control):
    engine.register_control("org1", {"name": "Partial Ctrl", "control_status": "partial"})
    implemented = engine.list_controls("org1", control_status="implemented")
    assert all(c["control_status"] == "implemented" for c in implemented)


def test_list_controls_org_isolation(engine, control):
    results = engine.list_controls("org2")
    assert results == []


def test_get_control_returns_correct(engine, control):
    result = engine.get_control("org1", control["id"])
    assert result["id"] == control["id"]
    assert result["name"] == "MFA Enforcement"


def test_get_control_wrong_org_returns_none(engine, control):
    result = engine.get_control("org2", control["id"])
    assert result is None


def test_get_control_nonexistent_returns_none(engine):
    result = engine.get_control("org1", "nonexistent-id")
    assert result is None


# ===========================================================================
# 4. update_control_status
# ===========================================================================

def test_update_control_status_success(engine, control):
    updated = engine.update_control_status(
        "org1", control["id"], "partial", "https://example.com/partial"
    )
    assert updated["control_status"] == "partial"
    assert updated["evidence_url"] == "https://example.com/partial"


def test_update_control_status_sets_last_assessed(engine, control):
    updated = engine.update_control_status("org1", control["id"], "compensating")
    assert updated["last_assessed"] is not None


def test_update_control_status_invalid_raises(engine, control):
    with pytest.raises(ValueError, match="control_status"):
        engine.update_control_status("org1", control["id"], "super_implemented")


def test_update_control_status_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.update_control_status("org1", "bad-id", "partial")


# ===========================================================================
# 5. calculate_posture_score
# ===========================================================================

def test_calculate_posture_score_all_implemented(engine):
    engine.register_control("org1", {"name": "C1", "weight": 1.0, "control_status": "implemented"})
    engine.register_control("org1", {"name": "C2", "weight": 1.0, "control_status": "implemented"})
    result = engine.calculate_posture_score("org1")
    assert result["score"] == 100.0
    assert result["score_level"] == "excellent"
    assert result["control_count"] == 2
    assert result["domain"] == "all"


def test_calculate_posture_score_all_not_implemented(engine):
    engine.register_control("org1", {"name": "C1", "control_status": "not_implemented"})
    result = engine.calculate_posture_score("org1")
    assert result["score"] == 0.0
    assert result["score_level"] == "poor"


def test_calculate_posture_score_partial(engine):
    # partial = 0.5 multiplier => score 50 => "fair" (>=40)
    engine.register_control("org1", {"name": "C1", "weight": 1.0, "control_status": "partial"})
    result = engine.calculate_posture_score("org1")
    assert result["score"] == 50.0
    assert result["score_level"] == "fair"


def test_calculate_posture_score_compensating(engine):
    # compensating = 0.75 multiplier
    engine.register_control("org1", {"name": "C1", "weight": 1.0, "control_status": "compensating"})
    result = engine.calculate_posture_score("org1")
    assert result["score"] == 75.0
    assert result["score_level"] == "good"


def test_calculate_posture_score_weighted_mix(engine):
    # implemented w=2 (2.0), partial w=1 (0.5) => actual=2.5, total=3 => 83.33
    engine.register_control("org1", {"name": "C1", "weight": 2.0, "control_status": "implemented"})
    engine.register_control("org1", {"name": "C2", "weight": 1.0, "control_status": "partial"})
    result = engine.calculate_posture_score("org1")
    assert abs(result["score"] - 83.33) < 0.1
    assert result["score_level"] == "excellent"


def test_calculate_posture_score_domain_filter(engine):
    engine.register_control("org1", {"name": "ID Ctrl", "domain": "identity", "control_status": "implemented"})
    engine.register_control("org1", {"name": "Net Ctrl", "domain": "network", "control_status": "not_implemented"})
    result = engine.calculate_posture_score("org1", domain="identity")
    assert result["score"] == 100.0
    assert result["domain"] == "identity"
    assert result["control_count"] == 1


def test_calculate_posture_score_empty_org(engine):
    result = engine.calculate_posture_score("org_empty")
    assert result["score"] == 0.0
    assert result["control_count"] == 0


def test_calculate_posture_score_persists_snapshot(engine, control):
    engine.calculate_posture_score("org1")
    history = engine.get_posture_history("org1")
    assert len(history) == 1
    assert history[0]["score"] is not None


# ===========================================================================
# 6. score_level thresholds
# ===========================================================================

def test_score_level_excellent(engine):
    # score 100 => excellent
    engine.register_control("org1", {"name": "C", "control_status": "implemented"})
    r = engine.calculate_posture_score("org1")
    assert r["score_level"] == "excellent"


def test_score_level_good(engine):
    # compensating = 75 => good
    engine.register_control("org1", {"name": "C", "control_status": "compensating"})
    r = engine.calculate_posture_score("org1")
    assert r["score_level"] == "good"


def test_score_level_poor(engine):
    # not_implemented = 0 => poor
    engine.register_control("org1", {"name": "C", "control_status": "not_implemented"})
    r = engine.calculate_posture_score("org1")
    assert r["score_level"] == "poor"


# ===========================================================================
# 7. get_posture_history
# ===========================================================================

def test_get_posture_history_empty(engine):
    assert engine.get_posture_history("org1") == []


def test_get_posture_history_multiple_snapshots(engine, control):
    engine.calculate_posture_score("org1")
    engine.calculate_posture_score("org1")
    engine.calculate_posture_score("org1")
    history = engine.get_posture_history("org1")
    assert len(history) == 3


def test_get_posture_history_limit(engine, control):
    for _ in range(5):
        engine.calculate_posture_score("org1")
    history = engine.get_posture_history("org1", limit=2)
    assert len(history) == 2


def test_get_posture_history_domain_filter(engine):
    engine.register_control("org1", {"name": "ID", "domain": "identity", "control_status": "implemented"})
    engine.calculate_posture_score("org1", domain="identity")
    engine.calculate_posture_score("org1")  # domain="all"
    history = engine.get_posture_history("org1", domain="identity")
    assert len(history) == 1
    assert history[0]["domain"] == "identity"


def test_get_posture_history_org_isolation(engine, control):
    engine.calculate_posture_score("org1")
    assert engine.get_posture_history("org2") == []


# ===========================================================================
# 8. get_posture_stats
# ===========================================================================

def test_get_posture_stats_empty(engine):
    stats = engine.get_posture_stats("org1")
    assert stats["overall_score"] == 0.0
    assert stats["total_controls"] == 0
    assert stats["implemented_count"] == 0
    assert stats["gaps_count"] == 0
    assert stats["by_domain"] == {}


def test_get_posture_stats_counts(engine):
    engine.register_control("org1", {"name": "C1", "domain": "identity", "control_status": "implemented"})
    engine.register_control("org1", {"name": "C2", "domain": "network", "control_status": "not_implemented"})
    engine.register_control("org1", {"name": "C3", "domain": "identity", "control_status": "partial"})
    stats = engine.get_posture_stats("org1")
    assert stats["total_controls"] == 3
    assert stats["implemented_count"] == 1
    assert stats["gaps_count"] == 1
    assert "identity" in stats["by_domain"]
    assert "network" in stats["by_domain"]


def test_get_posture_stats_by_domain_scores(engine):
    engine.register_control("org1", {"name": "C1", "domain": "cloud", "control_status": "implemented"})
    stats = engine.get_posture_stats("org1")
    assert stats["by_domain"]["cloud"] == 100.0


def test_get_posture_stats_org_isolation(engine, control):
    stats = engine.get_posture_stats("org2")
    assert stats["total_controls"] == 0
    assert stats["overall_score"] == 0.0
