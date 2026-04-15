"""Tests for SecurityHealthScorecardEngine.

Covers domain upsert, status computation, snapshot taking, grade assignment,
target setting, scorecard retrieval, history, grade trend, and multi-tenancy.

Total: 35+ tests.
"""

from __future__ import annotations

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.security_health_scorecard_engine import SecurityHealthScorecardEngine


@pytest.fixture
def engine(tmp_path):
    return SecurityHealthScorecardEngine(db_path=str(tmp_path / "test.db"))


# ===========================================================================
# 1. Initialization
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "scorecard.db")
    SecurityHealthScorecardEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "scorecard.db")
    SecurityHealthScorecardEngine(db_path=db)
    SecurityHealthScorecardEngine(db_path=db)  # second init must not error


# ===========================================================================
# 2. upsert_domain — status computation
# ===========================================================================

def test_upsert_domain_returns_dict(engine):
    d = engine.upsert_domain("org1", "Vuln Mgmt", "vulnerability", 0.5, 80.0, 100.0)
    assert isinstance(d, dict)
    assert d["domain_name"] == "Vuln Mgmt"


def test_upsert_domain_status_green(engine):
    d = engine.upsert_domain("org1", "Cloud", "cloud", 1.0, 90.0, 100.0)
    assert d["status"] == "green"  # 90/100 = 0.9 >= 0.8


def test_upsert_domain_status_amber(engine):
    d = engine.upsert_domain("org1", "Network", "network", 1.0, 70.0, 100.0)
    assert d["status"] == "amber"  # 0.6 <= 0.7 < 0.8


def test_upsert_domain_status_red(engine):
    d = engine.upsert_domain("org1", "Identity", "identity", 1.0, 50.0, 100.0)
    assert d["status"] == "red"  # 0.5 < 0.6


def test_upsert_domain_status_exactly_80pct_is_green(engine):
    d = engine.upsert_domain("org1", "Data", "data", 1.0, 80.0, 100.0)
    assert d["status"] == "green"


def test_upsert_domain_status_exactly_60pct_is_amber(engine):
    d = engine.upsert_domain("org1", "Physical", "physical", 1.0, 60.0, 100.0)
    assert d["status"] == "amber"


def test_upsert_domain_weight_clamped_above_1(engine):
    d = engine.upsert_domain("org1", "Endpoint", "endpoint", 2.5, 80.0, 100.0)
    assert d["weight"] == 1.0


def test_upsert_domain_weight_clamped_below_0(engine):
    d = engine.upsert_domain("org1", "Compliance", "compliance", -0.5, 80.0, 100.0)
    assert d["weight"] == 0.0


def test_upsert_domain_invalid_category_raises(engine):
    with pytest.raises(ValueError, match="domain_category"):
        engine.upsert_domain("org1", "X", "invalid_cat", 0.5, 80.0, 100.0)


def test_upsert_domain_updates_existing(engine):
    engine.upsert_domain("org1", "Vuln Mgmt", "vulnerability", 0.5, 50.0, 100.0)
    d = engine.upsert_domain("org1", "Vuln Mgmt", "vulnerability", 0.8, 90.0, 100.0)
    # Should update, not create duplicate
    domains = engine.get_domains("org1")
    assert len([x for x in domains if x["domain_name"] == "Vuln Mgmt"]) == 1
    assert d["score"] == 90.0
    assert d["weight"] == 0.8


def test_upsert_domain_org_isolation(engine):
    engine.upsert_domain("org1", "Cloud", "cloud", 0.5, 80.0, 100.0)
    engine.upsert_domain("org2", "Cloud", "cloud", 0.5, 40.0, 100.0)
    d1 = engine.get_domains("org1")[0]
    d2 = engine.get_domains("org2")[0]
    assert d1["status"] == "green"
    assert d2["status"] == "red"


# ===========================================================================
# 3. take_snapshot — grade assignment
# ===========================================================================

def test_take_snapshot_empty_org(engine):
    snap = engine.take_snapshot("org_empty")
    assert snap["overall_score"] == 0.0
    assert snap["grade"] == "F"
    assert snap["improvement_areas"] == []


def test_take_snapshot_grade_A(engine):
    engine.upsert_domain("org1", "D1", "cloud", 1.0, 95.0, 100.0)
    snap = engine.take_snapshot("org1")
    assert snap["grade"] == "A"
    assert snap["overall_score"] >= 90.0


def test_take_snapshot_grade_B(engine):
    engine.upsert_domain("org1", "D1", "cloud", 1.0, 82.0, 100.0)
    snap = engine.take_snapshot("org1")
    assert snap["grade"] == "B"


def test_take_snapshot_grade_C(engine):
    engine.upsert_domain("org1", "D1", "cloud", 1.0, 72.0, 100.0)
    snap = engine.take_snapshot("org1")
    assert snap["grade"] == "C"


def test_take_snapshot_grade_D(engine):
    engine.upsert_domain("org1", "D1", "cloud", 1.0, 62.0, 100.0)
    snap = engine.take_snapshot("org1")
    assert snap["grade"] == "D"


def test_take_snapshot_grade_F(engine):
    engine.upsert_domain("org1", "D1", "cloud", 1.0, 55.0, 100.0)
    snap = engine.take_snapshot("org1")
    assert snap["grade"] == "F"


def test_take_snapshot_improvement_areas_are_red_domains(engine):
    engine.upsert_domain("org1", "Good", "cloud", 0.5, 90.0, 100.0)
    engine.upsert_domain("org1", "Bad", "network", 0.5, 40.0, 100.0)
    snap = engine.take_snapshot("org1")
    assert "Bad" in snap["improvement_areas"]
    assert "Good" not in snap["improvement_areas"]


def test_take_snapshot_domain_scores_in_result(engine):
    engine.upsert_domain("org1", "D1", "cloud", 1.0, 75.0, 100.0)
    snap = engine.take_snapshot("org1")
    assert "D1" in snap["domain_scores"]
    assert snap["domain_scores"]["D1"] == 75.0


def test_take_snapshot_weighted_avg(engine):
    # weight 0.8 at 100%, weight 0.2 at 0% → overall = 80.0
    engine.upsert_domain("org1", "Heavy", "cloud", 0.8, 100.0, 100.0)
    engine.upsert_domain("org1", "Light", "network", 0.2, 0.0, 100.0)
    snap = engine.take_snapshot("org1")
    assert abs(snap["overall_score"] - 80.0) < 0.5


def test_take_snapshot_date_format(engine):
    engine.upsert_domain("org1", "D1", "cloud", 1.0, 80.0, 100.0)
    snap = engine.take_snapshot("org1")
    # snapshot_date should be YYYY-MM-DD
    parts = snap["snapshot_date"].split("-")
    assert len(parts) == 3 and len(parts[0]) == 4


# ===========================================================================
# 4. set_target
# ===========================================================================

def test_set_target_creates_record(engine):
    t = engine.set_target("org1", "Cloud", 90.0, 70.0, "2026-12-31", "alice")
    assert t["target_score"] == 90.0
    assert t["owner"] == "alice"
    assert t["domain_name"] == "Cloud"


def test_set_target_upserts(engine):
    engine.set_target("org1", "Cloud", 90.0, 70.0, "2026-12-31", "alice")
    t = engine.set_target("org1", "Cloud", 95.0, 75.0, "2027-01-01", "bob")
    # Only one target per org+domain
    with engine._conn() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM scorecard_targets WHERE org_id='org1' AND domain_name='Cloud'"
        ).fetchone()[0]
    assert count == 1
    assert t["target_score"] == 95.0
    assert t["owner"] == "bob"


# ===========================================================================
# 5. get_current_scorecard
# ===========================================================================

def test_get_current_scorecard_no_snapshot(engine):
    engine.upsert_domain("org1", "D1", "cloud", 1.0, 80.0, 100.0)
    result = engine.get_current_scorecard("org1")
    assert result["snapshot"] is None
    assert len(result["domains"]) == 1
    assert result["targets"] == []


def test_get_current_scorecard_with_snapshot(engine):
    engine.upsert_domain("org1", "D1", "cloud", 1.0, 85.0, 100.0)
    engine.take_snapshot("org1")
    result = engine.get_current_scorecard("org1")
    assert result["snapshot"] is not None
    assert result["snapshot"]["grade"] in {"A", "B", "C", "D", "F"}
    assert len(result["domains"]) == 1


def test_get_current_scorecard_includes_targets(engine):
    engine.upsert_domain("org1", "D1", "cloud", 1.0, 80.0, 100.0)
    engine.set_target("org1", "D1", 95.0, 80.0, "2026-12-31", "ciso")
    result = engine.get_current_scorecard("org1")
    assert len(result["targets"]) == 1
    assert result["targets"][0]["owner"] == "ciso"


# ===========================================================================
# 6. get_domains — filter by status
# ===========================================================================

def test_get_domains_no_filter(engine):
    engine.upsert_domain("org1", "A", "cloud", 1.0, 90.0, 100.0)
    engine.upsert_domain("org1", "B", "network", 1.0, 40.0, 100.0)
    assert len(engine.get_domains("org1")) == 2


def test_get_domains_filter_green(engine):
    engine.upsert_domain("org1", "A", "cloud", 1.0, 90.0, 100.0)
    engine.upsert_domain("org1", "B", "network", 1.0, 40.0, 100.0)
    greens = engine.get_domains("org1", status="green")
    assert all(d["status"] == "green" for d in greens)
    assert len(greens) == 1


def test_get_domains_filter_red(engine):
    engine.upsert_domain("org1", "A", "cloud", 1.0, 90.0, 100.0)
    engine.upsert_domain("org1", "B", "network", 1.0, 40.0, 100.0)
    reds = engine.get_domains("org1", status="red")
    assert all(d["status"] == "red" for d in reds)


# ===========================================================================
# 7. get_snapshot_history and get_grade_trend
# ===========================================================================

def test_get_snapshot_history_returns_list(engine):
    engine.upsert_domain("org1", "D1", "cloud", 1.0, 80.0, 100.0)
    engine.take_snapshot("org1")
    history = engine.get_snapshot_history("org1", days=90)
    assert len(history) >= 1


def test_get_snapshot_history_domain_scores_decoded(engine):
    engine.upsert_domain("org1", "D1", "cloud", 1.0, 80.0, 100.0)
    engine.take_snapshot("org1")
    history = engine.get_snapshot_history("org1")
    assert isinstance(history[0]["domain_scores"], dict)
    assert isinstance(history[0]["improvement_areas"], list)


def test_get_grade_trend_chronological(engine):
    engine.upsert_domain("org1", "D1", "cloud", 1.0, 80.0, 100.0)
    engine.take_snapshot("org1")
    engine.take_snapshot("org1")
    trend = engine.get_grade_trend("org1")
    assert len(trend) >= 2
    assert "grade" in trend[0]
    assert "overall_score" in trend[0]
    assert "snapshot_date" in trend[0]


def test_get_grade_trend_org_isolation(engine):
    engine.upsert_domain("org1", "D1", "cloud", 1.0, 80.0, 100.0)
    engine.upsert_domain("org2", "D1", "cloud", 1.0, 90.0, 100.0)
    engine.take_snapshot("org1")
    engine.take_snapshot("org2")
    t1 = engine.get_grade_trend("org1")
    t2 = engine.get_grade_trend("org2")
    assert len(t1) == 1
    assert len(t2) == 1
