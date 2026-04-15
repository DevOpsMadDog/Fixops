"""Tests for KPITrackingEngine — 30+ tests covering all methods."""

from __future__ import annotations

import pytest

from core.kpi_tracking_engine import KPITrackingEngine, _compute_achievement


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_kpi_tracking.db")


@pytest.fixture
def engine(db_path):
    return KPITrackingEngine(db_path=db_path)


ORG = "org-kpi-test"
ORG2 = "org-kpi-other"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_kpi(engine, org=ORG, **kwargs):
    defaults = {
        "name": "Test KPI",
        "kpi_category": "security",
        "target_value": 100.0,
    }
    defaults.update(kwargs)
    return engine.create_kpi(org, defaults)


# ---------------------------------------------------------------------------
# _compute_achievement (unit tests)
# ---------------------------------------------------------------------------

def test_compute_achievement_higher_better_on_target():
    pct = _compute_achievement(100.0, 100.0, "higher_better")
    assert pct == 100.0


def test_compute_achievement_higher_better_over_target():
    pct = _compute_achievement(150.0, 100.0, "higher_better")
    assert pct == 150.0


def test_compute_achievement_higher_better_clamped():
    pct = _compute_achievement(300.0, 100.0, "higher_better")
    assert pct == 200.0


def test_compute_achievement_lower_better_on_target():
    pct = _compute_achievement(50.0, 50.0, "lower_better")
    assert pct == 100.0


def test_compute_achievement_lower_better_better_than_target():
    pct = _compute_achievement(25.0, 50.0, "lower_better")
    assert pct == 200.0


def test_compute_achievement_lower_better_zero_value():
    pct = _compute_achievement(0.0, 50.0, "lower_better")
    assert pct == 0.0


def test_compute_achievement_zero_target():
    pct = _compute_achievement(50.0, 0.0, "higher_better")
    assert pct == 0.0


# ---------------------------------------------------------------------------
# create_kpi
# ---------------------------------------------------------------------------

def test_create_kpi_minimal(engine):
    k = _make_kpi(engine)
    assert k["name"] == "Test KPI"
    assert k["kpi_category"] == "security"
    assert k["status"] == "active"
    assert k["direction"] == "higher_better"
    assert k["frequency"] == "monthly"
    assert k["unit"] == ""
    assert "id" in k
    assert "created_at" in k


def test_create_kpi_all_categories(engine):
    for cat in ("security", "compliance", "operational", "financial", "risk"):
        k = _make_kpi(engine, name=f"KPI {cat}", kpi_category=cat)
        assert k["kpi_category"] == cat


def test_create_kpi_all_directions(engine):
    for direction in ("higher_better", "lower_better"):
        k = _make_kpi(engine, name=f"KPI {direction}", direction=direction)
        assert k["direction"] == direction


def test_create_kpi_all_frequencies(engine):
    for freq in ("daily", "weekly", "monthly", "quarterly"):
        k = _make_kpi(engine, name=f"KPI {freq}", frequency=freq)
        assert k["frequency"] == freq


def test_create_kpi_with_unit(engine):
    k = _make_kpi(engine, unit="%", target_value=95.0)
    assert k["unit"] == "%"
    assert k["target_value"] == 95.0


def test_create_kpi_missing_name(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.create_kpi(ORG, {"kpi_category": "security", "target_value": 100.0})


def test_create_kpi_missing_target(engine):
    with pytest.raises(ValueError, match="target_value is required"):
        engine.create_kpi(ORG, {"name": "X", "kpi_category": "security"})


def test_create_kpi_invalid_category(engine):
    with pytest.raises(ValueError, match="Invalid kpi_category"):
        engine.create_kpi(ORG, {"name": "X", "kpi_category": "bogus", "target_value": 1.0})


def test_create_kpi_invalid_direction(engine):
    with pytest.raises(ValueError, match="Invalid direction"):
        engine.create_kpi(ORG, {"name": "X", "kpi_category": "security", "target_value": 1.0, "direction": "sideways"})


def test_create_kpi_invalid_frequency(engine):
    with pytest.raises(ValueError, match="Invalid frequency"):
        engine.create_kpi(ORG, {"name": "X", "kpi_category": "security", "target_value": 1.0, "frequency": "hourly"})


# ---------------------------------------------------------------------------
# list_kpis / get_kpi
# ---------------------------------------------------------------------------

def test_list_kpis_empty(engine):
    assert engine.list_kpis(ORG) == []


def test_list_kpis_returns_all(engine):
    _make_kpi(engine, name="A")
    _make_kpi(engine, name="B", kpi_category="compliance")
    result = engine.list_kpis(ORG)
    assert len(result) == 2


def test_list_kpis_filter_category(engine):
    _make_kpi(engine, name="Sec", kpi_category="security")
    _make_kpi(engine, name="Comp", kpi_category="compliance")
    result = engine.list_kpis(ORG, kpi_category="security")
    assert len(result) == 1
    assert result[0]["name"] == "Sec"


def test_list_kpis_filter_status(engine):
    _make_kpi(engine, name="Active")
    result = engine.list_kpis(ORG, status="active")
    assert len(result) == 1


def test_list_kpis_org_isolation(engine):
    _make_kpi(engine)
    assert engine.list_kpis(ORG2) == []


def test_get_kpi_found(engine):
    k = _make_kpi(engine)
    got = engine.get_kpi(ORG, k["id"])
    assert got["id"] == k["id"]


def test_get_kpi_not_found(engine):
    assert engine.get_kpi(ORG, "no-such-id") is None


def test_get_kpi_org_isolation(engine):
    k = _make_kpi(engine)
    assert engine.get_kpi(ORG2, k["id"]) is None


# ---------------------------------------------------------------------------
# record_measurement — achievement & status
# ---------------------------------------------------------------------------

def test_record_measurement_on_target_higher_better(engine):
    k = _make_kpi(engine, direction="higher_better", target_value=100.0)
    m = engine.record_measurement(ORG, k["id"], 100.0)
    assert m["achievement_pct"] == 100.0
    assert m["status"] == "on_target"


def test_record_measurement_near_target_higher_better(engine):
    k = _make_kpi(engine, direction="higher_better", target_value=100.0)
    m = engine.record_measurement(ORG, k["id"], 85.0)
    assert m["achievement_pct"] == 85.0
    assert m["status"] == "near_target"


def test_record_measurement_off_target_higher_better(engine):
    k = _make_kpi(engine, direction="higher_better", target_value=100.0)
    m = engine.record_measurement(ORG, k["id"], 50.0)
    assert m["achievement_pct"] == 50.0
    assert m["status"] == "off_target"


def test_record_measurement_on_target_lower_better(engine):
    k = _make_kpi(engine, direction="lower_better", target_value=50.0)
    m = engine.record_measurement(ORG, k["id"], 50.0)
    assert m["achievement_pct"] == 100.0
    assert m["status"] == "on_target"


def test_record_measurement_near_target_lower_better(engine):
    # value=55, target=50 → 50/55*100 ≈ 90.9 → near_target
    k = _make_kpi(engine, direction="lower_better", target_value=50.0)
    m = engine.record_measurement(ORG, k["id"], 55.0)
    assert m["achievement_pct"] == pytest.approx(90.909, rel=1e-3)
    assert m["status"] == "near_target"


def test_record_measurement_off_target_lower_better(engine):
    # value=200, target=50 → 50/200*100 = 25 → off_target
    k = _make_kpi(engine, direction="lower_better", target_value=50.0)
    m = engine.record_measurement(ORG, k["id"], 200.0)
    assert m["achievement_pct"] == 25.0
    assert m["status"] == "off_target"


def test_record_measurement_achievement_clamped_at_200(engine):
    k = _make_kpi(engine, direction="higher_better", target_value=100.0)
    m = engine.record_measurement(ORG, k["id"], 500.0)
    assert m["achievement_pct"] == 200.0
    assert m["status"] == "on_target"


def test_record_measurement_kpi_not_found(engine):
    result = engine.record_measurement(ORG, "no-such-id", 50.0)
    assert result is None


def test_record_measurement_has_notes(engine):
    k = _make_kpi(engine)
    m = engine.record_measurement(ORG, k["id"], 90.0, notes="Good progress")
    assert m["notes"] == "Good progress"


# ---------------------------------------------------------------------------
# list_measurements
# ---------------------------------------------------------------------------

def test_list_measurements_ordered_desc(engine):
    k = _make_kpi(engine)
    for v in (60.0, 70.0, 80.0):
        engine.record_measurement(ORG, k["id"], v)
    result = engine.list_measurements(ORG, k["id"])
    assert len(result) == 3
    assert result[0]["value"] == 80.0
    assert result[-1]["value"] == 60.0


def test_list_measurements_limit(engine):
    k = _make_kpi(engine)
    for i in range(10):
        engine.record_measurement(ORG, k["id"], float(i * 10))
    result = engine.list_measurements(ORG, k["id"], limit=5)
    assert len(result) == 5


def test_list_measurements_empty(engine):
    k = _make_kpi(engine)
    assert engine.list_measurements(ORG, k["id"]) == []


# ---------------------------------------------------------------------------
# get_kpi_performance
# ---------------------------------------------------------------------------

def test_get_kpi_performance_no_measurements(engine):
    k = _make_kpi(engine)
    perf = engine.get_kpi_performance(ORG, k["id"])
    assert perf is not None
    assert perf["last_measurement"] is None
    assert perf["avg_achievement_pct"] is None
    assert perf["trend"] is None


def test_get_kpi_performance_single_measurement(engine):
    k = _make_kpi(engine, target_value=100.0)
    engine.record_measurement(ORG, k["id"], 90.0)
    perf = engine.get_kpi_performance(ORG, k["id"])
    assert perf["last_measurement"]["value"] == 90.0
    assert perf["avg_achievement_pct"] == 90.0
    assert perf["trend"] == "stable"


def test_get_kpi_performance_trend_improving(engine):
    k = _make_kpi(engine, target_value=100.0, direction="higher_better")
    engine.record_measurement(ORG, k["id"], 70.0)  # prev: 70%
    engine.record_measurement(ORG, k["id"], 90.0)  # latest: 90% → improving
    perf = engine.get_kpi_performance(ORG, k["id"])
    assert perf["trend"] == "improving"


def test_get_kpi_performance_trend_declining(engine):
    k = _make_kpi(engine, target_value=100.0, direction="higher_better")
    engine.record_measurement(ORG, k["id"], 90.0)  # prev: 90%
    engine.record_measurement(ORG, k["id"], 70.0)  # latest: 70% → declining
    perf = engine.get_kpi_performance(ORG, k["id"])
    assert perf["trend"] == "declining"


def test_get_kpi_performance_trend_stable(engine):
    k = _make_kpi(engine, target_value=100.0, direction="higher_better")
    engine.record_measurement(ORG, k["id"], 90.0)
    engine.record_measurement(ORG, k["id"], 90.5)  # <1 pct diff → stable
    perf = engine.get_kpi_performance(ORG, k["id"])
    assert perf["trend"] == "stable"


def test_get_kpi_performance_not_found(engine):
    assert engine.get_kpi_performance(ORG, "no-such-id") is None


# ---------------------------------------------------------------------------
# get_kpi_stats
# ---------------------------------------------------------------------------

def test_get_kpi_stats_empty(engine):
    stats = engine.get_kpi_stats(ORG)
    assert stats["total_kpis"] == 0
    assert stats["active_kpis"] == 0
    assert stats["on_target_kpis"] == 0
    assert stats["off_target_kpis"] == 0
    assert stats["avg_achievement_pct"] is None
    assert stats["by_category"] == {}


def test_get_kpi_stats_counts(engine):
    k1 = _make_kpi(engine, name="K1", kpi_category="security", target_value=100.0)
    k2 = _make_kpi(engine, name="K2", kpi_category="compliance", target_value=100.0)
    engine.record_measurement(ORG, k1["id"], 100.0)   # on_target: 100%
    engine.record_measurement(ORG, k2["id"], 50.0)    # off_target: 50%

    stats = engine.get_kpi_stats(ORG)
    assert stats["total_kpis"] == 2
    assert stats["active_kpis"] == 2
    assert stats["on_target_kpis"] == 1
    assert stats["off_target_kpis"] == 1
    assert stats["avg_achievement_pct"] == pytest.approx(75.0, rel=1e-3)
    assert stats["by_category"]["security"] == 1
    assert stats["by_category"]["compliance"] == 1


def test_get_kpi_stats_org_isolation(engine):
    _make_kpi(engine, name="K1")
    stats = engine.get_kpi_stats(ORG2)
    assert stats["total_kpis"] == 0


def test_get_kpi_stats_uses_latest_measurement(engine):
    k = _make_kpi(engine, target_value=100.0)
    engine.record_measurement(ORG, k["id"], 50.0)   # off_target
    engine.record_measurement(ORG, k["id"], 100.0)  # on_target (latest)
    stats = engine.get_kpi_stats(ORG)
    assert stats["on_target_kpis"] == 1
    assert stats["off_target_kpis"] == 0
