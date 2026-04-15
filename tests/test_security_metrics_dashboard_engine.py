"""Tests for SecurityMetricsDashboardEngine — 30+ tests covering all methods."""

from __future__ import annotations

import pytest

from core.security_metrics_dashboard_engine import SecurityMetricsDashboardEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_smd.db")


@pytest.fixture
def engine(db_path):
    return SecurityMetricsDashboardEngine(db_path=db_path)


ORG = "org-smd-test"
ORG2 = "org-smd-other"


# ---------------------------------------------------------------------------
# create_dashboard
# ---------------------------------------------------------------------------

def test_create_dashboard_minimal(engine):
    d = engine.create_dashboard(ORG, {"name": "Ops Dashboard", "dashboard_type": "operational"})
    assert d["name"] == "Ops Dashboard"
    assert d["dashboard_type"] == "operational"
    assert d["status"] == "active"
    assert d["refresh_interval"] == 60
    assert d["widgets"] == []
    assert "id" in d
    assert "created_at" in d


def test_create_dashboard_all_types(engine):
    for dtype in ("executive", "operational", "tactical", "compliance", "threat"):
        d = engine.create_dashboard(ORG, {"name": f"Dashboard {dtype}", "dashboard_type": dtype})
        assert d["dashboard_type"] == dtype


def test_create_dashboard_custom_refresh(engine):
    d = engine.create_dashboard(ORG, {"name": "Fast", "dashboard_type": "tactical", "refresh_interval": 5})
    assert d["refresh_interval"] == 5


def test_create_dashboard_with_widgets_json(engine):
    widgets = [{"type": "chart", "metric": "cpu"}]
    d = engine.create_dashboard(ORG, {"name": "W", "dashboard_type": "operational", "widgets": widgets})
    assert d["widgets"] == widgets


def test_create_dashboard_missing_name(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.create_dashboard(ORG, {"dashboard_type": "operational"})


def test_create_dashboard_invalid_type(engine):
    with pytest.raises(ValueError, match="Invalid dashboard_type"):
        engine.create_dashboard(ORG, {"name": "X", "dashboard_type": "bogus"})


def test_create_dashboard_invalid_refresh_interval(engine):
    with pytest.raises(ValueError, match="refresh_interval must be an integer"):
        engine.create_dashboard(ORG, {"name": "X", "dashboard_type": "operational", "refresh_interval": "fast"})


# ---------------------------------------------------------------------------
# list_dashboards
# ---------------------------------------------------------------------------

def test_list_dashboards_empty(engine):
    assert engine.list_dashboards(ORG) == []


def test_list_dashboards_returns_all(engine):
    engine.create_dashboard(ORG, {"name": "A", "dashboard_type": "executive"})
    engine.create_dashboard(ORG, {"name": "B", "dashboard_type": "tactical"})
    result = engine.list_dashboards(ORG)
    assert len(result) == 2


def test_list_dashboards_filter_by_type(engine):
    engine.create_dashboard(ORG, {"name": "Exec", "dashboard_type": "executive"})
    engine.create_dashboard(ORG, {"name": "Ops", "dashboard_type": "operational"})
    result = engine.list_dashboards(ORG, dashboard_type="executive")
    assert len(result) == 1
    assert result[0]["name"] == "Exec"


def test_list_dashboards_org_isolation(engine):
    engine.create_dashboard(ORG, {"name": "Mine", "dashboard_type": "threat"})
    assert engine.list_dashboards(ORG2) == []


# ---------------------------------------------------------------------------
# get_dashboard
# ---------------------------------------------------------------------------

def test_get_dashboard_found(engine):
    d = engine.create_dashboard(ORG, {"name": "Test", "dashboard_type": "compliance"})
    got = engine.get_dashboard(ORG, d["id"])
    assert got["id"] == d["id"]
    assert got["name"] == "Test"


def test_get_dashboard_not_found(engine):
    assert engine.get_dashboard(ORG, "no-such-id") is None


def test_get_dashboard_org_isolation(engine):
    d = engine.create_dashboard(ORG, {"name": "Test", "dashboard_type": "operational"})
    assert engine.get_dashboard(ORG2, d["id"]) is None


# ---------------------------------------------------------------------------
# add_widget / list_widgets
# ---------------------------------------------------------------------------

def test_add_widget_success(engine):
    d = engine.create_dashboard(ORG, {"name": "D", "dashboard_type": "operational"})
    w = engine.add_widget(ORG, d["id"], {
        "widget_type": "chart",
        "metric_name": "cpu_usage",
        "data_source": "prometheus",
    })
    assert w is not None
    assert w["widget_type"] == "chart"
    assert w["metric_name"] == "cpu_usage"
    assert w["position_x"] == 0
    assert w["position_y"] == 0
    assert "id" in w


def test_add_widget_all_types(engine):
    d = engine.create_dashboard(ORG, {"name": "D", "dashboard_type": "operational"})
    for wtype in ("chart", "table", "gauge", "counter", "heatmap", "timeline"):
        w = engine.add_widget(ORG, d["id"], {
            "widget_type": wtype,
            "metric_name": "m",
            "data_source": "src",
        })
        assert w["widget_type"] == wtype


def test_add_widget_with_position(engine):
    d = engine.create_dashboard(ORG, {"name": "D", "dashboard_type": "operational"})
    w = engine.add_widget(ORG, d["id"], {
        "widget_type": "gauge",
        "metric_name": "latency",
        "data_source": "api",
        "position_x": 2,
        "position_y": 3,
        "config": {"unit": "ms"},
    })
    assert w["position_x"] == 2
    assert w["position_y"] == 3
    assert w["config"] == {"unit": "ms"}


def test_add_widget_invalid_type(engine):
    d = engine.create_dashboard(ORG, {"name": "D", "dashboard_type": "operational"})
    with pytest.raises(ValueError, match="Invalid widget_type"):
        engine.add_widget(ORG, d["id"], {
            "widget_type": "pie",
            "metric_name": "m",
            "data_source": "s",
        })


def test_add_widget_missing_metric_name(engine):
    d = engine.create_dashboard(ORG, {"name": "D", "dashboard_type": "operational"})
    with pytest.raises(ValueError, match="metric_name is required"):
        engine.add_widget(ORG, d["id"], {"widget_type": "chart", "data_source": "s"})


def test_add_widget_missing_data_source(engine):
    d = engine.create_dashboard(ORG, {"name": "D", "dashboard_type": "operational"})
    with pytest.raises(ValueError, match="data_source is required"):
        engine.add_widget(ORG, d["id"], {"widget_type": "chart", "metric_name": "m"})


def test_add_widget_dashboard_not_found(engine):
    result = engine.add_widget(ORG, "no-such-id", {
        "widget_type": "chart",
        "metric_name": "m",
        "data_source": "s",
    })
    assert result is None


def test_list_widgets(engine):
    d = engine.create_dashboard(ORG, {"name": "D", "dashboard_type": "operational"})
    engine.add_widget(ORG, d["id"], {"widget_type": "chart", "metric_name": "a", "data_source": "s"})
    engine.add_widget(ORG, d["id"], {"widget_type": "gauge", "metric_name": "b", "data_source": "s"})
    widgets = engine.list_widgets(ORG, d["id"])
    assert len(widgets) == 2


def test_list_widgets_empty(engine):
    d = engine.create_dashboard(ORG, {"name": "D", "dashboard_type": "operational"})
    assert engine.list_widgets(ORG, d["id"]) == []


# ---------------------------------------------------------------------------
# record_metric_snapshot / get_metric_history
# ---------------------------------------------------------------------------

def test_record_metric_snapshot(engine):
    d = engine.create_dashboard(ORG, {"name": "D", "dashboard_type": "operational"})
    s = engine.record_metric_snapshot(ORG, {
        "dashboard_id": d["id"],
        "metric_name": "cpu",
        "metric_value": 72.5,
        "metric_unit": "%",
    })
    assert s["metric_value"] == 72.5
    assert s["metric_unit"] == "%"
    assert s["metric_name"] == "cpu"
    assert "id" in s
    assert "snapshot_at" in s


def test_record_metric_snapshot_with_tags(engine):
    d = engine.create_dashboard(ORG, {"name": "D", "dashboard_type": "operational"})
    s = engine.record_metric_snapshot(ORG, {
        "dashboard_id": d["id"],
        "metric_name": "errors",
        "metric_value": 5.0,
        "tags": {"host": "server1", "region": "us-east"},
    })
    assert s["tags"] == {"host": "server1", "region": "us-east"}


def test_record_metric_snapshot_missing_dashboard_id(engine):
    with pytest.raises(ValueError, match="dashboard_id is required"):
        engine.record_metric_snapshot(ORG, {"metric_name": "cpu", "metric_value": 1.0})


def test_record_metric_snapshot_missing_metric_name(engine):
    with pytest.raises(ValueError, match="metric_name is required"):
        engine.record_metric_snapshot(ORG, {"dashboard_id": "x", "metric_value": 1.0})


def test_record_metric_snapshot_missing_value(engine):
    with pytest.raises(ValueError, match="metric_value is required"):
        engine.record_metric_snapshot(ORG, {"dashboard_id": "x", "metric_name": "cpu"})


def test_get_metric_history_ordered_desc(engine):
    d = engine.create_dashboard(ORG, {"name": "D", "dashboard_type": "operational"})
    for v in (10.0, 20.0, 30.0):
        engine.record_metric_snapshot(ORG, {
            "dashboard_id": d["id"],
            "metric_name": "cpu",
            "metric_value": v,
        })
    history = engine.get_metric_history(ORG, d["id"], "cpu")
    assert len(history) == 3
    # Most recent first
    assert history[0]["metric_value"] == 30.0
    assert history[-1]["metric_value"] == 10.0


def test_get_metric_history_limit(engine):
    d = engine.create_dashboard(ORG, {"name": "D", "dashboard_type": "operational"})
    for i in range(10):
        engine.record_metric_snapshot(ORG, {
            "dashboard_id": d["id"],
            "metric_name": "mem",
            "metric_value": float(i),
        })
    history = engine.get_metric_history(ORG, d["id"], "mem", limit=5)
    assert len(history) == 5


def test_get_metric_history_empty(engine):
    assert engine.get_metric_history(ORG, "no-id", "cpu") == []


# ---------------------------------------------------------------------------
# get_dashboard_stats
# ---------------------------------------------------------------------------

def test_get_dashboard_stats_empty(engine):
    stats = engine.get_dashboard_stats(ORG)
    assert stats["total_dashboards"] == 0
    assert stats["total_widgets"] == 0
    assert stats["total_snapshots_24h"] == 0
    assert stats["by_type"] == {}
    assert stats["active_dashboards"] == 0


def test_get_dashboard_stats_counts(engine):
    d1 = engine.create_dashboard(ORG, {"name": "E", "dashboard_type": "executive"})
    d2 = engine.create_dashboard(ORG, {"name": "O", "dashboard_type": "operational"})
    engine.add_widget(ORG, d1["id"], {"widget_type": "chart", "metric_name": "m", "data_source": "s"})
    engine.add_widget(ORG, d1["id"], {"widget_type": "gauge", "metric_name": "n", "data_source": "s"})
    engine.record_metric_snapshot(ORG, {"dashboard_id": d1["id"], "metric_name": "cpu", "metric_value": 50.0})
    engine.record_metric_snapshot(ORG, {"dashboard_id": d2["id"], "metric_name": "mem", "metric_value": 75.0})

    stats = engine.get_dashboard_stats(ORG)
    assert stats["total_dashboards"] == 2
    assert stats["active_dashboards"] == 2
    assert stats["total_widgets"] == 2
    assert stats["total_snapshots_24h"] == 2
    assert stats["by_type"]["executive"] == 1
    assert stats["by_type"]["operational"] == 1


def test_get_dashboard_stats_org_isolation(engine):
    engine.create_dashboard(ORG, {"name": "X", "dashboard_type": "threat"})
    stats = engine.get_dashboard_stats(ORG2)
    assert stats["total_dashboards"] == 0
