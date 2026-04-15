"""Tests for SecurityMetricsAggregatorEngine — 30+ tests covering all major paths."""

from __future__ import annotations

import pytest


@pytest.fixture
def sma_engine(tmp_path):
    from core.security_metrics_aggregator_engine import SecurityMetricsAggregatorEngine
    return SecurityMetricsAggregatorEngine(db_dir=str(tmp_path))


ORG = "test-org-sma"
ORG2 = "other-org-sma"


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def test_register_source_basic(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "Splunk SIEM", "source_type": "siem"})
    assert src["id"]
    assert src["source_name"] == "Splunk SIEM"
    assert src["source_type"] == "siem"
    assert src["active"] is True
    assert src["metric_count"] == 0


def test_register_source_all_types(sma_engine):
    for st in ("siem", "edr", "sca", "dast", "dlp", "firewall", "iam",
               "vulnerability_scanner", "cloud_security", "custom"):
        src = sma_engine.register_source(ORG, {"source_name": f"Src-{st}", "source_type": st})
        assert src["source_type"] == st


def test_register_source_missing_name(sma_engine):
    with pytest.raises(ValueError, match="source_name"):
        sma_engine.register_source(ORG, {"source_type": "siem"})


def test_register_source_invalid_type(sma_engine):
    with pytest.raises(ValueError):
        sma_engine.register_source(ORG, {"source_name": "X", "source_type": "unknown"})


def test_register_source_inactive(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "Inactive Src", "active": False})
    assert src["active"] is False


def test_list_sources_empty(sma_engine):
    assert sma_engine.list_sources(ORG) == []


def test_list_sources_filter_by_type(sma_engine):
    sma_engine.register_source(ORG, {"source_name": "A", "source_type": "siem"})
    sma_engine.register_source(ORG, {"source_name": "B", "source_type": "edr"})
    results = sma_engine.list_sources(ORG, source_type="siem")
    assert len(results) == 1
    assert results[0]["source_name"] == "A"


def test_list_sources_filter_by_active(sma_engine):
    sma_engine.register_source(ORG, {"source_name": "Active", "active": True})
    sma_engine.register_source(ORG, {"source_name": "Inactive", "active": False})
    active = sma_engine.list_sources(ORG, active=True)
    assert len(active) == 1
    assert active[0]["source_name"] == "Active"


def test_list_sources_org_isolation(sma_engine):
    sma_engine.register_source(ORG, {"source_name": "Org1Src"})
    assert sma_engine.list_sources(ORG2) == []


def test_sync_source(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "SyncSrc"})
    updated = sma_engine.sync_source(ORG, src["id"], 50)
    assert updated["metric_count"] == 50
    assert updated["last_sync"] is not None


def test_sync_source_increments(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "IncrSrc"})
    sma_engine.sync_source(ORG, src["id"], 30)
    updated = sma_engine.sync_source(ORG, src["id"], 20)
    assert updated["metric_count"] == 50


def test_sync_source_not_found(sma_engine):
    with pytest.raises(KeyError):
        sma_engine.sync_source(ORG, "nonexistent-id", 10)


def test_sync_source_wrong_org(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "OrgSrc"})
    with pytest.raises(KeyError):
        sma_engine.sync_source(ORG2, src["id"], 10)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def test_record_metric_basic(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "MetricSrc"})
    m = sma_engine.record_metric(ORG, {
        "source_id": src["id"],
        "metric_name": "mean_time_to_detect",
        "metric_type": "gauge",
        "value": 42.5,
        "unit": "minutes",
        "category": "security",
    })
    assert m["id"]
    assert m["metric_name"] == "mean_time_to_detect"
    assert m["value"] == 42.5
    assert m["unit"] == "minutes"
    assert m["category"] == "security"


def test_record_metric_all_types(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "TypeSrc"})
    for mt in ("counter", "gauge", "histogram", "percentage", "score"):
        m = sma_engine.record_metric(ORG, {
            "source_id": src["id"],
            "metric_name": f"metric-{mt}",
            "metric_type": mt,
            "value": 1.0,
        })
        assert m["metric_type"] == mt


def test_record_metric_all_categories(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "CatSrc"})
    for cat in ("security", "compliance", "operational", "risk", "performance"):
        m = sma_engine.record_metric(ORG, {
            "source_id": src["id"],
            "metric_name": f"metric-{cat}",
            "category": cat,
            "value": 0.0,
        })
        assert m["category"] == cat


def test_record_metric_tags_roundtrip(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "TagSrc"})
    tags = {"env": "prod", "team": "soc", "priority": "high"}
    m = sma_engine.record_metric(ORG, {
        "source_id": src["id"],
        "metric_name": "tagged_metric",
        "value": 7.0,
        "tags": tags,
    })
    assert m["tags"] == tags


def test_record_metric_missing_source_id(sma_engine):
    with pytest.raises(ValueError, match="source_id"):
        sma_engine.record_metric(ORG, {"metric_name": "x", "value": 1.0})


def test_record_metric_missing_metric_name(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "NoNameSrc"})
    with pytest.raises(ValueError, match="metric_name"):
        sma_engine.record_metric(ORG, {"source_id": src["id"], "value": 1.0})


def test_record_metric_invalid_type(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "BadTypeSrc"})
    with pytest.raises(ValueError):
        sma_engine.record_metric(ORG, {
            "source_id": src["id"],
            "metric_name": "x",
            "metric_type": "unknown",
            "value": 1.0,
        })


def test_record_metric_invalid_category(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "BadCatSrc"})
    with pytest.raises(ValueError):
        sma_engine.record_metric(ORG, {
            "source_id": src["id"],
            "metric_name": "x",
            "category": "unknown",
            "value": 1.0,
        })


def test_list_metrics_filter_source(sma_engine):
    src1 = sma_engine.register_source(ORG, {"source_name": "Src1"})
    src2 = sma_engine.register_source(ORG, {"source_name": "Src2"})
    sma_engine.record_metric(ORG, {"source_id": src1["id"], "metric_name": "m1", "value": 1.0})
    sma_engine.record_metric(ORG, {"source_id": src2["id"], "metric_name": "m2", "value": 2.0})
    results = sma_engine.list_metrics(ORG, source_id=src1["id"])
    assert len(results) == 1
    assert results[0]["metric_name"] == "m1"


def test_list_metrics_filter_category(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "CatFilterSrc"})
    sma_engine.record_metric(ORG, {"source_id": src["id"], "metric_name": "sec-m", "value": 1.0, "category": "security"})
    sma_engine.record_metric(ORG, {"source_id": src["id"], "metric_name": "risk-m", "value": 2.0, "category": "risk"})
    results = sma_engine.list_metrics(ORG, category="security")
    assert len(results) == 1
    assert results[0]["metric_name"] == "sec-m"


def test_list_metrics_filter_metric_type(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "TypeFilterSrc"})
    sma_engine.record_metric(ORG, {"source_id": src["id"], "metric_name": "counter-m", "metric_type": "counter", "value": 5.0})
    sma_engine.record_metric(ORG, {"source_id": src["id"], "metric_name": "gauge-m", "metric_type": "gauge", "value": 10.0})
    results = sma_engine.list_metrics(ORG, metric_type="counter")
    assert len(results) == 1
    assert results[0]["metric_name"] == "counter-m"


def test_list_metrics_org_isolation(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "IsoSrc"})
    sma_engine.record_metric(ORG, {"source_id": src["id"], "metric_name": "iso-m", "value": 1.0})
    assert sma_engine.list_metrics(ORG2) == []


def test_get_latest_metric_returns_most_recent(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "LatestSrc"})
    sma_engine.record_metric(ORG, {
        "source_id": src["id"],
        "metric_name": "mttd",
        "value": 10.0,
        "collected_at": "2026-01-01T00:00:00+00:00",
    })
    sma_engine.record_metric(ORG, {
        "source_id": src["id"],
        "metric_name": "mttd",
        "value": 20.0,
        "collected_at": "2026-01-02T00:00:00+00:00",
    })
    result = sma_engine.get_latest_metric(ORG, "mttd")
    assert result is not None
    assert result["value"] == 20.0


def test_get_latest_metric_not_found(sma_engine):
    result = sma_engine.get_latest_metric(ORG, "nonexistent_metric")
    assert result is None


def test_get_latest_metric_org_isolation(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "IsoLatestSrc"})
    sma_engine.record_metric(ORG, {"source_id": src["id"], "metric_name": "iso-latest", "value": 5.0})
    assert sma_engine.get_latest_metric(ORG2, "iso-latest") is None


def test_get_latest_metric_tags_deserialized(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "TagLatestSrc"})
    tags = {"region": "us-east-1", "severity": "high"}
    sma_engine.record_metric(ORG, {
        "source_id": src["id"],
        "metric_name": "tagged-latest",
        "value": 3.0,
        "tags": tags,
    })
    result = sma_engine.get_latest_metric(ORG, "tagged-latest")
    assert result["tags"] == tags


# ---------------------------------------------------------------------------
# Aggregations
# ---------------------------------------------------------------------------

def test_create_aggregation_basic(sma_engine):
    agg = sma_engine.create_aggregation(ORG, {
        "aggregation_name": "MTTD Average",
        "aggregation_type": "avg",
        "metric_names": ["mttd", "mttr"],
        "time_window_hours": 24,
        "result_value": 35.0,
    })
    assert agg["id"]
    assert agg["aggregation_name"] == "MTTD Average"
    assert agg["aggregation_type"] == "avg"
    assert agg["metric_names"] == ["mttd", "mttr"]
    assert agg["result_value"] == 35.0


def test_create_aggregation_all_types(sma_engine):
    for at in ("sum", "avg", "min", "max", "count", "weighted_avg"):
        agg = sma_engine.create_aggregation(ORG, {
            "aggregation_name": f"Agg-{at}",
            "aggregation_type": at,
            "result_value": 1.0,
        })
        assert agg["aggregation_type"] == at


def test_create_aggregation_metric_names_roundtrip(sma_engine):
    names = ["metric_a", "metric_b", "metric_c"]
    agg = sma_engine.create_aggregation(ORG, {
        "aggregation_name": "Multi",
        "metric_names": names,
        "result_value": 0.0,
    })
    assert agg["metric_names"] == names


def test_create_aggregation_confidence_clamped(sma_engine):
    agg = sma_engine.create_aggregation(ORG, {
        "aggregation_name": "OverConfident",
        "result_value": 1.0,
        "confidence": 150.0,
    })
    assert agg["confidence"] == 100.0

    agg2 = sma_engine.create_aggregation(ORG, {
        "aggregation_name": "UnderConfident",
        "result_value": 1.0,
        "confidence": -5.0,
    })
    assert agg2["confidence"] == 0.0


def test_create_aggregation_missing_name(sma_engine):
    with pytest.raises(ValueError, match="aggregation_name"):
        sma_engine.create_aggregation(ORG, {"aggregation_type": "avg", "result_value": 1.0})


def test_create_aggregation_invalid_type(sma_engine):
    with pytest.raises(ValueError):
        sma_engine.create_aggregation(ORG, {
            "aggregation_name": "X",
            "aggregation_type": "median",
            "result_value": 1.0,
        })


def test_list_aggregations_filter_type(sma_engine):
    sma_engine.create_aggregation(ORG, {"aggregation_name": "SumAgg", "aggregation_type": "sum", "result_value": 1.0})
    sma_engine.create_aggregation(ORG, {"aggregation_name": "AvgAgg", "aggregation_type": "avg", "result_value": 2.0})
    results = sma_engine.list_aggregations(ORG, aggregation_type="sum")
    assert len(results) == 1
    assert results[0]["aggregation_name"] == "SumAgg"


def test_list_aggregations_org_isolation(sma_engine):
    sma_engine.create_aggregation(ORG, {"aggregation_name": "OrgAgg", "result_value": 1.0})
    assert sma_engine.list_aggregations(ORG2) == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_aggregator_stats_empty(sma_engine):
    stats = sma_engine.get_aggregator_stats(ORG)
    assert stats["total_sources"] == 0
    assert stats["active_sources"] == 0
    assert stats["total_metrics"] == 0
    assert stats["total_aggregations"] == 0
    assert stats["by_source_type"] == {}
    assert stats["by_category"] == {}
    assert stats["by_metric_type"] == {}


def test_get_aggregator_stats_populated(sma_engine):
    src1 = sma_engine.register_source(ORG, {"source_name": "SIEM1", "source_type": "siem", "active": True})
    src2 = sma_engine.register_source(ORG, {"source_name": "EDR1", "source_type": "edr", "active": False})
    sma_engine.record_metric(ORG, {"source_id": src1["id"], "metric_name": "m1", "value": 1.0, "category": "security", "metric_type": "gauge"})
    sma_engine.record_metric(ORG, {"source_id": src2["id"], "metric_name": "m2", "value": 2.0, "category": "risk", "metric_type": "counter"})
    sma_engine.create_aggregation(ORG, {"aggregation_name": "Agg1", "result_value": 1.0})

    stats = sma_engine.get_aggregator_stats(ORG)
    assert stats["total_sources"] == 2
    assert stats["active_sources"] == 1
    assert stats["total_metrics"] == 2
    assert stats["total_aggregations"] == 1
    assert stats["by_source_type"]["siem"] == 1
    assert stats["by_source_type"]["edr"] == 1
    assert stats["by_category"]["security"] == 1
    assert stats["by_category"]["risk"] == 1
    assert stats["by_metric_type"]["gauge"] == 1
    assert stats["by_metric_type"]["counter"] == 1


def test_get_aggregator_stats_org_isolation(sma_engine):
    src = sma_engine.register_source(ORG, {"source_name": "IsoSrc2"})
    sma_engine.record_metric(ORG, {"source_id": src["id"], "metric_name": "iso-stat", "value": 1.0})
    stats = sma_engine.get_aggregator_stats(ORG2)
    assert stats["total_sources"] == 0
    assert stats["total_metrics"] == 0
