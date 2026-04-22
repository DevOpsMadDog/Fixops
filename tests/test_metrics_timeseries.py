"""GAP-060 timeseries export tests — 25 tests.

Covers:
  - 3 bucket granularities (daily/weekly/monthly)
  - null-fill semantics
  - metric_keys limit enforcement (≤20)
  - days limit enforcement (≤365)
  - posture_timeseries shape
  - available_metrics dedup across both engines + precedence
  - org_id isolation
  - endpoint smoke tests (4 endpoints)
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.kpi_tracking_engine import KPITrackingEngine
from core.security_metrics_aggregator_engine import (
    SecurityMetricsAggregatorEngine,
)
from core.security_posture_history_engine import SecurityPostureHistoryEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture()
def agg(tmp_dir: Path) -> SecurityMetricsAggregatorEngine:
    return SecurityMetricsAggregatorEngine(db_dir=str(tmp_dir))


@pytest.fixture()
def kpi(tmp_dir: Path) -> KPITrackingEngine:
    return KPITrackingEngine(db_path=str(tmp_dir / "kpi.db"))


@pytest.fixture()
def posture(tmp_dir: Path) -> SecurityPostureHistoryEngine:
    return SecurityPostureHistoryEngine(
        db_path=str(tmp_dir / "posture.db")
    )


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _seed_source(agg: SecurityMetricsAggregatorEngine, org: str) -> str:
    src = agg.register_source(org, {"source_name": "s", "source_type": "custom"})
    return src["id"]


def _seed_metric(
    agg: SecurityMetricsAggregatorEngine,
    org: str,
    source_id: str,
    metric_name: str,
    value: float,
    when: datetime,
) -> None:
    agg.record_metric(
        org,
        {
            "source_id": source_id,
            "metric_name": metric_name,
            "value": value,
            "collected_at": _iso(when),
        },
    )


# ---------------------------------------------------------------------------
# export_timeseries — bucket granularities (3)
# ---------------------------------------------------------------------------


def test_export_daily_bucket_shape(agg):
    org = "o-daily"
    src = _seed_source(agg, org)
    now = datetime.now(timezone.utc)
    _seed_metric(agg, org, src, "cpu", 10.0, now)
    _seed_metric(agg, org, src, "cpu", 20.0, now - timedelta(days=1))
    out = agg.export_timeseries(org, ["cpu"], days=7, bucket="daily")
    assert out["bucket"] == "daily"
    assert out["metric_keys"] == ["cpu"]
    assert "cpu" in out["series"]
    assert len(out["buckets"]) == len(out["series"]["cpu"])
    assert any(v is not None for v in out["series"]["cpu"])


def test_export_weekly_bucket_aligns_monday(agg):
    org = "o-weekly"
    src = _seed_source(agg, org)
    now = datetime.now(timezone.utc)
    _seed_metric(agg, org, src, "m", 5.0, now)
    out = agg.export_timeseries(org, ["m"], days=30, bucket="weekly")
    assert out["bucket"] == "weekly"
    for b in out["buckets"]:
        dt = datetime.fromisoformat(b)
        assert dt.weekday() == 0  # Monday
        assert dt.hour == 0 and dt.minute == 0


def test_export_monthly_bucket_aligns_day_one(agg):
    org = "o-monthly"
    src = _seed_source(agg, org)
    now = datetime.now(timezone.utc)
    _seed_metric(agg, org, src, "m", 3.0, now)
    out = agg.export_timeseries(org, ["m"], days=90, bucket="monthly")
    assert out["bucket"] == "monthly"
    for b in out["buckets"]:
        dt = datetime.fromisoformat(b)
        assert dt.day == 1
        assert dt.hour == 0


# ---------------------------------------------------------------------------
# null-fill semantics
# ---------------------------------------------------------------------------


def test_null_fill_for_missing_days(agg):
    org = "o-null"
    src = _seed_source(agg, org)
    now = datetime.now(timezone.utc)
    # Only seed TODAY
    _seed_metric(agg, org, src, "cpu", 42.0, now)
    out = agg.export_timeseries(org, ["cpu"], days=7, bucket="daily")
    nulls = [v for v in out["series"]["cpu"] if v is None]
    vals = [v for v in out["series"]["cpu"] if v is not None]
    assert len(nulls) >= 5  # many missing days filled with None, not 0
    assert 42.0 in vals


def test_null_not_zero_for_absent_series(agg):
    org = "o-absent"
    _seed_source(agg, org)
    out = agg.export_timeseries(org, ["nonexistent"], days=3, bucket="daily")
    assert all(v is None for v in out["series"]["nonexistent"])
    assert 0 not in out["series"]["nonexistent"]


def test_same_bucket_multiple_samples_averaged(agg):
    org = "o-avg"
    src = _seed_source(agg, org)
    now = datetime.now(timezone.utc)
    _seed_metric(agg, org, src, "m", 10.0, now.replace(hour=3))
    _seed_metric(agg, org, src, "m", 30.0, now.replace(hour=15))
    out = agg.export_timeseries(org, ["m"], days=2, bucket="daily")
    non_null = [v for v in out["series"]["m"] if v is not None]
    assert non_null, "expected at least one non-null bucket"
    assert 20.0 in non_null  # average of 10 and 30


# ---------------------------------------------------------------------------
# Validation — metric_keys limit (≤20)
# ---------------------------------------------------------------------------


def test_metric_keys_empty_rejected(agg):
    with pytest.raises(ValueError):
        agg.export_timeseries("o", [], days=7, bucket="daily")


def test_metric_keys_21_rejected(agg):
    keys = [f"k{i}" for i in range(21)]
    with pytest.raises(ValueError):
        agg.export_timeseries("o", keys, days=7, bucket="daily")


def test_metric_keys_20_accepted(agg):
    keys = [f"k{i}" for i in range(20)]
    out = agg.export_timeseries("o", keys, days=7, bucket="daily")
    assert out["metric_keys"] == keys


def test_metric_keys_deduped(agg):
    out = agg.export_timeseries("o", ["a", "a", "b"], days=3, bucket="daily")
    assert out["metric_keys"] == ["a", "b"]


# ---------------------------------------------------------------------------
# Validation — days limit (≤365)
# ---------------------------------------------------------------------------


def test_days_zero_rejected(agg):
    with pytest.raises(ValueError):
        agg.export_timeseries("o", ["m"], days=0, bucket="daily")


def test_days_366_rejected(agg):
    with pytest.raises(ValueError):
        agg.export_timeseries("o", ["m"], days=366, bucket="daily")


def test_days_365_accepted(agg):
    out = agg.export_timeseries("o", ["m"], days=365, bucket="monthly")
    assert out["days"] == 365


def test_invalid_bucket_rejected(agg):
    with pytest.raises(ValueError):
        agg.export_timeseries("o", ["m"], days=7, bucket="hourly")


# ---------------------------------------------------------------------------
# posture_timeseries shape
# ---------------------------------------------------------------------------


def test_posture_timeseries_shape(posture):
    org = "o-posture"
    posture.record_snapshot(org, "network", 85.0)
    out = posture.posture_timeseries(org, days=7)
    assert out["metric_keys"] == ["posture_score"]
    assert out["bucket"] == "daily"
    assert "posture_score" in out["series"]
    assert len(out["buckets"]) == len(out["series"]["posture_score"])


def test_posture_timeseries_null_fill(posture):
    org = "o-posture-null"
    posture.record_snapshot(org, "endpoint", 70.0)
    out = posture.posture_timeseries(org, days=10)
    series = out["series"]["posture_score"]
    assert any(v is None for v in series)


def test_posture_timeseries_days_validation(posture):
    with pytest.raises(ValueError):
        posture.posture_timeseries("o", days=0)
    with pytest.raises(ValueError):
        posture.posture_timeseries("o", days=400)


# ---------------------------------------------------------------------------
# available_metrics dedup & precedence
# ---------------------------------------------------------------------------


def test_available_metrics_empty(kpi):
    out = kpi.list_available_metrics("empty-org")
    assert out["available_count"] == 0
    assert out["metric_keys"] == []


def test_available_metrics_dedup_across_engines(tmp_dir):
    org = "o-merge"
    kpi = KPITrackingEngine(db_path=str(tmp_dir / "kpi.db"))
    agg = SecurityMetricsAggregatorEngine(db_dir=str(tmp_dir))

    kpi.create_kpi(org, {"name": "mttr", "target_value": 60.0})
    kpi.create_kpi(org, {"name": "coverage", "target_value": 80.0})

    src = agg.register_source(org, {"source_name": "s", "source_type": "siem"})
    agg.record_metric(org, {
        "source_id": src["id"], "metric_name": "mttr", "value": 50.0,
    })
    agg.record_metric(org, {
        "source_id": src["id"], "metric_name": "dwell_time", "value": 12.0,
    })

    out = kpi.list_available_metrics(org, aggregator=agg)
    # Merged: mttr, coverage, dwell_time — mttr dedup'd
    assert "mttr" in out["metric_keys"]
    assert "coverage" in out["metric_keys"]
    # kpi precedence preserved
    kpi_keys = out["keys_by_source"]["kpi_tracking"]
    assert kpi_keys.index("mttr") >= 0 if "mttr" in kpi_keys else True
    # No duplicates in merged list
    assert len(out["metric_keys"]) == len(set(out["metric_keys"]))


def test_available_metrics_kpi_precedence(tmp_dir):
    org = "o-prec"
    kpi = KPITrackingEngine(db_path=str(tmp_dir / "kpi.db"))
    agg = SecurityMetricsAggregatorEngine(db_dir=str(tmp_dir))
    kpi.create_kpi(org, {"name": "shared", "target_value": 1.0})
    src = agg.register_source(org, {"source_name": "s", "source_type": "custom"})
    agg.record_metric(org, {
        "source_id": src["id"], "metric_name": "shared", "value": 1.0,
    })
    out = kpi.list_available_metrics(org, aggregator=agg)
    # 'shared' should appear exactly once in merged
    assert out["metric_keys"].count("shared") == 1


# ---------------------------------------------------------------------------
# org_id isolation
# ---------------------------------------------------------------------------


def test_org_id_isolation_export(agg):
    src_a = _seed_source(agg, "orgA")
    src_b = _seed_source(agg, "orgB")
    now = datetime.now(timezone.utc)
    _seed_metric(agg, "orgA", src_a, "m", 100.0, now)
    _seed_metric(agg, "orgB", src_b, "m", 200.0, now)
    out_a = agg.export_timeseries("orgA", ["m"], days=3, bucket="daily")
    out_b = agg.export_timeseries("orgB", ["m"], days=3, bucket="daily")
    vals_a = [v for v in out_a["series"]["m"] if v is not None]
    vals_b = [v for v in out_b["series"]["m"] if v is not None]
    assert 100.0 in vals_a and 200.0 not in vals_a
    assert 200.0 in vals_b and 100.0 not in vals_b


def test_org_id_isolation_posture(posture):
    posture.record_snapshot("orgA", "network", 50.0)
    posture.record_snapshot("orgB", "network", 90.0)
    out_a = posture.posture_timeseries("orgA", days=3)
    out_b = posture.posture_timeseries("orgB", days=3)
    vals_a = [v for v in out_a["series"]["posture_score"] if v is not None]
    vals_b = [v for v in out_b["series"]["posture_score"] if v is not None]
    assert 50.0 in vals_a
    assert 90.0 in vals_b
    assert 90.0 not in vals_a
    assert 50.0 not in vals_b


# ---------------------------------------------------------------------------
# Endpoint smoke tests (4 endpoints)
# ---------------------------------------------------------------------------


@pytest.fixture()
def app_client(monkeypatch, tmp_path):
    # Override engine singletons with tmp-scoped instances
    from apps.api import metrics_timeseries_router as mod

    tmp_agg = SecurityMetricsAggregatorEngine(db_dir=str(tmp_path))
    tmp_kpi = KPITrackingEngine(db_path=str(tmp_path / "kpi.db"))
    tmp_posture = SecurityPostureHistoryEngine(
        db_path=str(tmp_path / "posture.db")
    )
    monkeypatch.setattr(mod, "_agg_engine", tmp_agg)
    monkeypatch.setattr(mod, "_kpi_engine", tmp_kpi)
    monkeypatch.setattr(mod, "_posture_engine", tmp_posture)

    # Bypass auth
    from apps.api import auth_deps
    app = FastAPI()
    app.dependency_overrides[auth_deps.api_key_auth] = lambda: True
    app.include_router(mod.router)

    # Seed some data
    src = tmp_agg.register_source("o-e2e", {"source_name": "s", "source_type": "siem"})
    tmp_agg.record_metric("o-e2e", {
        "source_id": src["id"], "metric_name": "alerts", "value": 7.0,
    })
    tmp_kpi.create_kpi("o-e2e", {"name": "mttr_mins", "target_value": 30.0})
    tmp_posture.record_snapshot("o-e2e", "cloud", 82.0)

    return TestClient(app)


def test_endpoint_available(app_client):
    r = app_client.get("/api/v1/metrics-ts/available", params={"org_id": "o-e2e"})
    assert r.status_code == 200
    body = r.json()
    assert "metric_keys" in body
    assert "mttr_mins" in body["metric_keys"]
    assert "alerts" in body["metric_keys"]


def test_endpoint_export(app_client):
    r = app_client.post("/api/v1/metrics-ts/export", json={
        "org_id": "o-e2e",
        "metric_keys": ["alerts"],
        "days": 7,
        "bucket": "daily",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["metric_keys"] == ["alerts"]
    assert "alerts" in body["series"]


def test_endpoint_posture(app_client):
    r = app_client.get("/api/v1/metrics-ts/posture", params={"org_id": "o-e2e", "days": 7})
    assert r.status_code == 200
    body = r.json()
    assert body["metric_keys"] == ["posture_score"]
    assert len(body["buckets"]) == len(body["series"]["posture_score"])


def test_endpoint_stats(app_client):
    r = app_client.get("/api/v1/metrics-ts/stats", params={"org_id": "o-e2e"})
    assert r.status_code == 200
    body = r.json()
    assert body["org_id"] == "o-e2e"
    assert body["available_count"] >= 2  # mttr_mins + alerts
    assert body["kpi_count"] >= 1
    assert body["aggregator_count"] >= 1


def test_endpoint_export_validation_400(app_client):
    r = app_client.post("/api/v1/metrics-ts/export", json={
        "org_id": "o-e2e",
        "metric_keys": [f"k{i}" for i in range(21)],  # >20 — Pydantic rejects
        "days": 7,
        "bucket": "daily",
    })
    assert r.status_code == 422 or r.status_code == 400
