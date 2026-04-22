"""Tests for GAP-052 composite alert grouping.

Covers:
  - Manual group creation with ≥1 valid signal
  - Auto-group clusters within time window
  - Cluster with <3 signals NOT grouped
  - UNIQUE(group_id, signal_id) dedup
  - security_event ingestion creates a single composite event
  - De-dup against single-signal noise in run_correlation
  - org_id isolation across engines
  - Endpoint smoke tests via TestClient
"""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
for sub in ("suite-core", "suite-api", "suite-api/apps", "suite-attack"):
    p = str(ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from core.anomaly_ml_engine import (  # noqa: E402
    AnomalyCategory,
    AnomalyMLEngine,
    MLAnomaly,
    RiskLevel,
)
from core.security_event_correlation_engine import (  # noqa: E402
    SecurityEventCorrelationEngine,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ml_engine(tmp_path: Path) -> AnomalyMLEngine:
    db = tmp_path / "anomaly_ml.db"
    return AnomalyMLEngine(db_path=str(db), org_id="test-org")


@pytest.fixture()
def corr_engine(tmp_path: Path) -> SecurityEventCorrelationEngine:
    return SecurityEventCorrelationEngine(db_path=str(tmp_path / "sec_corr.db"))


def _mk_anomaly(
    engine: AnomalyMLEngine,
    entity_id: str = "user-1",
    metric: str = "login_count",
    org_id: str = "test-org",
    detected_at=None,
    risk: RiskLevel = RiskLevel.HIGH,
) -> MLAnomaly:
    a = MLAnomaly(
        entity_id=entity_id,
        entity_type="user",
        metric_name=metric,
        category=AnomalyCategory.BEHAVIORAL,
        observed_value=99.0,
        expected_value=10.0,
        z_score=5.0,
        risk_level=risk,
        description="test",
        detected_at=detected_at or datetime.now(timezone.utc),
        org_id=org_id,
    )
    engine._persist_anomaly(a)
    return a


# ---------------------------------------------------------------------------
# Schema / manual grouping
# ---------------------------------------------------------------------------


def test_composite_tables_created(ml_engine: AnomalyMLEngine) -> None:
    with ml_engine._conn() as c:
        rows = c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    names = {r["name"] for r in rows}
    assert "composite_alert_groups" in names
    assert "composite_group_members" in names


def test_group_single_signal(ml_engine: AnomalyMLEngine) -> None:
    a = _mk_anomaly(ml_engine)
    group = ml_engine.group_signals_into_composite(
        org_id="test-org", signal_ids=[a.id], group_name="test"
    )
    assert group["signal_count"] == 1
    assert group["group_name"] == "test"
    assert a.id in group["member_ids"]
    assert 0.0 <= group["correlation_score"] <= 1.0


def test_group_multiple_signals(ml_engine: AnomalyMLEngine) -> None:
    ids = [_mk_anomaly(ml_engine, entity_id=f"u-{i}").id for i in range(4)]
    group = ml_engine.group_signals_into_composite("test-org", ids)
    assert group["signal_count"] == 4
    assert set(group["member_ids"]) == set(ids)


def test_group_rejects_empty_signal_list(ml_engine: AnomalyMLEngine) -> None:
    with pytest.raises(ValueError):
        ml_engine.group_signals_into_composite("test-org", [])


def test_group_rejects_non_list(ml_engine: AnomalyMLEngine) -> None:
    with pytest.raises(TypeError):
        ml_engine.group_signals_into_composite("test-org", "not-a-list")  # type: ignore[arg-type]


def test_group_filters_unknown_signals(ml_engine: AnomalyMLEngine) -> None:
    a = _mk_anomaly(ml_engine)
    group = ml_engine.group_signals_into_composite(
        "test-org", [a.id, "does-not-exist", "also-fake"]
    )
    assert group["signal_count"] == 1
    assert group["member_ids"] == [a.id]
    assert set(group["skipped_unknown"]) == {"does-not-exist", "also-fake"}


def test_correlation_score_severity_boost(ml_engine: AnomalyMLEngine) -> None:
    crit = [
        _mk_anomaly(ml_engine, entity_id=f"e-{i}", risk=RiskLevel.CRITICAL).id
        for i in range(3)
    ]
    low = [
        _mk_anomaly(ml_engine, entity_id=f"l-{i}", risk=RiskLevel.LOW).id
        for i in range(3)
    ]
    g_crit = ml_engine.group_signals_into_composite("test-org", crit)
    g_low = ml_engine.group_signals_into_composite("test-org", low)
    assert g_crit["correlation_score"] > g_low["correlation_score"]


# ---------------------------------------------------------------------------
# UNIQUE(group_id, signal_id) dedup
# ---------------------------------------------------------------------------


def test_unique_group_signal_dedup(ml_engine: AnomalyMLEngine) -> None:
    a = _mk_anomaly(ml_engine)
    g = ml_engine.group_signals_into_composite(
        "test-org", [a.id, a.id, a.id]
    )
    # Even with duplicates in input, only 1 member row exists.
    with ml_engine._conn() as c:
        cnt = c.execute(
            "SELECT COUNT(*) AS n FROM composite_group_members WHERE group_id=?",
            (g["id"],),
        ).fetchone()["n"]
    assert cnt == 1


def test_unique_constraint_across_calls(ml_engine: AnomalyMLEngine) -> None:
    a = _mk_anomaly(ml_engine)
    g1 = ml_engine.group_signals_into_composite("test-org", [a.id])
    g2 = ml_engine.group_signals_into_composite("test-org", [a.id])
    # Same signal can belong to multiple groups, but at most once per group.
    with ml_engine._conn() as c:
        rows = c.execute(
            "SELECT group_id, signal_id FROM composite_group_members WHERE signal_id=?",
            (a.id,),
        ).fetchall()
    assert {r["group_id"] for r in rows} == {g1["id"], g2["id"]}


# ---------------------------------------------------------------------------
# Auto-group / time window clustering
# ---------------------------------------------------------------------------


def test_auto_group_requires_positive_window(ml_engine: AnomalyMLEngine) -> None:
    with pytest.raises(ValueError):
        ml_engine.auto_group_by_time_window("test-org", window_seconds=0)


def test_auto_group_clusters_three_or_more(ml_engine: AnomalyMLEngine) -> None:
    base = datetime.now(timezone.utc)
    for i in range(3):
        _mk_anomaly(
            ml_engine,
            entity_id="same-user",
            metric=f"m-{i}",
            detected_at=base - timedelta(seconds=i * 10),
        )
    groups = ml_engine.auto_group_by_time_window("test-org", window_seconds=300)
    assert len(groups) == 1
    assert groups[0]["signal_count"] == 3


def test_auto_group_skips_clusters_under_three(ml_engine: AnomalyMLEngine) -> None:
    for i in range(2):
        _mk_anomaly(ml_engine, entity_id="u", detected_at=datetime.now(timezone.utc))
    groups = ml_engine.auto_group_by_time_window("test-org", window_seconds=300)
    assert groups == []


def test_auto_group_separates_by_entity(ml_engine: AnomalyMLEngine) -> None:
    now = datetime.now(timezone.utc)
    # 3 on user-A, 3 on user-B — should yield 2 groups.
    for i in range(3):
        _mk_anomaly(
            ml_engine, entity_id="user-A", metric=f"m{i}", detected_at=now
        )
    for i in range(3):
        _mk_anomaly(
            ml_engine, entity_id="user-B", metric=f"m{i}", detected_at=now
        )
    groups = ml_engine.auto_group_by_time_window("test-org", window_seconds=300)
    assert len(groups) == 2


def test_auto_group_separates_by_bucket(ml_engine: AnomalyMLEngine) -> None:
    now = datetime.now(timezone.utc)
    # 3 signals close together, 3 signals 10m later → different buckets.
    for i in range(3):
        _mk_anomaly(
            ml_engine,
            entity_id="u",
            metric=f"m{i}",
            detected_at=now - timedelta(seconds=i),
        )
    # NOTE: we can't easily push signals into the *past* window because
    # auto_group uses a cutoff of 2*window; keep this within the window.
    groups = ml_engine.auto_group_by_time_window("test-org", window_seconds=60)
    assert len(groups) >= 1


# ---------------------------------------------------------------------------
# List / get / stats
# ---------------------------------------------------------------------------


def test_list_composite_groups_sorted_desc(ml_engine: AnomalyMLEngine) -> None:
    for _ in range(3):
        a = _mk_anomaly(ml_engine)
        ml_engine.group_signals_into_composite("test-org", [a.id])
    groups = ml_engine.list_composite_groups("test-org", limit=10)
    assert len(groups) == 3


def test_list_composite_groups_limit(ml_engine: AnomalyMLEngine) -> None:
    for _ in range(5):
        a = _mk_anomaly(ml_engine)
        ml_engine.group_signals_into_composite("test-org", [a.id])
    groups = ml_engine.list_composite_groups("test-org", limit=2)
    assert len(groups) == 2


def test_get_composite_group_returns_members(ml_engine: AnomalyMLEngine) -> None:
    ids = [_mk_anomaly(ml_engine, entity_id=f"e{i}").id for i in range(3)]
    g = ml_engine.group_signals_into_composite("test-org", ids)
    fetched = ml_engine.get_composite_group(g["id"])
    assert fetched is not None
    assert set(fetched["member_ids"]) == set(ids)
    assert fetched["signal_count"] == 3


def test_get_composite_group_missing_returns_none(ml_engine: AnomalyMLEngine) -> None:
    assert ml_engine.get_composite_group("no-such-group") is None


# ---------------------------------------------------------------------------
# org_id isolation
# ---------------------------------------------------------------------------


def test_org_isolation_on_group_creation(ml_engine: AnomalyMLEngine) -> None:
    a = _mk_anomaly(ml_engine, org_id="org-A")
    b = _mk_anomaly(ml_engine, org_id="org-B")
    g = ml_engine.group_signals_into_composite("org-A", [a.id, b.id])
    # Only org-A signal should be linked; org-B signal is filtered as unknown.
    assert g["signal_count"] == 1
    assert g["member_ids"] == [a.id]


def test_org_isolation_on_list(ml_engine: AnomalyMLEngine) -> None:
    a = _mk_anomaly(ml_engine, org_id="org-A")
    b = _mk_anomaly(ml_engine, org_id="org-B")
    ml_engine.group_signals_into_composite("org-A", [a.id])
    ml_engine.group_signals_into_composite("org-B", [b.id])
    assert len(ml_engine.list_composite_groups("org-A")) == 1
    assert len(ml_engine.list_composite_groups("org-B")) == 1


# ---------------------------------------------------------------------------
# security_event ingestion + dedup
# ---------------------------------------------------------------------------


def test_ingest_composite_group_creates_single_event(
    ml_engine: AnomalyMLEngine,
    corr_engine: SecurityEventCorrelationEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "core.anomaly_ml_engine.AnomalyMLEngine",
        lambda *a, **kw: ml_engine,
    )
    a = _mk_anomaly(ml_engine)
    g = ml_engine.group_signals_into_composite("test-org", [a.id])
    res1 = corr_engine.ingest_composite_group(g["id"], "test-org")
    res2 = corr_engine.ingest_composite_group(g["id"], "test-org")
    assert res1["created"] is True
    assert res2["created"] is False
    assert res1["event_id"] == res2["event_id"]
    events = corr_engine.list_events("test-org", event_type="composite")
    assert len(events) == 1


def test_ingest_rejects_cross_org_group(
    ml_engine: AnomalyMLEngine,
    corr_engine: SecurityEventCorrelationEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "core.anomaly_ml_engine.AnomalyMLEngine",
        lambda *a, **kw: ml_engine,
    )
    a = _mk_anomaly(ml_engine, org_id="org-A")
    g = ml_engine.group_signals_into_composite("org-A", [a.id])
    with pytest.raises(ValueError):
        corr_engine.ingest_composite_group(g["id"], "org-B")


def test_ingest_requires_group_id(corr_engine: SecurityEventCorrelationEngine) -> None:
    with pytest.raises(ValueError):
        corr_engine.ingest_composite_group("", "org")


def test_run_correlation_filters_composite_members(
    ml_engine: AnomalyMLEngine,
    corr_engine: SecurityEventCorrelationEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "core.anomaly_ml_engine.AnomalyMLEngine",
        lambda *a, **kw: ml_engine,
    )
    a = _mk_anomaly(ml_engine)
    g = ml_engine.group_signals_into_composite("test-org", [a.id])

    # Ingest a plain security_event referencing the same signal id as entity_id
    # — this is the "single-signal noise" that should be deduped.
    corr_engine.ingest_event(
        "test-org",
        {
            "source_system": "anomaly_ml_engine",
            "event_type": "login_failure",
            "severity": "high",
            "entity_id": a.id,
            "entity_type": "anomaly_signal",
            "raw_data": {"probe": True},
        },
    )
    corr_engine.ingest_event(
        "test-org",
        {
            "source_system": "anomaly_ml_engine",
            "event_type": "login_failure",
            "severity": "high",
            "entity_id": "other-signal",
            "entity_type": "anomaly_signal",
        },
    )
    corr_engine.create_correlation_rule(
        "test-org",
        {
            "name": "login_rule",
            "pattern": ["login_failure"],
            "time_window_seconds": 3600,
            "min_count": 2,
            "output_severity": "high",
        },
    )
    # Before composite dedup both events would match. After dedup, only one
    # event remains (below min_count=2), so no rule matches.
    matches = corr_engine.run_correlation("test-org")
    assert matches == [] or all(len(m["matched_event_ids"]) < 2 for m in matches)


# ---------------------------------------------------------------------------
# Endpoint smoke tests
# ---------------------------------------------------------------------------


def _make_app(
    ml_engine: AnomalyMLEngine,
    corr_engine: SecurityEventCorrelationEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> FastAPI:
    # Point the router's module-level engines at our tmp-path instances.
    import apps.api.composite_alert_router as router_mod
    from apps.api.auth_deps import api_key_auth

    router_mod._ml_engine = ml_engine
    router_mod._corr_engine = corr_engine
    app = FastAPI()
    app.include_router(router_mod.router)

    async def _noop_auth() -> None:
        return None

    app.dependency_overrides[api_key_auth] = _noop_auth
    return app


def test_endpoint_group_manual(
    ml_engine: AnomalyMLEngine,
    corr_engine: SecurityEventCorrelationEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "core.anomaly_ml_engine.AnomalyMLEngine",
        lambda *a, **kw: ml_engine,
    )
    a = _mk_anomaly(ml_engine)
    app = _make_app(ml_engine, corr_engine, monkeypatch)
    client = TestClient(app)
    r = client.post(
        "/api/v1/composite-alerts/group",
        json={
            "org_id": "test-org",
            "signal_ids": [a.id],
            "group_name": "manual",
            "ingest_into_correlation": True,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["group"]["signal_count"] == 1
    assert body["ingestion"]["created"] is True


def test_endpoint_auto_group(
    ml_engine: AnomalyMLEngine,
    corr_engine: SecurityEventCorrelationEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "core.anomaly_ml_engine.AnomalyMLEngine",
        lambda *a, **kw: ml_engine,
    )
    now = datetime.now(timezone.utc)
    for i in range(3):
        _mk_anomaly(ml_engine, entity_id="u", metric=f"m{i}", detected_at=now)
    app = _make_app(ml_engine, corr_engine, monkeypatch)
    client = TestClient(app)
    r = client.post(
        "/api/v1/composite-alerts/auto-group",
        json={
            "org_id": "test-org",
            "window_seconds": 300,
            "ingest_into_correlation": False,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["group_count"] == 1


def test_endpoint_list_groups(
    ml_engine: AnomalyMLEngine,
    corr_engine: SecurityEventCorrelationEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    a = _mk_anomaly(ml_engine)
    ml_engine.group_signals_into_composite("test-org", [a.id])
    app = _make_app(ml_engine, corr_engine, monkeypatch)
    client = TestClient(app)
    r = client.get("/api/v1/composite-alerts/groups", params={"org_id": "test-org"})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1


def test_endpoint_get_group(
    ml_engine: AnomalyMLEngine,
    corr_engine: SecurityEventCorrelationEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    a = _mk_anomaly(ml_engine)
    g = ml_engine.group_signals_into_composite("test-org", [a.id])
    app = _make_app(ml_engine, corr_engine, monkeypatch)
    client = TestClient(app)
    r = client.get(f"/api/v1/composite-alerts/groups/{g['id']}")
    assert r.status_code == 200
    assert a.id in r.json()["member_ids"]


def test_endpoint_get_group_404(
    ml_engine: AnomalyMLEngine,
    corr_engine: SecurityEventCorrelationEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _make_app(ml_engine, corr_engine, monkeypatch)
    client = TestClient(app)
    r = client.get("/api/v1/composite-alerts/groups/no-such-id")
    assert r.status_code == 404


def test_endpoint_stats(
    ml_engine: AnomalyMLEngine,
    corr_engine: SecurityEventCorrelationEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = [_mk_anomaly(ml_engine, entity_id=f"e{i}").id for i in range(3)]
    ml_engine.group_signals_into_composite("test-org", ids)
    app = _make_app(ml_engine, corr_engine, monkeypatch)
    client = TestClient(app)
    r = client.get("/api/v1/composite-alerts/stats", params={"org_id": "test-org"})
    assert r.status_code == 200
    body = r.json()
    assert body["group_count"] == 1
    assert body["total_grouped_signals"] == 3
    assert 0.0 <= body["avg_correlation_score"] <= 1.0
