"""Tests for GAP-028 (FAIR per-BU) + GAP-051 (ROI-of-fixes trend).

Merged onto RiskQuantificationEngineV2.
Covers: engine methods, org_id isolation, boundary conditions, endpoint smoke.
"""
from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# Ensure suite paths present (sitecustomize usually handles this)
_ROOT = Path(__file__).resolve().parents[1]
for sub in ("suite-core", "suite-api"):
    p = str(_ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from core.risk_quantification_engine_v2 import RiskQuantificationEngineV2  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine(tmp_path):
    db = tmp_path / "rqv2.db"
    return RiskQuantificationEngineV2(db_path=str(db))


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Business Units — seed / idempotency
# ---------------------------------------------------------------------------

def test_business_units_seed_creates_five_defaults(engine):
    bus = engine.business_units("org-a")
    names = {b["name"] for b in bus}
    assert names == {"Finance", "Engineering", "Sales", "Ops", "HR"}
    assert len(bus) == 5


def test_business_units_idempotent_no_duplicates_on_second_call(engine):
    first = engine.business_units("org-a")
    second = engine.business_units("org-a")
    assert len(first) == 5
    assert len(second) == 5
    # IDs stable across calls
    assert {b["id"] for b in first} == {b["id"] for b in second}


def test_business_units_criticality_assigned(engine):
    bus = {b["name"]: b["criticality"] for b in engine.business_units("org-a")}
    assert bus["Finance"] == "critical"
    assert bus["Engineering"] == "high"
    assert bus["HR"] == "medium"


def test_business_units_org_isolation(engine):
    a = engine.business_units("org-a")
    b = engine.business_units("org-b")
    a_ids = {x["id"] for x in a}
    b_ids = {x["id"] for x in b}
    assert a_ids.isdisjoint(b_ids)


def test_business_units_each_has_required_fields(engine):
    bus = engine.business_units("org-a")
    for bu in bus:
        assert "id" in bu and "name" in bu and "criticality" in bu and "created_at" in bu
        assert bu["org_id"] == "org-a"


# ---------------------------------------------------------------------------
# Per-BU Risk
# ---------------------------------------------------------------------------

def test_per_bu_risk_empty_findings_returns_clean_zeros(engine):
    bus = engine.business_units("org-a")
    finance = next(b for b in bus if b["name"] == "Finance")
    result = engine.compute_per_bu_risk("org-a", finance["id"], findings=[])
    assert result["ale_mean"] == 0.0
    assert result["ale_p95"] == 0.0
    assert result["sle_mean"] == 0.0
    assert result["contributing_findings_count"] == 0


def test_per_bu_risk_none_findings_returns_clean_zeros(engine):
    bus = engine.business_units("org-a")
    bu = bus[0]
    # None triggers _findings_for_bu which returns [] when no DB
    result = engine.compute_per_bu_risk("org-a", bu["id"], findings=None)
    assert result["ale_mean"] == 0.0
    assert result["contributing_findings_count"] == 0


def test_per_bu_risk_with_synthetic_findings_ale_positive(engine):
    bus = engine.business_units("org-a")
    finance = next(b for b in bus if b["name"] == "Finance")
    findings = [
        {"id": "f1", "severity": "critical"},
        {"id": "f2", "severity": "high"},
        {"id": "f3", "severity": "medium"},
    ]
    result = engine.compute_per_bu_risk("org-a", finance["id"], findings=findings)
    assert result["ale_mean"] > 0
    assert result["ale_p95"] > result["ale_mean"]  # p95 strictly above mean
    assert result["contributing_findings_count"] == 3


def test_per_bu_risk_criticality_multiplier_applied(engine):
    bus = engine.business_units("org-a")
    finance = next(b for b in bus if b["name"] == "Finance")       # critical
    hr = next(b for b in bus if b["name"] == "HR")                 # medium
    findings = [{"id": "f1", "severity": "high"}]
    finance_risk = engine.compute_per_bu_risk("org-a", finance["id"], findings=findings)
    hr_risk = engine.compute_per_bu_risk("org-a", hr["id"], findings=findings)
    # Critical BU multiplier 2.0x vs medium 1.0x → finance > hr
    assert finance_risk["ale_mean"] > hr_risk["ale_mean"]


def test_per_bu_risk_unknown_bu_raises(engine):
    with pytest.raises(ValueError):
        engine.compute_per_bu_risk("org-a", "bogus-bu-id", findings=[])


def test_per_bu_risk_unknown_severity_defaults_to_medium(engine):
    bus = engine.business_units("org-a")
    bu = bus[0]
    result = engine.compute_per_bu_risk(
        "org-a", bu["id"], findings=[{"id": "x", "severity": "weird"}]
    )
    assert result["ale_mean"] > 0


def test_per_bu_risk_returns_required_shape(engine):
    bus = engine.business_units("org-a")
    bu = bus[0]
    result = engine.compute_per_bu_risk("org-a", bu["id"], findings=[])
    for key in ("bu_id", "name", "sle_mean", "aro", "ale_mean",
                "ale_p95", "contributing_findings_count"):
        assert key in result


def test_per_bu_risk_org_isolation(engine):
    engine.business_units("org-a")
    engine.business_units("org-b")
    bu_a = engine.business_units("org-a")[0]
    # BU from org-a is not visible to org-b
    with pytest.raises(ValueError):
        engine.compute_per_bu_risk("org-b", bu_a["id"], findings=[])


# ---------------------------------------------------------------------------
# Fix Cost Recording
# ---------------------------------------------------------------------------

def test_record_fix_cost_persists(engine):
    rec = engine.record_fix_cost(
        "org-a", finding_id="F-1", cost=500.0, fixed_at=_iso(datetime.now(timezone.utc))
    )
    assert rec["cost"] == 500.0
    assert rec["ale_reduced"] > 0  # inferred from default severity=medium


def test_record_fix_cost_explicit_ale_reduced(engine):
    rec = engine.record_fix_cost(
        "org-a", finding_id="F-2", cost=1000.0,
        fixed_at=_iso(datetime.now(timezone.utc)), ale_reduced=50_000.0,
    )
    assert rec["ale_reduced"] == 50_000.0


def test_record_fix_cost_negative_cost_clamped(engine):
    rec = engine.record_fix_cost(
        "org-a", finding_id="F-3", cost=-100.0,
        fixed_at=_iso(datetime.now(timezone.utc)),
    )
    assert rec["cost"] == 0.0


def test_record_fix_cost_empty_fixed_at_raises(engine):
    with pytest.raises(ValueError):
        engine.record_fix_cost("org-a", finding_id="F-x", cost=100.0, fixed_at="")


# ---------------------------------------------------------------------------
# ROI-of-Fixes Trend
# ---------------------------------------------------------------------------

def test_roi_trend_empty_returns_zeros_with_correct_shape(engine):
    trend = engine.roi_of_fixes_trend("org-a", window_days=90)
    # 90 // 7 = 12, so 13 points
    assert len(trend["weeks"]) == 13
    assert all(v == 0.0 for v in trend["cumulative_ale_reduced"])
    assert all(v == 0.0 for v in trend["cumulative_cost"])
    assert all(v == 0.0 for v in trend["roi_trend"])


def test_roi_trend_weekly_buckets_n_plus_1(engine):
    trend_90 = engine.roi_of_fixes_trend("org-a", 90)
    trend_28 = engine.roi_of_fixes_trend("org-a", 28)
    trend_7 = engine.roi_of_fixes_trend("org-a", 7)
    assert len(trend_90["weeks"]) == (90 // 7) + 1  # 13
    assert len(trend_28["weeks"]) == (28 // 7) + 1  # 5
    assert len(trend_7["weeks"]) == (7 // 7) + 1    # 2


def test_roi_trend_cumulative_non_decreasing(engine):
    now = datetime.now(timezone.utc)
    # Record 3 fixes across window
    engine.record_fix_cost("org-a", "F1", 100.0, _iso(now - timedelta(days=60)), ale_reduced=1000.0)
    engine.record_fix_cost("org-a", "F2", 200.0, _iso(now - timedelta(days=30)), ale_reduced=2000.0)
    engine.record_fix_cost("org-a", "F3", 300.0, _iso(now - timedelta(days=5)), ale_reduced=3000.0)

    trend = engine.roi_of_fixes_trend("org-a", 90)
    costs = trend["cumulative_cost"]
    ales = trend["cumulative_ale_reduced"]
    assert costs == sorted(costs)       # non-decreasing
    assert ales == sorted(ales)         # non-decreasing
    assert costs[-1] == 600.0
    assert ales[-1] == 6000.0


def test_roi_trend_roi_pct_formula(engine):
    now = datetime.now(timezone.utc)
    engine.record_fix_cost("org-a", "F1", 1000.0, _iso(now - timedelta(days=5)), ale_reduced=11_000.0)
    trend = engine.roi_of_fixes_trend("org-a", 90)
    # ROI = (11000 - 1000) / 1000 * 100 = 1000%
    assert trend["roi_trend"][-1] == 1000.0


def test_roi_trend_excludes_fixes_outside_window(engine):
    now = datetime.now(timezone.utc)
    # Fix outside window (100 days ago)
    engine.record_fix_cost("org-a", "old", 500.0, _iso(now - timedelta(days=100)), ale_reduced=5000.0)
    # Fix inside window
    engine.record_fix_cost("org-a", "new", 200.0, _iso(now - timedelta(days=10)), ale_reduced=2000.0)

    trend = engine.roi_of_fixes_trend("org-a", 90)
    assert trend["cumulative_cost"][-1] == 200.0
    assert trend["cumulative_ale_reduced"][-1] == 2000.0


def test_roi_trend_org_isolation(engine):
    now = datetime.now(timezone.utc)
    engine.record_fix_cost("org-a", "Fa", 100.0, _iso(now - timedelta(days=5)), ale_reduced=500.0)
    engine.record_fix_cost("org-b", "Fb", 999.0, _iso(now - timedelta(days=5)), ale_reduced=9999.0)

    trend_a = engine.roi_of_fixes_trend("org-a", 90)
    trend_b = engine.roi_of_fixes_trend("org-b", 90)
    assert trend_a["cumulative_cost"][-1] == 100.0
    assert trend_b["cumulative_cost"][-1] == 999.0


def test_roi_trend_weeks_are_iso_date_strings(engine):
    trend = engine.roi_of_fixes_trend("org-a", 90)
    for w in trend["weeks"]:
        # ISO YYYY-MM-DD parseable
        datetime.fromisoformat(w)


# ---------------------------------------------------------------------------
# Endpoint Smoke
# ---------------------------------------------------------------------------

def _make_client(tmp_path, monkeypatch):
    """Spin up a minimal FastAPI app with just the fair_per_bu_router.

    Stubs auth and points the singleton engine at tmp_path.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from apps.api import auth_deps
    from apps.api import fair_per_bu_router as fpb

    fpb._engine = RiskQuantificationEngineV2(db_path=str(tmp_path / "router_rqv2.db"))

    app = FastAPI()

    async def _allow():
        return {"org_id": "default"}

    # Override the dependency used by the router
    app.dependency_overrides[auth_deps.api_key_auth] = _allow
    app.include_router(fpb.router)
    return TestClient(app)


def test_endpoint_business_units_smoke(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    r = client.get("/api/v1/fair/business-units?org_id=t1")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 5
    assert len(body["business_units"]) == 5


def test_endpoint_per_bu_risk_smoke(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    bus = client.get("/api/v1/fair/business-units?org_id=t1").json()["business_units"]
    bu_id = bus[0]["id"]
    r = client.post(
        "/api/v1/fair/per-bu-risk?org_id=t1",
        json={"bu_id": bu_id, "findings": [{"id": "f1", "severity": "high"}]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ale_mean"] > 0
    assert body["contributing_findings_count"] == 1


def test_endpoint_fix_cost_and_roi_trend_smoke(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    now = datetime.now(timezone.utc)
    r = client.post(
        "/api/v1/fair/fix-cost?org_id=t1",
        json={
            "finding_id": "F-smoke",
            "cost": 500.0,
            "fixed_at": _iso(now - timedelta(days=3)),
            "ale_reduced": 5000.0,
        },
    )
    assert r.status_code == 201

    r2 = client.get("/api/v1/fair/roi-trend?org_id=t1&window_days=90")
    assert r2.status_code == 200
    body = r2.json()
    assert len(body["weeks"]) == 13
    assert body["cumulative_cost"][-1] == 500.0
    assert body["cumulative_ale_reduced"][-1] == 5000.0


def test_endpoint_stats_smoke(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    r = client.get("/api/v1/fair/stats?org_id=t1")
    assert r.status_code == 200
    body = r.json()
    assert body["business_unit_count"] == 5
    assert body["weekly_points"] == 13
