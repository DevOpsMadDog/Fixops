"""Tests for CloudCostSecurityEngine — 25+ tests.

Covers:
- Snapshot recording and anomaly auto-detection (spike, abandoned, security_exposure)
- Snapshot listing and filters
- Abandoned resource CRUD and termination
- Budget management and status computation
- Anomaly lifecycle (record, list, resolve, filter)
- Stats aggregation
- Org isolation
"""

import sys
sys.path.insert(0, "suite-core")

import pytest
from datetime import datetime, timezone, timedelta

from core.cloud_cost_security_engine import CloudCostSecurityEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    """CloudCostSecurityEngine backed by a temporary SQLite database."""
    return CloudCostSecurityEngine(db_path=str(tmp_path / "cloud_cost_test.db"))


def _past_iso(days: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# 1. Snapshot recording — basic
# ---------------------------------------------------------------------------

def test_record_snapshot_returns_dict(engine):
    snap = engine.record_snapshot("org1", {
        "provider": "aws",
        "service_name": "EC2",
        "region": "us-east-1",
        "cost_usd": 100.0,
        "previous_cost_usd": 90.0,
    })
    assert isinstance(snap, dict)
    assert "id" in snap
    assert snap["org_id"] == "org1"


def test_record_snapshot_has_uuid_id(engine):
    import uuid
    snap = engine.record_snapshot("org1", {"provider": "aws", "cost_usd": 10.0})
    uuid.UUID(snap["id"])  # raises if invalid


def test_record_snapshot_computes_change_pct(engine):
    snap = engine.record_snapshot("org1", {
        "provider": "aws",
        "cost_usd": 300.0,
        "previous_cost_usd": 100.0,
    })
    assert snap["change_pct"] == pytest.approx(200.0, abs=1.0)


def test_record_snapshot_invalid_provider_raises(engine):
    with pytest.raises(ValueError):
        engine.record_snapshot("org1", {"provider": "digitalocean", "cost_usd": 10.0})


# ---------------------------------------------------------------------------
# 2. Anomaly detection — spike
# ---------------------------------------------------------------------------

def test_record_snapshot_spike_detected(engine):
    snap = engine.record_snapshot("org1", {
        "provider": "aws",
        "cost_usd": 1000.0,
        "previous_cost_usd": 100.0,  # 900% change → spike
    })
    assert snap["anomaly"] is True
    assert snap["anomaly_type"] == "spike"


def test_record_snapshot_no_spike_below_threshold(engine):
    snap = engine.record_snapshot("org1", {
        "provider": "aws",
        "cost_usd": 110.0,
        "previous_cost_usd": 100.0,  # 10% change → no anomaly
    })
    assert snap["anomaly"] is False


def test_record_snapshot_spike_creates_anomaly_record(engine):
    engine.record_snapshot("orgS", {
        "provider": "aws",
        "cost_usd": 5000.0,
        "previous_cost_usd": 100.0,
    })
    anomalies = engine.list_anomalies("orgS")
    assert len(anomalies) >= 1
    assert any(a["anomaly_type"] == "spike" for a in anomalies)


# ---------------------------------------------------------------------------
# 3. Anomaly detection — abandoned
# ---------------------------------------------------------------------------

def test_record_snapshot_abandoned_detected(engine):
    snap = engine.record_snapshot("org2", {
        "provider": "azure",
        "cost_usd": 50.0,
        "previous_cost_usd": 50.0,
        "last_used": _past_iso(45),  # 45 days ago → abandoned
    })
    assert snap["anomaly"] is True
    assert snap["anomaly_type"] == "abandoned"


def test_record_snapshot_not_abandoned_recent_use(engine):
    snap = engine.record_snapshot("org2", {
        "provider": "azure",
        "cost_usd": 50.0,
        "previous_cost_usd": 50.0,
        "last_used": _past_iso(5),  # only 5 days ago → not abandoned
    })
    assert snap["anomaly"] is False


# ---------------------------------------------------------------------------
# 4. Anomaly detection — security_exposure
# ---------------------------------------------------------------------------

def test_record_snapshot_security_exposure_detected(engine):
    snap = engine.record_snapshot("org3", {
        "provider": "gcp",
        "cost_usd": 20.0,
        "previous_cost_usd": 20.0,
        "has_public_ip": True,
        "is_idle": True,
    })
    assert snap["anomaly"] is True
    assert snap["anomaly_type"] == "security_exposure"


def test_record_snapshot_no_exposure_if_not_idle(engine):
    snap = engine.record_snapshot("org3", {
        "provider": "gcp",
        "cost_usd": 20.0,
        "has_public_ip": True,
        "is_idle": False,
    })
    assert snap["anomaly"] is False


# ---------------------------------------------------------------------------
# 5. List snapshots
# ---------------------------------------------------------------------------

def test_list_snapshots_returns_created(engine):
    engine.record_snapshot("org4", {"provider": "aws", "cost_usd": 10.0})
    engine.record_snapshot("org4", {"provider": "azure", "cost_usd": 20.0})
    snaps = engine.list_snapshots("org4")
    assert len(snaps) >= 2


def test_list_snapshots_anomaly_filter(engine):
    engine.record_snapshot("org5", {
        "provider": "aws", "cost_usd": 5000.0, "previous_cost_usd": 100.0
    })
    engine.record_snapshot("org5", {
        "provider": "aws", "cost_usd": 105.0, "previous_cost_usd": 100.0
    })
    anomaly_snaps = engine.list_snapshots("org5", anomaly=True)
    for s in anomaly_snaps:
        assert s["anomaly"] is True


# ---------------------------------------------------------------------------
# 6. Abandoned resources
# ---------------------------------------------------------------------------

def test_add_abandoned_resource_returns_dict(engine):
    res = engine.add_abandoned_resource("org6", {
        "resource_id": "i-12345",
        "resource_type": "ec2_instance",
        "resource_name": "old-dev-server",
        "provider": "aws",
        "monthly_cost_usd": 150.0,
        "security_risk": True,
        "risk_reason": "Public IP with no active connections",
    })
    assert isinstance(res, dict)
    assert "id" in res
    assert res["security_risk"] is True


def test_list_abandoned_resources_filtered_by_provider(engine):
    engine.add_abandoned_resource("org7", {"provider": "aws", "resource_id": "r1"})
    engine.add_abandoned_resource("org7", {"provider": "azure", "resource_id": "r2"})
    aws_only = engine.list_abandoned_resources("org7", provider="aws")
    for r in aws_only:
        assert r["provider"] == "aws"


def test_terminate_resource_marks_terminated(engine):
    res = engine.add_abandoned_resource("org8", {
        "provider": "gcp",
        "resource_id": "vm-001",
        "monthly_cost_usd": 80.0,
    })
    ok = engine.terminate_resource("org8", res["id"])
    assert ok is True
    terminated = engine.list_abandoned_resources("org8", status="terminated")
    assert any(r["id"] == res["id"] for r in terminated)


def test_terminate_resource_wrong_org_returns_false(engine):
    res = engine.add_abandoned_resource("org9", {"provider": "aws", "resource_id": "x"})
    ok = engine.terminate_resource("other_org", res["id"])
    assert ok is False


# ---------------------------------------------------------------------------
# 7. Budgets
# ---------------------------------------------------------------------------

def test_create_budget_returns_dict(engine):
    budget = engine.create_budget("org10", {
        "budget_name": "Q1 AWS Budget",
        "period": "monthly",
        "limit_usd": 10000.0,
        "current_spend_usd": 5000.0,
        "alert_threshold_pct": 80,
    })
    assert isinstance(budget, dict)
    assert budget["budget_name"] == "Q1 AWS Budget"
    assert budget["status"] == "ok"  # 50% spend < 80% threshold


def test_create_budget_warning_status(engine):
    budget = engine.create_budget("org10", {
        "budget_name": "Warning Budget",
        "period": "monthly",
        "limit_usd": 10000.0,
        "current_spend_usd": 9000.0,  # 90% → warning
        "alert_threshold_pct": 80,
    })
    assert budget["status"] == "warning"


def test_create_budget_exceeded_status(engine):
    budget = engine.create_budget("org10", {
        "budget_name": "Exceeded Budget",
        "period": "monthly",
        "limit_usd": 10000.0,
        "current_spend_usd": 12000.0,  # 120% → exceeded
        "alert_threshold_pct": 80,
    })
    assert budget["status"] == "exceeded"


def test_create_budget_requires_name(engine):
    with pytest.raises(ValueError):
        engine.create_budget("org10", {"limit_usd": 100.0})


def test_list_budgets_returns_created(engine):
    engine.create_budget("org11", {"budget_name": "B1", "limit_usd": 1000.0})
    engine.create_budget("org11", {"budget_name": "B2", "limit_usd": 2000.0})
    budgets = engine.list_budgets("org11")
    assert len(budgets) >= 2
    names = [b["budget_name"] for b in budgets]
    assert "B1" in names and "B2" in names


# ---------------------------------------------------------------------------
# 8. Cost anomalies lifecycle
# ---------------------------------------------------------------------------

def test_record_anomaly_returns_dict(engine):
    anomaly = engine.record_anomaly("org12", {
        "service_name": "S3",
        "cost_usd": 500.0,
        "expected_usd": 100.0,
        "deviation_pct": 400.0,
        "anomaly_type": "spike",
        "severity": "high",
    })
    assert isinstance(anomaly, dict)
    assert anomaly["investigation_status"] == "open"
    assert anomaly["severity"] == "high"


def test_list_anomalies_severity_filter(engine):
    engine.record_anomaly("org13", {"severity": "critical", "anomaly_type": "spike"})
    engine.record_anomaly("org13", {"severity": "low", "anomaly_type": "abandoned"})
    critical = engine.list_anomalies("org13", severity="critical")
    for a in critical:
        assert a["severity"] == "critical"


def test_resolve_anomaly(engine):
    anomaly = engine.record_anomaly("org14", {
        "service_name": "RDS",
        "severity": "high",
        "anomaly_type": "spike",
    })
    ok = engine.resolve_anomaly("org14", anomaly["id"])
    assert ok is True
    resolved = engine.list_anomalies("org14", status="resolved")
    assert any(a["id"] == anomaly["id"] for a in resolved)


def test_resolve_anomaly_wrong_org_returns_false(engine):
    anomaly = engine.record_anomaly("org15", {"severity": "medium", "anomaly_type": "spike"})
    ok = engine.resolve_anomaly("other_org", anomaly["id"])
    assert ok is False


# ---------------------------------------------------------------------------
# 9. Stats
# ---------------------------------------------------------------------------

def test_get_cost_stats_returns_dict(engine):
    stats = engine.get_cost_stats("org16")
    assert isinstance(stats, dict)
    assert "total_spend_this_month" in stats
    assert "by_provider" in stats
    assert "by_service" in stats
    assert "anomalies_this_month" in stats
    assert "abandoned_resources" in stats
    assert "potential_savings_usd" in stats
    assert "budgets_exceeded" in stats


def test_get_cost_stats_counts_abandoned(engine):
    engine.add_abandoned_resource("org17", {
        "provider": "aws",
        "monthly_cost_usd": 200.0,
        "status": "active",
    })
    stats = engine.get_cost_stats("org17")
    assert stats["abandoned_resources"] >= 1
    assert stats["potential_savings_usd"] >= 200.0


# ---------------------------------------------------------------------------
# 10. Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_snapshots(engine):
    engine.record_snapshot("orgA", {"provider": "aws", "cost_usd": 100.0})
    engine.record_snapshot("orgB", {"provider": "azure", "cost_usd": 200.0})
    snaps_a = engine.list_snapshots("orgA")
    snaps_b = engine.list_snapshots("orgB")
    ids_a = {s["id"] for s in snaps_a}
    ids_b = {s["id"] for s in snaps_b}
    assert ids_a.isdisjoint(ids_b)


def test_org_isolation_budgets(engine):
    engine.create_budget("orgC", {"budget_name": "C Budget", "limit_usd": 1000.0})
    engine.create_budget("orgD", {"budget_name": "D Budget", "limit_usd": 2000.0})
    c_budgets = engine.list_budgets("orgC")
    d_budgets = engine.list_budgets("orgD")
    c_names = [b["budget_name"] for b in c_budgets]
    d_names = [b["budget_name"] for b in d_budgets]
    assert "C Budget" in c_names and "D Budget" not in c_names
    assert "D Budget" in d_names and "C Budget" not in d_names
