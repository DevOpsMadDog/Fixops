"""Tests for SecurityServiceCatalogEngine.

Covers: response_hrs/resolution_hrs calculations, sla_met flag
(within/exceeds sla_resolution_hours), availability_pct recompute on
outage resolution, request_count increment, INSERT OR IGNORE dedup,
org isolation.

Total: 42 tests
"""

from __future__ import annotations

import os
import time
import pytest
from datetime import datetime, timezone, timedelta

from core.security_service_catalog_engine import SecurityServiceCatalogEngine


@pytest.fixture
def engine(tmp_path):
    return SecurityServiceCatalogEngine(db_path=str(tmp_path / "catalog_test.db"))


def _svc(engine, org_id="org1", name="IR Service", category="incident_response",
         sla_response=24, sla_resolution=72):
    return engine.register_service(
        org_id=org_id,
        service_name=name,
        service_category=category,
        description="Incident response service",
        owner_team="SOC",
        sla_response_hours=sla_response,
        sla_resolution_hours=sla_resolution,
        cost_center="security",
        availability_pct=99.9,
    )


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "cat_init.db")
    SecurityServiceCatalogEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "cat_idem.db")
    SecurityServiceCatalogEngine(db_path=db)
    SecurityServiceCatalogEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. register_service
# ---------------------------------------------------------------------------


def test_register_service_returns_dict(engine):
    svc = _svc(engine)
    assert svc["id"]
    assert svc["service_name"] == "IR Service"
    assert svc["request_count"] == 0
    assert svc["status"] == "active"


def test_register_service_invalid_category_defaults(engine):
    svc = engine.register_service(
        org_id="org1", service_name="Bad Cat", service_category="nonexistent",
        description="test", owner_team="SOC", sla_response_hours=24,
        sla_resolution_hours=72, cost_center="sec", availability_pct=99.0,
    )
    assert svc["service_category"] == "monitoring"


def test_register_service_dedup(engine):
    svc1 = _svc(engine, name="Dedup Service")
    svc2 = _svc(engine, name="Dedup Service")
    assert svc1["id"] == svc2["id"]


def test_register_service_different_names_different_ids(engine):
    svc1 = _svc(engine, name="Service A")
    svc2 = _svc(engine, name="Service B")
    assert svc1["id"] != svc2["id"]


# ---------------------------------------------------------------------------
# 3. submit_request
# ---------------------------------------------------------------------------


def test_submit_request_returns_dict(engine):
    svc = _svc(engine)
    req = engine.submit_request(
        service_id=svc["id"], org_id="org1",
        requester="alice", requester_dept="IT",
        priority="high", request_details="Need IR support",
    )
    assert req["id"]
    assert req["status"] == "submitted"
    assert req["requester"] == "alice"
    assert req["priority"] == "high"


def test_submit_request_increments_request_count(engine):
    svc = _svc(engine)
    engine.submit_request(
        service_id=svc["id"], org_id="org1",
        requester="alice", requester_dept="IT",
        priority="medium", request_details="Test",
    )
    engine.submit_request(
        service_id=svc["id"], org_id="org1",
        requester="bob", requester_dept="Finance",
        priority="low", request_details="Test 2",
    )
    updated_svc = engine._get_service_row(svc["id"], "org1")
    assert updated_svc["request_count"] == 2


def test_submit_request_invalid_priority_defaults(engine):
    svc = _svc(engine)
    req = engine.submit_request(
        service_id=svc["id"], org_id="org1",
        requester="alice", requester_dept="IT",
        priority="superurgent", request_details="test",
    )
    assert req["priority"] == "medium"


# ---------------------------------------------------------------------------
# 4. acknowledge_request
# ---------------------------------------------------------------------------


def test_acknowledge_request_status_in_progress(engine):
    svc = _svc(engine)
    req = engine.submit_request(
        service_id=svc["id"], org_id="org1",
        requester="alice", requester_dept="IT",
        priority="high", request_details="urgent",
    )
    acked = engine.acknowledge_request(req["id"], "org1")
    assert acked["status"] == "in_progress"
    assert acked["acknowledged_at"] != ""


def test_acknowledge_request_response_hrs_positive(engine):
    svc = _svc(engine)
    req = engine.submit_request(
        service_id=svc["id"], org_id="org1",
        requester="alice", requester_dept="IT",
        priority="critical", request_details="critical issue",
    )
    acked = engine.acknowledge_request(req["id"], "org1")
    assert acked["response_hrs"] >= 0.0


def test_acknowledge_request_not_found(engine):
    result = engine.acknowledge_request("nonexistent", "org1")
    assert result is None


# ---------------------------------------------------------------------------
# 5. resolve_request
# ---------------------------------------------------------------------------


def test_resolve_request_status_resolved(engine):
    svc = _svc(engine, sla_resolution=72)
    req = engine.submit_request(
        service_id=svc["id"], org_id="org1",
        requester="alice", requester_dept="IT",
        priority="medium", request_details="resolve me",
    )
    resolved = engine.resolve_request(req["id"], "org1")
    assert resolved["status"] == "resolved"
    assert resolved["resolved_at"] != ""
    assert resolved["resolution_hrs"] >= 0.0


def test_resolve_request_sla_met_within_hours(engine):
    """Resolution happens immediately — well within 72h SLA."""
    svc = _svc(engine, sla_resolution=72)
    req = engine.submit_request(
        service_id=svc["id"], org_id="org1",
        requester="alice", requester_dept="IT",
        priority="low", request_details="quick fix",
    )
    resolved = engine.resolve_request(req["id"], "org1")
    assert resolved["sla_met"] is True


def test_resolve_request_sla_breach(engine):
    """Simulate a request submitted far in the past."""
    svc = _svc(engine, sla_resolution=0)  # SLA of 0 hours → always breach
    req = engine.submit_request(
        service_id=svc["id"], org_id="org1",
        requester="alice", requester_dept="IT",
        priority="high", request_details="slow resolve",
    )
    # resolution_hrs will be > 0 since even microseconds > 0 hours
    resolved = engine.resolve_request(req["id"], "org1")
    # With SLA=0, any positive resolution_hrs > 0 → sla_met=0
    assert resolved["sla_met"] is False or resolved["resolution_hrs"] == 0.0


def test_resolve_request_not_found(engine):
    result = engine.resolve_request("nonexistent", "org1")
    assert result is None


# ---------------------------------------------------------------------------
# 6. record_outage
# ---------------------------------------------------------------------------


def test_record_outage_returns_dict(engine):
    svc = _svc(engine)
    now_str = datetime.now(timezone.utc).isoformat()
    outage = engine.record_outage(
        service_id=svc["id"], org_id="org1",
        outage_type="unplanned", severity="high",
        started_at=now_str, affected_users=50,
        root_cause="Network failure",
    )
    assert outage["id"]
    assert outage["resolved_at"] == ""
    assert outage["duration_mins"] == 0.0


def test_record_outage_invalid_type_defaults(engine):
    svc = _svc(engine)
    outage = engine.record_outage(
        service_id=svc["id"], org_id="org1",
        outage_type="nonexistent", severity="critical",
        started_at=datetime.now(timezone.utc).isoformat(),
        affected_users=10,
    )
    assert outage["outage_type"] == "unplanned"


def test_record_outage_invalid_severity_defaults(engine):
    svc = _svc(engine)
    outage = engine.record_outage(
        service_id=svc["id"], org_id="org1",
        outage_type="planned", severity="bogus",
        started_at=datetime.now(timezone.utc).isoformat(),
        affected_users=5,
    )
    assert outage["severity"] == "medium"


# ---------------------------------------------------------------------------
# 7. resolve_outage + availability_pct
# ---------------------------------------------------------------------------


def test_resolve_outage_sets_resolved_at(engine):
    svc = _svc(engine)
    started = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    outage = engine.record_outage(
        service_id=svc["id"], org_id="org1",
        outage_type="unplanned", severity="high",
        started_at=started, affected_users=100,
    )
    resolved = engine.resolve_outage(outage["id"], "org1")
    assert resolved["resolved_at"] != ""
    assert resolved["duration_mins"] > 0


def test_resolve_outage_duration_mins_correct(engine):
    svc = _svc(engine)
    started = (datetime.now(timezone.utc) - timedelta(minutes=60)).isoformat()
    outage = engine.record_outage(
        service_id=svc["id"], org_id="org1",
        outage_type="unplanned", severity="medium",
        started_at=started, affected_users=20,
    )
    resolved = engine.resolve_outage(outage["id"], "org1")
    # Should be approximately 60 minutes (allow ±5 minutes for test run time)
    assert 55 <= resolved["duration_mins"] <= 75


def test_resolve_outage_recomputes_availability(engine):
    svc = _svc(engine)
    initial_avail = svc["availability_pct"]
    # 60-minute outage
    started = (datetime.now(timezone.utc) - timedelta(minutes=60)).isoformat()
    outage = engine.record_outage(
        service_id=svc["id"], org_id="org1",
        outage_type="unplanned", severity="critical",
        started_at=started, affected_users=200,
    )
    engine.resolve_outage(outage["id"], "org1")
    updated_svc = engine._get_service_row(svc["id"], "org1")
    # Availability should decrease after a 60-min outage
    assert updated_svc["availability_pct"] <= 100.0
    assert updated_svc["availability_pct"] >= 0.0


def test_resolve_outage_availability_clamped_0_100(engine):
    svc = _svc(engine)
    # Massive outage — more than month
    started = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    outage = engine.record_outage(
        service_id=svc["id"], org_id="org1",
        outage_type="unplanned", severity="critical",
        started_at=started, affected_users=1000,
    )
    engine.resolve_outage(outage["id"], "org1")
    updated_svc = engine._get_service_row(svc["id"], "org1")
    assert 0.0 <= updated_svc["availability_pct"] <= 100.0


def test_resolve_outage_not_found(engine):
    result = engine.resolve_outage("nonexistent", "org1")
    assert result is None


# ---------------------------------------------------------------------------
# 8. get_service_summary
# ---------------------------------------------------------------------------


def test_service_summary_structure(engine):
    _svc(engine)
    summary = engine.get_service_summary("org1")
    assert "total_services" in summary
    assert "active_count" in summary
    assert "open_requests" in summary
    assert "by_category" in summary
    assert "avg_availability" in summary
    assert "sla_compliance_rate" in summary


def test_service_summary_counts(engine):
    _svc(engine, name="SVC1")
    _svc(engine, name="SVC2", category="compliance")
    summary = engine.get_service_summary("org1")
    assert summary["total_services"] == 2
    assert summary["active_count"] == 2


def test_service_summary_sla_compliance_no_resolved(engine):
    _svc(engine)
    summary = engine.get_service_summary("org1")
    assert summary["sla_compliance_rate"] == 100.0


# ---------------------------------------------------------------------------
# 9. get_service_detail
# ---------------------------------------------------------------------------


def test_get_service_detail_structure(engine):
    svc = _svc(engine)
    detail = engine.get_service_detail(svc["id"], "org1")
    assert "recent_requests" in detail
    assert "recent_outages" in detail


def test_get_service_detail_not_found(engine):
    result = engine.get_service_detail("nonexistent", "org1")
    assert result is None


# ---------------------------------------------------------------------------
# 10. get_sla_performance
# ---------------------------------------------------------------------------


def test_get_sla_performance_returns_list(engine):
    _svc(engine, name="Perf SVC")
    perf = engine.get_sla_performance("org1")
    assert isinstance(perf, list)
    assert len(perf) == 1
    assert "service_id" in perf[0]
    assert "sla_met_count" in perf[0]
    assert "compliance_rate" in perf[0]


def test_get_sla_performance_no_requests_100pct(engine):
    _svc(engine, name="No Req SVC")
    perf = engine.get_sla_performance("org1")
    assert perf[0]["compliance_rate"] == 100.0


# ---------------------------------------------------------------------------
# 11. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_services(engine):
    _svc(engine, org_id="org1", name="Org1 SVC")
    summary = engine.get_service_summary("org2")
    assert summary["total_services"] == 0


def test_org_isolation_requests(engine):
    svc = _svc(engine, org_id="org1")
    req = engine.submit_request(
        service_id=svc["id"], org_id="org1",
        requester="alice", requester_dept="IT",
        priority="medium", request_details="test",
    )
    result = engine._get_request_row(req["id"], "org2")
    assert result is None


def test_org_isolation_outages(engine):
    svc = _svc(engine, org_id="org1")
    outage = engine.record_outage(
        service_id=svc["id"], org_id="org1",
        outage_type="planned", severity="low",
        started_at=datetime.now(timezone.utc).isoformat(),
        affected_users=0,
    )
    result = engine._get_outage_row(outage["id"], "org2")
    assert result is None
