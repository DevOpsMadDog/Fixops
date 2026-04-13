"""
Tests for SLA Engine (suite-core/core/sla_engine.py).

Covers:
- SLA policy creation and upsert
- Deadline calculation by severity (default + policy-based)
- Finding tracking (idempotency)
- Status progression: ON_TRACK → AT_RISK → BREACHED → RESOLVED
- get_at_risk_findings filtering
- record_resolution (within SLA vs breached)
- calculate_compliance_rate
- Breach alert logic (>90% threshold)
- dashboard aggregation
- KeyError on missing finding
- Multi-org isolation
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

# Ensure suite-core is importable
_SUITE_CORE = str(Path(__file__).parent.parent / "suite-core")
if _SUITE_CORE not in sys.path:
    sys.path.insert(0, _SUITE_CORE)

from core.sla_engine import SLAEngine, SLAStatusEnum


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _engine() -> SLAEngine:
    """Return a fresh in-memory SLAEngine."""
    return SLAEngine(db_path=":memory:")


# ---------------------------------------------------------------------------
# Policy creation
# ---------------------------------------------------------------------------


def test_create_policy_returns_policy():
    eng = _engine()
    policy = eng.create_sla_policy(
        name="strict", deadlines={"critical": 12, "high": 48}, org_id="org1"
    )
    assert policy.id
    assert policy.name == "strict"
    assert policy.org_id == "org1"
    assert policy.deadlines["critical"] == 12


def test_create_policy_upsert_same_name_org():
    eng = _engine()
    p1 = eng.create_sla_policy("pol", {"critical": 12}, "orgA")
    p2 = eng.create_sla_policy("pol", {"critical": 6}, "orgA")
    assert p1.id == p2.id
    assert p2.deadlines["critical"] == 6


def test_create_policy_different_orgs_are_independent():
    eng = _engine()
    p1 = eng.create_sla_policy("pol", {"critical": 12}, "orgA")
    p2 = eng.create_sla_policy("pol", {"critical": 24}, "orgB")
    assert p1.id != p2.id


# ---------------------------------------------------------------------------
# Deadline calculation by severity
# ---------------------------------------------------------------------------


def test_default_deadline_critical():
    eng = _engine()
    before = _now()
    tr = eng.track_finding("f-crit", "critical", org_id="org1")
    after = _now()
    expected_min = before + timedelta(hours=24)
    expected_max = after + timedelta(hours=24)
    assert expected_min <= tr.deadline <= expected_max


def test_default_deadline_high():
    eng = _engine()
    tr = eng.track_finding("f-high", "high", org_id="org1")
    delta = tr.deadline - tr.created_at
    assert abs(delta.total_seconds() - 72 * 3600) < 5


def test_default_deadline_medium():
    eng = _engine()
    tr = eng.track_finding("f-med", "medium", org_id="org1")
    delta = tr.deadline - tr.created_at
    assert abs(delta.total_seconds() - 7 * 24 * 3600) < 5


def test_default_deadline_low():
    eng = _engine()
    tr = eng.track_finding("f-low", "low", org_id="org1")
    delta = tr.deadline - tr.created_at
    assert abs(delta.total_seconds() - 30 * 24 * 3600) < 5


def test_policy_deadline_overrides_default():
    eng = _engine()
    policy = eng.create_sla_policy("fast", {"critical": 4, "high": 8}, "org1")
    tr = eng.track_finding("f-policy", "critical", policy_id=policy.id, org_id="org1")
    delta = tr.deadline - tr.created_at
    assert abs(delta.total_seconds() - 4 * 3600) < 5


# ---------------------------------------------------------------------------
# Tracking
# ---------------------------------------------------------------------------


def test_track_finding_returns_tracking():
    eng = _engine()
    tr = eng.track_finding("finding-001", "high", org_id="org1")
    assert tr.finding_id == "finding-001"
    assert tr.severity == "high"
    assert tr.status == SLAStatusEnum.ON_TRACK


def test_track_finding_idempotent():
    eng = _engine()
    tr1 = eng.track_finding("finding-dup", "high", org_id="org1")
    tr2 = eng.track_finding("finding-dup", "critical", org_id="org1")
    assert tr1.tracking_id == tr2.tracking_id
    assert tr2.severity == "high"  # original severity preserved


def test_track_finding_custom_discovered_at():
    eng = _engine()
    past = _now() - timedelta(hours=12)
    tr = eng.track_finding("f-past", "high", org_id="org1", discovered_at=past)
    assert abs((tr.created_at - past).total_seconds()) < 2


# ---------------------------------------------------------------------------
# Status: ON_TRACK
# ---------------------------------------------------------------------------


def test_check_status_on_track():
    eng = _engine()
    eng.track_finding("f-ontrack", "low", org_id="org1")
    s = eng.check_status("f-ontrack")
    assert s.status == SLAStatusEnum.ON_TRACK
    assert s.pct_elapsed < 0.75


def test_check_status_unknown_finding_raises():
    eng = _engine()
    with pytest.raises(KeyError):
        eng.check_status("nonexistent")


# ---------------------------------------------------------------------------
# Status: AT_RISK
# ---------------------------------------------------------------------------


def test_check_status_at_risk():
    """Finding 80% through its deadline should be AT_RISK."""
    eng = _engine()
    # 4-hour deadline, started 3.5 hours ago → 87.5% elapsed → AT_RISK
    created = _now() - timedelta(hours=3, minutes=30)
    deadline = created + timedelta(hours=4)
    eng._conn.execute(
        "INSERT INTO sla_tracking"
        "(tracking_id, finding_id, severity, policy_id, org_id, created_at, deadline, status)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("tid-at-risk", "f-at-risk", "critical", None, "org1",
         created.isoformat(), deadline.isoformat(), "ON_TRACK"),
    )
    eng._conn.commit()
    s = eng.check_status("f-at-risk")
    assert s.status == SLAStatusEnum.AT_RISK


# ---------------------------------------------------------------------------
# Status: BREACHED
# ---------------------------------------------------------------------------


def test_check_status_breached():
    """Finding past its deadline should be BREACHED."""
    eng = _engine()
    created = _now() - timedelta(hours=25)
    deadline = created + timedelta(hours=24)
    eng._conn.execute(
        "INSERT INTO sla_tracking"
        "(tracking_id, finding_id, severity, policy_id, org_id, created_at, deadline, status)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("tid-breach", "f-breach", "critical", None, "org1",
         created.isoformat(), deadline.isoformat(), "ON_TRACK"),
    )
    eng._conn.commit()
    s = eng.check_status("f-breach")
    assert s.status == SLAStatusEnum.BREACHED


# ---------------------------------------------------------------------------
# Status: RESOLVED
# ---------------------------------------------------------------------------


def test_record_resolution_marks_resolved():
    eng = _engine()
    eng.track_finding("f-resolve", "high", org_id="org1")
    s = eng.record_resolution("f-resolve")
    assert s.status == SLAStatusEnum.RESOLVED
    assert s.resolution_time is not None


def test_record_resolution_unknown_raises():
    eng = _engine()
    with pytest.raises(KeyError):
        eng.record_resolution("nonexistent-finding")


# ---------------------------------------------------------------------------
# get_at_risk_findings
# ---------------------------------------------------------------------------


def test_get_at_risk_findings_empty():
    eng = _engine()
    eng.track_finding("f-fresh", "low", org_id="org1")
    results = eng.get_at_risk_findings(org_id="org1")
    assert results == []


def test_get_at_risk_findings_returns_at_risk_and_breached():
    eng = _engine()
    now = _now()

    # AT_RISK: 80% elapsed
    created_ar = now - timedelta(hours=3, minutes=12)  # 3.2h of 4h = 80%
    deadline_ar = created_ar + timedelta(hours=4)
    eng._conn.execute(
        "INSERT INTO sla_tracking"
        "(tracking_id, finding_id, severity, policy_id, org_id, created_at, deadline, status)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("t-ar", "f-at-risk2", "critical", None, "org1",
         created_ar.isoformat(), deadline_ar.isoformat(), "ON_TRACK"),
    )

    # BREACHED: past deadline
    created_br = now - timedelta(hours=26)
    deadline_br = created_br + timedelta(hours=24)
    eng._conn.execute(
        "INSERT INTO sla_tracking"
        "(tracking_id, finding_id, severity, policy_id, org_id, created_at, deadline, status)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("t-br", "f-breach2", "high", None, "org1",
         created_br.isoformat(), deadline_br.isoformat(), "ON_TRACK"),
    )
    eng._conn.commit()

    results = eng.get_at_risk_findings(org_id="org1")
    statuses = {r.finding_id: r.status for r in results}
    assert statuses.get("f-at-risk2") == SLAStatusEnum.AT_RISK
    assert statuses.get("f-breach2") == SLAStatusEnum.BREACHED


def test_get_at_risk_excludes_resolved():
    eng = _engine()
    eng.track_finding("f-done", "critical", org_id="org1")
    eng.record_resolution("f-done")
    results = eng.get_at_risk_findings(org_id="org1")
    ids = [r.finding_id for r in results]
    assert "f-done" not in ids


# ---------------------------------------------------------------------------
# Compliance rate
# ---------------------------------------------------------------------------


def test_compliance_rate_no_resolved_findings():
    eng = _engine()
    rate = eng.calculate_compliance_rate(org_id="org-empty", days=30)
    assert rate == 100.0


def test_compliance_rate_all_resolved_within_sla():
    eng = _engine()
    eng.track_finding("f-comp1", "high", org_id="org-comp")
    eng.track_finding("f-comp2", "high", org_id="org-comp")
    eng.record_resolution("f-comp1")
    eng.record_resolution("f-comp2")
    rate = eng.calculate_compliance_rate(org_id="org-comp", days=30)
    assert rate == 100.0


def test_compliance_rate_partial():
    """One resolved within SLA, one resolved after breach."""
    eng = _engine()
    now = _now()

    # Within SLA: resolved before deadline
    created1 = now - timedelta(hours=10)
    deadline1 = created1 + timedelta(hours=24)
    resolution1 = created1 + timedelta(hours=8)
    eng._conn.execute(
        "INSERT INTO sla_tracking"
        "(tracking_id, finding_id, severity, policy_id, org_id, created_at, deadline, status, resolution_time)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("t-c1", "f-within", "high", None, "org-partial",
         created1.isoformat(), deadline1.isoformat(), "RESOLVED", resolution1.isoformat()),
    )

    # Breached: resolved after deadline
    created2 = now - timedelta(hours=30)
    deadline2 = created2 + timedelta(hours=24)
    resolution2 = now - timedelta(hours=1)  # after deadline
    eng._conn.execute(
        "INSERT INTO sla_tracking"
        "(tracking_id, finding_id, severity, policy_id, org_id, created_at, deadline, status, resolution_time)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("t-c2", "f-late", "high", None, "org-partial",
         created2.isoformat(), deadline2.isoformat(), "RESOLVED", resolution2.isoformat()),
    )
    eng._conn.commit()

    rate = eng.calculate_compliance_rate(org_id="org-partial", days=30)
    assert rate == 50.0


# ---------------------------------------------------------------------------
# Breach alerts
# ---------------------------------------------------------------------------


def test_send_breach_alerts_returns_alert_ids():
    eng = _engine()
    now = _now()
    # 95% elapsed of a 4-hour window
    created = now - timedelta(minutes=228)  # 3h48m = 95% of 4h
    deadline = created + timedelta(hours=4)
    eng._conn.execute(
        "INSERT INTO sla_tracking"
        "(tracking_id, finding_id, severity, policy_id, org_id, created_at, deadline, status)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("t-alert", "f-alert", "critical", None, "org1",
         created.isoformat(), deadline.isoformat(), "ON_TRACK"),
    )
    eng._conn.commit()
    alerts = eng.send_breach_alerts()
    assert len(alerts) == 1
    assert alerts[0]  # non-empty alert_id


def test_send_breach_alerts_not_sent_twice():
    eng = _engine()
    now = _now()
    created = now - timedelta(minutes=228)
    deadline = created + timedelta(hours=4)
    eng._conn.execute(
        "INSERT INTO sla_tracking"
        "(tracking_id, finding_id, severity, policy_id, org_id, created_at, deadline, status)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("t-alert2", "f-alert2", "critical", None, "org1",
         created.isoformat(), deadline.isoformat(), "ON_TRACK"),
    )
    eng._conn.commit()
    first = eng.send_breach_alerts()
    second = eng.send_breach_alerts()
    assert len(first) == 1
    assert len(second) == 0  # already flagged


def test_send_breach_alerts_on_track_not_alerted():
    eng = _engine()
    eng.track_finding("f-safe", "low", org_id="org1")
    alerts = eng.send_breach_alerts()
    assert len(alerts) == 0


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


def test_dashboard_counts():
    eng = _engine()
    eng.track_finding("d1", "critical", org_id="org-dash")
    eng.track_finding("d2", "high", org_id="org-dash")
    eng.record_resolution("d2")
    dash = eng.get_dashboard(org_id="org-dash")
    assert dash["total_tracked"] == 2
    assert dash["on_track"] + dash["at_risk"] + dash["breached"] + dash["resolved"] == 2
    assert dash["resolved"] == 1
    assert "compliance_rate_30d" in dash


# ---------------------------------------------------------------------------
# Multi-org isolation
# ---------------------------------------------------------------------------


def test_org_isolation():
    eng = _engine()
    eng.track_finding("shared-id-1", "critical", org_id="orgA")
    eng.track_finding("shared-id-2", "high", org_id="orgB")
    at_risk_a = eng.get_at_risk_findings(org_id="orgA")
    at_risk_b = eng.get_at_risk_findings(org_id="orgB")
    ids_a = {r.finding_id for r in at_risk_a}
    ids_b = {r.finding_id for r in at_risk_b}
    assert ids_a.isdisjoint(ids_b)
