"""Tests for SLA Management Engine (suite-core/core/sla_manager.py).

Covers:
- Policy CRUD
- Finding tracking with deadline calculation per severity
- SLA status: WITHIN_SLA, AT_RISK, BREACHED
- Mark resolved within / outside SLA
- Mark exempt (risk-accepted)
- Compliance rate calculation
- MTTR by severity
- Escalation check
- Dashboard data
- Bulk tracking
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

# Ensure suite-core is on the path
_SUITE_CORE = str(Path(__file__).parent.parent / "suite-core")
if _SUITE_CORE not in sys.path:
    sys.path.insert(0, _SUITE_CORE)

from core.sla_manager import SLAManager, SLAPolicy, SLARecord, SLAStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_manager() -> SLAManager:
    """Return a fresh in-memory SLAManager."""
    return SLAManager(db_path=":memory:")


def _default_policy(org_id: str = "org-test") -> SLAPolicy:
    return SLAPolicy(
        org_id=org_id,
        name="Test Policy",
        severity_deadlines={"critical": 24, "high": 72, "medium": 336, "low": 720},
        escalation_chain=["security@example.com"],
        grace_period_hours=0,
        enabled=True,
    )


# ---------------------------------------------------------------------------
# Policy CRUD
# ---------------------------------------------------------------------------


class TestPolicyCRUD:
    def test_create_policy(self):
        mgr = _make_manager()
        policy = _default_policy()
        result = mgr.create_policy(policy)
        assert result.org_id == "org-test"
        assert result.name == "Test Policy"
        assert result.severity_deadlines["critical"] == 24

    def test_get_policy_none_when_missing(self):
        mgr = _make_manager()
        assert mgr.get_policy("nonexistent-org") is None

    def test_get_policy_returns_created(self):
        mgr = _make_manager()
        mgr.create_policy(_default_policy())
        result = mgr.get_policy("org-test")
        assert result is not None
        assert result.name == "Test Policy"

    def test_update_policy(self):
        mgr = _make_manager()
        mgr.create_policy(_default_policy())
        updated = mgr.update_policy("org-test", {"name": "Updated Policy", "grace_period_hours": 4})
        assert updated.name == "Updated Policy"
        assert updated.grace_period_hours == 4

    def test_update_policy_raises_if_missing(self):
        mgr = _make_manager()
        with pytest.raises(ValueError, match="No SLA policy found"):
            mgr.update_policy("ghost-org", {"name": "x"})

    def test_create_policy_upserts(self):
        mgr = _make_manager()
        p1 = _default_policy()
        p2 = SLAPolicy(org_id="org-test", name="V2 Policy", severity_deadlines={"critical": 12})
        mgr.create_policy(p1)
        mgr.create_policy(p2)
        result = mgr.get_policy("org-test")
        assert result is not None
        assert result.name == "V2 Policy"

    def test_policy_escalation_chain(self):
        mgr = _make_manager()
        policy = SLAPolicy(
            org_id="org-chain",
            name="Chain Policy",
            escalation_chain=["a@x.com", "b@x.com"],
        )
        mgr.create_policy(policy)
        result = mgr.get_policy("org-chain")
        assert result is not None
        assert result.escalation_chain == ["a@x.com", "b@x.com"]

    def test_policy_enabled_flag(self):
        mgr = _make_manager()
        policy = SLAPolicy(org_id="org-dis", name="Disabled", enabled=False)
        mgr.create_policy(policy)
        result = mgr.get_policy("org-dis")
        assert result is not None
        assert result.enabled is False


# ---------------------------------------------------------------------------
# Finding tracking
# ---------------------------------------------------------------------------


class TestFindingTracking:
    def test_track_finding_creates_record(self):
        mgr = _make_manager()
        disc = _now()
        rec = mgr.track_finding("f-001", "critical", disc, "org-a")
        assert rec.finding_id == "f-001"
        assert rec.severity == "critical"
        assert rec.org_id == "org-a"

    def test_track_finding_critical_deadline_24h(self):
        mgr = _make_manager()
        disc = _now()
        rec = mgr.track_finding("f-crit", "critical", disc, "org-a")
        expected = disc + timedelta(hours=24)
        delta = abs((rec.deadline - expected).total_seconds())
        assert delta < 5  # within 5 seconds

    def test_track_finding_high_deadline_72h(self):
        mgr = _make_manager()
        disc = _now()
        rec = mgr.track_finding("f-high", "high", disc, "org-a")
        expected = disc + timedelta(hours=72)
        delta = abs((rec.deadline - expected).total_seconds())
        assert delta < 5

    def test_track_finding_medium_deadline_336h(self):
        mgr = _make_manager()
        disc = _now()
        rec = mgr.track_finding("f-med", "medium", disc, "org-a")
        expected = disc + timedelta(hours=336)
        delta = abs((rec.deadline - expected).total_seconds())
        assert delta < 5

    def test_track_finding_low_deadline_720h(self):
        mgr = _make_manager()
        disc = _now()
        rec = mgr.track_finding("f-low", "low", disc, "org-a")
        expected = disc + timedelta(hours=720)
        delta = abs((rec.deadline - expected).total_seconds())
        assert delta < 5

    def test_track_finding_idempotent(self):
        mgr = _make_manager()
        disc = _now()
        rec1 = mgr.track_finding("f-idem", "high", disc, "org-a")
        rec2 = mgr.track_finding("f-idem", "critical", disc, "org-a")
        assert rec1.id == rec2.id
        assert rec2.severity == "high"  # original severity preserved

    def test_track_finding_with_policy_deadline(self):
        mgr = _make_manager()
        policy = SLAPolicy(
            org_id="org-custom",
            name="Custom",
            severity_deadlines={"critical": 12},
        )
        mgr.create_policy(policy)
        disc = _now()
        rec = mgr.track_finding("f-custom", "critical", disc, "org-custom")
        expected = disc + timedelta(hours=12)
        delta = abs((rec.deadline - expected).total_seconds())
        assert delta < 5

    def test_track_finding_with_grace_period(self):
        mgr = _make_manager()
        policy = SLAPolicy(
            org_id="org-grace",
            name="Grace",
            severity_deadlines={"critical": 24},
            grace_period_hours=4,
        )
        mgr.create_policy(policy)
        disc = _now()
        rec = mgr.track_finding("f-grace", "critical", disc, "org-grace")
        expected = disc + timedelta(hours=28)
        delta = abs((rec.deadline - expected).total_seconds())
        assert delta < 5

    def test_track_finding_severity_normalized_lowercase(self):
        mgr = _make_manager()
        disc = _now()
        rec = mgr.track_finding("f-case", "HIGH", disc, "org-a")
        assert rec.severity == "high"


# ---------------------------------------------------------------------------
# SLA Status
# ---------------------------------------------------------------------------


class TestSLAStatus:
    def test_within_sla_new_finding(self):
        mgr = _make_manager()
        disc = _now()
        mgr.track_finding("f-fresh", "critical", disc, "org-a")
        status = mgr.check_sla_status("f-fresh")
        assert status == SLAStatus.WITHIN_SLA

    def test_breached_past_deadline(self):
        mgr = _make_manager()
        disc = _now() - timedelta(hours=30)
        mgr.track_finding("f-breach", "critical", disc, "org-a")
        status = mgr.check_sla_status("f-breach")
        assert status == SLAStatus.BREACHED

    def test_at_risk_near_deadline(self):
        mgr = _make_manager()
        # Critical = 24h. Place discovered_at such that 90% of time has elapsed
        # (deadline - now < 20% of 24h = 4.8h)
        disc = _now() - timedelta(hours=20)  # 20h elapsed of 24h window
        mgr.track_finding("f-risk", "critical", disc, "org-a")
        status = mgr.check_sla_status("f-risk")
        assert status == SLAStatus.AT_RISK

    def test_exempt_status_not_overwritten(self):
        mgr = _make_manager()
        disc = _now() - timedelta(hours=100)
        mgr.track_finding("f-exempt", "critical", disc, "org-a")
        mgr.mark_exempt("f-exempt", "risk accepted")
        status = mgr.check_sla_status("f-exempt")
        assert status == SLAStatus.EXEMPT

    def test_unknown_finding_returns_within_sla(self):
        mgr = _make_manager()
        status = mgr.check_sla_status("nonexistent")
        assert status == SLAStatus.WITHIN_SLA

    def test_breached_status_persisted(self):
        mgr = _make_manager()
        disc = _now() - timedelta(hours=100)
        mgr.track_finding("f-persist", "critical", disc, "org-a")
        mgr.check_sla_status("f-persist")
        record = mgr.get_record("f-persist")
        assert record is not None
        assert record.status == SLAStatus.BREACHED


# ---------------------------------------------------------------------------
# Mark resolved
# ---------------------------------------------------------------------------


class TestMarkResolved:
    def test_mark_resolved_within_sla(self):
        mgr = _make_manager()
        disc = _now() - timedelta(hours=10)
        mgr.track_finding("f-res1", "critical", disc, "org-a")
        mgr.mark_resolved("f-res1")
        record = mgr.get_record("f-res1")
        assert record is not None
        assert record.resolved_at is not None
        assert record.status == SLAStatus.WITHIN_SLA

    def test_mark_resolved_outside_sla(self):
        mgr = _make_manager()
        disc = _now() - timedelta(hours=50)
        mgr.track_finding("f-res2", "critical", disc, "org-a")
        mgr.mark_resolved("f-res2")
        record = mgr.get_record("f-res2")
        assert record is not None
        assert record.status == SLAStatus.BREACHED

    def test_mark_resolved_with_custom_time(self):
        mgr = _make_manager()
        disc = _now() - timedelta(hours=100)
        mgr.track_finding("f-res3", "critical", disc, "org-a")
        resolved_at = disc + timedelta(hours=20)
        mgr.mark_resolved("f-res3", resolved_at=resolved_at)
        record = mgr.get_record("f-res3")
        assert record is not None
        # resolved 20h after disc, deadline is 24h → within SLA
        assert record.status == SLAStatus.WITHIN_SLA

    def test_mark_resolved_noop_if_not_tracked(self):
        mgr = _make_manager()
        # Should not raise
        mgr.mark_resolved("nonexistent-finding")


# ---------------------------------------------------------------------------
# Mark exempt
# ---------------------------------------------------------------------------


class TestMarkExempt:
    def test_mark_exempt_sets_status(self):
        mgr = _make_manager()
        disc = _now()
        mgr.track_finding("f-ex1", "high", disc, "org-a")
        mgr.mark_exempt("f-ex1", "risk accepted by CISO")
        record = mgr.get_record("f-ex1")
        assert record is not None
        assert record.status == SLAStatus.EXEMPT
        assert record.exempt_reason == "risk accepted by CISO"

    def test_exempt_overrides_breach(self):
        mgr = _make_manager()
        disc = _now() - timedelta(hours=100)
        mgr.track_finding("f-ex2", "critical", disc, "org-a")
        mgr.check_sla_status("f-ex2")  # marks as BREACHED
        mgr.mark_exempt("f-ex2", "accepted")
        record = mgr.get_record("f-ex2")
        assert record is not None
        assert record.status == SLAStatus.EXEMPT


# ---------------------------------------------------------------------------
# Queries: breached & at-risk
# ---------------------------------------------------------------------------


class TestQueries:
    def test_get_breached_returns_only_breached(self):
        mgr = _make_manager()
        disc_old = _now() - timedelta(hours=100)
        disc_new = _now()
        mgr.track_finding("f-b1", "critical", disc_old, "org-q")
        mgr.track_finding("f-b2", "high", disc_new, "org-q")
        mgr.check_sla_status("f-b1")
        mgr.check_sla_status("f-b2")
        breached = mgr.get_breached("org-q")
        ids = [r.finding_id for r in breached]
        assert "f-b1" in ids
        assert "f-b2" not in ids

    def test_get_at_risk_returns_approaching(self):
        mgr = _make_manager()
        # Critical = 24h. Discovering 22h ago means 2h remain → within 24h threshold
        disc = _now() - timedelta(hours=22)
        mgr.track_finding("f-ar1", "critical", disc, "org-q")
        at_risk = mgr.get_at_risk("org-q", hours_threshold=4.0)
        ids = [r.finding_id for r in at_risk]
        assert "f-ar1" in ids

    def test_get_at_risk_excludes_resolved(self):
        mgr = _make_manager()
        disc = _now() - timedelta(hours=22)
        mgr.track_finding("f-ar2", "critical", disc, "org-q")
        mgr.mark_resolved("f-ar2")
        at_risk = mgr.get_at_risk("org-q", hours_threshold=4.0)
        ids = [r.finding_id for r in at_risk]
        assert "f-ar2" not in ids

    def test_get_at_risk_excludes_exempt(self):
        mgr = _make_manager()
        disc = _now() - timedelta(hours=22)
        mgr.track_finding("f-ar3", "critical", disc, "org-q")
        mgr.mark_exempt("f-ar3", "accepted")
        at_risk = mgr.get_at_risk("org-q", hours_threshold=4.0)
        ids = [r.finding_id for r in at_risk]
        assert "f-ar3" not in ids


# ---------------------------------------------------------------------------
# Compliance rate
# ---------------------------------------------------------------------------


class TestComplianceRate:
    def test_100_percent_when_no_resolved(self):
        mgr = _make_manager()
        rate = mgr.get_sla_compliance_rate("org-c", period_days=30)
        assert rate == 100.0

    def test_compliance_rate_all_within_sla(self):
        mgr = _make_manager()
        for i in range(5):
            disc = _now() - timedelta(hours=5)
            mgr.track_finding(f"fc-{i}", "critical", disc, "org-c")
            mgr.mark_resolved(f"fc-{i}")
        rate = mgr.get_sla_compliance_rate("org-c")
        assert rate == 100.0

    def test_compliance_rate_mixed(self):
        mgr = _make_manager()
        # 2 within SLA
        for i in range(2):
            disc = _now() - timedelta(hours=5)
            mgr.track_finding(f"fm-w{i}", "critical", disc, "org-cm")
            mgr.mark_resolved(f"fm-w{i}")
        # 2 breached (resolved after deadline)
        for i in range(2):
            disc = _now() - timedelta(hours=100)
            mgr.track_finding(f"fm-b{i}", "critical", disc, "org-cm")
            mgr.mark_resolved(f"fm-b{i}")
        rate = mgr.get_sla_compliance_rate("org-cm")
        assert rate == 50.0

    def test_compliance_rate_period_filter(self):
        mgr = _make_manager()
        # Resolved long ago (outside 7-day period)
        old_disc = _now() - timedelta(days=100)
        mgr.track_finding("fm-old", "high", old_disc, "org-period")
        # Directly set resolved_at to an old date by resolving then overriding
        mgr.mark_resolved("fm-old", resolved_at=_now() - timedelta(days=90))
        rate = mgr.get_sla_compliance_rate("org-period", period_days=7)
        assert rate == 100.0  # Nothing in the 7-day window → default 100%


# ---------------------------------------------------------------------------
# MTTR by severity
# ---------------------------------------------------------------------------


class TestMTTR:
    def test_mttr_empty_org(self):
        mgr = _make_manager()
        result = mgr.get_mttr_by_severity("org-empty")
        assert result == {}

    def test_mttr_single_severity(self):
        mgr = _make_manager()
        disc = _now() - timedelta(hours=20)
        mgr.track_finding("fm-mttr1", "critical", disc, "org-mttr")
        mgr.mark_resolved("fm-mttr1", resolved_at=_now())
        mttr = mgr.get_mttr_by_severity("org-mttr")
        assert "critical" in mttr
        assert 19 <= mttr["critical"] <= 21  # approximately 20h

    def test_mttr_multiple_severities(self):
        mgr = _make_manager()
        for sev, hours in [("critical", 10), ("high", 50)]:
            disc = _now() - timedelta(hours=hours)
            mgr.track_finding(f"fm-ms-{sev}", sev, disc, "org-multi")
            mgr.mark_resolved(f"fm-ms-{sev}", resolved_at=_now())
        mttr = mgr.get_mttr_by_severity("org-multi")
        assert "critical" in mttr
        assert "high" in mttr
        assert mttr["critical"] < mttr["high"]

    def test_mttr_averages_multiple_findings(self):
        mgr = _make_manager()
        # 10h and 20h → avg 15h
        for i, hours in enumerate([10, 20]):
            disc = _now() - timedelta(hours=hours)
            mgr.track_finding(f"fm-avg-{i}", "high", disc, "org-avg")
            mgr.mark_resolved(f"fm-avg-{i}", resolved_at=_now())
        mttr = mgr.get_mttr_by_severity("org-avg")
        assert abs(mttr["high"] - 15.0) < 1.0


# ---------------------------------------------------------------------------
# Escalation check
# ---------------------------------------------------------------------------


class TestEscalation:
    def test_escalation_returns_zero_no_breaches(self):
        mgr = _make_manager()
        mgr.create_policy(_default_policy("org-esc"))
        count = mgr.run_escalation_check("org-esc")
        assert count == 0

    def test_escalation_counts_breached_records(self):
        mgr = _make_manager()
        mgr.create_policy(_default_policy("org-esc2"))
        disc = _now() - timedelta(hours=100)
        mgr.track_finding("f-esc1", "critical", disc, "org-esc2")
        mgr.track_finding("f-esc2", "high", disc, "org-esc2")
        mgr.check_sla_status("f-esc1")
        mgr.check_sla_status("f-esc2")
        count = mgr.run_escalation_check("org-esc2")
        assert count == 2

    def test_escalation_marks_records_escalated(self):
        mgr = _make_manager()
        mgr.create_policy(_default_policy("org-esc3"))
        disc = _now() - timedelta(hours=100)
        mgr.track_finding("f-esc3", "critical", disc, "org-esc3")
        mgr.check_sla_status("f-esc3")
        mgr.run_escalation_check("org-esc3")
        record = mgr.get_record("f-esc3")
        assert record is not None
        assert record.escalated is True

    def test_escalation_not_repeated(self):
        mgr = _make_manager()
        mgr.create_policy(_default_policy("org-esc4"))
        disc = _now() - timedelta(hours=100)
        mgr.track_finding("f-esc4", "critical", disc, "org-esc4")
        mgr.check_sla_status("f-esc4")
        count1 = mgr.run_escalation_check("org-esc4")
        count2 = mgr.run_escalation_check("org-esc4")
        assert count1 == 1
        assert count2 == 0  # already escalated


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


class TestDashboard:
    def test_dashboard_empty_org(self):
        mgr = _make_manager()
        dashboard = mgr.get_sla_dashboard("org-dash")
        assert dashboard["org_id"] == "org-dash"
        assert dashboard["total_findings"] == 0
        assert dashboard["compliance_rate"] == 100.0

    def test_dashboard_includes_all_fields(self):
        mgr = _make_manager()
        required_fields = [
            "org_id", "total_findings", "by_status", "by_severity",
            "compliance_rate", "mttr_by_severity", "breached", "at_risk",
            "sla_targets", "policy_enabled",
        ]
        dashboard = mgr.get_sla_dashboard("org-fields")
        for field in required_fields:
            assert field in dashboard, f"Missing field: {field}"

    def test_dashboard_counts_findings(self):
        mgr = _make_manager()
        disc = _now()
        for i in range(3):
            mgr.track_finding(f"fd-{i}", "high", disc, "org-count")
        dashboard = mgr.get_sla_dashboard("org-count")
        assert dashboard["total_findings"] == 3

    def test_dashboard_breached_list(self):
        mgr = _make_manager()
        disc = _now() - timedelta(hours=100)
        mgr.track_finding("fd-breach", "critical", disc, "org-dbreach")
        mgr.check_sla_status("fd-breach")
        dashboard = mgr.get_sla_dashboard("org-dbreach")
        assert len(dashboard["breached"]) == 1
        assert dashboard["breached"][0]["finding_id"] == "fd-breach"


# ---------------------------------------------------------------------------
# Bulk tracking
# ---------------------------------------------------------------------------


class TestBulkTrack:
    def test_bulk_track_returns_count(self):
        mgr = _make_manager()
        findings = [
            {"finding_id": f"bulk-{i}", "severity": "high", "discovered_at": _now()}
            for i in range(5)
        ]
        count = mgr.bulk_track(findings, "org-bulk")
        assert count == 5

    def test_bulk_track_idempotent(self):
        mgr = _make_manager()
        findings = [{"finding_id": "bulk-idem", "severity": "critical", "discovered_at": _now()}]
        mgr.bulk_track(findings, "org-bulk2")
        count2 = mgr.bulk_track(findings, "org-bulk2")
        # Second run: idempotent (finding already tracked, still returns 1 since track_finding returns existing)
        assert count2 == 1

    def test_bulk_track_skips_missing_id(self):
        mgr = _make_manager()
        findings = [
            {"finding_id": "bulk-valid", "severity": "high", "discovered_at": _now()},
            {"severity": "high", "discovered_at": _now()},  # no finding_id
        ]
        count = mgr.bulk_track(findings, "org-bulk3")
        assert count == 1

    def test_bulk_track_iso_string_discovered_at(self):
        mgr = _make_manager()
        findings = [
            {
                "finding_id": "bulk-iso",
                "severity": "medium",
                "discovered_at": _now().isoformat(),
            }
        ]
        count = mgr.bulk_track(findings, "org-bulk4")
        assert count == 1
        record = mgr.get_record("bulk-iso")
        assert record is not None
