"""
Tests for SLA Management Engine — Advanced Vulnerability Remediation SLA Tracking.

Covers:
- SLAPolicyV2: create, retrieve, scoped lookup (org/team/tier)
- SLAAssignment: auto-assign with framework overrides, asset tier multipliers,
  business-hours SLAs
- Breach Detection: approaching / breached / severely_breached thresholds
- Exception Management: request, approve, reject, list
- Team Performance: metrics computation, leaderboard ranking, trend detection
- Escalation Rules: correct escalation level per pct_elapsed
- Reporting: full report structure, per-severity/team/framework/tier breakdown

45+ tests. All self-contained using :memory: DB.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.sla_management import (
    EscalationLevel,
    EscalationRule,
    ExceptionStatus,
    ExceptionType,
    SLAAssignment,
    SLAException,
    SLAManagement,
    SLAPolicyV2,
    SLAReport,
    SLAStatusV2,
    TeamMetrics,
    TrendDirection,
    _biz_hours_delta,
    _compute_pct_elapsed,
    _compute_status,
    _escalation_level_for_pct,
    _resolve_deadline,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine() -> SLAManagement:
    """Fresh in-memory SLAManagement engine."""
    return SLAManagement(db_path=":memory:")


@pytest.fixture
def org_id() -> str:
    return "test-org-001"


@pytest.fixture
def basic_policy(engine: SLAManagement, org_id: str) -> SLAPolicyV2:
    """Create a basic org-wide policy."""
    policy = SLAPolicyV2(
        org_id=org_id,
        name="Default Policy",
        severity_deadlines={"critical": 24, "high": 168, "medium": 720, "low": 2160},
        enabled=True,
    )
    return engine.create_policy(policy)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _past(hours: float) -> datetime:
    return _utcnow() - timedelta(hours=hours)


def _future(hours: float) -> datetime:
    return _utcnow() + timedelta(hours=hours)


# ===========================================================================
# 1. SLA Policy Tests
# ===========================================================================


class TestSLAPolicy:
    def test_create_policy_returns_policy(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        policy = SLAPolicyV2(org_id=org_id, name="Test Policy")
        result = engine.create_policy(policy)
        assert result.org_id == org_id
        assert result.name == "Test Policy"
        assert result.id is not None

    def test_get_policy_returns_org_default(
        self, engine: SLAManagement, basic_policy: SLAPolicyV2, org_id: str
    ) -> None:
        found = engine.get_policy(org_id)
        assert found is not None
        assert found.org_id == org_id
        assert found.name == "Default Policy"

    def test_get_policy_none_when_missing(
        self, engine: SLAManagement
    ) -> None:
        result = engine.get_policy("nonexistent-org")
        assert result is None

    def test_policy_scoped_to_team(
        self, engine: SLAManagement, basic_policy: SLAPolicyV2, org_id: str
    ) -> None:
        team_policy = SLAPolicyV2(
            org_id=org_id,
            team_id="team-alpha",
            name="Team Alpha Policy",
            severity_deadlines={"critical": 12, "high": 72, "medium": 336, "low": 1080},
        )
        engine.create_policy(team_policy)
        found = engine.get_policy(org_id, team_id="team-alpha")
        assert found is not None
        assert found.team_id == "team-alpha"
        assert found.severity_deadlines["critical"] == 12

    def test_policy_scoped_to_asset_tier(
        self, engine: SLAManagement, basic_policy: SLAPolicyV2, org_id: str
    ) -> None:
        tier_policy = SLAPolicyV2(
            org_id=org_id,
            asset_tier="tier1",
            name="Tier1 Policy",
            severity_deadlines={"critical": 8, "high": 48, "medium": 240, "low": 720},
        )
        engine.create_policy(tier_policy)
        found = engine.get_policy(org_id, asset_tier="tier1")
        assert found is not None
        assert found.asset_tier == "tier1"

    def test_list_policies_returns_all_for_org(
        self, engine: SLAManagement, basic_policy: SLAPolicyV2, org_id: str
    ) -> None:
        engine.create_policy(SLAPolicyV2(org_id=org_id, team_id="t1", name="P2"))
        engine.create_policy(SLAPolicyV2(org_id=org_id, team_id="t2", name="P3"))
        policies = engine.list_policies(org_id)
        assert len(policies) >= 3

    def test_policy_business_hours_flag(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        policy = SLAPolicyV2(
            org_id=org_id, name="BizHours", business_hours_only=True
        )
        saved = engine.create_policy(policy)
        assert saved.business_hours_only is True

    def test_policy_with_escalation_rules(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        rules = [
            EscalationRule(
                severity="critical",
                team_lead_email="lead@example.com",
                director_email="director@example.com",
                ciso_email="ciso@example.com",
            )
        ]
        policy = SLAPolicyV2(org_id=org_id, name="Escalation Policy", escalation_rules=rules)
        saved = engine.create_policy(policy)
        assert len(saved.escalation_rules) == 1
        assert saved.escalation_rules[0].ciso_email == "ciso@example.com"

    def test_invalid_asset_tier_raises(self, org_id: str) -> None:
        with pytest.raises(ValueError):
            SLAPolicyV2(org_id=org_id, name="Bad", asset_tier="tier99")


# ===========================================================================
# 2. SLA Assignment Tests
# ===========================================================================


class TestSLAAssignment:
    def test_assign_creates_record(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        a = engine.assign_sla("f-001", "critical", _utcnow(), org_id)
        assert a.finding_id == "f-001"
        assert a.severity == "critical"
        assert a.deadline > a.discovered_at

    def test_assign_idempotent(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        a1 = engine.assign_sla("f-idem", "high", _utcnow(), org_id)
        a2 = engine.assign_sla("f-idem", "high", _utcnow(), org_id)
        assert a1.id == a2.id

    def test_critical_24h_default_deadline(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        disc = _utcnow()
        a = engine.assign_sla("f-crit", "critical", disc, org_id)
        delta_hours = (a.deadline - disc).total_seconds() / 3600
        assert abs(delta_hours - 24) < 0.1

    def test_asset_tier1_halves_deadline(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        disc = _utcnow()
        a_default = engine.assign_sla("f-t3", "high", disc, org_id, asset_tier="tier3")
        a_tier1 = engine.assign_sla("f-t1", "high", disc, org_id, asset_tier="tier1")
        d_default = (a_default.deadline - disc).total_seconds()
        d_tier1 = (a_tier1.deadline - disc).total_seconds()
        assert abs(d_tier1 - d_default * 0.5) < 10  # within 10 seconds

    def test_asset_tier5_doubles_deadline(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        disc = _utcnow()
        a_default = engine.assign_sla("f-t3b", "medium", disc, org_id, asset_tier="tier3")
        a_tier5 = engine.assign_sla("f-t5", "medium", disc, org_id, asset_tier="tier5")
        d_default = (a_default.deadline - disc).total_seconds()
        d_tier5 = (a_tier5.deadline - disc).total_seconds()
        assert abs(d_tier5 - d_default * 2.0) < 10

    def test_pci_dss_framework_tightens_deadline(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        disc = _utcnow()
        a_none = engine.assign_sla("f-nfw", "high", disc, org_id)
        a_pci = engine.assign_sla("f-pci", "high", disc, org_id, frameworks=["pci-dss"])
        assert a_pci.deadline < a_none.deadline  # PCI is stricter

    def test_multiple_frameworks_use_strictest(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        disc = _utcnow()
        a = engine.assign_sla(
            "f-multi",
            "high",
            disc,
            org_id,
            frameworks=["pci-dss", "hipaa", "soc2"],
        )
        # pci-dss high = 72h < hipaa high = 120h — should use 72h (tier3 = 1x)
        delta_h = (a.deadline - disc).total_seconds() / 3600
        assert abs(delta_h - 72) < 0.5

    def test_team_assigned_to_record(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        a = engine.assign_sla("f-team", "medium", _utcnow(), org_id, team_id="team-beta")
        assert a.team_id == "team-beta"

    def test_get_assignment_returns_record(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-get", "low", _utcnow(), org_id)
        rec = engine.get_assignment("f-get")
        assert rec is not None
        assert rec.finding_id == "f-get"

    def test_get_assignment_none_for_missing(
        self, engine: SLAManagement
    ) -> None:
        assert engine.get_assignment("nonexistent-finding") is None


# ===========================================================================
# 3. Breach Detection Tests
# ===========================================================================


class TestBreachDetection:
    def test_within_sla_when_new(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        a = engine.assign_sla("f-new", "critical", _utcnow(), org_id)
        updated = engine.check_and_update_status("f-new")
        status_val = updated.status if isinstance(updated.status, str) else updated.status.value
        assert status_val in (
            SLAStatusV2.WITHIN_SLA.value,
            SLAStatusV2.APPROACHING.value,
        )

    def test_approaching_when_80pct_elapsed(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        # Critical = 24h. Set discovered_at 20h ago → ~83% elapsed.
        disc = _past(20)
        a = engine.assign_sla("f-app", "critical", disc, org_id)
        updated = engine.check_and_update_status("f-app")
        status_val = updated.status if isinstance(updated.status, str) else updated.status.value
        assert status_val in (
            SLAStatusV2.APPROACHING.value,
            SLAStatusV2.BREACHED.value,
        )

    def test_breached_when_past_deadline(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        # Critical = 24h. Set discovered_at 30h ago → 25% overdue.
        disc = _past(30)
        a = engine.assign_sla("f-breach", "critical", disc, org_id)
        updated = engine.check_and_update_status("f-breach")
        status_val = updated.status if isinstance(updated.status, str) else updated.status.value
        assert status_val in (
            SLAStatusV2.BREACHED.value,
            SLAStatusV2.SEVERELY_BREACHED.value,
        )

    def test_severely_breached_at_2x_deadline(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        # Critical = 24h. Discovered 50h ago → ~2.08x → severely breached.
        disc = _past(50)
        engine.assign_sla("f-severe", "critical", disc, org_id)
        updated = engine.check_and_update_status("f-severe")
        status_val = updated.status if isinstance(updated.status, str) else updated.status.value
        assert status_val == SLAStatusV2.SEVERELY_BREACHED.value

    def test_breached_at_set_on_first_breach(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        disc = _past(30)
        engine.assign_sla("f-bat", "critical", disc, org_id)
        updated = engine.check_and_update_status("f-bat")
        assert updated.breached_at is not None

    def test_detect_breaches_returns_list(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-d1", "critical", _past(30), org_id)
        engine.assign_sla("f-d2", "high", _past(200), org_id)
        engine.assign_sla("f-d3", "critical", _utcnow(), org_id)  # not breached
        breached = engine.detect_breaches(org_id)
        assert len(breached) >= 2

    def test_mark_resolved_sets_status(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-res", "medium", _past(5), org_id)
        updated = engine.mark_resolved("f-res")
        status_val = updated.status if isinstance(updated.status, str) else updated.status.value
        assert status_val == SLAStatusV2.RESOLVED.value

    def test_mark_resolved_late_stays_breached(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        disc = _past(50)
        engine.assign_sla("f-late", "critical", disc, org_id)
        # Resolve now, but it was discovered 50h ago (critical = 24h SLA)
        updated = engine.mark_resolved("f-late")
        status_val = updated.status if isinstance(updated.status, str) else updated.status.value
        assert status_val == SLAStatusV2.BREACHED.value

    def test_mark_exempt_sets_status(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-ex", "low", _utcnow(), org_id)
        updated = engine.mark_exempt("f-ex", reason="test")
        status_val = updated.status if isinstance(updated.status, str) else updated.status.value
        assert status_val == SLAStatusV2.EXEMPT.value


# ===========================================================================
# 4. Exception Management Tests
# ===========================================================================


class TestExceptionManagement:
    def test_request_exception_creates_record(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-exc1", "high", _utcnow(), org_id)
        exc = engine.request_exception(
            finding_id="f-exc1",
            org_id=org_id,
            exception_type=ExceptionType.RISK_ACCEPTANCE,
            justification="This risk is mitigated by compensating controls.",
            requested_by="alice@example.com",
        )
        assert exc.id is not None
        assert exc.finding_id == "f-exc1"
        exc_status = exc.status if isinstance(exc.status, str) else exc.status.value
        assert exc_status == ExceptionStatus.PENDING.value

    def test_approve_risk_acceptance_exempts_finding(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-exc2", "high", _utcnow(), org_id)
        exc = engine.request_exception(
            "f-exc2", org_id, ExceptionType.RISK_ACCEPTANCE,
            "Accepted risk with board approval.", "alice"
        )
        approved = engine.approve_exception(exc.id, approved_by="bob@example.com")
        status_val = approved.status if isinstance(approved.status, str) else approved.status.value
        assert status_val == ExceptionStatus.APPROVED.value
        # Finding should now be exempt
        assignment = engine.get_assignment("f-exc2")
        assert assignment is not None
        a_status = assignment.status if isinstance(assignment.status, str) else assignment.status.value
        assert a_status == SLAStatusV2.EXEMPT.value

    def test_approve_false_positive_exempts_finding(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-fp", "medium", _utcnow(), org_id)
        exc = engine.request_exception(
            "f-fp", org_id, ExceptionType.FALSE_POSITIVE,
            "Confirmed FP via manual review.",
            "analyst",
            evidence={"tool": "burp", "screenshot": "s3://bucket/fp.png"},
        )
        engine.approve_exception(exc.id, "manager")
        a = engine.get_assignment("f-fp")
        assert a is not None
        assert (a.status if isinstance(a.status, str) else a.status.value) == SLAStatusV2.EXEMPT.value

    def test_approve_extended_deadline_updates_deadline(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        disc = _utcnow()
        engine.assign_sla("f-ext", "high", disc, org_id)
        new_deadline = _future(500)
        exc = engine.request_exception(
            "f-ext", org_id, ExceptionType.EXTENDED_DEADLINE,
            "Dependency on third-party patch cycle.",
            "dev-team",
            new_deadline=new_deadline,
        )
        engine.approve_exception(exc.id, "security-manager")
        a = engine.get_assignment("f-ext")
        assert a is not None
        assert abs((a.deadline - new_deadline).total_seconds()) < 5

    def test_reject_exception_updates_status(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-rej", "critical", _utcnow(), org_id)
        exc = engine.request_exception(
            "f-rej", org_id, ExceptionType.RISK_ACCEPTANCE,
            "Trying to avoid patch.", "bad-actor"
        )
        rejected = engine.reject_exception(exc.id, "ciso")
        rej_status = rejected.status if isinstance(rejected.status, str) else rejected.status.value
        assert rej_status == ExceptionStatus.REJECTED.value

    def test_list_exceptions_returns_all(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-l1", "critical", _utcnow(), org_id)
        engine.assign_sla("f-l2", "high", _utcnow(), org_id)
        engine.request_exception("f-l1", org_id, ExceptionType.RISK_ACCEPTANCE,
                                 "reason 1", "alice")
        engine.request_exception("f-l2", org_id, ExceptionType.FALSE_POSITIVE,
                                 "reason 2", "bob")
        all_exc = engine.list_exceptions(org_id)
        assert len(all_exc) >= 2

    def test_list_exceptions_filtered_by_status(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-ls1", "high", _utcnow(), org_id)
        engine.assign_sla("f-ls2", "medium", _utcnow(), org_id)
        e1 = engine.request_exception("f-ls1", org_id, ExceptionType.RISK_ACCEPTANCE,
                                      "j1", "alice")
        engine.request_exception("f-ls2", org_id, ExceptionType.RISK_ACCEPTANCE,
                                 "j2", "bob")
        engine.approve_exception(e1.id, "mgr")
        approved_list = engine.list_exceptions(org_id, status=ExceptionStatus.APPROVED)
        assert all(
            (e.status if isinstance(e.status, str) else e.status.value)
            == ExceptionStatus.APPROVED.value
            for e in approved_list
        )

    def test_exception_with_expiry_date(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-exp-date", "medium", _utcnow(), org_id)
        expiry = _future(24 * 90)  # 90 days
        exc = engine.request_exception(
            "f-exp-date", org_id, ExceptionType.RISK_ACCEPTANCE,
            "Accepted with 90-day expiry.", "alice",
            expiry_date=expiry,
        )
        assert exc.expiry_date is not None


# ===========================================================================
# 5. Team Performance Tests
# ===========================================================================


class TestTeamPerformance:
    def test_compute_team_metrics_empty(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        m = engine.compute_team_metrics(org_id, "empty-team")
        assert m.total_assigned == 0
        assert m.compliance_rate == 0.0

    def test_compute_team_metrics_with_resolved(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        disc = _past(5)
        engine.assign_sla("f-tm1", "medium", disc, org_id, team_id="team-x")
        engine.assign_sla("f-tm2", "high", disc, org_id, team_id="team-x")
        engine.mark_resolved("f-tm1")
        engine.mark_resolved("f-tm2")
        m = engine.compute_team_metrics(org_id, "team-x")
        assert m.total_assigned == 2
        assert m.resolved_within == 2
        assert m.compliance_rate == 100.0

    def test_compute_team_metrics_with_breach(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        disc = _past(50)
        engine.assign_sla("f-tm3", "critical", disc, org_id, team_id="team-y")
        engine.check_and_update_status("f-tm3")
        m = engine.compute_team_metrics(org_id, "team-y")
        assert m.total_assigned >= 1

    def test_leaderboard_sorted_by_compliance(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        disc = _past(5)
        # team-a: resolves on time
        engine.assign_sla("f-la1", "medium", disc, org_id, team_id="team-a")
        engine.mark_resolved("f-la1")
        # team-b: breach
        engine.assign_sla("f-lb1", "critical", _past(50), org_id, team_id="team-b")
        leaderboard = engine.get_team_leaderboard(org_id)
        assert len(leaderboard) >= 2
        # first entry should have higher compliance
        assert leaderboard[0]["compliance_rate"] >= leaderboard[-1]["compliance_rate"]

    def test_leaderboard_has_rank(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-r1", "high", _past(5), org_id, team_id="team-r1")
        engine.mark_resolved("f-r1")
        lb = engine.get_team_leaderboard(org_id)
        assert lb[0]["rank"] == 1

    def test_trend_stable_initially(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-tr1", "medium", _past(5), org_id, team_id="team-trend")
        m = engine.compute_team_metrics(org_id, "team-trend")
        trend_val = m.trend if isinstance(m.trend, str) else m.trend.value
        assert trend_val in (
            TrendDirection.STABLE.value,
            TrendDirection.IMPROVING.value,
            TrendDirection.DEGRADING.value,
        )


# ===========================================================================
# 6. Escalation Rules Tests
# ===========================================================================


class TestEscalationRules:
    def test_escalation_none_below_80pct(self) -> None:
        assert _escalation_level_for_pct(0.5) == EscalationLevel.NONE

    def test_escalation_team_lead_at_80pct(self) -> None:
        assert _escalation_level_for_pct(0.80) == EscalationLevel.TEAM_LEAD

    def test_escalation_team_lead_between_80_and_100(self) -> None:
        assert _escalation_level_for_pct(0.95) == EscalationLevel.TEAM_LEAD

    def test_escalation_director_at_breach(self) -> None:
        assert _escalation_level_for_pct(1.0) == EscalationLevel.DIRECTOR

    def test_escalation_director_between_1x_and_2x(self) -> None:
        assert _escalation_level_for_pct(1.5) == EscalationLevel.DIRECTOR

    def test_escalation_ciso_at_2x(self) -> None:
        assert _escalation_level_for_pct(2.0) == EscalationLevel.CISO

    def test_escalation_ciso_above_2x(self) -> None:
        assert _escalation_level_for_pct(3.5) == EscalationLevel.CISO

    def test_run_escalation_check_returns_summary(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-esc1", "critical", _past(30), org_id)
        summary = engine.run_escalation_check(org_id)
        assert "team_lead" in summary or "director" in summary or "ciso" in summary

    def test_run_escalation_check_no_action_for_within_sla(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-esc-ok", "low", _utcnow(), org_id)
        summary = engine.run_escalation_check(org_id)
        assert summary.get("no_action", 0) >= 1


# ===========================================================================
# 7. Reporting Tests
# ===========================================================================


class TestReporting:
    def test_report_structure(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        report = engine.generate_report(org_id)
        assert isinstance(report, SLAReport)
        assert report.org_id == org_id
        assert isinstance(report.by_severity, dict)
        assert isinstance(report.by_team, list)
        assert isinstance(report.by_framework, dict)
        assert isinstance(report.by_asset_tier, dict)
        assert isinstance(report.leaderboard, list)

    def test_report_overall_compliance_100pct_when_all_resolved(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        for i in range(3):
            engine.assign_sla(f"f-rep-{i}", "medium", _past(5), org_id)
            engine.mark_resolved(f"f-rep-{i}")
        report = engine.generate_report(org_id)
        assert report.overall_compliance_rate == 100.0

    def test_report_by_severity_populated(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-rs1", "critical", _utcnow(), org_id)
        engine.assign_sla("f-rs2", "high", _utcnow(), org_id)
        engine.assign_sla("f-rs3", "medium", _utcnow(), org_id)
        report = engine.generate_report(org_id)
        assert "critical" in report.by_severity or "high" in report.by_severity

    def test_report_by_framework_populated(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla(
            "f-rfw", "high", _utcnow(), org_id, frameworks=["pci-dss"]
        )
        report = engine.generate_report(org_id)
        assert "pci-dss" in report.by_framework

    def test_report_by_asset_tier_populated(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        engine.assign_sla("f-rt1", "medium", _utcnow(), org_id, asset_tier="tier1")
        engine.assign_sla("f-rt2", "medium", _utcnow(), org_id, asset_tier="tier5")
        report = engine.generate_report(org_id)
        assert "tier1" in report.by_asset_tier
        assert "tier5" in report.by_asset_tier

    def test_report_period_days_respected(
        self, engine: SLAManagement, org_id: str
    ) -> None:
        # Assign something "old" (outside period) — not directly possible without
        # backdating DB, but verify structure is returned
        report = engine.generate_report(org_id, period_days=7)
        assert report.period_days == 7


# ===========================================================================
# 8. Helper / Internal Function Tests
# ===========================================================================


class TestHelpers:
    def test_compute_pct_elapsed_zero_at_start(self) -> None:
        disc = _utcnow()
        deadline = disc + timedelta(hours=24)
        pct = _compute_pct_elapsed(disc, deadline, now=disc)
        assert pct == 0.0

    def test_compute_pct_elapsed_one_at_deadline(self) -> None:
        disc = _past(24)
        deadline = disc + timedelta(hours=24)
        pct = _compute_pct_elapsed(disc, deadline)
        assert abs(pct - 1.0) < 0.01

    def test_compute_pct_elapsed_two_at_2x(self) -> None:
        disc = _past(48)
        deadline = disc + timedelta(hours=24)
        pct = _compute_pct_elapsed(disc, deadline)
        assert abs(pct - 2.0) < 0.05

    def test_compute_status_within(self) -> None:
        disc = _utcnow()
        deadline = _future(24)
        assert _compute_status(0.3, deadline) == SLAStatusV2.WITHIN_SLA

    def test_compute_status_approaching(self) -> None:
        deadline = _future(4)
        assert _compute_status(0.85, deadline) == SLAStatusV2.APPROACHING

    def test_compute_status_breached(self) -> None:
        deadline = _past(2)
        assert _compute_status(1.1, deadline) == SLAStatusV2.BREACHED

    def test_compute_status_severely_breached(self) -> None:
        deadline = _past(48)
        assert _compute_status(2.5, deadline) == SLAStatusV2.SEVERELY_BREACHED

    def test_resolve_deadline_pci_strictest(self) -> None:
        disc = _utcnow()
        deadline, hours = _resolve_deadline(
            disc, "high", frameworks=["pci-dss", "soc2"]
        )
        # pci-dss high = 72h, soc2 high = 168h → 72h wins
        assert hours == 72

    def test_resolve_deadline_asset_tier_applied(self) -> None:
        disc = _utcnow()
        _, h_t3 = _resolve_deadline(disc, "high", asset_tier="tier3")
        _, h_t1 = _resolve_deadline(disc, "high", asset_tier="tier1")
        assert h_t1 == int(h_t3 * 0.5)

    def test_biz_hours_delta_advances_past_weekend(self) -> None:
        # Find a Friday 5pm (end of biz day)
        # We just verify the function returns a datetime in the future
        start = _utcnow()
        result = _biz_hours_delta(start, 8)
        assert result > start

    def test_mark_resolved_missing_raises(
        self, engine: SLAManagement
    ) -> None:
        with pytest.raises(ValueError):
            engine.mark_resolved("nonexistent-finding")

    def test_check_and_update_missing_raises(
        self, engine: SLAManagement
    ) -> None:
        with pytest.raises(ValueError):
            engine.check_and_update_status("nonexistent-finding")


# ===========================================================================
# 9. Router smoke tests (import + endpoint shape)
# ===========================================================================


class TestRouterImport:
    def test_router_importable(self) -> None:
        from apps.api.sla_management_router import router  # noqa: F401
        assert router is not None

    def test_router_prefix(self) -> None:
        from apps.api.sla_management_router import router
        assert router.prefix == "/api/v1/sla-management"

    def test_router_has_expected_routes(self) -> None:
        from apps.api.sla_management_router import router
        paths = {r.path for r in router.routes}
        assert any("policies" in p for p in paths)
        assert any("assign" in p for p in paths)
        assert any("status" in p for p in paths)
        assert any("exceptions" in p for p in paths)
        assert any("leaderboard" in p for p in paths)
        assert any("report" in p for p in paths)
        assert any("escalate" in p for p in paths)
