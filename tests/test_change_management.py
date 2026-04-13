"""
Tests for Change Management / CAB Engine — ALDECI.

Covers:
- Change request lifecycle (draft → submitted → reviewing → approved/rejected
  → implementing → completed/rolled_back)
- Risk scoring and auto-classification
- CAB approval workflow (approve, reject, conditional, multi-approver)
- Impact analysis attachment and risk override
- Rollback planning and execution tracking
- Change calendar: maintenance windows, freeze periods, conflict detection
- SLA expiry
- Metrics computation
- Router endpoints (FastAPI TestClient)

All tests use in-memory SQLite (:memory: via temp file) — no external deps.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Generator
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Environment setup before any project imports
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.change_management import (
    ApprovalDecision,
    CABApproval,
    ChangeAdvisoryBoard,
    ChangeCategory,
    ChangeManagementDB,
    ChangeRiskLevel,
    ChangeStatus,
    FreezePeriod,
    ImpactAnalysis,
    MaintenanceWindow,
    RollbackPlan,
    classify_risk_level,
    compute_risk_score,
    get_cab,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db(tmp_path) -> ChangeManagementDB:
    """Return a ChangeManagementDB backed by a temporary file."""
    db_file = str(tmp_path / "test_change.db")
    return ChangeManagementDB(db_path=db_file)


@pytest.fixture()
def cab(tmp_db) -> ChangeAdvisoryBoard:
    """Return a CAB engine backed by the temporary DB."""
    return ChangeAdvisoryBoard(db=tmp_db)


@pytest.fixture()
def simple_rollback() -> RollbackPlan:
    return RollbackPlan(
        steps=["Revert deployment", "Restart services"],
        validation_criteria=["Health check passes", "No errors in logs"],
        max_rollback_time_minutes=30,
        responsible_person="ops-team",
    )


@pytest.fixture()
def low_impact() -> ImpactAnalysis:
    return ImpactAnalysis(
        affected_services=["auth-service"],
        blast_radius_score=1.5,
        security_impact=False,
        data_migration_required=False,
        production_impact=False,
        estimated_downtime_minutes=0,
        user_impact_count=10,
    )


@pytest.fixture()
def high_impact() -> ImpactAnalysis:
    return ImpactAnalysis(
        affected_services=["auth-service", "billing", "api-gateway"],
        blast_radius_score=8.0,
        security_impact=True,
        data_migration_required=True,
        production_impact=True,
        estimated_downtime_minutes=90,
        user_impact_count=5000,
    )


def _make_change(cab: ChangeAdvisoryBoard, rollback: RollbackPlan, **kwargs):
    """Helper: create a change with defaults."""
    defaults = dict(
        title="Test change request",
        description="This is a test change with enough detail.",
        category=ChangeCategory.APPLICATION,
        requestor_id="user-1",
        requestor_name="Alice",
        rollback_plan=rollback,
    )
    defaults.update(kwargs)
    return cab.create_change_request(**defaults)


# ---------------------------------------------------------------------------
# 1. Pydantic model validation
# ---------------------------------------------------------------------------


class TestModels:
    def test_rollback_plan_requires_steps(self):
        with pytest.raises(Exception):
            RollbackPlan(steps=[], responsible_person="bob", max_rollback_time_minutes=30)

    def test_maintenance_window_end_before_start_raises(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(ValueError):
            MaintenanceWindow(
                name="bad",
                start_time=now + timedelta(hours=2),
                end_time=now + timedelta(hours=1),
            )

    def test_freeze_period_end_before_start_raises(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(ValueError):
            FreezePeriod(
                name="freeze",
                start_time=now + timedelta(hours=2),
                end_time=now + timedelta(hours=1),
                reason="holiday",
            )

    def test_change_request_scheduled_end_before_start_raises(self, simple_rollback):
        from core.change_management import ChangeRequest
        now = datetime.now(timezone.utc)
        with pytest.raises(ValueError):
            ChangeRequest(
                title="Bad schedule",
                description="A change with bad scheduling params set here.",
                category=ChangeCategory.APPLICATION,
                requestor_id="u1",
                requestor_name="Bob",
                rollback_plan=simple_rollback,
                scheduled_start=now + timedelta(hours=2),
                scheduled_end=now + timedelta(hours=1),
            )

    def test_impact_analysis_blast_radius_bounds(self):
        with pytest.raises(Exception):
            ImpactAnalysis(blast_radius_score=11.0)
        with pytest.raises(Exception):
            ImpactAnalysis(blast_radius_score=-1.0)


# ---------------------------------------------------------------------------
# 2. Risk scoring
# ---------------------------------------------------------------------------


class TestRiskScoring:
    def test_low_impact_score_is_small(self, low_impact):
        score = compute_risk_score(low_impact)
        assert score < 20.0

    def test_high_impact_score_is_large(self, high_impact):
        score = compute_risk_score(high_impact)
        assert score >= 60.0

    def test_score_capped_at_100(self):
        impact = ImpactAnalysis(
            blast_radius_score=10.0,
            security_impact=True,
            data_migration_required=True,
            production_impact=True,
            estimated_downtime_minutes=300,
            user_impact_count=100000,
        )
        assert compute_risk_score(impact) <= 100.0

    def test_classify_low_impact_standard(self, low_impact):
        level = classify_risk_level(low_impact)
        assert level == ChangeRiskLevel.STANDARD

    def test_classify_high_impact_normal(self, high_impact):
        level = classify_risk_level(high_impact)
        assert level == ChangeRiskLevel.NORMAL

    def test_security_production_combo_is_normal(self):
        impact = ImpactAnalysis(
            blast_radius_score=5.0,
            security_impact=True,
            production_impact=True,
        )
        assert classify_risk_level(impact) == ChangeRiskLevel.NORMAL


# ---------------------------------------------------------------------------
# 3. Change request creation
# ---------------------------------------------------------------------------


class TestCreateChange:
    def test_creates_in_draft(self, cab, simple_rollback):
        change = _make_change(cab, simple_rollback)
        assert change.status == ChangeStatus.DRAFT
        assert change.id

    def test_auto_classifies_risk_from_impact(self, cab, simple_rollback, low_impact):
        change = _make_change(cab, simple_rollback, impact_analysis=low_impact)
        assert change.risk_level == ChangeRiskLevel.STANDARD

    def test_high_impact_sets_normal_risk(self, cab, simple_rollback, high_impact):
        change = _make_change(cab, simple_rollback, impact_analysis=high_impact)
        assert change.risk_level == ChangeRiskLevel.NORMAL

    def test_impact_risk_score_populated(self, cab, simple_rollback, high_impact):
        change = _make_change(cab, simple_rollback, impact_analysis=high_impact)
        assert change.impact_analysis.risk_score > 0

    def test_standard_has_no_required_approvers(self, cab, simple_rollback, low_impact):
        change = _make_change(cab, simple_rollback, impact_analysis=low_impact)
        assert change.required_approvers == []

    def test_normal_has_required_approvers(self, cab, simple_rollback, high_impact):
        change = _make_change(cab, simple_rollback, impact_analysis=high_impact)
        assert len(change.required_approvers) > 0

    def test_audit_entry_created(self, cab, simple_rollback):
        change = _make_change(cab, simple_rollback)
        trail = cab.get_audit_trail(change.id)
        assert len(trail) == 1
        assert trail[0].action == "created"

    def test_persisted_to_db(self, cab, simple_rollback):
        change = _make_change(cab, simple_rollback)
        fetched = cab.get_change(change.id)
        assert fetched is not None
        assert fetched.title == change.title

    def test_get_nonexistent_returns_none(self, cab):
        assert cab.get_change("nonexistent-id") is None

    def test_tags_stored(self, cab, simple_rollback):
        change = _make_change(cab, simple_rollback, tags=["infra", "q4-2026"])
        fetched = cab.get_change(change.id)
        assert "infra" in fetched.tags


# ---------------------------------------------------------------------------
# 4. Submit lifecycle
# ---------------------------------------------------------------------------


class TestSubmitChange:
    def test_standard_auto_approved_on_submit(self, cab, simple_rollback, low_impact):
        change = _make_change(cab, simple_rollback, impact_analysis=low_impact)
        submitted = cab.submit_change(change.id, "user-1", "Alice")
        assert submitted.status == ChangeStatus.APPROVED

    def test_normal_goes_to_reviewing(self, cab, simple_rollback, high_impact):
        change = _make_change(cab, simple_rollback, impact_analysis=high_impact)
        submitted = cab.submit_change(change.id, "user-1", "Alice")
        assert submitted.status == ChangeStatus.REVIEWING

    def test_sla_deadline_set_for_normal(self, cab, simple_rollback, high_impact):
        change = _make_change(cab, simple_rollback, impact_analysis=high_impact)
        submitted = cab.submit_change(change.id, "user-1", "Alice")
        assert submitted.sla_review_deadline is not None

    def test_submit_non_draft_raises(self, cab, simple_rollback, high_impact):
        change = _make_change(cab, simple_rollback, impact_analysis=high_impact)
        cab.submit_change(change.id, "u1", "Alice")
        with pytest.raises(ValueError):
            cab.submit_change(change.id, "u1", "Alice")

    def test_submit_nonexistent_raises(self, cab):
        with pytest.raises(KeyError):
            cab.submit_change("bad-id", "u1", "Alice")

    def test_audit_entry_for_submit(self, cab, simple_rollback, high_impact):
        change = _make_change(cab, simple_rollback, impact_analysis=high_impact)
        cab.submit_change(change.id, "u1", "Alice")
        trail = cab.get_audit_trail(change.id)
        actions = [e.action for e in trail]
        assert "submitted" in actions


# ---------------------------------------------------------------------------
# 5. CAB approval workflow
# ---------------------------------------------------------------------------


class TestCABApproval:
    def _reviewing_change(self, cab, simple_rollback, high_impact):
        change = _make_change(cab, simple_rollback, impact_analysis=high_impact)
        return cab.submit_change(change.id, "u1", "Alice")

    def test_single_approver_approves(self, cab, simple_rollback, high_impact):
        change = self._reviewing_change(cab, simple_rollback, high_impact)
        approval = CABApproval(
            approver_id="mgr-1",
            approver_name="Bob",
            approver_role="change_manager",
            decision=ApprovalDecision.APPROVED,
        )
        updated, resolved = cab.add_approval(change.id, approval)
        # Still needs tech_lead
        assert not resolved
        assert updated.status == ChangeStatus.REVIEWING

    def test_all_approvers_approve_resolves(self, cab, simple_rollback, high_impact):
        change = self._reviewing_change(cab, simple_rollback, high_impact)
        for role in ["change_manager", "tech_lead"]:
            approval = CABApproval(
                approver_id=f"{role}-id",
                approver_name=role,
                approver_role=role,
                decision=ApprovalDecision.APPROVED,
            )
            updated, resolved = cab.add_approval(change.id, approval)
        assert resolved
        assert updated.status == ChangeStatus.APPROVED

    def test_rejection_immediately_resolves(self, cab, simple_rollback, high_impact):
        change = self._reviewing_change(cab, simple_rollback, high_impact)
        approval = CABApproval(
            approver_id="mgr-1",
            approver_name="Bob",
            approver_role="change_manager",
            decision=ApprovalDecision.REJECTED,
            comments="Too risky right now",
        )
        updated, resolved = cab.add_approval(change.id, approval)
        assert resolved
        assert updated.status == ChangeStatus.REJECTED

    def test_conditional_approval_counts(self, cab, simple_rollback, high_impact):
        change = self._reviewing_change(cab, simple_rollback, high_impact)
        for role in ["change_manager", "tech_lead"]:
            approval = CABApproval(
                approver_id=f"{role}-id",
                approver_name=role,
                approver_role=role,
                decision=ApprovalDecision.CONDITIONAL,
                conditions=["Must test in staging first"],
            )
            updated, resolved = cab.add_approval(change.id, approval)
        assert resolved
        assert updated.status == ChangeStatus.APPROVED

    def test_duplicate_approver_replaced(self, cab, simple_rollback, high_impact):
        """A second vote from the same approver replaces the first (non-terminal)."""
        change = self._reviewing_change(cab, simple_rollback, high_impact)
        # First vote: conditional (non-terminal — change stays reviewing)
        approval1 = CABApproval(
            approver_id="mgr-1",
            approver_name="Bob",
            approver_role="change_manager",
            decision=ApprovalDecision.CONDITIONAL,
            conditions=["Test in staging first"],
        )
        updated, _ = cab.add_approval(change.id, approval1)
        assert len([a for a in updated.approvals if a.approver_id == "mgr-1"]) == 1

        # Second vote from same approver: approved — replaces the conditional
        approval2 = CABApproval(
            approver_id="mgr-1",
            approver_name="Bob",
            approver_role="change_manager",
            decision=ApprovalDecision.APPROVED,
        )
        updated2, _ = cab.add_approval(change.id, approval2)
        mgr_approvals = [a for a in updated2.approvals if a.approver_id == "mgr-1"]
        assert len(mgr_approvals) == 1
        assert mgr_approvals[0].decision == ApprovalDecision.APPROVED

    def test_approval_on_wrong_status_raises(self, cab, simple_rollback):
        change = _make_change(cab, simple_rollback)  # DRAFT
        approval = CABApproval(
            approver_id="mgr-1", approver_name="Bob",
            approver_role="change_manager", decision=ApprovalDecision.APPROVED,
        )
        with pytest.raises(ValueError):
            cab.add_approval(change.id, approval)

    def test_direct_reject_from_draft(self, cab, simple_rollback):
        change = _make_change(cab, simple_rollback)
        rejected = cab.reject_change(change.id, "mgr-1", "Bob", "Not needed")
        assert rejected.status == ChangeStatus.REJECTED

    def test_audit_trail_captures_approval(self, cab, simple_rollback, high_impact):
        change = self._reviewing_change(cab, simple_rollback, high_impact)
        approval = CABApproval(
            approver_id="mgr-1", approver_name="Bob",
            approver_role="change_manager", decision=ApprovalDecision.APPROVED,
        )
        cab.add_approval(change.id, approval)
        trail = cab.get_audit_trail(change.id)
        actions = [e.action for e in trail]
        assert "approval_approved" in actions


# ---------------------------------------------------------------------------
# 6. Implementation lifecycle
# ---------------------------------------------------------------------------


class TestImplementation:
    def _approved_change(self, cab, simple_rollback, low_impact):
        change = _make_change(cab, simple_rollback, impact_analysis=low_impact)
        return cab.submit_change(change.id, "u1", "Alice")

    def test_start_implementation(self, cab, simple_rollback, low_impact):
        change = self._approved_change(cab, simple_rollback, low_impact)
        impl = cab.start_implementation(change.id, "eng-1", "Carol")
        assert impl.status == ChangeStatus.IMPLEMENTING
        assert impl.implementation_started_at is not None

    def test_complete_change(self, cab, simple_rollback, low_impact):
        change = self._approved_change(cab, simple_rollback, low_impact)
        cab.start_implementation(change.id, "eng-1", "Carol")
        done = cab.complete_change(change.id, "eng-1", "Carol", "All good", "PIR complete")
        assert done.status == ChangeStatus.COMPLETED
        assert done.implementation_completed_at is not None
        assert done.implementation_notes == "All good"
        assert done.post_implementation_review == "PIR complete"

    def test_rollback_from_implementing(self, cab, simple_rollback, low_impact):
        change = self._approved_change(cab, simple_rollback, low_impact)
        cab.start_implementation(change.id, "eng-1", "Carol")
        rolled = cab.rollback_change(change.id, "eng-1", "Carol", "Health check failed")
        assert rolled.status == ChangeStatus.ROLLED_BACK
        assert rolled.rollback_executed is True
        assert rolled.rollback_reason == "Health check failed"
        assert rolled.rollback_executed_at is not None

    def test_rollback_from_completed(self, cab, simple_rollback, low_impact):
        change = self._approved_change(cab, simple_rollback, low_impact)
        cab.start_implementation(change.id, "eng-1", "Carol")
        cab.complete_change(change.id, "eng-1", "Carol")
        rolled = cab.rollback_change(change.id, "eng-1", "Carol", "Regression found")
        assert rolled.status == ChangeStatus.ROLLED_BACK

    def test_implement_non_approved_raises(self, cab, simple_rollback):
        change = _make_change(cab, simple_rollback)  # DRAFT
        with pytest.raises(ValueError):
            cab.start_implementation(change.id, "eng-1", "Carol")

    def test_complete_non_implementing_raises(self, cab, simple_rollback, low_impact):
        change = self._approved_change(cab, simple_rollback, low_impact)
        with pytest.raises(ValueError):
            cab.complete_change(change.id, "eng-1", "Carol")

    def test_rollback_draft_raises(self, cab, simple_rollback):
        change = _make_change(cab, simple_rollback)
        with pytest.raises(ValueError):
            cab.rollback_change(change.id, "eng-1", "Carol", "reason")

    def test_full_lifecycle_audit_trail_length(self, cab, simple_rollback, low_impact):
        change = self._approved_change(cab, simple_rollback, low_impact)
        cab.start_implementation(change.id, "eng-1", "Carol")
        cab.complete_change(change.id, "eng-1", "Carol")
        trail = cab.get_audit_trail(change.id)
        # created, submitted (auto-approved = 1 step), implementation_started, completed
        assert len(trail) >= 3


# ---------------------------------------------------------------------------
# 7. Impact analysis
# ---------------------------------------------------------------------------


class TestImpactAnalysis:
    def test_attach_impact_updates_risk(self, cab, simple_rollback):
        change = _make_change(cab, simple_rollback)
        impact = ImpactAnalysis(
            affected_services=["svc-a"],
            blast_radius_score=1.0,
            security_impact=False,
        )
        updated = cab.assess_impact(change.id, impact, "u1", "Alice")
        assert updated.impact_analysis is not None
        assert updated.impact_analysis.risk_score >= 0

    def test_high_impact_upgrades_risk_level(self, cab, simple_rollback, high_impact):
        change = _make_change(cab, simple_rollback)
        assert change.risk_level == ChangeRiskLevel.NORMAL  # default
        updated = cab.assess_impact(change.id, high_impact, "u1", "Alice")
        assert updated.risk_level == ChangeRiskLevel.NORMAL
        assert len(updated.required_approvers) > 0

    def test_risk_score_stored_in_db(self, cab, simple_rollback, high_impact):
        change = _make_change(cab, simple_rollback)
        cab.assess_impact(change.id, high_impact, "u1", "Alice")
        fetched = cab.get_change(change.id)
        assert fetched.impact_analysis.risk_score > 0

    def test_override_risk_level(self, cab, simple_rollback):
        change = _make_change(cab, simple_rollback)
        updated = cab.override_risk_level(
            change.id, ChangeRiskLevel.EMERGENCY, "mgr-1", "Bob", "Urgent security patch"
        )
        assert updated.risk_level == ChangeRiskLevel.EMERGENCY

    def test_override_audit_trail(self, cab, simple_rollback):
        change = _make_change(cab, simple_rollback)
        cab.override_risk_level(change.id, ChangeRiskLevel.EMERGENCY, "mgr-1", "Bob", "justification")
        trail = cab.get_audit_trail(change.id)
        assert any(e.action == "risk_overridden" for e in trail)


# ---------------------------------------------------------------------------
# 8. Change calendar
# ---------------------------------------------------------------------------


class TestChangeCalendar:
    def _future_window(self, hours_from_now=24, duration=2):
        now = datetime.now(timezone.utc)
        return now + timedelta(hours=hours_from_now), now + timedelta(hours=hours_from_now + duration)

    def test_create_maintenance_window(self, cab):
        start, end = self._future_window()
        window = MaintenanceWindow(name="Nightly maintenance", start_time=start, end_time=end)
        created = cab.create_maintenance_window(window)
        assert created.id
        windows = cab.list_maintenance_windows()
        assert any(w.id == created.id for w in windows)

    def test_create_freeze_period(self, cab):
        start, end = self._future_window(hours_from_now=100, duration=48)
        period = FreezePeriod(
            name="Q4 Freeze", start_time=start, end_time=end, reason="Year-end freeze"
        )
        created = cab.create_freeze_period(period)
        assert created.id
        periods = cab.list_freeze_periods()
        assert any(p.id == created.id for p in periods)

    def test_no_conflict_outside_freeze(self, cab, simple_rollback):
        # Freeze is in the far future
        freeze_start = datetime.now(timezone.utc) + timedelta(days=30)
        freeze_end = freeze_start + timedelta(days=2)
        cab.create_freeze_period(FreezePeriod(
            name="Future freeze", start_time=freeze_start, end_time=freeze_end, reason="test"
        ))
        # Change is scheduled next week
        sched_start = datetime.now(timezone.utc) + timedelta(days=5)
        sched_end = sched_start + timedelta(hours=2)
        change = _make_change(
            cab, simple_rollback, scheduled_start=sched_start, scheduled_end=sched_end
        )
        result = cab.check_conflicts(change)
        assert not result.has_conflict

    def test_conflict_inside_freeze(self, cab, simple_rollback):
        now = datetime.now(timezone.utc)
        freeze_start = now + timedelta(hours=1)
        freeze_end = now + timedelta(hours=5)
        cab.create_freeze_period(FreezePeriod(
            name="Holiday freeze", start_time=freeze_start, end_time=freeze_end, reason="holiday"
        ))
        sched_start = now + timedelta(hours=2)
        sched_end = now + timedelta(hours=4)
        change = _make_change(
            cab, simple_rollback, scheduled_start=sched_start, scheduled_end=sched_end
        )
        result = cab.check_conflicts(change)
        assert result.has_conflict
        assert any(c["type"] == "freeze_period" for c in result.conflicts)

    def test_emergency_change_exempt_from_freeze_when_allowed(self, cab, simple_rollback):
        now = datetime.now(timezone.utc)
        freeze_start = now + timedelta(hours=1)
        freeze_end = now + timedelta(hours=5)
        cab.create_freeze_period(FreezePeriod(
            name="Soft freeze", start_time=freeze_start, end_time=freeze_end,
            reason="maintenance", exception_allowed=True
        ))
        sched_start = now + timedelta(hours=2)
        sched_end = now + timedelta(hours=3)
        change = _make_change(
            cab, simple_rollback, scheduled_start=sched_start, scheduled_end=sched_end
        )
        # Override to emergency
        cab.override_risk_level(change.id, ChangeRiskLevel.EMERGENCY, "mgr-1", "Bob", "urgent")
        change = cab.get_change(change.id)
        result = cab.check_conflicts(change)
        assert not result.has_conflict

    def test_no_conflict_without_schedule(self, cab, simple_rollback):
        change = _make_change(cab, simple_rollback)
        result = cab.check_conflicts(change)
        assert not result.has_conflict


# ---------------------------------------------------------------------------
# 9. SLA expiry
# ---------------------------------------------------------------------------


class TestSLAExpiry:
    def test_expire_stale_changes(self, cab, simple_rollback, high_impact):
        change = _make_change(cab, simple_rollback, impact_analysis=high_impact)
        submitted = cab.submit_change(change.id, "u1", "Alice")
        assert submitted.status == ChangeStatus.REVIEWING

        # Manually backdate the SLA deadline
        submitted.sla_review_deadline = datetime.now(timezone.utc) - timedelta(hours=1)
        cab._db.update_change(submitted)

        expired = cab.expire_stale_changes()
        assert change.id in expired
        fetched = cab.get_change(change.id)
        assert fetched.status == ChangeStatus.EXPIRED

    def test_non_stale_not_expired(self, cab, simple_rollback, high_impact):
        change = _make_change(cab, simple_rollback, impact_analysis=high_impact)
        cab.submit_change(change.id, "u1", "Alice")
        expired = cab.expire_stale_changes()
        assert change.id not in expired


# ---------------------------------------------------------------------------
# 10. Listing and filtering
# ---------------------------------------------------------------------------


class TestListing:
    def test_list_all_changes(self, cab, simple_rollback):
        for i in range(3):
            _make_change(cab, simple_rollback, title=f"Change {i}", description="Long enough description here.")
        changes = cab.list_changes()
        assert len(changes) >= 3

    def test_filter_by_status(self, cab, simple_rollback, low_impact, high_impact):
        c1 = _make_change(cab, simple_rollback, impact_analysis=low_impact)
        c2 = _make_change(cab, simple_rollback, impact_analysis=high_impact)
        cab.submit_change(c1.id, "u1", "Alice")
        cab.submit_change(c2.id, "u1", "Alice")
        approved = cab.list_changes(status="approved")
        reviewing = cab.list_changes(status="reviewing")
        assert any(c.id == c1.id for c in approved)
        assert any(c.id == c2.id for c in reviewing)

    def test_filter_by_risk_level(self, cab, simple_rollback, low_impact, high_impact):
        _make_change(cab, simple_rollback, impact_analysis=low_impact)
        _make_change(cab, simple_rollback, impact_analysis=high_impact)
        standards = cab.list_changes(risk_level="standard")
        normals = cab.list_changes(risk_level="normal")
        assert len(standards) >= 1
        assert len(normals) >= 1

    def test_filter_by_requestor(self, cab, simple_rollback):
        _make_change(cab, simple_rollback, requestor_id="user-alpha", requestor_name="Alpha")
        _make_change(cab, simple_rollback, requestor_id="user-beta", requestor_name="Beta")
        alpha = cab.list_changes(requestor_id="user-alpha")
        assert all(c.requestor_id == "user-alpha" for c in alpha)

    def test_pagination(self, cab, simple_rollback):
        for i in range(5):
            _make_change(cab, simple_rollback, title=f"Ch {i}", description="Description that is long enough.")
        page1 = cab.list_changes(limit=2, offset=0)
        page2 = cab.list_changes(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) >= 1
        ids1 = {c.id for c in page1}
        ids2 = {c.id for c in page2}
        assert ids1.isdisjoint(ids2)


# ---------------------------------------------------------------------------
# 11. Metrics
# ---------------------------------------------------------------------------


class TestMetrics:
    def test_metrics_empty(self, cab):
        m = cab.get_metrics(period_days=30)
        assert m.total_changes == 0
        assert m.success_rate == 0.0

    def test_metrics_counts(self, cab, simple_rollback, low_impact, high_impact):
        # Create completed change
        c1 = _make_change(cab, simple_rollback, impact_analysis=low_impact)
        cab.submit_change(c1.id, "u1", "Alice")
        cab.start_implementation(c1.id, "eng-1", "Carol")
        cab.complete_change(c1.id, "eng-1", "Carol")

        # Create rolled back change
        c2 = _make_change(cab, simple_rollback, impact_analysis=low_impact)
        cab.submit_change(c2.id, "u1", "Alice")
        cab.start_implementation(c2.id, "eng-1", "Carol")
        cab.rollback_change(c2.id, "eng-1", "Carol", "failed")

        m = cab.get_metrics(period_days=30)
        assert m.total_changes >= 2
        assert m.by_status.get("completed", 0) >= 1
        assert m.by_status.get("rolled_back", 0) >= 1
        assert m.success_rate > 0
        assert m.rollback_rate > 0

    def test_metrics_period_filtering(self, cab, simple_rollback):
        change = _make_change(cab, simple_rollback)
        m = cab.get_metrics(period_days=1)
        assert m.total_changes >= 1

    def test_emergency_rate_computed(self, cab, simple_rollback):
        change = _make_change(cab, simple_rollback)
        cab.override_risk_level(change.id, ChangeRiskLevel.EMERGENCY, "mgr-1", "Bob", "urgent")
        m = cab.get_metrics(period_days=30)
        assert m.emergency_rate > 0


# ---------------------------------------------------------------------------
# 12. Router endpoints
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def test_client(tmp_path_factory):
    """FastAPI test client with a fresh CAB instance."""
    db_file = str(tmp_path_factory.mktemp("router_db") / "router_test.db")
    db = ChangeManagementDB(db_path=db_file)
    cab_instance = ChangeAdvisoryBoard(db=db)

    from apps.api.change_management_router import router

    app = FastAPI()
    app.include_router(router)

    # Patch the module-level _cab in router
    with patch("apps.api.change_management_router._cab", cab_instance):
        with TestClient(app) as client:
            yield client


def _rollback_payload():
    return {
        "steps": ["Revert", "Restart"],
        "validation_criteria": ["Health check passes"],
        "max_rollback_time_minutes": 30,
        "responsible_person": "ops-team",
        "automated": False,
    }


def _create_payload(**overrides):
    base = {
        "title": "Router test change",
        "description": "A change submitted through the API router.",
        "category": "application",
        "requestor_id": "user-1",
        "requestor_name": "Alice",
        "rollback_plan": _rollback_payload(),
        "priority": "medium",
    }
    base.update(overrides)
    return base


class TestRouterEndpoints:
    def test_create_change_201(self, test_client):
        r = test_client.post("/api/v1/changes", json=_create_payload())
        assert r.status_code == 201
        data = r.json()
        assert data["status"] == "draft"
        assert data["id"]

    def test_list_changes_200(self, test_client):
        test_client.post("/api/v1/changes", json=_create_payload())
        r = test_client.get("/api/v1/changes")
        assert r.status_code == 200
        data = r.json()
        assert "items" in data
        assert data["total"] >= 1

    def test_get_change_200(self, test_client):
        r = test_client.post("/api/v1/changes", json=_create_payload())
        change_id = r.json()["id"]
        r2 = test_client.get(f"/api/v1/changes/{change_id}")
        assert r2.status_code == 200
        assert r2.json()["id"] == change_id

    def test_get_change_404(self, test_client):
        r = test_client.get("/api/v1/changes/nonexistent-id-xyz")
        assert r.status_code == 404

    def test_submit_change(self, test_client):
        r = test_client.post("/api/v1/changes", json=_create_payload())
        change_id = r.json()["id"]
        r2 = test_client.post(
            f"/api/v1/changes/{change_id}/submit",
            json={"actor_id": "u1", "actor_name": "Alice"},
        )
        assert r2.status_code == 200

    def test_get_audit_trail(self, test_client):
        r = test_client.post("/api/v1/changes", json=_create_payload())
        change_id = r.json()["id"]
        r2 = test_client.get(f"/api/v1/changes/{change_id}/audit")
        assert r2.status_code == 200
        data = r2.json()
        assert data["total"] >= 1

    def test_conflict_check_no_schedule(self, test_client):
        r = test_client.post("/api/v1/changes", json=_create_payload())
        change_id = r.json()["id"]
        r2 = test_client.get(f"/api/v1/changes/{change_id}/conflicts")
        assert r2.status_code == 200
        assert r2.json()["has_conflict"] is False

    def test_metrics_endpoint(self, test_client):
        r = test_client.get("/api/v1/changes/metrics/summary")
        assert r.status_code == 200
        data = r.json()
        assert "total_changes" in data
        assert "success_rate" in data

    def test_create_maintenance_window(self, test_client):
        now = datetime.now(timezone.utc)
        r = test_client.post("/api/v1/changes/calendar/windows", json={
            "name": "Test window",
            "start_time": (now + timedelta(days=1)).isoformat(),
            "end_time": (now + timedelta(days=1, hours=2)).isoformat(),
        })
        assert r.status_code == 201
        assert r.json()["name"] == "Test window"

    def test_list_maintenance_windows(self, test_client):
        r = test_client.get("/api/v1/changes/calendar/windows")
        assert r.status_code == 200
        assert "items" in r.json()

    def test_create_freeze_period(self, test_client):
        now = datetime.now(timezone.utc)
        r = test_client.post("/api/v1/changes/calendar/freezes", json={
            "name": "Q4 Freeze",
            "start_time": (now + timedelta(days=10)).isoformat(),
            "end_time": (now + timedelta(days=12)).isoformat(),
            "reason": "Year-end lock",
        })
        assert r.status_code == 201

    def test_list_freeze_periods(self, test_client):
        r = test_client.get("/api/v1/changes/calendar/freezes")
        assert r.status_code == 200
        assert "items" in r.json()

    def test_impact_assessment_endpoint(self, test_client):
        r = test_client.post("/api/v1/changes", json=_create_payload())
        change_id = r.json()["id"]
        r2 = test_client.post(f"/api/v1/changes/{change_id}/impact", json={
            "actor_id": "u1",
            "actor_name": "Alice",
            "impact": {
                "affected_services": ["svc-a"],
                "blast_radius_score": 3.0,
                "security_impact": False,
            },
        })
        assert r2.status_code == 200
        data = r2.json()
        assert data["impact_analysis"]["blast_radius_score"] == 3.0

    def test_risk_override_endpoint(self, test_client):
        r = test_client.post("/api/v1/changes", json=_create_payload())
        change_id = r.json()["id"]
        r2 = test_client.post(f"/api/v1/changes/{change_id}/risk-override", json={
            "actor_id": "mgr-1",
            "actor_name": "Bob",
            "new_risk": "emergency",
            "justification": "Critical security patch",
        })
        assert r2.status_code == 200
        assert r2.json()["risk_level"] == "emergency"

    def test_expire_stale_endpoint(self, test_client):
        r = test_client.post("/api/v1/changes/admin/expire-stale")
        assert r.status_code == 200
        assert "expired_count" in r.json()

    def test_full_lifecycle_via_router(self, test_client):
        """E2E: create → submit (auto-approved standard) → implement → complete."""
        payload = _create_payload()
        payload["impact_analysis"] = {
            "affected_services": ["low-risk-svc"],
            "blast_radius_score": 1.0,
            "security_impact": False,
            "data_migration_required": False,
            "production_impact": False,
            "estimated_downtime_minutes": 0,
            "user_impact_count": 5,
        }
        r = test_client.post("/api/v1/changes", json=payload)
        assert r.status_code == 201
        change_id = r.json()["id"]

        # Submit — standard risk auto-approves
        r2 = test_client.post(
            f"/api/v1/changes/{change_id}/submit",
            json={"actor_id": "u1", "actor_name": "Alice"},
        )
        assert r2.status_code == 200
        assert r2.json()["status"] == "approved"

        # Implement
        r3 = test_client.post(
            f"/api/v1/changes/{change_id}/implement",
            json={"actor_id": "eng-1", "actor_name": "Carol"},
        )
        assert r3.status_code == 200
        assert r3.json()["status"] == "implementing"

        # Complete
        r4 = test_client.post(
            f"/api/v1/changes/{change_id}/complete",
            json={
                "actor_id": "eng-1",
                "actor_name": "Carol",
                "implementation_notes": "Deployed successfully",
            },
        )
        assert r4.status_code == 200
        assert r4.json()["status"] == "completed"
