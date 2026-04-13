"""
Tests for the Regulatory Change Tracker — RegulatoryTracker + API router.

Coverage:
- Regulation / RegulatoryImpact Pydantic models
- RegulatoryTracker: add, assess_impact, get_upcoming, get_active,
  get_impact_summary, generate_action_plan, get_regulatory_timeline,
  get_tracker_stats, built-in seed data
- API router: all 8 endpoints

>= 30 tests total. All use in-memory SQLite to avoid I/O side-effects.

Compliance: SOC2 CC6.1 (Change management test coverage)
"""
from __future__ import annotations

import sys
import uuid
from typing import Any, Dict

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.regulatory_tracker import (
    Regulation,
    RegulatoryImpact,
    RegulatoryTracker,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tracker() -> RegulatoryTracker:
    """In-memory tracker pre-seeded with built-in regulations."""
    return RegulatoryTracker(db_path=":memory:", org_id="test-org")


@pytest.fixture
def sample_regulation() -> Regulation:
    return Regulation(
        framework="TEST",
        title="Test Reg v1",
        description="A test regulation",
        effective_date="2025-06-01",
        impact="medium",
        affected_controls=["CTRL-1", "CTRL-2"],
        status="upcoming",
        org_id="test-org",
    )


# ============================================================================
# Pydantic model tests
# ============================================================================


class TestRegulationModel:
    def test_defaults_assigned(self) -> None:
        reg = Regulation(
            framework="GDPR",
            title="Test",
            effective_date="2025-01-01",
            impact="low",
            org_id="org1",
        )
        assert reg.id  # auto-generated UUID
        assert reg.status == "upcoming"
        assert reg.affected_controls == []
        assert reg.description == ""

    def test_custom_id_preserved(self) -> None:
        custom_id = str(uuid.uuid4())
        reg = Regulation(
            id=custom_id,
            framework="NIS2",
            title="Custom",
            effective_date="2024-10-17",
            impact="high",
            org_id="org2",
        )
        assert reg.id == custom_id

    def test_all_fields_roundtrip(self, sample_regulation: Regulation) -> None:
        dumped = sample_regulation.model_dump()
        restored = Regulation(**dumped)
        assert restored.framework == "TEST"
        assert restored.affected_controls == ["CTRL-1", "CTRL-2"]


class TestRegulatoryImpactModel:
    def test_defaults(self) -> None:
        impact = RegulatoryImpact(regulation_id="reg-1")
        assert impact.gap_count == 0
        assert impact.controls_affected == []
        assert impact.remediation_needed is False
        assert impact.estimated_effort_days == 0.0

    def test_full_model(self) -> None:
        impact = RegulatoryImpact(
            regulation_id="reg-2",
            gap_count=5,
            controls_affected=["A", "B"],
            remediation_needed=True,
            estimated_effort_days=10.0,
        )
        assert impact.gap_count == 5
        assert len(impact.controls_affected) == 2


# ============================================================================
# RegulatoryTracker — core functionality
# ============================================================================


class TestRegulatoryTrackerInit:
    def test_init_creates_tracker(self, tracker: RegulatoryTracker) -> None:
        assert tracker.db_path == ":memory:"
        assert tracker.org_id == "test-org"

    def test_builtin_regulations_seeded(self, tracker: RegulatoryTracker) -> None:
        """All 6 built-in regulations must be present after init."""
        timeline = tracker.get_regulatory_timeline("test-org")
        assert len(timeline) >= 6

    def test_builtin_frameworks_present(self, tracker: RegulatoryTracker) -> None:
        stats = tracker.get_tracker_stats("test-org")
        frameworks = set(stats["by_framework"].keys())
        for expected in ("GDPR", "PCI-DSS", "SEC", "NIS2", "DORA", "AI-Act"):
            assert expected in frameworks, f"{expected} missing from builtins"

    def test_seed_is_idempotent(self) -> None:
        """Creating two trackers against the same DB should not duplicate seeds."""
        t1 = RegulatoryTracker(db_path=":memory:", org_id="idem-org")
        # _seed_builtins is called in __init__; call again manually to verify idempotency
        t1._seed_builtins()
        timeline = t1.get_regulatory_timeline("idem-org")
        # Expect exactly 6 built-ins, not 12
        assert len(timeline) == 6


class TestAddRegulation:
    def test_add_returns_id(
        self, tracker: RegulatoryTracker, sample_regulation: Regulation
    ) -> None:
        reg_id = tracker.add_regulation(sample_regulation)
        assert reg_id == sample_regulation.id

    def test_added_regulation_appears_in_upcoming(
        self, tracker: RegulatoryTracker, sample_regulation: Regulation
    ) -> None:
        tracker.add_regulation(sample_regulation)
        upcoming = tracker.get_upcoming("test-org")
        ids = [r.id for r in upcoming]
        assert sample_regulation.id in ids

    def test_add_active_regulation(self, tracker: RegulatoryTracker) -> None:
        reg = Regulation(
            framework="HIPAA",
            title="HIPAA Omnibus",
            effective_date="2013-03-26",
            impact="high",
            status="active",
            org_id="test-org",
        )
        tracker.add_regulation(reg)
        active = tracker.get_active("test-org")
        ids = [r.id for r in active]
        assert reg.id in ids

    def test_add_replace_on_same_id(
        self, tracker: RegulatoryTracker, sample_regulation: Regulation
    ) -> None:
        tracker.add_regulation(sample_regulation)
        # Replace with updated title
        updated = sample_regulation.model_copy(update={"title": "Test Reg v2"})
        tracker.add_regulation(updated)
        timeline = tracker.get_regulatory_timeline("test-org")
        titles = [r["title"] for r in timeline]
        assert "Test Reg v2" in titles
        assert "Test Reg v1" not in titles


class TestAssessImpact:
    def test_assess_returns_impact(
        self, tracker: RegulatoryTracker, sample_regulation: Regulation
    ) -> None:
        tracker.add_regulation(sample_regulation)
        impact = tracker.assess_impact(sample_regulation.id, "test-org")
        assert isinstance(impact, RegulatoryImpact)
        assert impact.regulation_id == sample_regulation.id

    def test_gap_count_matches_controls(
        self, tracker: RegulatoryTracker, sample_regulation: Regulation
    ) -> None:
        tracker.add_regulation(sample_regulation)
        impact = tracker.assess_impact(sample_regulation.id, "test-org")
        assert impact.gap_count == 2  # CTRL-1, CTRL-2
        assert impact.remediation_needed is True

    def test_effort_days_for_high_impact(self, tracker: RegulatoryTracker) -> None:
        reg = Regulation(
            framework="X",
            title="High Impact Reg",
            effective_date="2025-12-01",
            impact="high",
            affected_controls=["C1"],
            org_id="test-org",
        )
        tracker.add_regulation(reg)
        impact = tracker.assess_impact(reg.id, "test-org")
        assert impact.estimated_effort_days == 30.0

    def test_effort_days_for_low_impact(self, tracker: RegulatoryTracker) -> None:
        reg = Regulation(
            framework="Y",
            title="Low Impact Reg",
            effective_date="2025-12-01",
            impact="low",
            affected_controls=["C1"],
            org_id="test-org",
        )
        tracker.add_regulation(reg)
        impact = tracker.assess_impact(reg.id, "test-org")
        assert impact.estimated_effort_days == 3.0

    def test_assess_unknown_regulation_raises(
        self, tracker: RegulatoryTracker
    ) -> None:
        with pytest.raises(ValueError, match="not found"):
            tracker.assess_impact("nonexistent-id", "test-org")

    def test_assess_wrong_org_raises(
        self, tracker: RegulatoryTracker, sample_regulation: Regulation
    ) -> None:
        tracker.add_regulation(sample_regulation)
        with pytest.raises(ValueError, match="not found"):
            tracker.assess_impact(sample_regulation.id, "other-org")


class TestGetUpcomingActive:
    def test_get_upcoming_returns_only_upcoming(
        self, tracker: RegulatoryTracker
    ) -> None:
        upcoming = tracker.get_upcoming("test-org")
        for reg in upcoming:
            assert reg.status == "upcoming"

    def test_get_active_returns_only_active(
        self, tracker: RegulatoryTracker
    ) -> None:
        active = tracker.get_active("test-org")
        for reg in active:
            assert reg.status == "active"

    def test_org_isolation(self, tracker: RegulatoryTracker) -> None:
        """Regulations for org-A must not appear in org-B queries."""
        reg = Regulation(
            framework="ISO",
            title="ISO 27001",
            effective_date="2023-01-01",
            impact="medium",
            status="active",
            org_id="org-A",
        )
        tracker.add_regulation(reg)
        active_b = tracker.get_active("org-B")
        ids = [r.id for r in active_b]
        assert reg.id not in ids


class TestGetImpactSummary:
    def test_summary_has_required_keys(self, tracker: RegulatoryTracker) -> None:
        summary = tracker.get_impact_summary("test-org")
        for key in (
            "org_id",
            "total_regulations",
            "total_gaps",
            "total_effort_days",
            "high_impact_count",
            "frameworks_affected",
        ):
            assert key in summary, f"Missing key: {key}"

    def test_summary_counts_regulations(self, tracker: RegulatoryTracker) -> None:
        summary = tracker.get_impact_summary("test-org")
        assert summary["total_regulations"] >= 6

    def test_summary_high_impact_nonzero(self, tracker: RegulatoryTracker) -> None:
        summary = tracker.get_impact_summary("test-org")
        assert summary["high_impact_count"] >= 1

    def test_summary_effort_increases_after_assess(
        self, tracker: RegulatoryTracker, sample_regulation: Regulation
    ) -> None:
        tracker.add_regulation(sample_regulation)
        before = tracker.get_impact_summary("test-org")["total_effort_days"]
        tracker.assess_impact(sample_regulation.id, "test-org")
        after = tracker.get_impact_summary("test-org")["total_effort_days"]
        assert after >= before  # effort days added


class TestGenerateActionPlan:
    def test_plan_has_required_keys(
        self, tracker: RegulatoryTracker, sample_regulation: Regulation
    ) -> None:
        tracker.add_regulation(sample_regulation)
        plan = tracker.generate_action_plan(sample_regulation.id)
        for key in (
            "regulation_id",
            "framework",
            "title",
            "effective_date",
            "impact",
            "total_effort_days",
            "action_steps",
            "generated_at",
        ):
            assert key in plan, f"Missing key: {key}"

    def test_plan_has_six_steps(
        self, tracker: RegulatoryTracker, sample_regulation: Regulation
    ) -> None:
        tracker.add_regulation(sample_regulation)
        plan = tracker.generate_action_plan(sample_regulation.id)
        assert len(plan["action_steps"]) == 6

    def test_steps_are_ordered(
        self, tracker: RegulatoryTracker, sample_regulation: Regulation
    ) -> None:
        tracker.add_regulation(sample_regulation)
        plan = tracker.generate_action_plan(sample_regulation.id)
        steps = plan["action_steps"]
        for i, step in enumerate(steps, start=1):
            assert step["step"] == i

    def test_plan_unknown_regulation_raises(
        self, tracker: RegulatoryTracker
    ) -> None:
        with pytest.raises(ValueError, match="not found"):
            tracker.generate_action_plan("no-such-id")


class TestGetRegulatoryTimeline:
    def test_timeline_ordered_by_date(self, tracker: RegulatoryTracker) -> None:
        timeline = tracker.get_regulatory_timeline("test-org")
        dates = [r["effective_date"] for r in timeline]
        assert dates == sorted(dates)

    def test_timeline_contains_all_builtins(
        self, tracker: RegulatoryTracker
    ) -> None:
        timeline = tracker.get_regulatory_timeline("test-org")
        assert len(timeline) >= 6

    def test_timeline_has_required_fields(
        self, tracker: RegulatoryTracker
    ) -> None:
        timeline = tracker.get_regulatory_timeline("test-org")
        for entry in timeline:
            for key in ("id", "framework", "title", "effective_date", "impact", "status"):
                assert key in entry, f"Missing field: {key}"


class TestGetTrackerStats:
    def test_stats_has_required_keys(self, tracker: RegulatoryTracker) -> None:
        stats = tracker.get_tracker_stats("test-org")
        for key in ("org_id", "by_framework", "by_impact", "by_status"):
            assert key in stats

    def test_stats_by_impact_covers_known_levels(
        self, tracker: RegulatoryTracker
    ) -> None:
        stats = tracker.get_tracker_stats("test-org")
        # Built-ins include high, medium — both must be present
        by_impact = stats["by_impact"]
        assert "high" in by_impact
        assert "medium" in by_impact

    def test_stats_by_status_covers_builtin_statuses(
        self, tracker: RegulatoryTracker
    ) -> None:
        stats = tracker.get_tracker_stats("test-org")
        by_status = stats["by_status"]
        # Built-ins have active and upcoming entries
        assert "active" in by_status
        assert "upcoming" in by_status


# ============================================================================
# API Router tests
# ============================================================================


@pytest.fixture
def client():
    """TestClient with regulatory router mounted on a fresh app."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api import regulatory_tracker_router as rtr_module
    from core.regulatory_tracker import RegulatoryTracker as RT

    # Replace the module-level tracker with a fresh in-memory one
    fresh_tracker = RT(db_path=":memory:", org_id="default")
    rtr_module._tracker = fresh_tracker

    app = FastAPI()
    app.include_router(rtr_module.router)
    return TestClient(app)


class TestRegulatoryRouterEndpoints:
    def test_add_regulation_201(self, client) -> None:
        resp = client.post(
            "/api/v1/regulatory/regulations",
            json={
                "framework": "HIPAA",
                "title": "HIPAA Test Rule",
                "effective_date": "2025-01-01",
                "impact": "medium",
                "status": "upcoming",
            },
        )
        assert resp.status_code == 201
        assert "regulation_id" in resp.json()

    def test_add_regulation_invalid_impact(self, client) -> None:
        resp = client.post(
            "/api/v1/regulatory/regulations",
            json={
                "framework": "X",
                "title": "Bad Impact",
                "effective_date": "2025-01-01",
                "impact": "extreme",
            },
        )
        assert resp.status_code == 422

    def test_add_regulation_invalid_status(self, client) -> None:
        resp = client.post(
            "/api/v1/regulatory/regulations",
            json={
                "framework": "X",
                "title": "Bad Status",
                "effective_date": "2025-01-01",
                "impact": "low",
                "status": "obsolete",
            },
        )
        assert resp.status_code == 422

    def test_get_upcoming_returns_list(self, client) -> None:
        resp = client.get("/api/v1/regulatory/regulations/upcoming")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_active_returns_list(self, client) -> None:
        resp = client.get("/api/v1/regulatory/regulations/active")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_timeline_returns_ordered_list(self, client) -> None:
        resp = client.get("/api/v1/regulatory/regulations/timeline")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        if len(data) >= 2:
            dates = [r["effective_date"] for r in data]
            assert dates == sorted(dates)

    def test_get_impact_summary(self, client) -> None:
        resp = client.get("/api/v1/regulatory/impact/summary")
        assert resp.status_code == 200
        body = resp.json()
        assert "total_regulations" in body
        assert body["total_regulations"] >= 6

    def test_assess_impact_404_on_missing(self, client) -> None:
        resp = client.post("/api/v1/regulatory/impact/nonexistent-id")
        assert resp.status_code == 404

    def test_assess_impact_success(self, client) -> None:
        # Add a regulation first
        add_resp = client.post(
            "/api/v1/regulatory/regulations",
            json={
                "framework": "TEST",
                "title": "Router Impact Test",
                "effective_date": "2025-06-01",
                "impact": "high",
                "affected_controls": ["C1", "C2", "C3"],
                "status": "upcoming",
            },
        )
        reg_id = add_resp.json()["regulation_id"]
        resp = client.post(f"/api/v1/regulatory/impact/{reg_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["regulation_id"] == reg_id
        assert body["gap_count"] == 3
        assert body["remediation_needed"] is True

    def test_get_action_plan_404_on_missing(self, client) -> None:
        resp = client.get("/api/v1/regulatory/action-plan/no-such-id")
        assert resp.status_code == 404

    def test_get_action_plan_success(self, client) -> None:
        add_resp = client.post(
            "/api/v1/regulatory/regulations",
            json={
                "framework": "DORA",
                "title": "DORA Router Test",
                "effective_date": "2025-01-17",
                "impact": "high",
                "status": "active",
            },
        )
        reg_id = add_resp.json()["regulation_id"]
        resp = client.get(f"/api/v1/regulatory/action-plan/{reg_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert "action_steps" in body
        assert len(body["action_steps"]) == 6

    def test_get_stats(self, client) -> None:
        resp = client.get("/api/v1/regulatory/stats")
        assert resp.status_code == 200
        body = resp.json()
        assert "by_framework" in body
        assert "by_impact" in body
        assert "by_status" in body
