"""
Tests for Vulnerability Lifecycle Tracker — Phase 11 addition.

Covers:
- LifecycleStage enum values
- LifecycleEvent model construction
- VulnLifecycle.validate_transition (all valid + invalid paths)
- VulnLifecycle.transition (happy path, invalid transition, initial discovery)
- VulnLifecycle.get_lifecycle (ordering, empty)
- VulnLifecycle.get_current_stage (none, after transitions)
- VulnLifecycle.get_stage_distribution (empty, populated)
- VulnLifecycle.get_avg_time_per_stage (no data, single cycle)
- VulnLifecycle.get_bottlenecks (ordering)
- VulnLifecycle.get_flow_metrics (throughput, cycle time, lead time, wip, reopen)
- Router endpoint smoke tests (all 8 endpoints via FastAPI TestClient)

35+ tests total.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

# Ensure suite-core is on path
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.vuln_lifecycle import (
    LifecycleEvent,
    LifecycleStage,
    TransitionError,
    VulnLifecycle,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def tracker(tmp_path) -> VulnLifecycle:
    """VulnLifecycle backed by a temp SQLite database."""
    return VulnLifecycle(db_path=str(tmp_path / "test_lifecycle.db"))


@pytest.fixture
def fid() -> str:
    return f"finding-{uuid.uuid4()}"


@pytest.fixture
def org_id() -> str:
    return "org-test-001"


def _full_cycle(tracker: VulnLifecycle, finding_id: str, org_id: str) -> None:
    """Push a finding through the complete happy path."""
    tracker.transition(finding_id, LifecycleStage.DISCOVERED, "scanner", org_id=org_id)
    tracker.transition(finding_id, LifecycleStage.TRIAGED, "analyst", org_id=org_id)
    tracker.transition(finding_id, LifecycleStage.ASSIGNED, "lead", org_id=org_id)
    tracker.transition(finding_id, LifecycleStage.IN_PROGRESS, "dev", org_id=org_id)
    tracker.transition(finding_id, LifecycleStage.FIXED, "dev", org_id=org_id)
    tracker.transition(finding_id, LifecycleStage.VERIFIED, "qa", org_id=org_id)
    tracker.transition(finding_id, LifecycleStage.CLOSED, "manager", org_id=org_id)


# ============================================================================
# ENUM TESTS
# ============================================================================


class TestLifecycleStage:
    def test_all_stages_present(self):
        stages = {s.value for s in LifecycleStage}
        assert stages == {
            "discovered", "triaged", "assigned", "in_progress",
            "fixed", "verified", "closed", "reopened", "wont_fix",
        }

    def test_str_returns_value(self):
        assert str(LifecycleStage.DISCOVERED) == "discovered"
        assert str(LifecycleStage.WONT_FIX) == "wont_fix"


# ============================================================================
# MODEL TESTS
# ============================================================================


class TestLifecycleEvent:
    def test_defaults_populated(self):
        event = LifecycleEvent(
            finding_id="f1",
            to_stage=LifecycleStage.DISCOVERED,
            changed_by="system",
            org_id="org1",
        )
        assert event.id is not None
        assert event.from_stage is None
        assert event.reason == ""
        assert event.timestamp is not None

    def test_explicit_values(self):
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        event = LifecycleEvent(
            id="evt-001",
            finding_id="f2",
            from_stage=LifecycleStage.TRIAGED,
            to_stage=LifecycleStage.ASSIGNED,
            changed_by="alice",
            reason="assigned to bob",
            timestamp=ts,
            org_id="org2",
        )
        assert event.id == "evt-001"
        assert event.reason == "assigned to bob"
        assert event.timestamp == ts


# ============================================================================
# STATE MACHINE VALIDATION TESTS
# ============================================================================


class TestValidateTransition:
    def test_initial_discovery_valid(self, tracker):
        assert tracker.validate_transition(None, LifecycleStage.DISCOVERED) is True

    def test_initial_to_non_discovered_invalid(self, tracker):
        assert tracker.validate_transition(None, LifecycleStage.TRIAGED) is False

    def test_discovered_to_triaged(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.DISCOVERED, LifecycleStage.TRIAGED
        ) is True

    def test_discovered_to_wont_fix(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.DISCOVERED, LifecycleStage.WONT_FIX
        ) is True

    def test_discovered_to_assigned_invalid(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.DISCOVERED, LifecycleStage.ASSIGNED
        ) is False

    def test_triaged_to_assigned(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.TRIAGED, LifecycleStage.ASSIGNED
        ) is True

    def test_assigned_to_in_progress(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.ASSIGNED, LifecycleStage.IN_PROGRESS
        ) is True

    def test_in_progress_to_fixed(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.IN_PROGRESS, LifecycleStage.FIXED
        ) is True

    def test_fixed_to_verified(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.FIXED, LifecycleStage.VERIFIED
        ) is True

    def test_fixed_to_closed_invalid(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.FIXED, LifecycleStage.CLOSED
        ) is False

    def test_verified_to_closed(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.VERIFIED, LifecycleStage.CLOSED
        ) is True

    def test_verified_to_reopened(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.VERIFIED, LifecycleStage.REOPENED
        ) is True

    def test_closed_to_reopened(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.CLOSED, LifecycleStage.REOPENED
        ) is True

    def test_closed_to_triaged_invalid(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.CLOSED, LifecycleStage.TRIAGED
        ) is False

    def test_wont_fix_to_reopened(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.WONT_FIX, LifecycleStage.REOPENED
        ) is True

    def test_reopened_to_triaged(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.REOPENED, LifecycleStage.TRIAGED
        ) is True

    def test_reopened_to_wont_fix(self, tracker):
        assert tracker.validate_transition(
            LifecycleStage.REOPENED, LifecycleStage.WONT_FIX
        ) is True


# ============================================================================
# TRANSITION TESTS
# ============================================================================


class TestTransition:
    def test_initial_discovery(self, tracker, fid, org_id):
        event = tracker.transition(fid, LifecycleStage.DISCOVERED, "scanner", org_id=org_id)
        assert event.finding_id == fid
        assert event.to_stage == LifecycleStage.DISCOVERED
        assert event.from_stage is None

    def test_valid_chain(self, tracker, fid, org_id):
        tracker.transition(fid, LifecycleStage.DISCOVERED, "scanner", org_id=org_id)
        evt = tracker.transition(fid, LifecycleStage.TRIAGED, "analyst", reason="confirmed", org_id=org_id)
        assert evt.from_stage == LifecycleStage.DISCOVERED
        assert evt.to_stage == LifecycleStage.TRIAGED
        assert evt.reason == "confirmed"

    def test_invalid_transition_raises(self, tracker, fid, org_id):
        tracker.transition(fid, LifecycleStage.DISCOVERED, "scanner", org_id=org_id)
        with pytest.raises(TransitionError):
            tracker.transition(fid, LifecycleStage.FIXED, "dev", org_id=org_id)

    def test_initial_non_discovered_raises(self, tracker, fid, org_id):
        with pytest.raises(TransitionError):
            tracker.transition(fid, LifecycleStage.TRIAGED, "analyst", org_id=org_id)

    def test_event_persisted(self, tracker, fid, org_id):
        tracker.transition(fid, LifecycleStage.DISCOVERED, "scanner", org_id=org_id)
        history = tracker.get_lifecycle(fid)
        assert len(history) == 1
        assert history[0].to_stage == LifecycleStage.DISCOVERED


# ============================================================================
# GET LIFECYCLE TESTS
# ============================================================================


class TestGetLifecycle:
    def test_empty_for_unknown_finding(self, tracker):
        assert tracker.get_lifecycle("nonexistent-finding") == []

    def test_returns_chronological_order(self, tracker, fid, org_id):
        tracker.transition(fid, LifecycleStage.DISCOVERED, "scanner", org_id=org_id)
        tracker.transition(fid, LifecycleStage.TRIAGED, "analyst", org_id=org_id)
        tracker.transition(fid, LifecycleStage.ASSIGNED, "lead", org_id=org_id)
        history = tracker.get_lifecycle(fid)
        assert len(history) == 3
        assert history[0].to_stage == LifecycleStage.DISCOVERED
        assert history[1].to_stage == LifecycleStage.TRIAGED
        assert history[2].to_stage == LifecycleStage.ASSIGNED

    def test_full_cycle_history_length(self, tracker, fid, org_id):
        _full_cycle(tracker, fid, org_id)
        assert len(tracker.get_lifecycle(fid)) == 7


# ============================================================================
# GET CURRENT STAGE TESTS
# ============================================================================


class TestGetCurrentStage:
    def test_none_for_unknown(self, tracker):
        assert tracker.get_current_stage("no-such-finding") is None

    def test_returns_latest_stage(self, tracker, fid, org_id):
        tracker.transition(fid, LifecycleStage.DISCOVERED, "scanner", org_id=org_id)
        tracker.transition(fid, LifecycleStage.TRIAGED, "analyst", org_id=org_id)
        assert tracker.get_current_stage(fid) == LifecycleStage.TRIAGED

    def test_after_full_cycle(self, tracker, fid, org_id):
        _full_cycle(tracker, fid, org_id)
        assert tracker.get_current_stage(fid) == LifecycleStage.CLOSED


# ============================================================================
# STAGE DISTRIBUTION TESTS
# ============================================================================


class TestGetStageDistribution:
    def test_all_stages_present_in_result(self, tracker, org_id):
        dist = tracker.get_stage_distribution(org_id)
        for stage in LifecycleStage:
            assert stage.value in dist

    def test_empty_org_all_zeros(self, tracker, org_id):
        dist = tracker.get_stage_distribution(org_id)
        assert all(v == 0 for v in dist.values())

    def test_counts_current_stages(self, tracker, org_id):
        f1 = f"f-{uuid.uuid4()}"
        f2 = f"f-{uuid.uuid4()}"
        tracker.transition(f1, LifecycleStage.DISCOVERED, "scanner", org_id=org_id)
        tracker.transition(f2, LifecycleStage.DISCOVERED, "scanner", org_id=org_id)
        tracker.transition(f2, LifecycleStage.TRIAGED, "analyst", org_id=org_id)
        dist = tracker.get_stage_distribution(org_id)
        assert dist["discovered"] == 1
        assert dist["triaged"] == 1

    def test_closed_finding_counted(self, tracker, fid, org_id):
        _full_cycle(tracker, fid, org_id)
        dist = tracker.get_stage_distribution(org_id)
        assert dist["closed"] == 1


# ============================================================================
# AVG TIME PER STAGE TESTS
# ============================================================================


class TestGetAvgTimePerStage:
    def test_no_data_returns_none_per_stage(self, tracker, org_id):
        result = tracker.get_avg_time_per_stage(org_id)
        assert all(v is None for v in result.values())

    def test_completed_dwell_measured(self, tracker, fid, org_id):
        tracker.transition(fid, LifecycleStage.DISCOVERED, "scanner", org_id=org_id)
        tracker.transition(fid, LifecycleStage.TRIAGED, "analyst", org_id=org_id)
        result = tracker.get_avg_time_per_stage(org_id)
        # DISCOVERED dwell should be >= 0 (could be sub-second in tests)
        assert result["discovered"] is not None
        assert result["discovered"] >= 0.0

    def test_all_stages_in_result(self, tracker, org_id):
        result = tracker.get_avg_time_per_stage(org_id)
        for stage in LifecycleStage:
            assert stage.value in result


# ============================================================================
# BOTTLENECKS TESTS
# ============================================================================


class TestGetBottlenecks:
    def test_empty_org_returns_empty(self, tracker, org_id):
        result = tracker.get_bottlenecks(org_id)
        assert result == []

    def test_sorted_descending_by_avg_hours(self, tracker, fid, org_id):
        tracker.transition(fid, LifecycleStage.DISCOVERED, "scanner", org_id=org_id)
        tracker.transition(fid, LifecycleStage.TRIAGED, "analyst", org_id=org_id)
        result = tracker.get_bottlenecks(org_id)
        if len(result) > 1:
            for i in range(len(result) - 1):
                assert result[i]["avg_hours"] >= result[i + 1]["avg_hours"]

    def test_bottleneck_has_expected_keys(self, tracker, fid, org_id):
        tracker.transition(fid, LifecycleStage.DISCOVERED, "scanner", org_id=org_id)
        tracker.transition(fid, LifecycleStage.TRIAGED, "analyst", org_id=org_id)
        result = tracker.get_bottlenecks(org_id)
        if result:
            assert "stage" in result[0]
            assert "avg_hours" in result[0]


# ============================================================================
# FLOW METRICS TESTS
# ============================================================================


class TestGetFlowMetrics:
    def test_empty_org(self, tracker, org_id):
        metrics = tracker.get_flow_metrics(org_id)
        assert metrics["throughput"] == 0
        assert metrics["wip"] == 0
        assert metrics["total_findings"] == 0
        assert metrics["reopen_rate"] == 0.0

    def test_wip_increments_for_open_finding(self, tracker, fid, org_id):
        tracker.transition(fid, LifecycleStage.DISCOVERED, "scanner", org_id=org_id)
        metrics = tracker.get_flow_metrics(org_id)
        assert metrics["wip"] == 1

    def test_throughput_increments_on_close(self, tracker, fid, org_id):
        _full_cycle(tracker, fid, org_id)
        metrics = tracker.get_flow_metrics(org_id)
        assert metrics["throughput"] == 1
        assert metrics["wip"] == 0

    def test_wont_fix_counts_as_throughput(self, tracker, fid, org_id):
        tracker.transition(fid, LifecycleStage.DISCOVERED, "scanner", org_id=org_id)
        tracker.transition(fid, LifecycleStage.WONT_FIX, "analyst", org_id=org_id)
        metrics = tracker.get_flow_metrics(org_id)
        assert metrics["throughput"] == 1

    def test_reopen_rate_nonzero_after_reopen(self, tracker, fid, org_id):
        _full_cycle(tracker, fid, org_id)
        tracker.transition(fid, LifecycleStage.REOPENED, "analyst", org_id=org_id)
        metrics = tracker.get_flow_metrics(org_id)
        assert metrics["reopen_rate"] > 0.0

    def test_flow_metrics_keys(self, tracker, org_id):
        metrics = tracker.get_flow_metrics(org_id)
        expected_keys = {
            "throughput", "cycle_time_hours", "lead_time_hours",
            "wip", "reopen_rate", "total_findings",
        }
        assert expected_keys.issubset(set(metrics.keys()))

    def test_lead_time_computed_for_closed_finding(self, tracker, fid, org_id):
        _full_cycle(tracker, fid, org_id)
        metrics = tracker.get_flow_metrics(org_id)
        # lead time should be >= 0 (sub-second in tests is fine)
        assert metrics["lead_time_hours"] is not None
        assert metrics["lead_time_hours"] >= 0.0


# ============================================================================
# ROUTER TESTS
# ============================================================================


class TestVulnLifecycleRouter:
    """Smoke tests for all 8 REST endpoints via FastAPI TestClient."""

    @pytest.fixture(autouse=True)
    def setup_router(self, tmp_path, monkeypatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        # Patch the module-level tracker to use a temp DB
        import apps.api.vuln_lifecycle_router as router_module
        monkeypatch.setattr(
            router_module,
            "_tracker",
            VulnLifecycle(db_path=str(tmp_path / "router_test.db")),
        )

        # Patch get_org_id to return a fixed org
        import apps.api.dependencies as deps
        monkeypatch.setattr(deps, "get_org_id", lambda: "router-org")

        app = FastAPI()
        app.include_router(router_module.router)
        self.client = TestClient(app)
        self.org_id = "router-org"

    def test_validate_valid_transition(self):
        resp = self.client.post(
            "/api/v1/vuln-lifecycle/validate",
            json={"from_stage": None, "to_stage": "discovered"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True

    def test_validate_invalid_transition(self):
        resp = self.client.post(
            "/api/v1/vuln-lifecycle/validate",
            json={"from_stage": "discovered", "to_stage": "fixed"},
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    def test_transition_initial_discovery(self):
        fid = f"finding-{uuid.uuid4()}"
        resp = self.client.post(
            f"/api/v1/vuln-lifecycle/{fid}/transition",
            json={"to_stage": "discovered", "changed_by": "scanner"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["to_stage"] == "discovered"
        assert data["finding_id"] == fid

    def test_transition_invalid_returns_422(self):
        fid = f"finding-{uuid.uuid4()}"
        # Trying to go to TRIAGED without first being DISCOVERED
        resp = self.client.post(
            f"/api/v1/vuln-lifecycle/{fid}/transition",
            json={"to_stage": "triaged", "changed_by": "analyst"},
        )
        assert resp.status_code == 422

    def test_get_history_empty(self):
        resp = self.client.get(f"/api/v1/vuln-lifecycle/unknown-finding-xyz/history")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_history_populated(self):
        fid = f"finding-{uuid.uuid4()}"
        self.client.post(
            f"/api/v1/vuln-lifecycle/{fid}/transition",
            json={"to_stage": "discovered", "changed_by": "scanner"},
        )
        self.client.post(
            f"/api/v1/vuln-lifecycle/{fid}/transition",
            json={"to_stage": "triaged", "changed_by": "analyst"},
        )
        resp = self.client.get(f"/api/v1/vuln-lifecycle/{fid}/history")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_get_current_stage_none(self):
        resp = self.client.get("/api/v1/vuln-lifecycle/no-finding/stage")
        assert resp.status_code == 200
        assert resp.json()["stage"] is None

    def test_get_current_stage_after_transition(self):
        fid = f"finding-{uuid.uuid4()}"
        self.client.post(
            f"/api/v1/vuln-lifecycle/{fid}/transition",
            json={"to_stage": "discovered", "changed_by": "scanner"},
        )
        resp = self.client.get(f"/api/v1/vuln-lifecycle/{fid}/stage")
        assert resp.status_code == 200
        assert resp.json()["stage"] == "discovered"

    def test_distribution_endpoint(self):
        resp = self.client.get("/api/v1/vuln-lifecycle/distribution")
        assert resp.status_code == 200
        data = resp.json()
        assert "discovered" in data
        assert "closed" in data

    def test_bottlenecks_endpoint(self):
        resp = self.client.get("/api/v1/vuln-lifecycle/bottlenecks")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_avg_time_endpoint(self):
        resp = self.client.get("/api/v1/vuln-lifecycle/avg-time")
        assert resp.status_code == 200
        data = resp.json()
        assert "discovered" in data

    def test_flow_endpoint(self):
        resp = self.client.get("/api/v1/vuln-lifecycle/flow")
        assert resp.status_code == 200
        data = resp.json()
        assert "throughput" in data
        assert "wip" in data
        assert "reopen_rate" in data
