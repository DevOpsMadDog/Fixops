"""
Comprehensive tests for PatchManager — Automated Security Patch Management.

Covers:
- PatchPriority / PatchStatus enums
- Patch Pydantic model
- PatchManager: discover, add, list, schedule, deploy, rollback, fail
- Analytics: compliance, overdue, velocity, stats
- Router endpoints via FastAPI TestClient (8 endpoints)

30+ tests, all isolated with temp DBs.
"""

from __future__ import annotations

import sys
import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Generator

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.patch_manager import (
    Patch,
    PatchManager,
    PatchPriority,
    PatchStatus,
    _SLA_DAYS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db() -> Generator[str, None, None]:
    """Return path to a fresh temp SQLite DB."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def pm(tmp_db: str) -> PatchManager:
    """Fresh PatchManager backed by a temp DB."""
    return PatchManager(db_path=tmp_db)


@pytest.fixture
def sample_patch(pm: PatchManager) -> Patch:
    """Add a single MEDIUM-priority available patch and return it."""
    p = Patch(
        cve_id="CVE-2024-9999",
        package_name="testpkg",
        current_version="1.0.0",
        fixed_version="1.0.1",
        priority=PatchPriority.MEDIUM,
        org_id="test-org",
    )
    return pm.add_patch(p)


# ===========================================================================
# Enum tests
# ===========================================================================


class TestPatchPriorityEnum:
    def test_all_values_exist(self):
        values = {p.value for p in PatchPriority}
        assert values == {"emergency", "critical", "high", "medium", "low"}

    def test_str_enum(self):
        assert PatchPriority.EMERGENCY == "emergency"
        assert PatchPriority.CRITICAL == "critical"
        assert PatchPriority.HIGH == "high"

    def test_five_levels(self):
        assert len(list(PatchPriority)) == 5


class TestPatchStatusEnum:
    def test_all_values_exist(self):
        values = {s.value for s in PatchStatus}
        assert values == {"available", "scheduled", "testing", "deployed", "failed", "rolled_back"}

    def test_six_states(self):
        assert len(list(PatchStatus)) == 6

    def test_str_enum(self):
        assert PatchStatus.DEPLOYED == "deployed"
        assert PatchStatus.ROLLED_BACK == "rolled_back"


class TestSLADays:
    def test_sla_days_defined_for_all_priorities(self):
        for p in PatchPriority:
            assert p.value in _SLA_DAYS

    def test_emergency_sla_is_one_day(self):
        assert _SLA_DAYS["emergency"] == 1

    def test_critical_sla_is_seven_days(self):
        assert _SLA_DAYS["critical"] == 7

    def test_low_sla_is_180_days(self):
        assert _SLA_DAYS["low"] == 180


# ===========================================================================
# Patch model tests
# ===========================================================================


class TestPatchModel:
    def test_default_id_generated(self):
        p = Patch(package_name="pkg", current_version="1.0", fixed_version="1.1")
        assert p.id.startswith("patch-")

    def test_default_status_available(self):
        p = Patch(package_name="pkg", current_version="1.0", fixed_version="1.1")
        assert p.status == PatchStatus.AVAILABLE

    def test_default_priority_medium(self):
        p = Patch(package_name="pkg", current_version="1.0", fixed_version="1.1")
        assert p.priority == PatchPriority.MEDIUM

    def test_affected_assets_defaults_empty(self):
        p = Patch(package_name="pkg", current_version="1.0", fixed_version="1.1")
        assert p.affected_assets == []

    def test_full_construction(self):
        p = Patch(
            cve_id="CVE-2024-0001",
            package_name="openssl",
            current_version="1.1.1t",
            fixed_version="3.0.12",
            priority=PatchPriority.CRITICAL,
            status=PatchStatus.SCHEDULED,
            affected_assets=["asset-1", "asset-2"],
            org_id="org-abc",
            notes="SEV-1234",
        )
        assert p.cve_id == "CVE-2024-0001"
        assert p.package_name == "openssl"
        assert len(p.affected_assets) == 2
        assert p.notes == "SEV-1234"


# ===========================================================================
# PatchManager core operation tests
# ===========================================================================


class TestPatchManagerDiscover:
    def test_discover_returns_list(self, pm: PatchManager):
        patches = pm.discover_patches("org-1")
        assert isinstance(patches, list)
        assert len(patches) > 0

    def test_discover_persists_patches(self, pm: PatchManager):
        pm.discover_patches("org-1")
        listed = pm.list_patches("org-1")
        assert len(listed) > 0

    def test_discover_idempotent(self, pm: PatchManager):
        first = pm.discover_patches("org-1")
        second = pm.discover_patches("org-1")
        # Second run should find no new patches (all already tracked)
        assert len(second) == 0

    def test_discover_org_isolation(self, pm: PatchManager):
        pm.discover_patches("org-a")
        pm.discover_patches("org-b")
        a_patches = pm.list_patches("org-a")
        b_patches = pm.list_patches("org-b")
        assert len(a_patches) > 0
        assert len(b_patches) > 0
        # IDs should differ between orgs
        a_ids = {p.id for p in a_patches}
        b_ids = {p.id for p in b_patches}
        assert a_ids.isdisjoint(b_ids)

    def test_discovered_patches_have_status_available(self, pm: PatchManager):
        patches = pm.discover_patches("org-1")
        assert all(p.status == PatchStatus.AVAILABLE for p in patches)


class TestPatchManagerAddAndGet:
    def test_add_patch_returns_patch(self, pm: PatchManager):
        p = Patch(package_name="curl", current_version="7.0", fixed_version="8.0", org_id="org-1")
        result = pm.add_patch(p)
        assert result.id == p.id

    def test_get_patch_found(self, pm: PatchManager, sample_patch: Patch):
        fetched = pm.get_patch(sample_patch.id)
        assert fetched is not None
        assert fetched.id == sample_patch.id

    def test_get_patch_not_found(self, pm: PatchManager):
        result = pm.get_patch("patch-nonexistent")
        assert result is None

    def test_list_patches_empty_org(self, pm: PatchManager):
        result = pm.list_patches("empty-org")
        assert result == []

    def test_list_patches_filter_by_priority(self, pm: PatchManager):
        pm.add_patch(Patch(package_name="a", current_version="1", fixed_version="2",
                           priority=PatchPriority.CRITICAL, org_id="org-1"))
        pm.add_patch(Patch(package_name="b", current_version="1", fixed_version="2",
                           priority=PatchPriority.LOW, org_id="org-1"))
        critical = pm.list_patches("org-1", priority="critical")
        assert all(p.priority == PatchPriority.CRITICAL for p in critical)
        assert len(critical) == 1

    def test_list_patches_filter_by_status(self, pm: PatchManager, sample_patch: Patch):
        pm.schedule_patch(sample_patch.id, "2026-05-01T00:00:00+00:00")
        scheduled = pm.list_patches("test-org", status="scheduled")
        assert len(scheduled) == 1
        assert scheduled[0].status == PatchStatus.SCHEDULED

    def test_list_patches_filter_by_package(self, pm: PatchManager):
        pm.add_patch(Patch(package_name="nginx", current_version="1.24", fixed_version="1.25", org_id="org-1"))
        pm.add_patch(Patch(package_name="curl", current_version="7.88", fixed_version="8.0", org_id="org-1"))
        nginx_patches = pm.list_patches("org-1", package_name="nginx")
        assert len(nginx_patches) == 1
        assert nginx_patches[0].package_name == "nginx"


class TestPatchManagerSchedule:
    def test_schedule_patch_changes_status(self, pm: PatchManager, sample_patch: Patch):
        updated = pm.schedule_patch(sample_patch.id, "2026-05-01T00:00:00+00:00")
        assert updated.status == PatchStatus.SCHEDULED
        assert updated.scheduled_date == "2026-05-01T00:00:00+00:00"

    def test_schedule_not_found_raises(self, pm: PatchManager):
        with pytest.raises(ValueError, match="not found"):
            pm.schedule_patch("patch-missing", "2026-05-01T00:00:00+00:00")

    def test_schedule_deployed_raises(self, pm: PatchManager, sample_patch: Patch):
        pm.deploy_patch(sample_patch.id)
        with pytest.raises(ValueError, match="already deployed"):
            pm.schedule_patch(sample_patch.id, "2026-06-01T00:00:00+00:00")


class TestPatchManagerDeploy:
    def test_deploy_sets_status_and_date(self, pm: PatchManager, sample_patch: Patch):
        updated = pm.deploy_patch(sample_patch.id)
        assert updated.status == PatchStatus.DEPLOYED
        assert updated.deployed_date is not None

    def test_deploy_not_found_raises(self, pm: PatchManager):
        with pytest.raises(ValueError, match="not found"):
            pm.deploy_patch("patch-missing")

    def test_deploy_already_deployed_raises(self, pm: PatchManager, sample_patch: Patch):
        pm.deploy_patch(sample_patch.id)
        with pytest.raises(ValueError, match="already deployed"):
            pm.deploy_patch(sample_patch.id)

    def test_deploy_rolled_back_raises(self, pm: PatchManager, sample_patch: Patch):
        pm.deploy_patch(sample_patch.id)
        pm.rollback_patch(sample_patch.id)
        with pytest.raises(ValueError, match="rolled back"):
            pm.deploy_patch(sample_patch.id)


class TestPatchManagerRollback:
    def test_rollback_deployed_patch(self, pm: PatchManager, sample_patch: Patch):
        pm.deploy_patch(sample_patch.id)
        rolled = pm.rollback_patch(sample_patch.id)
        assert rolled.status == PatchStatus.ROLLED_BACK

    def test_rollback_not_deployed_raises(self, pm: PatchManager, sample_patch: Patch):
        with pytest.raises(ValueError, match="Only DEPLOYED"):
            pm.rollback_patch(sample_patch.id)

    def test_rollback_not_found_raises(self, pm: PatchManager):
        with pytest.raises(ValueError, match="not found"):
            pm.rollback_patch("patch-missing")


class TestPatchManagerMarkFailed:
    def test_mark_failed_sets_status(self, pm: PatchManager, sample_patch: Patch):
        updated = pm.mark_failed(sample_patch.id)
        assert updated.status == PatchStatus.FAILED

    def test_mark_failed_not_found_raises(self, pm: PatchManager):
        with pytest.raises(ValueError, match="not found"):
            pm.mark_failed("patch-missing")


# ===========================================================================
# Analytics tests
# ===========================================================================


class TestGetPatchCompliance:
    def test_empty_org_returns_100_pct(self, pm: PatchManager):
        result = pm.get_patch_compliance("empty-org")
        assert result["compliance_pct"] == 100.0
        assert result["total_patches"] == 0

    def test_deployed_within_sla_is_compliant(self, pm: PatchManager):
        # MEDIUM SLA = 90 days; discovered now, deploy now → compliant
        p = Patch(
            package_name="pkg", current_version="1.0", fixed_version="2.0",
            priority=PatchPriority.MEDIUM, org_id="org-1",
        )
        pm.add_patch(p)
        pm.deploy_patch(p.id)
        result = pm.get_patch_compliance("org-1")
        assert result["compliance_pct"] == 100.0

    def test_overdue_patch_reduces_compliance(self, pm: PatchManager, tmp_db: str):
        # Create patch with discovered_date 10 days ago; EMERGENCY SLA = 1 day → overdue
        past = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        p = Patch(
            package_name="pkg", current_version="1.0", fixed_version="2.0",
            priority=PatchPriority.EMERGENCY, org_id="org-2",
            discovered_date=past,
        )
        pm.add_patch(p)
        result = pm.get_patch_compliance("org-2")
        assert result["compliance_pct"] < 100.0

    def test_compliance_has_by_priority_breakdown(self, pm: PatchManager, sample_patch: Patch):
        result = pm.get_patch_compliance("test-org")
        assert "by_priority" in result
        assert "medium" in result["by_priority"]

    def test_compliance_keys_present(self, pm: PatchManager, sample_patch: Patch):
        result = pm.get_patch_compliance("test-org")
        for key in ("org_id", "total_patches", "compliant_patches", "compliance_pct", "by_priority"):
            assert key in result


class TestGetOverduePatches:
    def test_no_overdue_when_fresh(self, pm: PatchManager, sample_patch: Patch):
        # MEDIUM SLA = 90 days; just created → not overdue
        overdue = pm.get_overdue_patches("test-org")
        assert sample_patch.id not in {p.id for p in overdue}

    def test_deployed_patches_not_overdue(self, pm: PatchManager, sample_patch: Patch):
        pm.deploy_patch(sample_patch.id)
        overdue = pm.get_overdue_patches("test-org")
        assert len(overdue) == 0

    def test_emergency_patch_overdue_after_2_days(self, pm: PatchManager):
        past = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        p = Patch(
            package_name="pkg", current_version="1.0", fixed_version="2.0",
            priority=PatchPriority.EMERGENCY, org_id="org-over",
            discovered_date=past,
        )
        pm.add_patch(p)
        overdue = pm.get_overdue_patches("org-over")
        assert any(op.id == p.id for op in overdue)


class TestGetPatchVelocity:
    def test_velocity_returns_correct_keys(self, pm: PatchManager):
        result = pm.get_patch_velocity("org-1")
        for key in ("org_id", "weeks", "weekly_counts", "average_per_week", "total_deployed"):
            assert key in result

    def test_velocity_default_8_weeks(self, pm: PatchManager):
        result = pm.get_patch_velocity("org-1")
        assert result["weeks"] == 8
        assert len(result["weekly_counts"]) == 8

    def test_velocity_custom_weeks(self, pm: PatchManager):
        result = pm.get_patch_velocity("org-1", weeks=4)
        assert result["weeks"] == 4
        assert len(result["weekly_counts"]) == 4

    def test_velocity_counts_deployed_patches(self, pm: PatchManager):
        p = Patch(package_name="pkg", current_version="1.0", fixed_version="2.0", org_id="org-v")
        pm.add_patch(p)
        pm.deploy_patch(p.id)
        result = pm.get_patch_velocity("org-v")
        assert result["total_deployed"] == 1


class TestGetPatchStats:
    def test_stats_keys_present(self, pm: PatchManager, sample_patch: Patch):
        result = pm.get_patch_stats("test-org")
        for key in ("org_id", "total", "by_priority", "by_status", "by_package"):
            assert key in result

    def test_stats_total_count(self, pm: PatchManager, sample_patch: Patch):
        result = pm.get_patch_stats("test-org")
        assert result["total"] == 1

    def test_stats_by_priority_all_levels_present(self, pm: PatchManager, sample_patch: Patch):
        result = pm.get_patch_stats("test-org")
        for p in PatchPriority:
            assert p.value in result["by_priority"]

    def test_stats_by_status_all_states_present(self, pm: PatchManager, sample_patch: Patch):
        result = pm.get_patch_stats("test-org")
        for s in PatchStatus:
            assert s.value in result["by_status"]

    def test_stats_by_package_counts(self, pm: PatchManager, sample_patch: Patch):
        result = pm.get_patch_stats("test-org")
        assert result["by_package"]["testpkg"] == 1

    def test_stats_empty_org(self, pm: PatchManager):
        result = pm.get_patch_stats("no-org")
        assert result["total"] == 0


# ===========================================================================
# Router endpoint tests
# ===========================================================================


class TestPatchManagerRouter:
    """Integration tests for the 8 patch management API endpoints."""

    @pytest.fixture(autouse=True)
    def client(self, tmp_db: str, monkeypatch):
        """Create TestClient with isolated PatchManager singleton."""
        import core.patch_manager as pm_module
        fresh_pm = PatchManager(db_path=tmp_db)
        monkeypatch.setattr(pm_module, "_instance", fresh_pm)

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api.patch_manager_router import router

        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app)
        self.pm = fresh_pm

    def test_discover_endpoint(self):
        resp = self.client.post("/api/v1/patches/discover?org_id=org-1")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_add_patch_endpoint(self):
        resp = self.client.post("/api/v1/patches", json={
            "package_name": "nginx",
            "current_version": "1.24.0",
            "fixed_version": "1.25.4",
            "priority": "high",
            "org_id": "org-r",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["package_name"] == "nginx"
        assert data["status"] == "available"

    def test_list_patches_endpoint(self):
        self.client.post("/api/v1/patches/discover?org_id=org-list")
        resp = self.client.get("/api/v1/patches?org_id=org-list")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_patch_endpoint(self):
        add = self.client.post("/api/v1/patches", json={
            "package_name": "curl", "current_version": "7.88", "fixed_version": "8.0", "org_id": "org-g"
        })
        patch_id = add.json()["id"]
        resp = self.client.get(f"/api/v1/patches/{patch_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == patch_id

    def test_get_patch_not_found(self):
        resp = self.client.get("/api/v1/patches/patch-doesnotexist")
        assert resp.status_code == 404

    def test_schedule_patch_endpoint(self):
        add = self.client.post("/api/v1/patches", json={
            "package_name": "openssl", "current_version": "1.1.1t", "fixed_version": "3.0.12", "org_id": "org-s"
        })
        patch_id = add.json()["id"]
        resp = self.client.post(f"/api/v1/patches/{patch_id}/schedule", json={
            "scheduled_date": "2026-05-01T00:00:00+00:00"
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "scheduled"

    def test_deploy_patch_endpoint(self):
        add = self.client.post("/api/v1/patches", json={
            "package_name": "sqlite3", "current_version": "3.41.0", "fixed_version": "3.44.2", "org_id": "org-d"
        })
        patch_id = add.json()["id"]
        resp = self.client.post(f"/api/v1/patches/{patch_id}/deploy")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "deployed"
        assert data["deployed_date"] is not None

    def test_rollback_patch_endpoint(self):
        add = self.client.post("/api/v1/patches", json={
            "package_name": "glibc", "current_version": "2.35", "fixed_version": "2.39", "org_id": "org-rb"
        })
        patch_id = add.json()["id"]
        self.client.post(f"/api/v1/patches/{patch_id}/deploy")
        resp = self.client.post(f"/api/v1/patches/{patch_id}/rollback")
        assert resp.status_code == 200
        assert resp.json()["status"] == "rolled_back"

    def test_rollback_not_deployed_returns_400(self):
        add = self.client.post("/api/v1/patches", json={
            "package_name": "expat", "current_version": "2.5.0", "fixed_version": "2.6.0", "org_id": "org-rb2"
        })
        patch_id = add.json()["id"]
        resp = self.client.post(f"/api/v1/patches/{patch_id}/rollback")
        assert resp.status_code == 400

    def test_stats_endpoint(self):
        self.client.post("/api/v1/patches/discover?org_id=org-st")
        resp = self.client.get("/api/v1/patches/stats?org_id=org-st")
        assert resp.status_code == 200
        data = resp.json()
        assert "by_priority" in data
        assert "by_status" in data

    def test_compliance_endpoint(self):
        resp = self.client.get("/api/v1/patches/compliance?org_id=org-c")
        assert resp.status_code == 200
        data = resp.json()
        assert "compliance_pct" in data

    def test_overdue_endpoint(self):
        resp = self.client.get("/api/v1/patches/overdue?org_id=org-od")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_velocity_endpoint(self):
        resp = self.client.get("/api/v1/patches/velocity?org_id=org-v&weeks=4")
        assert resp.status_code == 200
        data = resp.json()
        assert data["weeks"] == 4
        assert len(data["weekly_counts"]) == 4
