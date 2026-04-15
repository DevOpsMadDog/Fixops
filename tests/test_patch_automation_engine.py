"""Tests for PatchAutomationEngine — automated patch management with CVE correlation."""

from __future__ import annotations

import pytest

from core.patch_automation_engine import PatchAutomationEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_engine(tmp_path):
    """Return a PatchAutomationEngine backed by a temp directory."""
    return PatchAutomationEngine(org_id="org-test", db_dir=str(tmp_path))


@pytest.fixture
def alt_engine(tmp_path):
    """Second org engine — used for isolation tests."""
    return PatchAutomationEngine(org_id="org-other", db_dir=str(tmp_path))


@pytest.fixture
def sample_patch():
    return {
        "patch_id": "MS23-001",
        "vendor": "Microsoft",
        "product": "Windows Server 2022",
        "version": "KB5023705",
        "patch_type": "security",
        "cves_addressed": ["CVE-2023-21554", "CVE-2023-28252"],
        "severity": "critical",
        "release_date": "2023-04-11T00:00:00+00:00",
        "kb_article": "https://support.microsoft.com/kb/5023705",
        "download_url": "https://catalog.update.microsoft.com/kb5023705",
        "status": "available",
    }


@pytest.fixture
def sample_patch_id(tmp_engine, sample_patch):
    rec = tmp_engine.add_patch("org-test", sample_patch)
    return rec["id"]


# ---------------------------------------------------------------------------
# Patch Catalog Tests
# ---------------------------------------------------------------------------

class TestAddPatch:
    def test_add_patch_returns_record(self, tmp_engine, sample_patch):
        rec = tmp_engine.add_patch("org-test", sample_patch)
        assert rec["id"]
        assert rec["org_id"] == "org-test"
        assert rec["patch_id"] == "MS23-001"
        assert rec["vendor"] == "Microsoft"
        assert rec["severity"] == "critical"
        assert rec["status"] == "available"
        assert isinstance(rec["cves_addressed"], list)
        assert "CVE-2023-21554" in rec["cves_addressed"]

    def test_add_patch_missing_patch_id_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="patch_id"):
            tmp_engine.add_patch("org-test", {"vendor": "Microsoft"})

    def test_add_patch_invalid_type_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="patch_type"):
            tmp_engine.add_patch("org-test", {"patch_id": "p1", "patch_type": "unknown"})

    def test_add_patch_invalid_severity_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="severity"):
            tmp_engine.add_patch("org-test", {"patch_id": "p1", "severity": "extreme"})

    def test_add_patch_invalid_status_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="status"):
            tmp_engine.add_patch("org-test", {"patch_id": "p1", "status": "unknown"})

    def test_add_patch_all_types(self, tmp_engine):
        for pt in ("security", "critical", "important", "optional"):
            rec = tmp_engine.add_patch("org-test", {"patch_id": f"p-{pt}", "patch_type": pt})
            assert rec["patch_type"] == pt

    def test_add_patch_all_severities(self, tmp_engine):
        for sev in ("critical", "high", "medium", "low"):
            rec = tmp_engine.add_patch("org-test", {"patch_id": f"p-{sev}", "severity": sev})
            assert rec["severity"] == sev


class TestListPatches:
    def test_list_patches_empty(self, tmp_engine):
        assert tmp_engine.list_patches("org-test") == []

    def test_list_patches_returns_created(self, tmp_engine, sample_patch):
        tmp_engine.add_patch("org-test", sample_patch)
        results = tmp_engine.list_patches("org-test")
        assert len(results) == 1
        assert isinstance(results[0]["cves_addressed"], list)

    def test_list_patches_filter_by_status(self, tmp_engine):
        tmp_engine.add_patch("org-test", {"patch_id": "p1", "status": "available"})
        tmp_engine.add_patch("org-test", {"patch_id": "p2", "status": "deployed"})
        avail = tmp_engine.list_patches("org-test", status="available")
        assert len(avail) == 1
        assert avail[0]["patch_id"] == "p1"

    def test_list_patches_filter_by_severity(self, tmp_engine):
        tmp_engine.add_patch("org-test", {"patch_id": "p1", "severity": "critical"})
        tmp_engine.add_patch("org-test", {"patch_id": "p2", "severity": "low"})
        crits = tmp_engine.list_patches("org-test", severity="critical")
        assert len(crits) == 1

    def test_list_patches_filter_by_vendor(self, tmp_engine):
        tmp_engine.add_patch("org-test", {"patch_id": "p1", "vendor": "Microsoft"})
        tmp_engine.add_patch("org-test", {"patch_id": "p2", "vendor": "Red Hat"})
        ms = tmp_engine.list_patches("org-test", vendor="Microsoft")
        assert len(ms) == 1

    def test_list_patches_org_isolation(self, tmp_engine, alt_engine, sample_patch):
        tmp_engine.add_patch("org-test", sample_patch)
        assert alt_engine.list_patches("org-other") == []


class TestApprovePatch:
    def test_approve_patch_sets_approved(self, tmp_engine, sample_patch, sample_patch_id):
        result = tmp_engine.approve_patch("org-test", sample_patch_id)
        assert result is True
        patches = tmp_engine.list_patches("org-test", status="approved")
        assert len(patches) == 1

    def test_approve_patch_wrong_org_returns_false(self, tmp_engine, sample_patch_id):
        result = tmp_engine.approve_patch("org-other", sample_patch_id)
        assert result is False

    def test_approve_patch_nonexistent_returns_false(self, tmp_engine):
        assert tmp_engine.approve_patch("org-test", "nonexistent") is False


# ---------------------------------------------------------------------------
# Deployment Tests
# ---------------------------------------------------------------------------

class TestDeployPatch:
    def test_deploy_patch_returns_pending(self, tmp_engine, sample_patch_id):
        rec = tmp_engine.deploy_patch(
            "org-test", sample_patch_id, "asset-001", "web-server-01", "admin@corp.com"
        )
        assert rec["id"]
        assert rec["status"] == "pending"
        assert rec["patch_id"] == sample_patch_id
        assert rec["asset_id"] == "asset-001"
        assert rec["asset_name"] == "web-server-01"
        assert rec["deployed_by"] == "admin@corp.com"

    def test_deploy_patch_invalid_type_raises(self, tmp_engine, sample_patch_id):
        with pytest.raises(ValueError, match="deployment_type"):
            tmp_engine.deploy_patch(
                "org-test", sample_patch_id, "a1", "server", "admin", deployment_type="invalid"
            )

    def test_deploy_patch_automated(self, tmp_engine, sample_patch_id):
        rec = tmp_engine.deploy_patch(
            "org-test", sample_patch_id, "a1", "server", "swarmclaw", deployment_type="automated"
        )
        assert rec["deployment_type"] == "automated"


class TestUpdateDeployment:
    def test_update_deployment_success(self, tmp_engine, sample_patch_id):
        dep = tmp_engine.deploy_patch("org-test", sample_patch_id, "a1", "srv", "admin")
        result = tmp_engine.update_deployment("org-test", dep["id"], "success")
        assert result is True
        deps = tmp_engine.list_deployments("org-test", status="success")
        assert len(deps) == 1
        assert deps[0]["completed_at"] is not None

    def test_update_deployment_failed_with_error_msg(self, tmp_engine, sample_patch_id):
        dep = tmp_engine.deploy_patch("org-test", sample_patch_id, "a1", "srv", "admin")
        result = tmp_engine.update_deployment(
            "org-test", dep["id"], "failed", error_msg="Reboot required"
        )
        assert result is True

    def test_update_deployment_invalid_status_raises(self, tmp_engine, sample_patch_id):
        dep = tmp_engine.deploy_patch("org-test", sample_patch_id, "a1", "srv", "admin")
        with pytest.raises(ValueError, match="status"):
            tmp_engine.update_deployment("org-test", dep["id"], "unknown")

    def test_update_deployment_nonexistent_returns_false(self, tmp_engine):
        assert tmp_engine.update_deployment("org-test", "nonexistent", "success") is False

    def test_update_deployment_all_terminal_statuses(self, tmp_engine, sample_patch):
        for status in ("success", "failed", "rolled_back"):
            patch = tmp_engine.add_patch("org-test", {**sample_patch, "patch_id": f"p-{status}"})
            dep = tmp_engine.deploy_patch("org-test", patch["id"], "a1", "srv", "admin")
            result = tmp_engine.update_deployment("org-test", dep["id"], status)
            assert result is True


class TestListDeployments:
    def test_list_deployments_empty(self, tmp_engine):
        assert tmp_engine.list_deployments("org-test") == []

    def test_list_deployments_returns_created(self, tmp_engine, sample_patch_id):
        tmp_engine.deploy_patch("org-test", sample_patch_id, "a1", "srv", "admin")
        results = tmp_engine.list_deployments("org-test")
        assert len(results) == 1

    def test_list_deployments_filter_by_status(self, tmp_engine, sample_patch):
        p1 = tmp_engine.add_patch("org-test", {**sample_patch, "patch_id": "p1"})
        p2 = tmp_engine.add_patch("org-test", {**sample_patch, "patch_id": "p2"})
        d1 = tmp_engine.deploy_patch("org-test", p1["id"], "a1", "srv", "admin")
        tmp_engine.deploy_patch("org-test", p2["id"], "a2", "srv2", "admin")
        tmp_engine.update_deployment("org-test", d1["id"], "success")
        success = tmp_engine.list_deployments("org-test", status="success")
        assert len(success) == 1

    def test_list_deployments_filter_by_patch_id(self, tmp_engine, sample_patch):
        p1 = tmp_engine.add_patch("org-test", {**sample_patch, "patch_id": "p1"})
        p2 = tmp_engine.add_patch("org-test", {**sample_patch, "patch_id": "p2"})
        tmp_engine.deploy_patch("org-test", p1["id"], "a1", "srv", "admin")
        tmp_engine.deploy_patch("org-test", p2["id"], "a2", "srv", "admin")
        p1_deps = tmp_engine.list_deployments("org-test", patch_id=p1["id"])
        assert len(p1_deps) == 1

    def test_list_deployments_org_isolation(self, tmp_engine, alt_engine, sample_patch_id):
        tmp_engine.deploy_patch("org-test", sample_patch_id, "a1", "srv", "admin")
        assert alt_engine.list_deployments("org-other") == []


# ---------------------------------------------------------------------------
# Exception Tests
# ---------------------------------------------------------------------------

class TestAddException:
    def test_add_exception_returns_record(self, tmp_engine, sample_patch_id):
        rec = tmp_engine.add_exception("org-test", {
            "patch_id": sample_patch_id,
            "asset_id": "asset-legacy-001",
            "reason": "Legacy system cannot be rebooted during Q2",
            "approved_by": "ciso@corp.com",
            "expires_at": "2023-07-01T00:00:00+00:00",
        })
        assert rec["id"]
        assert rec["patch_id"] == sample_patch_id
        assert rec["asset_id"] == "asset-legacy-001"

    def test_add_exception_missing_patch_id_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="patch_id"):
            tmp_engine.add_exception("org-test", {"asset_id": "a1"})

    def test_add_exception_missing_asset_id_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="asset_id"):
            tmp_engine.add_exception("org-test", {"patch_id": "p1"})


class TestListExceptions:
    def test_list_exceptions_empty(self, tmp_engine):
        assert tmp_engine.list_exceptions("org-test") == []

    def test_list_exceptions_returns_created(self, tmp_engine, sample_patch_id):
        tmp_engine.add_exception("org-test", {"patch_id": sample_patch_id, "asset_id": "a1"})
        results = tmp_engine.list_exceptions("org-test")
        assert len(results) == 1

    def test_list_exceptions_org_isolation(self, tmp_engine, alt_engine, sample_patch_id):
        tmp_engine.add_exception("org-test", {"patch_id": sample_patch_id, "asset_id": "a1"})
        assert alt_engine.list_exceptions("org-other") == []


# ---------------------------------------------------------------------------
# Maintenance Window Tests
# ---------------------------------------------------------------------------

class TestCreatePatchWindow:
    def test_create_window_returns_record(self, tmp_engine):
        rec = tmp_engine.create_patch_window("org-test", {
            "name": "Sunday Maintenance",
            "schedule_cron": "0 2 * * 0",
            "asset_groups": ["prod", "staging"],
            "auto_approve": True,
            "max_batch_pct": 25,
        })
        assert rec["id"]
        assert rec["name"] == "Sunday Maintenance"
        assert rec["auto_approve"] is True
        assert rec["max_batch_pct"] == 25
        assert isinstance(rec["asset_groups"], list)
        assert "prod" in rec["asset_groups"]

    def test_create_window_missing_name_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="name"):
            tmp_engine.create_patch_window("org-test", {"schedule_cron": "0 2 * * 0"})

    def test_create_window_defaults(self, tmp_engine):
        rec = tmp_engine.create_patch_window("org-test", {"name": "Weekend"})
        assert rec["auto_approve"] is False
        assert rec["max_batch_pct"] == 20
        assert rec["asset_groups"] == []


class TestListPatchWindows:
    def test_list_windows_empty(self, tmp_engine):
        assert tmp_engine.list_patch_windows("org-test") == []

    def test_list_windows_returns_created(self, tmp_engine):
        tmp_engine.create_patch_window("org-test", {"name": "Window 1"})
        results = tmp_engine.list_patch_windows("org-test")
        assert len(results) == 1

    def test_list_windows_org_isolation(self, tmp_engine, alt_engine):
        tmp_engine.create_patch_window("org-test", {"name": "Win"})
        assert alt_engine.list_patch_windows("org-other") == []


# ---------------------------------------------------------------------------
# CVE → Patch Mapping Tests
# ---------------------------------------------------------------------------

class TestGetCvePatchMap:
    def test_cve_patch_map_finds_patch(self, tmp_engine, sample_patch):
        tmp_engine.add_patch("org-test", sample_patch)
        results = tmp_engine.get_cve_patch_map("org-test", "CVE-2023-21554")
        assert len(results) == 1
        assert results[0]["patch_id"] == "MS23-001"

    def test_cve_patch_map_no_match(self, tmp_engine, sample_patch):
        tmp_engine.add_patch("org-test", sample_patch)
        results = tmp_engine.get_cve_patch_map("org-test", "CVE-9999-9999")
        assert results == []

    def test_cve_patch_map_multiple_patches(self, tmp_engine, sample_patch):
        tmp_engine.add_patch("org-test", sample_patch)
        tmp_engine.add_patch("org-test", {
            "patch_id": "MS23-002",
            "cves_addressed": ["CVE-2023-21554", "CVE-2023-99999"],
        })
        results = tmp_engine.get_cve_patch_map("org-test", "CVE-2023-21554")
        assert len(results) == 2

    def test_cve_patch_map_org_isolation(self, tmp_engine, alt_engine, sample_patch):
        tmp_engine.add_patch("org-test", sample_patch)
        results = alt_engine.get_cve_patch_map("org-other", "CVE-2023-21554")
        assert results == []

    def test_cve_patch_map_partial_id_not_matched(self, tmp_engine, sample_patch):
        """Ensure CVE-2023-215 does not match CVE-2023-21554."""
        tmp_engine.add_patch("org-test", sample_patch)
        results = tmp_engine.get_cve_patch_map("org-test", "CVE-2023-215")
        assert results == []


# ---------------------------------------------------------------------------
# Stats Tests
# ---------------------------------------------------------------------------

class TestGetPatchStats:
    def test_stats_empty_org(self, tmp_engine):
        stats = tmp_engine.get_patch_stats("org-test")
        assert stats["total_patches"] == 0
        assert stats["success_rate"] == 0.0
        assert stats["pending_critical"] == 0
        assert stats["exceptions_count"] == 0

    def test_stats_reflect_catalog(self, tmp_engine, sample_patch):
        tmp_engine.add_patch("org-test", sample_patch)
        tmp_engine.add_patch("org-test", {"patch_id": "p2", "severity": "low"})
        stats = tmp_engine.get_patch_stats("org-test")
        assert stats["total_patches"] == 2
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_severity"]["low"] == 1

    def test_stats_success_rate(self, tmp_engine, sample_patch):
        p = tmp_engine.add_patch("org-test", sample_patch)
        d1 = tmp_engine.deploy_patch("org-test", p["id"], "a1", "srv1", "admin")
        d2 = tmp_engine.deploy_patch("org-test", p["id"], "a2", "srv2", "admin")
        tmp_engine.update_deployment("org-test", d1["id"], "success")
        tmp_engine.update_deployment("org-test", d2["id"], "failed")
        stats = tmp_engine.get_patch_stats("org-test")
        assert stats["success_rate"] == 50.0

    def test_stats_pending_critical(self, tmp_engine, sample_patch):
        tmp_engine.add_patch("org-test", sample_patch)  # critical + available
        stats = tmp_engine.get_patch_stats("org-test")
        assert stats["pending_critical"] == 1

    def test_stats_exceptions_count(self, tmp_engine, sample_patch_id):
        tmp_engine.add_exception("org-test", {"patch_id": sample_patch_id, "asset_id": "a1"})
        tmp_engine.add_exception("org-test", {"patch_id": sample_patch_id, "asset_id": "a2"})
        stats = tmp_engine.get_patch_stats("org-test")
        assert stats["exceptions_count"] == 2

    def test_stats_org_isolation(self, tmp_engine, alt_engine, sample_patch):
        tmp_engine.add_patch("org-test", sample_patch)
        stats = alt_engine.get_patch_stats("org-other")
        assert stats["total_patches"] == 0
