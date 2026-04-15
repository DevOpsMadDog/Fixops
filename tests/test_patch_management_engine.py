"""Tests for PatchManagementEngine — ALDECI."""

from __future__ import annotations

import pytest

from core.patch_management_engine import PatchManagementEngine


@pytest.fixture
def engine(tmp_path):
    return PatchManagementEngine(db_path=str(tmp_path / "patch_mgmt.db"))


# ---------------------------------------------------------------------------
# register_patch — validation
# ---------------------------------------------------------------------------

def test_register_patch_minimal(engine):
    p = engine.register_patch("org1", {"title": "KB5001234"})
    assert p["id"]
    assert p["org_id"] == "org1"
    assert p["title"] == "KB5001234"
    assert p["status"] == "available"
    assert p["patch_type"] == "security"
    assert p["severity"] == "medium"
    assert p["deployed_count"] == 0
    assert p["failed_count"] == 0
    assert p["created_at"]


def test_register_patch_all_fields(engine):
    p = engine.register_patch("org1", {
        "title": "Security Update",
        "cve_ids": ["CVE-2024-1234", "CVE-2024-5678"],
        "patch_type": "hotfix",
        "severity": "critical",
        "vendor": "Microsoft",
        "affected_os": "windows",
        "version": "1.2.3",
        "release_date": "2024-01-15T00:00:00+00:00",
    })
    assert p["patch_type"] == "hotfix"
    assert p["severity"] == "critical"
    assert p["vendor"] == "Microsoft"
    assert p["version"] == "1.2.3"
    assert "CVE-2024-1234" in p["cve_ids_json"]


def test_register_patch_missing_title_raises(engine):
    with pytest.raises(ValueError, match="title"):
        engine.register_patch("org1", {"severity": "high"})


def test_register_patch_empty_title_raises(engine):
    with pytest.raises(ValueError, match="title"):
        engine.register_patch("org1", {"title": "   "})


def test_register_patch_invalid_patch_type_raises(engine):
    with pytest.raises(ValueError, match="patch_type"):
        engine.register_patch("org1", {"title": "P1", "patch_type": "unknown_type"})


def test_register_patch_invalid_severity_raises(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.register_patch("org1", {"title": "P1", "severity": "extreme"})


@pytest.mark.parametrize("pt", ["security", "feature", "hotfix", "rollup", "service_pack", "firmware"])
def test_register_patch_all_valid_patch_types(engine, pt):
    p = engine.register_patch("org1", {"title": f"Patch {pt}", "patch_type": pt})
    assert p["patch_type"] == pt


@pytest.mark.parametrize("sev", ["critical", "high", "medium", "low"])
def test_register_patch_all_valid_severities(engine, sev):
    p = engine.register_patch("org1", {"title": f"Patch {sev}", "severity": sev})
    assert p["severity"] == sev


# ---------------------------------------------------------------------------
# list_patches / get_patch
# ---------------------------------------------------------------------------

def test_list_patches_empty(engine):
    assert engine.list_patches("org1") == []


def test_list_patches_returns_own_org_only(engine):
    engine.register_patch("org1", {"title": "P1"})
    engine.register_patch("org2", {"title": "P2"})
    assert len(engine.list_patches("org1")) == 1
    assert len(engine.list_patches("org2")) == 1


def test_list_patches_filter_patch_type(engine):
    engine.register_patch("org1", {"title": "P1", "patch_type": "security"})
    engine.register_patch("org1", {"title": "P2", "patch_type": "hotfix"})
    result = engine.list_patches("org1", patch_type="hotfix")
    assert len(result) == 1
    assert result[0]["patch_type"] == "hotfix"


def test_list_patches_filter_severity(engine):
    engine.register_patch("org1", {"title": "P1", "severity": "critical"})
    engine.register_patch("org1", {"title": "P2", "severity": "low"})
    result = engine.list_patches("org1", severity="critical")
    assert len(result) == 1


def test_list_patches_filter_status(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    engine.update_patch_status("org1", p["id"], "testing")
    result = engine.list_patches("org1", status="testing")
    assert len(result) == 1


def test_get_patch_exists(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    fetched = engine.get_patch("org1", p["id"])
    assert fetched["id"] == p["id"]


def test_get_patch_not_found_returns_none(engine):
    assert engine.get_patch("org1", "nonexistent") is None


def test_get_patch_wrong_org_returns_none(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    assert engine.get_patch("org2", p["id"]) is None


# ---------------------------------------------------------------------------
# update_patch_status
# ---------------------------------------------------------------------------

def test_update_patch_status_valid(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    updated = engine.update_patch_status("org1", p["id"], "testing")
    assert updated["status"] == "testing"


def test_update_patch_status_with_notes(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    updated = engine.update_patch_status("org1", p["id"], "approved", notes="Passed QA")
    assert updated["status"] == "approved"
    assert updated["test_results"] == "Passed QA"


def test_update_patch_status_invalid_raises(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    with pytest.raises(ValueError, match="status"):
        engine.update_patch_status("org1", p["id"], "invalid_status")


def test_update_patch_status_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.update_patch_status("org1", "bad-id", "deployed")


@pytest.mark.parametrize("st", ["available", "testing", "approved", "deploying", "deployed", "failed", "rollback"])
def test_update_patch_all_valid_statuses(engine, st):
    p = engine.register_patch("org1", {"title": f"P_{st}"})
    updated = engine.update_patch_status("org1", p["id"], st)
    assert updated["status"] == st


# ---------------------------------------------------------------------------
# record_deployment / list_deployments
# ---------------------------------------------------------------------------

def test_record_deployment_success_increments_deployed_count(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    engine.record_deployment("org1", p["id"], {"hostname": "srv1", "status": "success", "os_type": "linux"})
    engine.record_deployment("org1", p["id"], {"hostname": "srv2", "status": "success", "os_type": "linux"})
    updated = engine.get_patch("org1", p["id"])
    assert updated["deployed_count"] == 2
    assert updated["failed_count"] == 0


def test_record_deployment_failed_increments_failed_count(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    engine.record_deployment("org1", p["id"], {"status": "failed", "os_type": "windows", "failure_reason": "timeout"})
    updated = engine.get_patch("org1", p["id"])
    assert updated["failed_count"] == 1
    assert updated["deployed_count"] == 0


def test_record_deployment_pending_no_counter_change(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    engine.record_deployment("org1", p["id"], {"status": "pending", "os_type": "linux"})
    updated = engine.get_patch("org1", p["id"])
    assert updated["deployed_count"] == 0
    assert updated["failed_count"] == 0


def test_record_deployment_invalid_status_raises(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    with pytest.raises(ValueError, match="status"):
        engine.record_deployment("org1", p["id"], {"status": "broken"})


def test_record_deployment_invalid_os_type_raises(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    with pytest.raises(ValueError, match="os_type"):
        engine.record_deployment("org1", p["id"], {"status": "success", "os_type": "beos"})


def test_record_deployment_returns_record(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    dep = engine.record_deployment("org1", p["id"], {
        "asset_id": "asset-1",
        "hostname": "web01",
        "os_type": "linux",
        "status": "success",
    })
    assert dep["id"]
    assert dep["patch_id"] == p["id"]
    assert dep["hostname"] == "web01"
    assert dep["status"] == "success"


def test_list_deployments_filter_by_patch_id(engine):
    p1 = engine.register_patch("org1", {"title": "P1"})
    p2 = engine.register_patch("org1", {"title": "P2"})
    engine.record_deployment("org1", p1["id"], {"status": "success", "os_type": "linux"})
    engine.record_deployment("org1", p2["id"], {"status": "success", "os_type": "linux"})
    result = engine.list_deployments("org1", patch_id=p1["id"])
    assert len(result) == 1


def test_list_deployments_filter_by_status(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    engine.record_deployment("org1", p["id"], {"status": "success", "os_type": "linux"})
    engine.record_deployment("org1", p["id"], {"status": "failed", "os_type": "linux"})
    result = engine.list_deployments("org1", status="failed")
    assert len(result) == 1


def test_list_deployments_filter_by_os_type(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    engine.record_deployment("org1", p["id"], {"status": "success", "os_type": "windows"})
    engine.record_deployment("org1", p["id"], {"status": "success", "os_type": "linux"})
    result = engine.list_deployments("org1", os_type="windows")
    assert len(result) == 1


# ---------------------------------------------------------------------------
# get_patch_stats
# ---------------------------------------------------------------------------

def test_get_patch_stats_empty(engine):
    stats = engine.get_patch_stats("org1")
    assert stats["total_patches"] == 0
    assert stats["critical_patches"] == 0
    assert stats["undeployed_critical"] == 0
    assert stats["total_deployments"] == 0
    assert stats["deployment_success_rate"] == 0.0


def test_get_patch_stats_counts(engine):
    engine.register_patch("org1", {"title": "C1", "severity": "critical"})
    engine.register_patch("org1", {"title": "H1", "severity": "high"})
    engine.register_patch("org1", {"title": "M1", "severity": "medium"})
    stats = engine.get_patch_stats("org1")
    assert stats["total_patches"] == 3
    assert stats["critical_patches"] == 1
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["high"] == 1


def test_get_patch_stats_undeployed_critical(engine):
    p = engine.register_patch("org1", {"title": "C1", "severity": "critical"})
    stats = engine.get_patch_stats("org1")
    assert stats["undeployed_critical"] == 1

    # Deploy it — should no longer be undeployed_critical
    engine.record_deployment("org1", p["id"], {"status": "success", "os_type": "linux"})
    stats2 = engine.get_patch_stats("org1")
    assert stats2["undeployed_critical"] == 0


def test_get_patch_stats_deployment_success_rate(engine):
    p = engine.register_patch("org1", {"title": "P1"})
    engine.record_deployment("org1", p["id"], {"status": "success", "os_type": "linux"})
    engine.record_deployment("org1", p["id"], {"status": "success", "os_type": "linux"})
    engine.record_deployment("org1", p["id"], {"status": "failed", "os_type": "linux"})
    stats = engine.get_patch_stats("org1")
    assert stats["total_deployments"] == 3
    assert abs(stats["deployment_success_rate"] - 66.67) < 0.1


def test_get_patch_stats_patches_needing_attention(engine):
    p = engine.register_patch("org1", {"title": "C1", "severity": "critical"})
    stats = engine.get_patch_stats("org1")
    assert len(stats["patches_needing_attention"]) == 1

    # Move to approved — no longer needs attention
    engine.update_patch_status("org1", p["id"], "approved")
    stats2 = engine.get_patch_stats("org1")
    assert len(stats2["patches_needing_attention"]) == 0


def test_get_patch_stats_org_isolation(engine):
    engine.register_patch("org1", {"title": "P1", "severity": "critical"})
    engine.register_patch("org2", {"title": "P2", "severity": "critical"})
    stats1 = engine.get_patch_stats("org1")
    stats2 = engine.get_patch_stats("org2")
    assert stats1["total_patches"] == 1
    assert stats2["total_patches"] == 1
