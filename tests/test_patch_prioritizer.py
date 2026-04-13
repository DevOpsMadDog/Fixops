"""Tests for the Patch Prioritization Engine.

22+ tests covering scoring, KEV detection, batch prioritization,
plan management, patching workflow, and stats.
"""

import sys
import os
import tempfile
import pytest

sys.path.insert(0, "suite-core")

# Use a temp DB so tests are isolated
os.environ.setdefault("FIXOPS_MODE", "test")

from core.patch_prioritizer import PatchPrioritizer, KEV_LIST


@pytest.fixture
def prioritizer(tmp_path):
    db_path = str(tmp_path / "test_patch.db")
    return PatchPrioritizer(db_path=db_path)


# ---------------------------------------------------------------------------
# score_cve — basic structure
# ---------------------------------------------------------------------------

def test_score_cve_returns_dict(prioritizer):
    result = prioritizer.score_cve("CVE-2021-44228", cvss_score=10.0, epss_score=0.97)
    assert isinstance(result, dict)


def test_score_cve_has_required_keys(prioritizer):
    result = prioritizer.score_cve("CVE-2021-44228")
    required = {"cve_id", "priority_score", "priority_band", "is_kev", "kev_due_date", "reasoning"}
    assert required.issubset(result.keys())


def test_score_cve_priority_score_is_float(prioritizer):
    result = prioritizer.score_cve("CVE-2021-44228", cvss_score=5.0, epss_score=0.5)
    assert isinstance(result["priority_score"], float)


def test_score_cve_priority_score_in_range(prioritizer):
    result = prioritizer.score_cve("CVE-2021-44228", cvss_score=10.0, epss_score=1.0)
    assert 0.0 <= result["priority_score"] <= 100.0


# ---------------------------------------------------------------------------
# KEV detection
# ---------------------------------------------------------------------------

def test_score_cve_log4shell_is_kev(prioritizer):
    result = prioritizer.score_cve("CVE-2021-44228")
    assert result["is_kev"] is True


def test_score_cve_log4shell_kev_due_date(prioritizer):
    result = prioritizer.score_cve("CVE-2021-44228")
    assert result["kev_due_date"] == "2021-12-24"


def test_score_cve_unknown_is_not_kev(prioritizer):
    result = prioritizer.score_cve("CVE-9999-99999")
    assert result["is_kev"] is False


def test_score_cve_unknown_kev_due_date_is_none(prioritizer):
    result = prioritizer.score_cve("CVE-9999-99999")
    assert result["kev_due_date"] is None


def test_is_kev_log4shell(prioritizer):
    assert prioritizer.is_kev("CVE-2021-44228") is True


def test_is_kev_unknown(prioritizer):
    assert prioritizer.is_kev("CVE-9999-99999") is False


# ---------------------------------------------------------------------------
# Scoring thresholds
# ---------------------------------------------------------------------------

def test_score_cve_high_inputs_high_score(prioritizer):
    result = prioritizer.score_cve(
        "CVE-2021-44228",
        cvss_score=10.0,
        epss_score=1.0,
        asset_criticality="critical",
    )
    assert result["priority_score"] >= 75.0


def test_score_cve_low_inputs_low_score(prioritizer):
    result = prioritizer.score_cve(
        "CVE-9999-99999",
        cvss_score=2.0,
        epss_score=0.01,
        asset_criticality="low",
    )
    assert result["priority_score"] < 50.0


def test_priority_band_valid_values(prioritizer):
    result = prioritizer.score_cve("CVE-9999-99999", cvss_score=5.0, epss_score=0.5)
    assert result["priority_band"] in {"critical", "high", "medium", "low"}


def test_reasoning_is_nonempty_string(prioritizer):
    result = prioritizer.score_cve("CVE-2021-44228", cvss_score=10.0, epss_score=0.9)
    assert isinstance(result["reasoning"], str) and len(result["reasoning"]) > 0


def test_reasoning_contains_kev_name(prioritizer):
    result = prioritizer.score_cve("CVE-2021-44228")
    assert "Log4Shell" in result["reasoning"]


# ---------------------------------------------------------------------------
# prioritize_batch
# ---------------------------------------------------------------------------

def test_prioritize_batch_returns_list(prioritizer):
    cves = [
        {"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.97, "asset_criticality": "critical"},
        {"cve_id": "CVE-9999-00001", "cvss_score": 2.0, "epss_score": 0.01, "asset_criticality": "low"},
    ]
    result = prioritizer.prioritize_batch(cves)
    assert isinstance(result, list)


def test_prioritize_batch_sorted_descending(prioritizer):
    cves = [
        {"cve_id": "CVE-9999-00001", "cvss_score": 2.0, "epss_score": 0.01, "asset_criticality": "low"},
        {"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.97, "asset_criticality": "critical"},
    ]
    result = prioritizer.prioritize_batch(cves)
    scores = [r["priority_score"] for r in result]
    assert scores == sorted(scores, reverse=True)


def test_prioritize_batch_empty_returns_empty(prioritizer):
    assert prioritizer.prioritize_batch([]) == []


def test_prioritize_batch_length_matches_input(prioritizer):
    cves = [
        {"cve_id": "CVE-2022-0778", "cvss_score": 7.5, "epss_score": 0.3, "asset_criticality": "high"},
        {"cve_id": "CVE-2021-34527", "cvss_score": 8.8, "epss_score": 0.6, "asset_criticality": "critical"},
        {"cve_id": "CVE-9999-11111", "cvss_score": 3.0, "epss_score": 0.05, "asset_criticality": "low"},
    ]
    result = prioritizer.prioritize_batch(cves)
    assert len(result) == 3


# ---------------------------------------------------------------------------
# create_patch_plan
# ---------------------------------------------------------------------------

def test_create_patch_plan_returns_dict_with_plan_id(prioritizer):
    cves = [{"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.97, "asset_criticality": "critical"}]
    plan = prioritizer.create_patch_plan(cves)
    assert "plan_id" in plan
    assert isinstance(plan["plan_id"], str) and len(plan["plan_id"]) > 0


def test_create_patch_plan_critical_count_correct(prioritizer):
    cves = [
        {"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 1.0, "asset_criticality": "critical"},
        {"cve_id": "CVE-9999-99999", "cvss_score": 1.0, "epss_score": 0.001, "asset_criticality": "low"},
    ]
    plan = prioritizer.create_patch_plan(cves)
    # At least the KEV+high-cvss CVE should be critical
    assert plan["critical_count"] >= 1


def test_create_patch_plan_total_cves_correct(prioritizer):
    cves = [
        {"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.97, "asset_criticality": "critical"},
        {"cve_id": "CVE-2022-0778", "cvss_score": 7.5, "epss_score": 0.3, "asset_criticality": "high"},
    ]
    plan = prioritizer.create_patch_plan(cves)
    assert plan["total_cves"] == 2


def test_create_patch_plan_has_patches_list(prioritizer):
    cves = [{"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.97, "asset_criticality": "critical"}]
    plan = prioritizer.create_patch_plan(cves)
    assert isinstance(plan["patches"], list)


# ---------------------------------------------------------------------------
# get_plan / list_plans
# ---------------------------------------------------------------------------

def test_get_plan_returns_created_plan(prioritizer):
    cves = [{"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.9, "asset_criticality": "high"}]
    plan = prioritizer.create_patch_plan(cves, org_id="org1", plan_name="Q1 Plan")
    retrieved = prioritizer.get_plan(plan["plan_id"])
    assert retrieved is not None
    assert retrieved["plan_id"] == plan["plan_id"]
    assert retrieved["plan_name"] == "Q1 Plan"


def test_get_plan_nonexistent_returns_none(prioritizer):
    assert prioritizer.get_plan("nonexistent-id") is None


def test_list_plans_returns_list(prioritizer):
    result = prioritizer.list_plans()
    assert isinstance(result, list)


def test_list_plans_contains_created_plan(prioritizer):
    cves = [{"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.9, "asset_criticality": "critical"}]
    plan = prioritizer.create_patch_plan(cves, org_id="org-list-test")
    plans = prioritizer.list_plans(org_id="org-list-test")
    ids = [p["plan_id"] for p in plans]
    assert plan["plan_id"] in ids


# ---------------------------------------------------------------------------
# mark_patched
# ---------------------------------------------------------------------------

def test_mark_patched_returns_record(prioritizer):
    cves = [{"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.9, "asset_criticality": "critical"}]
    plan = prioritizer.create_patch_plan(cves)
    record = prioritizer.mark_patched(plan["plan_id"], "CVE-2021-44228", patched_by="alice")
    assert isinstance(record, dict)
    assert record["cve_id"] == "CVE-2021-44228"
    assert record["plan_id"] == plan["plan_id"]
    assert record["patched_by"] == "alice"


def test_mark_patched_record_has_patched_at(prioritizer):
    cves = [{"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.9, "asset_criticality": "critical"}]
    plan = prioritizer.create_patch_plan(cves)
    record = prioritizer.mark_patched(plan["plan_id"], "CVE-2021-44228")
    assert "patched_at" in record and record["patched_at"]


# ---------------------------------------------------------------------------
# get_patch_stats
# ---------------------------------------------------------------------------

def test_get_patch_stats_returns_dict(prioritizer):
    result = prioritizer.get_patch_stats()
    assert isinstance(result, dict)


def test_get_patch_stats_has_required_keys(prioritizer):
    result = prioritizer.get_patch_stats()
    assert {"total_plans", "total_cves_prioritized", "kev_patched", "kev_overdue"}.issubset(result.keys())


def test_get_patch_stats_numeric_values(prioritizer):
    result = prioritizer.get_patch_stats()
    for key in ("total_plans", "total_cves_prioritized", "kev_patched", "kev_overdue"):
        assert isinstance(result[key], int)


def test_get_patch_stats_reflects_created_plan(prioritizer):
    cves = [
        {"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.9, "asset_criticality": "critical"},
        {"cve_id": "CVE-9999-99999", "cvss_score": 3.0, "epss_score": 0.05, "asset_criticality": "low"},
    ]
    prioritizer.create_patch_plan(cves, org_id="stats-org")
    stats = prioritizer.get_patch_stats(org_id="stats-org")
    assert stats["total_plans"] == 1
    assert stats["total_cves_prioritized"] == 2


def test_get_patch_stats_kev_patched_increments(prioritizer):
    cves = [{"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.9, "asset_criticality": "critical"}]
    plan = prioritizer.create_patch_plan(cves, org_id="kev-org")
    prioritizer.mark_patched(plan["plan_id"], "CVE-2021-44228")
    stats = prioritizer.get_patch_stats(org_id="kev-org")
    assert stats["kev_patched"] >= 1
