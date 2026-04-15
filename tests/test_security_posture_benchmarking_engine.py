"""
Comprehensive tests for SecurityPostureBenchmarkingEngine.

Covers:
- create_benchmark: valid, invalid framework, invalid category, status default
- list_benchmarks: all, filtered by framework, filtered by status, org isolation
- get_benchmark: found, not found, org isolation
- record_control: valid, invalid result, invalid severity, score computation
- list_controls: all, filtered by benchmark, result, severity
- add_comparison: valid, invalid peer_group, gap computation
- list_comparisons: all, filtered by benchmark
- complete_assessment: score recomputed, status=active, last_assessed set
- get_benchmarking_stats: totals, avg_score, above_industry_avg, critical_failures,
                          by_framework, by_category
- Multi-tenant isolation throughout
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.security_posture_benchmarking_engine import SecurityPostureBenchmarkingEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "spb.db")
    return SecurityPostureBenchmarkingEngine(db_path=db)


ORG = "org-spb-test"
ORG2 = "org-spb-other"


def _bench(overrides=None):
    base = {
        "benchmark_name": "CIS Level 1",
        "framework": "cis",
        "category": "network",
        "version": "v8",
    }
    if overrides:
        base.update(overrides)
    return base


def _control(benchmark_id, overrides=None):
    base = {
        "benchmark_id": benchmark_id,
        "control_id": "CIS 1.1",
        "title": "Inventory Assets",
        "result": "pass",
        "severity": "high",
    }
    if overrides:
        base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# create_benchmark
# ---------------------------------------------------------------------------

class TestCreateBenchmark:
    def test_returns_dict_with_id(self, engine):
        result = engine.create_benchmark(ORG, _bench())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_stores_name_and_framework(self, engine):
        result = engine.create_benchmark(ORG, _bench())
        assert result["benchmark_name"] == "CIS Level 1"
        assert result["framework"] == "cis"

    def test_status_defaults_to_draft(self, engine):
        result = engine.create_benchmark(ORG, _bench())
        assert result["status"] == "draft"

    def test_score_defaults_to_zero(self, engine):
        result = engine.create_benchmark(ORG, _bench())
        assert result["score"] == 0.0

    def test_passed_controls_defaults_to_zero(self, engine):
        result = engine.create_benchmark(ORG, _bench())
        assert result["passed_controls"] == 0

    def test_invalid_framework_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid framework"):
            engine.create_benchmark(ORG, _bench({"framework": "bad_fw"}))

    def test_invalid_category_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid category"):
            engine.create_benchmark(ORG, _bench({"category": "bad_cat"}))

    def test_all_valid_frameworks(self, engine):
        for fw in ("cis", "nist", "iso27001", "soc2", "pci_dss", "hipaa", "custom"):
            result = engine.create_benchmark(
                ORG, _bench({"framework": fw, "benchmark_name": f"bench-{fw}"})
            )
            assert result["framework"] == fw

    def test_all_valid_categories(self, engine):
        for cat in ("network", "endpoint", "cloud", "identity", "application",
                    "data", "operations", "compliance"):
            result = engine.create_benchmark(
                ORG, _bench({"category": cat, "benchmark_name": f"bench-{cat}"})
            )
            assert result["category"] == cat

    def test_org_id_stored(self, engine):
        result = engine.create_benchmark(ORG, _bench())
        assert result["org_id"] == ORG


# ---------------------------------------------------------------------------
# list_benchmarks
# ---------------------------------------------------------------------------

class TestListBenchmarks:
    def test_list_returns_created(self, engine):
        engine.create_benchmark(ORG, _bench())
        results = engine.list_benchmarks(ORG)
        assert len(results) >= 1

    def test_filter_by_framework(self, engine):
        engine.create_benchmark(ORG, _bench({"framework": "nist"}))
        engine.create_benchmark(ORG, _bench({"framework": "cis"}))
        results = engine.list_benchmarks(ORG, framework="nist")
        assert all(r["framework"] == "nist" for r in results)

    def test_filter_by_status(self, engine):
        engine.create_benchmark(ORG, _bench({"status": "active"}))
        engine.create_benchmark(ORG, _bench({"status": "draft"}))
        results = engine.list_benchmarks(ORG, status="active")
        assert all(r["status"] == "active" for r in results)

    def test_org_isolation(self, engine):
        engine.create_benchmark(ORG, _bench())
        results = engine.list_benchmarks(ORG2)
        assert results == []


# ---------------------------------------------------------------------------
# get_benchmark
# ---------------------------------------------------------------------------

class TestGetBenchmark:
    def test_found(self, engine):
        created = engine.create_benchmark(ORG, _bench())
        result = engine.get_benchmark(ORG, created["id"])
        assert result is not None
        assert result["id"] == created["id"]

    def test_not_found_returns_none(self, engine):
        result = engine.get_benchmark(ORG, "nonexistent-id")
        assert result is None

    def test_org_isolation(self, engine):
        created = engine.create_benchmark(ORG, _bench())
        result = engine.get_benchmark(ORG2, created["id"])
        assert result is None


# ---------------------------------------------------------------------------
# record_control
# ---------------------------------------------------------------------------

class TestRecordControl:
    def test_returns_dict_with_id(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        ctrl = engine.record_control(ORG, _control(bench["id"]))
        assert "id" in ctrl
        assert len(ctrl["id"]) == 36

    def test_invalid_result_raises(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        with pytest.raises(ValueError, match="Invalid result"):
            engine.record_control(ORG, _control(bench["id"], {"result": "unknown"}))

    def test_invalid_severity_raises(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        with pytest.raises(ValueError, match="Invalid severity"):
            engine.record_control(ORG, _control(bench["id"], {"severity": "extreme"}))

    def test_score_updated_on_pass(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        engine.record_control(ORG, _control(bench["id"], {"result": "pass"}))
        updated = engine.get_benchmark(ORG, bench["id"])
        assert updated["score"] == 100.0
        assert updated["passed_controls"] == 1

    def test_score_updated_on_fail(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        engine.record_control(ORG, _control(bench["id"], {"result": "pass"}))
        engine.record_control(ORG, _control(bench["id"], {"result": "fail"}))
        updated = engine.get_benchmark(ORG, bench["id"])
        assert updated["score"] == 50.0
        assert updated["passed_controls"] == 1
        assert updated["total_controls"] == 2

    def test_all_valid_results(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        for result in ("pass", "fail", "partial", "not_applicable"):
            ctrl = engine.record_control(ORG, _control(bench["id"], {"result": result}))
            assert ctrl["result"] == result

    def test_all_valid_severities(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        for sev in ("critical", "high", "medium", "low"):
            ctrl = engine.record_control(ORG, _control(bench["id"], {"severity": sev}))
            assert ctrl["severity"] == sev


# ---------------------------------------------------------------------------
# list_controls
# ---------------------------------------------------------------------------

class TestListControls:
    def test_list_returns_recorded(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        engine.record_control(ORG, _control(bench["id"]))
        controls = engine.list_controls(ORG)
        assert len(controls) >= 1

    def test_filter_by_benchmark(self, engine):
        bench1 = engine.create_benchmark(ORG, _bench())
        bench2 = engine.create_benchmark(ORG, _bench({"benchmark_name": "B2"}))
        engine.record_control(ORG, _control(bench1["id"]))
        engine.record_control(ORG, _control(bench2["id"]))
        controls = engine.list_controls(ORG, benchmark_id=bench1["id"])
        assert all(c["benchmark_id"] == bench1["id"] for c in controls)

    def test_filter_by_result(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        engine.record_control(ORG, _control(bench["id"], {"result": "fail"}))
        engine.record_control(ORG, _control(bench["id"], {"result": "pass"}))
        controls = engine.list_controls(ORG, result="fail")
        assert all(c["result"] == "fail" for c in controls)

    def test_filter_by_severity(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        engine.record_control(ORG, _control(bench["id"], {"severity": "critical"}))
        engine.record_control(ORG, _control(bench["id"], {"severity": "low"}))
        controls = engine.list_controls(ORG, severity="critical")
        assert all(c["severity"] == "critical" for c in controls)

    def test_org_isolation(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        engine.record_control(ORG, _control(bench["id"]))
        controls = engine.list_controls(ORG2)
        assert controls == []


# ---------------------------------------------------------------------------
# add_comparison
# ---------------------------------------------------------------------------

class TestAddComparison:
    def test_returns_dict_with_id(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        cmp = engine.add_comparison(ORG, {
            "benchmark_id": bench["id"],
            "peer_group": "enterprise",
            "peer_avg_score": 60.0,
            "our_score": 75.0,
        })
        assert "id" in cmp

    def test_gap_computed_correctly(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        cmp = engine.add_comparison(ORG, {
            "benchmark_id": bench["id"],
            "peer_group": "smb",
            "peer_avg_score": 60.0,
            "our_score": 75.0,
        })
        assert abs(cmp["gap"] - 15.0) < 0.01

    def test_negative_gap_when_below_peer(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        cmp = engine.add_comparison(ORG, {
            "benchmark_id": bench["id"],
            "peer_group": "finance",
            "peer_avg_score": 80.0,
            "our_score": 65.0,
        })
        assert cmp["gap"] < 0

    def test_invalid_peer_group_raises(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        with pytest.raises(ValueError, match="Invalid peer_group"):
            engine.add_comparison(ORG, {
                "benchmark_id": bench["id"],
                "peer_group": "unknown_group",
                "peer_avg_score": 50.0,
                "our_score": 60.0,
            })

    def test_all_valid_peer_groups(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        for pg in ("enterprise", "smb", "startup", "government", "healthcare", "finance", "retail"):
            cmp = engine.add_comparison(ORG, {
                "benchmark_id": bench["id"],
                "peer_group": pg,
                "peer_avg_score": 50.0,
                "our_score": 55.0,
            })
            assert cmp["peer_group"] == pg


# ---------------------------------------------------------------------------
# list_comparisons
# ---------------------------------------------------------------------------

class TestListComparisons:
    def test_list_returns_added(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        engine.add_comparison(ORG, {
            "benchmark_id": bench["id"],
            "peer_group": "enterprise",
            "peer_avg_score": 60.0,
            "our_score": 70.0,
        })
        cmps = engine.list_comparisons(ORG)
        assert len(cmps) >= 1

    def test_filter_by_benchmark(self, engine):
        bench1 = engine.create_benchmark(ORG, _bench())
        bench2 = engine.create_benchmark(ORG, _bench({"benchmark_name": "B2"}))
        engine.add_comparison(ORG, {"benchmark_id": bench1["id"], "peer_group": "smb",
                                    "peer_avg_score": 50.0, "our_score": 55.0})
        engine.add_comparison(ORG, {"benchmark_id": bench2["id"], "peer_group": "smb",
                                    "peer_avg_score": 50.0, "our_score": 55.0})
        cmps = engine.list_comparisons(ORG, benchmark_id=bench1["id"])
        assert all(c["benchmark_id"] == bench1["id"] for c in cmps)

    def test_org_isolation(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        engine.add_comparison(ORG, {"benchmark_id": bench["id"], "peer_group": "smb",
                                    "peer_avg_score": 50.0, "our_score": 55.0})
        cmps = engine.list_comparisons(ORG2)
        assert cmps == []


# ---------------------------------------------------------------------------
# complete_assessment
# ---------------------------------------------------------------------------

class TestCompleteAssessment:
    def test_sets_status_active(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        engine.record_control(ORG, _control(bench["id"], {"result": "pass"}))
        result = engine.complete_assessment(ORG, bench["id"])
        assert result["status"] == "active"

    def test_last_assessed_set(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        result = engine.complete_assessment(ORG, bench["id"])
        assert result["last_assessed"] is not None

    def test_score_recomputed_from_controls(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        engine.record_control(ORG, _control(bench["id"], {"result": "pass"}))
        engine.record_control(ORG, _control(bench["id"], {"result": "pass"}))
        engine.record_control(ORG, _control(bench["id"], {"result": "fail"}))
        result = engine.complete_assessment(ORG, bench["id"])
        assert abs(result["score"] - 66.67) < 0.1

    def test_returns_empty_dict_for_missing(self, engine):
        result = engine.complete_assessment(ORG, "nonexistent-id")
        assert result == {}

    def test_org_isolation(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        result = engine.complete_assessment(ORG2, bench["id"])
        assert result == {}


# ---------------------------------------------------------------------------
# get_benchmarking_stats
# ---------------------------------------------------------------------------

class TestGetBenchmarkingStats:
    def test_total_benchmarks(self, engine):
        engine.create_benchmark(ORG, _bench())
        engine.create_benchmark(ORG, _bench({"benchmark_name": "B2"}))
        stats = engine.get_benchmarking_stats(ORG)
        assert stats["total_benchmarks"] == 2

    def test_active_benchmarks(self, engine):
        engine.create_benchmark(ORG, _bench({"status": "active"}))
        engine.create_benchmark(ORG, _bench({"status": "draft"}))
        stats = engine.get_benchmarking_stats(ORG)
        assert stats["active_benchmarks"] == 1

    def test_above_industry_avg(self, engine):
        engine.create_benchmark(ORG, _bench({"score": 80.0, "industry_avg_score": 60.0}))
        engine.create_benchmark(ORG, _bench({"benchmark_name": "B2", "score": 50.0,
                                              "industry_avg_score": 60.0}))
        stats = engine.get_benchmarking_stats(ORG)
        assert stats["above_industry_avg"] == 1

    def test_critical_failures(self, engine):
        bench = engine.create_benchmark(ORG, _bench())
        engine.record_control(ORG, _control(bench["id"], {"result": "fail", "severity": "critical"}))
        engine.record_control(ORG, _control(bench["id"], {"result": "fail", "severity": "high"}))
        stats = engine.get_benchmarking_stats(ORG)
        assert stats["critical_failures"] == 1

    def test_by_framework(self, engine):
        engine.create_benchmark(ORG, _bench({"framework": "nist"}))
        engine.create_benchmark(ORG, _bench({"benchmark_name": "B2", "framework": "nist"}))
        engine.create_benchmark(ORG, _bench({"benchmark_name": "B3", "framework": "cis"}))
        stats = engine.get_benchmarking_stats(ORG)
        assert stats["by_framework"].get("nist", 0) == 2
        assert stats["by_framework"].get("cis", 0) == 1

    def test_by_category(self, engine):
        engine.create_benchmark(ORG, _bench({"category": "cloud"}))
        engine.create_benchmark(ORG, _bench({"benchmark_name": "B2", "category": "cloud"}))
        stats = engine.get_benchmarking_stats(ORG)
        assert stats["by_category"].get("cloud", 0) == 2

    def test_empty_org(self, engine):
        stats = engine.get_benchmarking_stats("empty-org-spb")
        assert stats["total_benchmarks"] == 0
        assert stats["avg_score"] == 0.0
        assert stats["critical_failures"] == 0

    def test_org_isolation(self, engine):
        engine.create_benchmark(ORG, _bench())
        engine.create_benchmark(ORG, _bench({"benchmark_name": "B2"}))
        engine.create_benchmark(ORG2, _bench())
        stats = engine.get_benchmarking_stats(ORG)
        stats2 = engine.get_benchmarking_stats(ORG2)
        assert stats["total_benchmarks"] == 2
        assert stats2["total_benchmarks"] == 1
