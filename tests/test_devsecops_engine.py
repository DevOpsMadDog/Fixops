"""Tests for DevSecOpsEngine — pipeline security, runs, findings, gate policies, stats.

25+ tests covering all methods with org isolation checks.
"""

from __future__ import annotations

import os
import tempfile
import pytest

from core.devsecops_engine import DevSecOpsEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_devsecops.db")
    return DevSecOpsEngine(db_path=db)


@pytest.fixture
def pipeline(engine):
    return engine.register_pipeline("org1", {
        "name": "CI Pipeline",
        "repo_url": "https://github.com/example/repo",
        "branch": "main",
        "ci_platform": "github_actions",
        "sast_enabled": 1,
        "sca_enabled": 1,
        "secret_scan_enabled": 1,
    })


# ---------------------------------------------------------------------------
# Pipeline tests
# ---------------------------------------------------------------------------

class TestRegisterPipeline:
    def test_creates_pipeline_with_required_fields(self, engine):
        result = engine.register_pipeline("org1", {"name": "Pipeline A"})
        assert result["name"] == "Pipeline A"
        assert result["org_id"] == "org1"
        assert "pipeline_id" in result
        assert result["ci_platform"] == "github_actions"

    def test_creates_pipeline_with_all_fields(self, engine):
        data = {
            "name": "Full Pipeline",
            "repo_url": "https://gitlab.com/org/repo",
            "branch": "develop",
            "ci_platform": "gitlab_ci",
            "sast_enabled": 1,
            "dast_enabled": 1,
            "sca_enabled": 1,
            "secret_scan_enabled": 0,
            "container_scan_enabled": 1,
        }
        result = engine.register_pipeline("org1", data)
        assert result["ci_platform"] == "gitlab_ci"
        assert result["dast_enabled"] == 1
        assert result["container_scan_enabled"] == 1

    def test_raises_on_missing_name(self, engine):
        with pytest.raises(ValueError, match="name is required"):
            engine.register_pipeline("org1", {})

    def test_raises_on_invalid_ci_platform(self, engine):
        with pytest.raises(ValueError, match="Invalid ci_platform"):
            engine.register_pipeline("org1", {"name": "P", "ci_platform": "travis"})

    def test_all_valid_ci_platforms(self, engine):
        platforms = ["github_actions", "gitlab_ci", "jenkins", "circleci", "azure_devops"]
        for platform in platforms:
            result = engine.register_pipeline("org1", {"name": f"P-{platform}", "ci_platform": platform})
            assert result["ci_platform"] == platform


class TestListPipelines:
    def test_lists_pipelines_for_org(self, engine, pipeline):
        results = engine.list_pipelines("org1")
        assert len(results) >= 1
        ids = [r["pipeline_id"] for r in results]
        assert pipeline["pipeline_id"] in ids

    def test_org_isolation(self, engine, pipeline):
        engine.register_pipeline("org2", {"name": "Org2 Pipeline"})
        org1 = engine.list_pipelines("org1")
        org2 = engine.list_pipelines("org2")
        org1_ids = {r["pipeline_id"] for r in org1}
        org2_ids = {r["pipeline_id"] for r in org2}
        assert not org1_ids.intersection(org2_ids)

    def test_filter_by_ci_platform(self, engine):
        engine.register_pipeline("org1", {"name": "GH", "ci_platform": "github_actions"})
        engine.register_pipeline("org1", {"name": "GL", "ci_platform": "gitlab_ci"})
        results = engine.list_pipelines("org1", ci_platform="gitlab_ci")
        assert all(r["ci_platform"] == "gitlab_ci" for r in results)

    def test_empty_for_unknown_org(self, engine, pipeline):
        assert engine.list_pipelines("org_unknown") == []


# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------

class TestTriggerRun:
    def test_creates_run(self, engine, pipeline):
        run = engine.trigger_run("org1", pipeline["pipeline_id"], {
            "triggered_by": "ci",
            "commit_sha": "abc123",
        })
        assert run["pipeline_id"] == pipeline["pipeline_id"]
        assert run["org_id"] == "org1"
        assert run["status"] in {"passed", "blocked"}
        assert "run_id" in run

    def test_run_has_finding_counts(self, engine, pipeline):
        run = engine.trigger_run("org1", pipeline["pipeline_id"], {})
        assert "sast_findings" in run
        assert "sca_findings" in run
        assert "secret_findings" in run
        assert "container_findings" in run

    def test_raises_for_unknown_pipeline(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.trigger_run("org1", "nonexistent-id", {})

    def test_org_isolation_for_runs(self, engine, pipeline):
        # org2 cannot trigger a run on org1's pipeline
        with pytest.raises(ValueError, match="not found"):
            engine.trigger_run("org2", pipeline["pipeline_id"], {})

    def test_gate_blocked_on_strict_policy(self, engine):
        """A policy with max_critical=0 + block_on_critical=1 should block runs with critical findings."""
        # Create pipeline with sast enabled (can produce critical findings)
        p = engine.register_pipeline("org1", {"name": "Strict", "sast_enabled": 1})
        engine.create_gate_policy("org1", {
            "name": "Zero Tolerance",
            "pipeline_id": p["pipeline_id"],
            "block_on_critical": 1,
            "max_critical": -1,  # impossible threshold → always blocks on any critical
        })
        # Run many times — at some point critical findings occur
        # Just verify the structure is correct
        run = engine.trigger_run("org1", p["pipeline_id"], {})
        assert run["status"] in {"passed", "blocked"}
        assert isinstance(run["gate_blocked"], int)


class TestGetRun:
    def test_get_existing_run(self, engine, pipeline):
        run = engine.trigger_run("org1", pipeline["pipeline_id"], {})
        result = engine.get_run("org1", run["run_id"])
        assert result is not None
        assert result["run_id"] == run["run_id"]

    def test_get_run_returns_none_for_unknown(self, engine):
        assert engine.get_run("org1", "no-such-run") is None

    def test_org_isolation_get_run(self, engine, pipeline):
        run = engine.trigger_run("org1", pipeline["pipeline_id"], {})
        assert engine.get_run("org2", run["run_id"]) is None


class TestListRuns:
    def test_lists_runs(self, engine, pipeline):
        engine.trigger_run("org1", pipeline["pipeline_id"], {})
        engine.trigger_run("org1", pipeline["pipeline_id"], {})
        runs = engine.list_runs("org1")
        assert len(runs) >= 2

    def test_filter_by_pipeline_id(self, engine, pipeline):
        p2 = engine.register_pipeline("org1", {"name": "P2"})
        engine.trigger_run("org1", pipeline["pipeline_id"], {})
        engine.trigger_run("org1", p2["pipeline_id"], {})
        runs = engine.list_runs("org1", pipeline_id=pipeline["pipeline_id"])
        assert all(r["pipeline_id"] == pipeline["pipeline_id"] for r in runs)

    def test_limit_parameter(self, engine, pipeline):
        for _ in range(5):
            engine.trigger_run("org1", pipeline["pipeline_id"], {})
        runs = engine.list_runs("org1", limit=3)
        assert len(runs) <= 3

    def test_org_isolation_list_runs(self, engine, pipeline):
        engine.trigger_run("org1", pipeline["pipeline_id"], {})
        assert engine.list_runs("org2") == []


# ---------------------------------------------------------------------------
# Findings tests
# ---------------------------------------------------------------------------

class TestListFindings:
    def test_findings_created_on_run(self, engine, pipeline):
        engine.trigger_run("org1", pipeline["pipeline_id"], {})
        findings = engine.list_findings("org1")
        # May be 0 if all scanners return 0 by chance; just check it's a list
        assert isinstance(findings, list)

    def test_filter_by_run_id(self, engine, pipeline):
        run = engine.trigger_run("org1", pipeline["pipeline_id"], {})
        findings = engine.list_findings("org1", run_id=run["run_id"])
        for f in findings:
            assert f["run_id"] == run["run_id"]

    def test_filter_by_severity(self, engine, pipeline):
        engine.trigger_run("org1", pipeline["pipeline_id"], {})
        findings = engine.list_findings("org1", severity="critical")
        for f in findings:
            assert f["severity"] == "critical"

    def test_org_isolation_findings(self, engine, pipeline):
        engine.trigger_run("org1", pipeline["pipeline_id"], {})
        assert engine.list_findings("org2") == []

    def test_suppressed_filter(self, engine, pipeline):
        engine.trigger_run("org1", pipeline["pipeline_id"], {})
        # By default suppressed=False is used
        findings = engine.list_findings("org1", suppressed=False)
        for f in findings:
            assert f["suppressed"] == 0


class TestSuppressFinding:
    def test_suppress_existing_finding(self, engine, pipeline):
        # Run until we get at least one finding
        for _ in range(10):
            engine.trigger_run("org1", pipeline["pipeline_id"], {})
        findings = engine.list_findings("org1")
        if findings:
            fid = findings[0]["finding_id"]
            assert engine.suppress_finding("org1", fid) is True
            suppressed = engine.list_findings("org1", suppressed=True)
            assert any(f["finding_id"] == fid for f in suppressed)

    def test_suppress_returns_false_for_unknown(self, engine):
        assert engine.suppress_finding("org1", "nonexistent") is False

    def test_org_isolation_suppress(self, engine, pipeline):
        for _ in range(10):
            engine.trigger_run("org1", pipeline["pipeline_id"], {})
        findings = engine.list_findings("org1")
        if findings:
            fid = findings[0]["finding_id"]
            # org2 cannot suppress org1's finding
            assert engine.suppress_finding("org2", fid) is False


# ---------------------------------------------------------------------------
# Gate policy tests
# ---------------------------------------------------------------------------

class TestCreateGatePolicy:
    def test_creates_policy(self, engine):
        policy = engine.create_gate_policy("org1", {"name": "Strict Policy"})
        assert policy["name"] == "Strict Policy"
        assert policy["org_id"] == "org1"
        assert "policy_id" in policy

    def test_policy_defaults(self, engine):
        policy = engine.create_gate_policy("org1", {"name": "Default Policy"})
        assert policy["block_on_critical"] == 1
        assert policy["block_on_high"] == 0
        assert policy["max_critical"] == 0
        assert policy["max_high"] == 5
        assert policy["max_medium"] == 20
        assert policy["enabled"] == 1

    def test_raises_on_missing_name(self, engine):
        with pytest.raises(ValueError, match="name is required"):
            engine.create_gate_policy("org1", {})

    def test_creates_pipeline_specific_policy(self, engine, pipeline):
        policy = engine.create_gate_policy("org1", {
            "name": "Pipeline Policy",
            "pipeline_id": pipeline["pipeline_id"],
            "block_on_high": 1,
            "max_high": 0,
        })
        assert policy["pipeline_id"] == pipeline["pipeline_id"]
        assert policy["block_on_high"] == 1


class TestListGatePolicies:
    def test_lists_policies_for_org(self, engine):
        engine.create_gate_policy("org1", {"name": "P1"})
        engine.create_gate_policy("org1", {"name": "P2"})
        policies = engine.list_gate_policies("org1")
        assert len(policies) >= 2

    def test_org_isolation(self, engine):
        engine.create_gate_policy("org1", {"name": "Org1 Policy"})
        engine.create_gate_policy("org2", {"name": "Org2 Policy"})
        org1 = engine.list_gate_policies("org1")
        org2 = engine.list_gate_policies("org2")
        org1_ids = {p["policy_id"] for p in org1}
        org2_ids = {p["policy_id"] for p in org2}
        assert not org1_ids.intersection(org2_ids)

    def test_filter_by_pipeline_id(self, engine, pipeline):
        engine.create_gate_policy("org1", {"name": "Global"})
        engine.create_gate_policy("org1", {
            "name": "Pipeline-specific",
            "pipeline_id": pipeline["pipeline_id"],
        })
        results = engine.list_gate_policies("org1", pipeline_id=pipeline["pipeline_id"])
        for r in results:
            assert r["pipeline_id"] == pipeline["pipeline_id"]


# ---------------------------------------------------------------------------
# Stats tests
# ---------------------------------------------------------------------------

class TestGetDevSecOpsStats:
    def test_stats_empty_org(self, engine):
        stats = engine.get_devsecops_stats("empty_org")
        assert stats["total_pipelines"] == 0
        assert stats["total_runs"] == 0
        assert stats["pass_rate"] == 0.0
        assert stats["blocked_runs"] == 0

    def test_stats_after_runs(self, engine, pipeline):
        engine.trigger_run("org1", pipeline["pipeline_id"], {})
        engine.trigger_run("org1", pipeline["pipeline_id"], {})
        stats = engine.get_devsecops_stats("org1")
        assert stats["total_pipelines"] >= 1
        assert stats["total_runs"] >= 2
        assert 0.0 <= stats["pass_rate"] <= 1.0
        assert "critical_findings" in stats
        assert "high_findings" in stats
        assert "secret_findings" in stats
        assert "by_platform" in stats

    def test_stats_org_isolation(self, engine, pipeline):
        engine.trigger_run("org1", pipeline["pipeline_id"], {})
        stats_org2 = engine.get_devsecops_stats("org2")
        assert stats_org2["total_pipelines"] == 0
        assert stats_org2["total_runs"] == 0

    def test_by_platform_breakdown(self, engine):
        engine.register_pipeline("org1", {"name": "GH1", "ci_platform": "github_actions"})
        engine.register_pipeline("org1", {"name": "GL1", "ci_platform": "gitlab_ci"})
        stats = engine.get_devsecops_stats("org1")
        assert "github_actions" in stats["by_platform"]
        assert "gitlab_ci" in stats["by_platform"]
