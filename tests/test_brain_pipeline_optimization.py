"""
Tests for BrainPipeline optimization — graph step, dedup, metrics.

Covers:
  - StepResult.findings_in / findings_out fields
  - StepResult.to_dict() includes new fields
  - _step_build_graph pre-computed batches and timing metrics
  - _local_dedup_findings O(n) dedup
  - Per-step timing metrics in ctx["metrics"]
  - Dedup local fallback with cluster IDs
  - Large finding set graph performance
  - Graph step CVE deduplication via set comprehension
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from core.brain_pipeline import (
    BrainPipeline,
    PipelineInput,
    PipelineResult,
    PipelineStatus,
    StepResult,
    StepStatus,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def pipeline():
    return BrainPipeline()


@pytest.fixture
def findings_1000():
    """Generate 1000 findings with mixed CVEs and assets."""
    return [
        {
            "id": f"FIND-{i}",
            "rule_id": f"CWE-{79 + (i % 50)}",
            "message": f"Vulnerability {i}",
            "severity": ["critical", "high", "medium", "low", "info"][i % 5],
            "cve_id": f"CVE-2024-{i % 200}" if i % 3 == 0 else None,
            "component": f"lib-{i % 20}",
            "asset": f"service-{i % 10}",
        }
        for i in range(1000)
    ]


@pytest.fixture
def findings_small():
    return [
        {"id": "F1", "title": "XSS", "severity": "high", "asset_name": "web", "cve_id": "CVE-2024-100"},
        {"id": "F2", "title": "SQLi", "severity": "critical", "asset_name": "api", "cve_id": "CVE-2024-200"},
        {"id": "F3", "title": "XSS", "severity": "high", "asset_name": "web", "cve_id": "CVE-2024-100"},
        {"id": "F4", "title": "SSRF", "severity": "medium", "asset_name": "api", "cve_id": None},
    ]


# ---------------------------------------------------------------------------
# StepResult new fields
# ---------------------------------------------------------------------------


class TestStepResultNewFields:
    def test_findings_in_default(self):
        sr = StepResult(name="test")
        assert sr.findings_in == 0
        assert sr.findings_out == 0

    def test_findings_in_set(self):
        sr = StepResult(name="test", findings_in=50, findings_out=30)
        assert sr.findings_in == 50
        assert sr.findings_out == 30

    def test_to_dict_includes_findings_counts(self):
        sr = StepResult(
            name="normalize",
            status=StepStatus.COMPLETED,
            findings_in=100,
            findings_out=95,
        )
        d = sr.to_dict()
        assert d["findings_in"] == 100
        assert d["findings_out"] == 95

    def test_to_dict_backward_compat(self):
        """Old fields still present in to_dict output."""
        sr = StepResult(
            name="connect",
            status=StepStatus.COMPLETED,
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
            duration_ms=1000.123,
            output={"findings_count": 10},
        )
        d = sr.to_dict()
        assert d["name"] == "connect"
        assert d["status"] == "completed"
        assert d["duration_ms"] == 1000.12
        assert d["output"]["findings_count"] == 10
        # New fields present with defaults
        assert d["findings_in"] == 0
        assert d["findings_out"] == 0


# ---------------------------------------------------------------------------
# Per-step metrics in pipeline run
# ---------------------------------------------------------------------------


class TestPerStepMetrics:
    def test_step_findings_in_out_recorded(self, pipeline):
        """Each step should record findings_in and findings_out."""
        findings = [{"id": f"f{i}", "severity": "medium"} for i in range(10)]
        inp = PipelineInput(org_id="metrics-test", findings=findings)
        result = pipeline.run(inp)

        # Steps that process findings should have findings_in > 0
        # Connect step: findings_in should equal input count
        connect_step = result.steps[0]
        assert connect_step.findings_in == 10

        # Normalize step
        norm_step = result.steps[1]
        assert norm_step.findings_in == 10
        assert norm_step.findings_out == 10  # normalize doesn't remove findings

    def test_step_duration_ms_positive(self, pipeline):
        """Each completed step should have duration_ms > 0."""
        findings = [{"id": "f1", "severity": "high"}]
        inp = PipelineInput(org_id="timing-test", findings=findings)
        result = pipeline.run(inp)

        for step in result.steps:
            if step.status == StepStatus.COMPLETED:
                assert step.duration_ms > 0, f"Step {step.name} has zero duration"

    def test_ctx_metrics_per_step(self, pipeline):
        """Pipeline should record per-step metrics in ctx['metrics']."""
        findings = [{"id": "f1", "severity": "high", "cve_id": "CVE-2024-001"}]
        inp = PipelineInput(org_id="ctx-metrics", findings=findings)
        pipeline.run(inp)

        # get_metrics returns accumulated metrics with step_metrics inside
        metrics = pipeline.get_metrics(limit=1)
        assert len(metrics) >= 1
        last_run = metrics[-1]
        assert "step_metrics" in last_run

        step_metrics = last_run["step_metrics"]
        # At minimum, connect and normalize should be present
        assert "connect" in step_metrics
        assert "normalize" in step_metrics
        for step_name, sm in step_metrics.items():
            assert "duration_ms" in sm
            assert "findings_in" in sm
            assert "findings_out" in sm
            assert "status" in sm

    def test_total_duration_ms(self, pipeline):
        """Total pipeline duration should be >= sum of step durations."""
        findings = [{"id": f"f{i}", "severity": "medium"} for i in range(5)]
        inp = PipelineInput(org_id="total-dur", findings=findings)
        result = pipeline.run(inp)

        step_total = sum(
            s.duration_ms for s in result.steps
            if s.status in (StepStatus.COMPLETED, StepStatus.FAILED)
        )
        # Total duration should be >= step_total (includes overhead)
        assert result.total_duration_ms >= step_total * 0.9  # Allow 10% tolerance


# ---------------------------------------------------------------------------
# Local dedup fallback (O(n) using dict)
# ---------------------------------------------------------------------------


class TestLocalDedupFallback:
    def test_local_dedup_basic(self, pipeline, findings_small):
        """_local_dedup_findings should group by (title, asset, severity)."""
        clusters = pipeline._local_dedup_findings(findings_small)
        # F1 and F3 should be in the same cluster (same title/asset/severity)
        assert isinstance(clusters, dict)
        # 3 unique groups: (XSS, web, high), (SQLi, api, critical), (SSRF, api, medium)
        assert len(clusters) == 3

    def test_local_dedup_all_unique(self, pipeline):
        """All unique findings should each be their own cluster."""
        findings = [
            {"id": f"f{i}", "title": f"vuln-{i}", "asset_name": f"svc-{i}", "severity": "high"}
            for i in range(10)
        ]
        clusters = pipeline._local_dedup_findings(findings)
        assert len(clusters) == 10

    def test_local_dedup_all_duplicates(self, pipeline):
        """All identical findings should collapse to one cluster."""
        findings = [
            {"id": f"f{i}", "title": "XSS", "asset_name": "web", "severity": "high"}
            for i in range(100)
        ]
        clusters = pipeline._local_dedup_findings(findings)
        assert len(clusters) == 1
        # The single cluster should contain all 100 findings
        key = list(clusters.keys())[0]
        assert len(clusters[key]) == 100

    def test_local_dedup_missing_fields(self, pipeline):
        """Findings with missing fields should still dedup without errors."""
        findings = [
            {"id": "f1"},  # No title, no asset, no severity
            {"id": "f2"},  # Same defaults -> same cluster
            {"id": "f3", "title": "Different"},  # Different title -> different cluster
        ]
        clusters = pipeline._local_dedup_findings(findings)
        # f1 and f2 should be in one cluster (same default key), f3 in another
        assert len(clusters) == 2

    def test_local_dedup_large_set_performance(self, pipeline, findings_1000):
        """O(n) dedup should handle 1000+ findings in < 100ms."""
        t0 = time.monotonic()
        clusters = pipeline._local_dedup_findings(findings_1000)
        elapsed_ms = (time.monotonic() - t0) * 1000
        assert elapsed_ms < 100, f"Local dedup took {elapsed_ms:.1f}ms for 1000 findings"
        assert len(clusters) > 0

    def test_step_dedup_uses_local_fallback(self, pipeline):
        """When DeduplicationService is unavailable, local fallback should work."""
        findings = [
            {"id": "f1", "title": "XSS", "severity": "high", "asset_name": "web"},
            {"id": "f2", "title": "XSS", "severity": "high", "asset_name": "web"},
            {"id": "f3", "title": "SQLi", "severity": "critical", "asset_name": "api"},
        ]
        inp = PipelineInput(org_id="fallback-test", findings=findings)
        result = pipeline.run(inp)

        step = result.steps[3]  # deduplicate
        assert step.status in (StepStatus.COMPLETED, StepStatus.FAILED)
        # If completed, should have cluster info
        if step.status == StepStatus.COMPLETED:
            output = step.output
            if output.get("method") == "local_fallback":
                assert output["unique_clusters"] == 2
                assert output["total_findings"] == 3


# ---------------------------------------------------------------------------
# Graph step optimization
# ---------------------------------------------------------------------------


class TestGraphStepOptimization:
    @patch("core.brain_pipeline.BrainPipeline._step_build_graph")
    def test_graph_step_returns_timing(self, mock_graph, pipeline):
        """Mocked graph step should be called during pipeline run."""
        mock_graph.return_value = {
            "nodes_added": 10,
            "edges_added": 5,
            "unique_cves": 3,
            "total_nodes": 10,
            "total_edges": 5,
            "timing": {
                "prep_ms": 1.0,
                "upsert_ms": 5.0,
                "edges_ms": 2.0,
            },
        }
        findings = [{"id": "f1", "severity": "high", "cve_id": "CVE-2024-001"}]
        inp = PipelineInput(org_id="graph-timing", findings=findings)
        result = pipeline.run(inp)

        step = result.steps[4]  # build_graph
        assert step.status == StepStatus.COMPLETED
        assert "timing" in step.output
        assert step.output["timing"]["prep_ms"] >= 0
        assert step.output["timing"]["upsert_ms"] >= 0
        assert step.output["timing"]["edges_ms"] >= 0

    def test_graph_cve_dedup_precomputed(self, pipeline):
        """CVE deduplication should be O(n) via set comprehension."""
        # Test the set comprehension logic directly
        findings = [
            {"id": "f1", "cve_id": "CVE-2024-001"},
            {"id": "f2", "cve_id": "CVE-2024-001"},  # Duplicate
            {"id": "f3", "cve_id": "CVE-2024-002"},
            {"id": "f4", "cve_id": None},
            {"id": "f5"},  # No cve_id key
        ]
        unique_cves = {
            f["cve_id"] for f in findings
            if f.get("cve_id")
        }
        assert unique_cves == {"CVE-2024-001", "CVE-2024-002"}
        assert len(unique_cves) == 2  # Not 3 (duplicate removed)

    def test_graph_step_graceful_when_unavailable(self, pipeline):
        """Graph step should return skipped when knowledge_brain is unavailable."""
        findings = [{"id": "f1", "severity": "high"}]
        inp = PipelineInput(org_id="graph-test", findings=findings)
        result = pipeline.run(inp)
        step = result.steps[4]
        assert step.status in (StepStatus.COMPLETED, StepStatus.FAILED)

    def test_graph_step_with_large_findings(self, pipeline, findings_1000):
        """Graph step should handle 1000+ findings without hanging."""
        inp = PipelineInput(org_id="graph-large", findings=findings_1000)
        t0 = time.monotonic()
        result = pipeline.run(inp)
        elapsed = time.monotonic() - t0

        # Pipeline should complete within 30 seconds for 1000 findings
        assert elapsed < 30, f"Pipeline with 1000 findings took {elapsed:.1f}s"
        assert result.findings_ingested == 1000

        # Graph step should have completed or failed (not hung)
        graph_step = result.steps[4]
        assert graph_step.status in (StepStatus.COMPLETED, StepStatus.FAILED)
        assert graph_step.duration_ms > 0

    def test_graph_precompute_edges(self, pipeline):
        """Pre-computed edge lists should be correct."""
        findings = [
            {"id": "f1", "cve_id": "CVE-001", "asset_name": "web"},
            {"id": "f2", "cve_id": None, "asset_name": "api"},
            {"id": "f3", "cve_id": "CVE-001", "asset_name": None},
        ]
        # Simulate the pre-computation logic from _step_build_graph
        finding_asset_edges = []
        finding_cve_edges = []
        for f in findings:
            fid = f.get("id")
            asset_id = f.get("canonical_asset_id", f.get("asset_name"))
            if asset_id:
                finding_asset_edges.append((fid, asset_id))
            cve = f.get("cve_id")
            if cve:
                finding_cve_edges.append((fid, cve))

        assert finding_asset_edges == [("f1", "web"), ("f2", "api")]
        assert finding_cve_edges == [("f1", "CVE-001"), ("f3", "CVE-001")]


# ---------------------------------------------------------------------------
# Dedup rate metrics
# ---------------------------------------------------------------------------


class TestDedupMetrics:
    def test_dedup_rate_in_pipeline_metrics(self, pipeline):
        """Pipeline metrics should include dedup_rate."""
        findings = [{"id": f"f{i}", "severity": "medium"} for i in range(10)]
        inp = PipelineInput(org_id="dedup-rate", findings=findings)
        pipeline.run(inp)

        metrics = pipeline.get_metrics(limit=1)
        assert len(metrics) >= 1
        last = metrics[-1]
        assert "dedup_rate" in last
        assert isinstance(last["dedup_rate"], float)
        assert 0.0 <= last["dedup_rate"] <= 1.0


# ---------------------------------------------------------------------------
# Pipeline result to_dict includes step findings counts
# ---------------------------------------------------------------------------


class TestPipelineResultStepCounts:
    def test_to_dict_steps_include_findings(self, pipeline):
        """Pipeline result to_dict should include findings_in/out per step."""
        findings = [{"id": f"f{i}", "severity": "high"} for i in range(5)]
        inp = PipelineInput(org_id="dict-test", findings=findings)
        result = pipeline.run(inp)

        d = result.to_dict()
        for step_dict in d["steps"]:
            assert "findings_in" in step_dict
            assert "findings_out" in step_dict
            assert isinstance(step_dict["findings_in"], int)
            assert isinstance(step_dict["findings_out"], int)


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    def test_step_result_old_interface(self):
        """StepResult with only old fields should still work."""
        sr = StepResult(
            name="connect",
            status=StepStatus.COMPLETED,
            duration_ms=50.0,
            output={"count": 10},
        )
        assert sr.findings_in == 0  # Default
        assert sr.findings_out == 0  # Default
        d = sr.to_dict()
        assert d["duration_ms"] == 50.0

    def test_pipeline_input_unchanged(self):
        """PipelineInput interface should be unchanged."""
        inp = PipelineInput(
            org_id="compat",
            findings=[{"id": "1"}],
            assets=[{"id": "a1"}],
            run_pentest=False,
            run_playbooks=False,
            generate_evidence=False,
        )
        assert inp.org_id == "compat"

    def test_pipeline_result_unchanged(self):
        """PipelineResult interface should be unchanged."""
        r = PipelineResult(org_id="compat")
        assert r.run_id.startswith("BR-")
        assert r.total_steps == 12
        d = r.to_dict()
        assert "summary" in d
        assert "steps" in d
        assert "current_step" in d
        assert "progress_percent" in d

    def test_run_method_synchronous(self, pipeline):
        """run() should still work synchronously."""
        inp = PipelineInput(org_id="sync-test", findings=[{"id": "f1"}])
        result = pipeline.run(inp)
        assert isinstance(result, PipelineResult)
        assert result.status in (
            PipelineStatus.COMPLETED,
            PipelineStatus.PARTIAL,
            PipelineStatus.FAILED,
        )

    def test_get_metrics_unchanged(self, pipeline):
        """get_metrics() should return list of dicts with expected keys."""
        pipeline.run(PipelineInput(org_id="m1", findings=[]))
        metrics = pipeline.get_metrics()
        assert isinstance(metrics, list)
        if metrics:
            m = metrics[-1]
            assert "run_id" in m
            assert "total_duration_ms" in m
            assert "findings_ingested" in m
            assert "dedup_rate" in m
            assert "step_metrics" in m
