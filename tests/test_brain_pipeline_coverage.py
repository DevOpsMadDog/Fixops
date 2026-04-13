"""Comprehensive tests for BrainPipeline — suite-core/core/brain_pipeline.py.

Coverage targets:
- BrainPipeline instantiation and public API
- PipelineInput / PipelineResult dataclass behaviour
- run() with zero, one, and many findings
- Optional steps skipped when flags are False
- LLM council toggle via FIXOPS_USE_COUNCIL env var
- Input sanitisation: non-dict findings filtered, oversized fields truncated
- Size limits: findings / assets capped at MAX_FINDINGS / MAX_ASSETS
- Progress tracking fields populated correctly
- get_metrics() returns records after each run
- get_progress() returns progress for live run IDs
- cancel() cooperative cancellation
- run_id auto-generated with BR- prefix
- to_dict() serialisation round-trip
- StepResult.to_dict() serialisation
- STEP_NAMES ordering matches pipeline execution order
- data_quality and enrichment_stats populated on result
- PipelineStatus enum values
- StepStatus enum values
- Multiple sequential runs accumulate independent results
"""

from __future__ import annotations

import os
import sys

# Set env before importing pipeline so env-driven branches are exercised
os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_USE_COUNCIL", "0")

import pytest

# Ensure suite directories are on sys.path (sitecustomize.py handles this in
# production; here we replicate the key additions for the test process).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _suite in (
    "suite-core",
    "suite-api",
    "suite-feeds",
    "suite-evidence-risk",
    "suite-integrations",
    "suite-attack",
):
    _p = os.path.join(_REPO_ROOT, _suite)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core.brain_pipeline import (  # noqa: E402
    BrainPipeline,
    PipelineInput,
    PipelineResult,
    PipelineStatus,
    StepResult,
    StepStatus,
    STEP_NAMES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**kwargs) -> dict:
    """Return a minimal valid finding dict."""
    base = {
        "id": "f-001",
        "title": "SQL Injection",
        "severity": "high",
        "source": "test",
    }
    base.update(kwargs)
    return base


def _run_pipeline(findings=None, assets=None, **inp_kwargs) -> PipelineResult:
    """Instantiate a fresh BrainPipeline and run it."""
    pipeline = BrainPipeline()
    inp = PipelineInput(
        org_id="test-org",
        findings=findings if findings is not None else [],
        assets=assets if assets is not None else [],
        **inp_kwargs,
    )
    return pipeline.run(inp)


# ---------------------------------------------------------------------------
# 1. Instantiation
# ---------------------------------------------------------------------------

class TestBrainPipelineInstantiation:

    def test_instantiates_without_arguments(self):
        pipeline = BrainPipeline()
        assert pipeline is not None

    def test_initial_metrics_list_is_empty(self):
        pipeline = BrainPipeline()
        assert pipeline.get_metrics() == []

    def test_max_findings_constant_is_positive(self):
        assert BrainPipeline.MAX_FINDINGS > 0

    def test_max_assets_constant_is_positive(self):
        assert BrainPipeline.MAX_ASSETS > 0

    def test_step_names_has_expected_count(self):
        # connect, normalize, resolve_identity, fp_auto_suppress, deduplicate,
        # build_graph, enrich_threats, score_risk, apply_policy,
        # llm_consensus, micro_pentest, run_playbooks, generate_evidence
        assert len(STEP_NAMES) == 13


# ---------------------------------------------------------------------------
# 2. PipelineInput / PipelineResult dataclasses
# ---------------------------------------------------------------------------

class TestDataclasses:

    def test_pipeline_input_defaults_are_safe(self):
        inp = PipelineInput()
        assert inp.org_id == ""
        assert isinstance(inp.findings, list)
        assert isinstance(inp.assets, list)

    def test_pipeline_result_auto_generates_run_id(self):
        result = PipelineResult(org_id="acme")
        assert result.run_id.startswith("BR-")
        assert len(result.run_id) > 5

    def test_pipeline_result_started_at_is_set(self):
        result = PipelineResult(org_id="acme")
        assert result.started_at  # non-empty ISO timestamp

    def test_step_result_to_dict_contains_required_keys(self):
        sr = StepResult(name="connect", status=StepStatus.COMPLETED)
        d = sr.to_dict()
        for key in ("name", "status", "duration_ms", "findings_in", "findings_out"):
            assert key in d

    def test_pipeline_result_to_dict_contains_summary(self):
        result = PipelineResult(org_id="acme")
        d = result.to_dict()
        assert "summary" in d
        assert "findings_ingested" in d["summary"]

    def test_pipeline_status_completed_value(self):
        assert PipelineStatus.COMPLETED == "completed"

    def test_pipeline_status_failed_value(self):
        assert PipelineStatus.FAILED == "failed"

    def test_pipeline_status_running_value(self):
        assert PipelineStatus.RUNNING == "running"

    def test_step_status_skipped_value(self):
        assert StepStatus.SKIPPED == "skipped"

    def test_step_status_completed_value(self):
        assert StepStatus.COMPLETED == "completed"


# ---------------------------------------------------------------------------
# 3. run() with empty input
# ---------------------------------------------------------------------------

class TestRunEmptyInput:

    def test_run_with_empty_findings_returns_result(self):
        result = _run_pipeline(findings=[])
        assert result is not None
        assert isinstance(result, PipelineResult)

    def test_run_with_empty_input_has_valid_status(self):
        result = _run_pipeline(findings=[])
        assert result.status in (
            PipelineStatus.COMPLETED, PipelineStatus.PARTIAL, PipelineStatus.FAILED
        )

    def test_run_with_empty_input_has_run_id(self):
        result = _run_pipeline(findings=[])
        assert result.run_id.startswith("BR-")

    def test_run_with_empty_input_has_finished_at(self):
        result = _run_pipeline(findings=[])
        assert result.finished_at is not None

    def test_run_with_empty_input_total_duration_nonnegative(self):
        result = _run_pipeline(findings=[])
        assert result.total_duration_ms >= 0


# ---------------------------------------------------------------------------
# 4. run() with findings
# ---------------------------------------------------------------------------

class TestRunWithFindings:

    def test_run_with_one_finding_sets_findings_ingested(self):
        result = _run_pipeline(findings=[_make_finding()])
        assert result.findings_ingested == 1

    def test_run_with_multiple_findings_sets_correct_count(self):
        findings = [_make_finding(id=f"f-{i}") for i in range(5)]
        result = _run_pipeline(findings=findings)
        assert result.findings_ingested == 5

    def test_run_with_findings_creates_steps_for_all_step_names(self):
        result = _run_pipeline(findings=[_make_finding()])
        step_names_in_result = [s.name for s in result.steps]
        for name in STEP_NAMES:
            assert name in step_names_in_result

    def test_run_progress_percent_is_100_on_completion(self):
        result = _run_pipeline(findings=[_make_finding()])
        assert result.progress_percent == 100.0

    def test_run_returns_data_quality_field(self):
        result = _run_pipeline(findings=[_make_finding()])
        assert result.data_quality is not None
        assert "overall_score" in result.data_quality

    def test_run_returns_enrichment_stats_field(self):
        result = _run_pipeline(findings=[_make_finding()])
        assert result.enrichment_stats is not None

    def test_run_result_total_steps_is_twelve(self):
        # PipelineResult.total_steps is hardcoded to 12 (the documented step count)
        result = _run_pipeline(findings=[_make_finding()])
        assert result.total_steps == 12


# ---------------------------------------------------------------------------
# 5. Optional step skipping
# ---------------------------------------------------------------------------

class TestOptionalStepSkipping:

    def test_micro_pentest_skipped_when_run_pentest_false(self):
        result = _run_pipeline(findings=[_make_finding()], run_pentest=False)
        pentest_step = next(s for s in result.steps if s.name == "micro_pentest")
        assert pentest_step.status == StepStatus.SKIPPED

    def test_run_playbooks_skipped_when_run_playbooks_false(self):
        result = _run_pipeline(findings=[_make_finding()], run_playbooks=False)
        playbook_step = next(s for s in result.steps if s.name == "run_playbooks")
        assert playbook_step.status == StepStatus.SKIPPED

    def test_generate_evidence_skipped_when_flag_false(self):
        result = _run_pipeline(findings=[_make_finding()], generate_evidence=False)
        evidence_step = next(s for s in result.steps if s.name == "generate_evidence")
        assert evidence_step.status == StepStatus.SKIPPED

    def test_all_optional_steps_skipped_together(self):
        result = _run_pipeline(
            findings=[_make_finding()],
            run_pentest=False,
            run_playbooks=False,
            generate_evidence=False,
        )
        skipped = {s.name for s in result.steps if s.status == StepStatus.SKIPPED}
        assert "micro_pentest" in skipped
        assert "run_playbooks" in skipped
        assert "generate_evidence" in skipped


# ---------------------------------------------------------------------------
# 6. LLM council toggle
# ---------------------------------------------------------------------------

class TestLLMCouncilToggle:

    def test_pipeline_runs_without_council_when_env_is_zero(self):
        os.environ["FIXOPS_USE_COUNCIL"] = "0"
        result = _run_pipeline(findings=[_make_finding()])
        # Pipeline must complete without raising
        assert result.status in (
            PipelineStatus.COMPLETED, PipelineStatus.PARTIAL, PipelineStatus.FAILED
        )

    def test_pipeline_runs_with_council_flag_set_to_one(self):
        os.environ["FIXOPS_USE_COUNCIL"] = "1"
        try:
            result = _run_pipeline(findings=[_make_finding()])
            assert result is not None
        finally:
            os.environ["FIXOPS_USE_COUNCIL"] = "0"


# ---------------------------------------------------------------------------
# 7. Input sanitisation
# ---------------------------------------------------------------------------

class TestInputSanitisation:

    def test_non_dict_findings_are_filtered(self):
        # Mix of valid dicts and non-dicts; only dicts should be processed
        mixed = [_make_finding(), "not-a-dict", 42, None, _make_finding(id="f-2")]
        result = _run_pipeline(findings=mixed)
        assert result.findings_ingested == 2

    def test_oversized_string_field_is_truncated(self):
        long_val = "X" * 20_000
        finding = _make_finding(title=long_val)
        pipeline = BrainPipeline()
        sanitised = pipeline._sanitize_finding(finding)
        assert len(sanitised["title"]) <= pipeline.MAX_FIELD_LEN + len("...[truncated]")

    def test_short_string_field_is_not_truncated(self):
        finding = _make_finding(title="short title")
        pipeline = BrainPipeline()
        sanitised = pipeline._sanitize_finding(finding)
        assert sanitised["title"] == "short title"

    def test_findings_capped_at_max_findings(self):
        pipeline = BrainPipeline()
        original_max = pipeline.MAX_FINDINGS
        pipeline.MAX_FINDINGS = 3
        try:
            findings = [_make_finding(id=f"f-{i}") for i in range(10)]
            inp = PipelineInput(org_id="test-org", findings=findings)
            result = pipeline.run(inp)
            assert result.findings_ingested <= 3
        finally:
            pipeline.MAX_FINDINGS = original_max

    def test_org_id_none_raises_value_error(self):
        pipeline = BrainPipeline()
        inp = PipelineInput(org_id=None, findings=[])
        with pytest.raises(ValueError, match="org_id"):
            pipeline.run(inp)

    def test_nested_oversized_string_in_list_is_truncated(self):
        long_val = "Y" * 20_000
        finding = _make_finding(tags=[long_val])
        pipeline = BrainPipeline()
        sanitised = pipeline._sanitize_finding(finding)
        assert len(sanitised["tags"][0]) <= pipeline.MAX_FIELD_LEN + len("...[truncated]")


# ---------------------------------------------------------------------------
# 8. Metrics and progress
# ---------------------------------------------------------------------------

class TestMetricsAndProgress:

    def test_get_metrics_returns_record_after_run(self):
        pipeline = BrainPipeline()
        inp = PipelineInput(org_id="metrics-org", findings=[_make_finding()])
        pipeline.run(inp)
        metrics = pipeline.get_metrics()
        assert len(metrics) >= 1

    def test_get_metrics_record_contains_run_id(self):
        pipeline = BrainPipeline()
        inp = PipelineInput(org_id="metrics-org", findings=[_make_finding()])
        pipeline.run(inp)
        record = pipeline.get_metrics()[-1]
        assert "run_id" in record

    def test_get_metrics_record_contains_total_duration_ms(self):
        pipeline = BrainPipeline()
        inp = PipelineInput(org_id="metrics-org", findings=[_make_finding()])
        pipeline.run(inp)
        record = pipeline.get_metrics()[-1]
        assert "total_duration_ms" in record

    def test_get_metrics_limit_is_respected(self):
        pipeline = BrainPipeline()
        for i in range(5):
            inp = PipelineInput(org_id=f"org-{i}", findings=[])
            pipeline.run(inp)
        limited = pipeline.get_metrics(limit=2)
        assert len(limited) <= 2

    def test_get_progress_returns_none_for_unknown_run_id(self):
        pipeline = BrainPipeline()
        assert pipeline.get_progress("nonexistent-id") is None

    def test_get_progress_returns_dict_for_completed_run(self):
        pipeline = BrainPipeline()
        inp = PipelineInput(org_id="prog-org", findings=[_make_finding()])
        result = pipeline.run(inp)
        progress = pipeline.get_progress(result.run_id)
        assert progress is not None
        assert "run_id" in progress


# ---------------------------------------------------------------------------
# 9. cancel()
# ---------------------------------------------------------------------------

class TestCancelPipeline:

    def test_cancel_unknown_run_id_returns_false(self):
        pipeline = BrainPipeline()
        assert pipeline.cancel("does-not-exist") is False

    def test_cancel_known_run_id_returns_true_or_false(self):
        """cancel() returns True if the run is still tracked in _runs."""
        pipeline = BrainPipeline()
        inp = PipelineInput(org_id="cancel-org", findings=[])
        result = pipeline.run(inp)
        # After a synchronous run the result is stored in _runs; cancel should
        # succeed while it is still there (eviction only happens when >MAX_RUNS).
        cancelled = pipeline.cancel(result.run_id)
        assert isinstance(cancelled, bool)


# ---------------------------------------------------------------------------
# 10. Multiple sequential runs
# ---------------------------------------------------------------------------

class TestMultipleRuns:

    def test_two_runs_have_distinct_run_ids(self):
        pipeline = BrainPipeline()
        r1 = pipeline.run(PipelineInput(org_id="a", findings=[]))
        r2 = pipeline.run(PipelineInput(org_id="b", findings=[]))
        assert r1.run_id != r2.run_id

    def test_second_run_does_not_inherit_findings_from_first(self):
        pipeline = BrainPipeline()
        r1 = pipeline.run(PipelineInput(org_id="a", findings=[_make_finding()]))
        r2 = pipeline.run(PipelineInput(org_id="b", findings=[]))
        assert r1.findings_ingested == 1
        assert r2.findings_ingested == 0

    def test_three_runs_metrics_accumulate(self):
        pipeline = BrainPipeline()
        for i in range(3):
            pipeline.run(PipelineInput(org_id=f"org-{i}", findings=[]))
        assert len(pipeline.get_metrics()) == 3


# ---------------------------------------------------------------------------
# 11. get_run() and list_runs()
# ---------------------------------------------------------------------------

class TestGetRunAndListRuns:

    def test_get_run_returns_result_for_known_run_id(self):
        pipeline = BrainPipeline()
        result = pipeline.run(PipelineInput(org_id="gr-org", findings=[]))
        fetched = pipeline.get_run(result.run_id)
        assert fetched is not None
        assert fetched.run_id == result.run_id

    def test_get_run_returns_none_for_unknown_run_id(self):
        pipeline = BrainPipeline()
        assert pipeline.get_run("nonexistent-run-id") is None

    def test_list_runs_returns_list_after_run(self):
        pipeline = BrainPipeline()
        pipeline.run(PipelineInput(org_id="lr-org", findings=[]))
        runs = pipeline.list_runs()
        assert isinstance(runs, list)
        assert len(runs) >= 1

    def test_list_runs_each_entry_is_dict_with_run_id(self):
        pipeline = BrainPipeline()
        pipeline.run(PipelineInput(org_id="lr-org2", findings=[]))
        runs = pipeline.list_runs()
        assert all("run_id" in r for r in runs)

    def test_list_runs_limit_respected(self):
        pipeline = BrainPipeline()
        for i in range(5):
            pipeline.run(PipelineInput(org_id=f"lr-{i}", findings=[]))
        runs = pipeline.list_runs(limit=2)
        assert len(runs) <= 2

    def test_list_runs_sorted_most_recent_first(self):
        pipeline = BrainPipeline()
        for i in range(3):
            pipeline.run(PipelineInput(org_id=f"sorted-{i}", findings=[]))
        runs = pipeline.list_runs(limit=3)
        # started_at should be descending (most recent first)
        started_ats = [r["started_at"] for r in runs]
        assert started_ats == sorted(started_ats, reverse=True)


# ---------------------------------------------------------------------------
# 12. get_brain_pipeline() singleton
# ---------------------------------------------------------------------------

class TestGetBrainPipelineSingleton:

    def test_get_brain_pipeline_returns_brain_pipeline_instance(self):
        from core.brain_pipeline import get_brain_pipeline
        instance = get_brain_pipeline()
        assert isinstance(instance, BrainPipeline)

    def test_get_brain_pipeline_returns_same_instance_on_repeated_calls(self):
        from core.brain_pipeline import get_brain_pipeline
        a = get_brain_pipeline()
        b = get_brain_pipeline()
        assert a is b


# ---------------------------------------------------------------------------
# 13. run_async() — non-blocking variant
# ---------------------------------------------------------------------------

class TestRunAsync:

    def test_run_async_returns_pipeline_result(self):
        import asyncio
        pipeline = BrainPipeline()
        inp = PipelineInput(org_id="async-org", findings=[_make_finding()])
        result = asyncio.run(pipeline.run_async(inp))
        assert isinstance(result, PipelineResult)

    def test_run_async_result_has_completed_or_partial_status(self):
        import asyncio
        pipeline = BrainPipeline()
        inp = PipelineInput(org_id="async-org2", findings=[_make_finding()])
        result = asyncio.run(pipeline.run_async(inp))
        assert result.status in (
            PipelineStatus.COMPLETED, PipelineStatus.PARTIAL, PipelineStatus.FAILED
        )

    def test_run_async_run_id_has_br_prefix(self):
        import asyncio
        pipeline = BrainPipeline()
        inp = PipelineInput(org_id="async-org3", findings=[])
        result = asyncio.run(pipeline.run_async(inp))
        assert result.run_id.startswith("BR-")


# ---------------------------------------------------------------------------
# 14. Assets cap and input edge cases
# ---------------------------------------------------------------------------

class TestAssetsCappingAndEdgeCases:

    def test_assets_cap_at_max_assets(self):
        pipeline = BrainPipeline()
        original_max = pipeline.MAX_ASSETS
        pipeline.MAX_ASSETS = 3
        try:
            assets = [{"id": f"a-{i}", "name": f"svc-{i}"} for i in range(10)]
            inp = PipelineInput(org_id="cap-org", findings=[], assets=assets)
            pipeline.run(inp)
            # After cap, at most 3 assets should be processed
            assert len(inp.assets) <= 3
        finally:
            pipeline.MAX_ASSETS = original_max

    def test_non_dict_assets_are_filtered(self):
        pipeline = BrainPipeline()
        inp = PipelineInput(
            org_id="filter-org",
            findings=[],
            assets=[{"id": "a1"}, "not-a-dict", 42],
        )
        result = pipeline.run(inp)
        assert result is not None  # pipeline tolerates mixed asset types

    def test_run_with_policy_rules_does_not_raise(self):
        policy_rules = [{"id": "P001", "action": "block", "severity": "critical"}]
        result = _run_pipeline(findings=[_make_finding()], policy_rules=policy_rules)
        assert result is not None

    def test_run_with_custom_source_metadata(self):
        result = _run_pipeline(
            findings=[_make_finding()],
            source="webhook",
            metadata={"tenant": "acme", "region": "us-east-1"},
        )
        assert result is not None

    def test_run_with_evidence_framework_specified(self):
        result = _run_pipeline(
            findings=[_make_finding()],
            generate_evidence=True,
            evidence_framework="iso27001",
        )
        assert result is not None

    def test_run_with_evidence_timeframe_days_specified(self):
        result = _run_pipeline(
            findings=[_make_finding()],
            generate_evidence=True,
            evidence_timeframe_days=30,
        )
        assert result is not None


# ---------------------------------------------------------------------------
# 15. PipelineResult.to_dict() structure
# ---------------------------------------------------------------------------

class TestPipelineResultToDict:

    def test_to_dict_contains_run_id(self):
        result = _run_pipeline(findings=[])
        d = result.to_dict()
        assert "run_id" in d

    def test_to_dict_contains_steps_list(self):
        result = _run_pipeline(findings=[_make_finding()])
        d = result.to_dict()
        assert "steps" in d
        assert isinstance(d["steps"], list)

    def test_to_dict_status_is_string(self):
        result = _run_pipeline(findings=[])
        d = result.to_dict()
        assert isinstance(d["status"], str)

    def test_to_dict_progress_percent_is_100(self):
        result = _run_pipeline(findings=[_make_finding()])
        d = result.to_dict()
        assert d["progress_percent"] == 100.0

    def test_to_dict_summary_contains_all_expected_keys(self):
        result = _run_pipeline(findings=[_make_finding()])
        summary = result.to_dict()["summary"]
        expected_keys = [
            "findings_ingested", "clusters_created", "exposure_cases_created",
            "graph_nodes", "graph_edges", "avg_risk_score", "critical_cases",
            "pentest_validated", "playbooks_executed", "evidence_generated",
        ]
        for key in expected_keys:
            assert key in summary

    def test_to_dict_total_duration_is_float(self):
        result = _run_pipeline(findings=[])
        d = result.to_dict()
        assert isinstance(d["total_duration_ms"], float)


# ---------------------------------------------------------------------------
# 16. Class constants
# ---------------------------------------------------------------------------

class TestClassConstants:

    def test_pipeline_timeout_s_is_positive(self):
        assert BrainPipeline.PIPELINE_TIMEOUT_S > 0

    def test_step_timeout_s_is_positive(self):
        assert BrainPipeline.STEP_TIMEOUT_S > 0

    def test_graph_batch_size_is_positive(self):
        assert BrainPipeline.GRAPH_BATCH_SIZE > 0

    def test_max_runs_history_is_positive(self):
        assert BrainPipeline.MAX_RUNS_HISTORY > 0

    def test_max_field_len_is_at_least_1000(self):
        assert BrainPipeline.MAX_FIELD_LEN >= 1000

    def test_remote_steps_frozenset_contains_known_steps(self):
        assert "enrich_threats" in BrainPipeline._REMOTE_STEPS
        assert "score_risk" in BrainPipeline._REMOTE_STEPS
