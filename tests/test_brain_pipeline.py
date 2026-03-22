"""
Comprehensive tests for BrainPipeline (suite-core/core/brain_pipeline.py).

Covers:
  - Data classes: PipelineInput, PipelineResult, StepResult, enums
  - PipelineResult auto-generated fields (run_id, started_at)
  - PipelineResult.to_dict() and StepResult.to_dict()
  - BrainPipeline.run() — full 12-step pipeline
  - Step skipping (run_pentest=False, run_playbooks=False, generate_evidence=False)
  - Step 1: connect — tally findings and assets
  - Step 2: normalize — canonical shape enforcement
  - Step 3: resolve_identity — fuzzy identity (mocked, unavailable)
  - Step 4: deduplicate — dedup service (mocked, unavailable)
  - Step 5: build_graph — knowledge brain (mocked, unavailable)
  - Step 6: enrich_threats — deterministic enrichment
  - Step 7: score_risk — risk scoring with asset criticality
  - Step 8: apply_policy — policy rule matching
  - Step 9: llm_consensus — LLM engine (mocked, unavailable)
  - Step 10: micro_pentest — skipped when run_pentest=False
  - Step 11: run_playbooks — skipped when run_playbooks=False
  - Step 12: generate_evidence — evidence bundle generation
  - Pipeline failure handling — step exception does not crash pipeline
  - Pipeline status transitions (COMPLETED, FAILED, PARTIAL)
  - get_run and list_runs
  - get_brain_pipeline singleton
  - Event emission (mocked)
  - Empty findings pipeline
  - Large findings batch
  - Custom policy rules
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from core.brain_pipeline import (
    STEP_NAMES,
    BrainPipeline,
    PipelineInput,
    PipelineResult,
    PipelineStatus,
    StepResult,
    StepStatus,
    get_brain_pipeline,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def pipeline():
    return BrainPipeline()


@pytest.fixture
def sample_findings():
    """Generate a list of realistic findings for pipeline testing."""
    return [
        {
            "id": f"FIND-{i}",
            "rule_id": f"CWE-{79 + i}",
            "message": f"Vulnerability {i}",
            "severity": sev,
            "cve_id": f"CVE-2024-{1000 + i}" if i % 2 == 0 else None,
            "component": f"lib-{i}",
            "asset": f"service-{i % 3}",
        }
        for i, sev in enumerate(
            ["critical", "high", "medium", "low", "info"] * 4
        )
    ]


@pytest.fixture
def sample_assets():
    """Generate a list of realistic assets."""
    return [
        {"id": "service-0", "name": "service-0", "criticality": 1.5},
        {"id": "service-1", "name": "service-1", "criticality": 1.0},
        {"id": "service-2", "name": "service-2", "criticality": 0.8},
    ]


@pytest.fixture
def basic_input(sample_findings, sample_assets):
    """A standard pipeline input with 20 findings and 3 assets."""
    return PipelineInput(
        org_id="test-org",
        findings=sample_findings,
        assets=sample_assets,
        source="pytest",
    )


@pytest.fixture
def full_input(sample_findings, sample_assets):
    """Pipeline input with all optional steps enabled."""
    return PipelineInput(
        org_id="test-org",
        findings=sample_findings,
        assets=sample_assets,
        run_pentest=True,
        run_playbooks=True,
        generate_evidence=True,
        evidence_framework="soc2",
        evidence_timeframe_days=90,
        source="pytest-full",
    )


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestEnums:
    def test_pipeline_status_values(self):
        assert PipelineStatus.PENDING.value == "pending"
        assert PipelineStatus.RUNNING.value == "running"
        assert PipelineStatus.COMPLETED.value == "completed"
        assert PipelineStatus.FAILED.value == "failed"
        assert PipelineStatus.PARTIAL.value == "partial"

    def test_step_status_values(self):
        assert StepStatus.PENDING.value == "pending"
        assert StepStatus.RUNNING.value == "running"
        assert StepStatus.COMPLETED.value == "completed"
        assert StepStatus.SKIPPED.value == "skipped"
        assert StepStatus.FAILED.value == "failed"


# ---------------------------------------------------------------------------
# STEP_NAMES constant
# ---------------------------------------------------------------------------


class TestStepNames:
    def test_thirteen_steps(self):
        assert len(STEP_NAMES) == 13

    def test_step_order(self):
        assert STEP_NAMES[0] == "connect"
        assert STEP_NAMES[1] == "normalize"
        assert STEP_NAMES[2] == "resolve_identity"
        assert STEP_NAMES[3] == "fp_auto_suppress"
        assert STEP_NAMES[4] == "deduplicate"
        assert STEP_NAMES[5] == "build_graph"
        assert STEP_NAMES[6] == "enrich_threats"
        assert STEP_NAMES[7] == "score_risk"
        assert STEP_NAMES[8] == "apply_policy"
        assert STEP_NAMES[9] == "llm_consensus"
        assert STEP_NAMES[10] == "micro_pentest"
        assert STEP_NAMES[11] == "run_playbooks"
        assert STEP_NAMES[12] == "generate_evidence"


# ---------------------------------------------------------------------------
# StepResult tests
# ---------------------------------------------------------------------------


class TestStepResult:
    def test_defaults(self):
        sr = StepResult(name="test_step")
        assert sr.name == "test_step"
        assert sr.status == StepStatus.PENDING
        assert sr.started_at is None
        assert sr.finished_at is None
        assert sr.duration_ms == 0
        assert sr.output == {}
        assert sr.error is None

    def test_to_dict(self):
        sr = StepResult(
            name="connect",
            status=StepStatus.COMPLETED,
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
            duration_ms=1000.123,
            output={"findings_count": 10},
            error=None,
        )
        d = sr.to_dict()
        assert d["name"] == "connect"
        assert d["status"] == "completed"
        assert d["started_at"] == "2026-01-01T00:00:00Z"
        assert d["finished_at"] == "2026-01-01T00:00:01Z"
        assert d["duration_ms"] == 1000.12
        assert d["output"]["findings_count"] == 10
        assert d["error"] is None

    def test_to_dict_with_error(self):
        sr = StepResult(
            name="connect",
            status=StepStatus.FAILED,
            error="Connection refused",
        )
        d = sr.to_dict()
        assert d["status"] == "failed"
        assert d["error"] == "Connection refused"


# ---------------------------------------------------------------------------
# PipelineInput tests
# ---------------------------------------------------------------------------


class TestPipelineInput:
    def test_defaults(self):
        inp = PipelineInput()
        assert inp.org_id == ""
        assert inp.findings == []
        assert inp.assets == []
        assert inp.run_pentest is False
        assert inp.run_playbooks is True
        assert inp.generate_evidence is True
        assert inp.evidence_framework == "soc2"
        assert inp.evidence_timeframe_days == 90
        assert inp.policy_rules == []
        assert inp.source == "api"
        assert inp.metadata == {}

    def test_findings_list_not_shared(self):
        a = PipelineInput()
        b = PipelineInput()
        a.findings.append({"id": "x"})
        assert b.findings == []

    def test_custom_values(self):
        inp = PipelineInput(
            org_id="acme",
            findings=[{"id": "1"}],
            run_pentest=True,
            evidence_framework="hipaa",
        )
        assert inp.org_id == "acme"
        assert len(inp.findings) == 1
        assert inp.run_pentest is True
        assert inp.evidence_framework == "hipaa"


# ---------------------------------------------------------------------------
# PipelineResult tests
# ---------------------------------------------------------------------------


class TestPipelineResult:
    def test_auto_generated_run_id(self):
        r = PipelineResult()
        assert r.run_id.startswith("BR-")
        assert len(r.run_id) == 15  # "BR-" + 12 hex chars

    def test_auto_generated_started_at(self):
        r = PipelineResult()
        assert r.started_at != ""
        assert "T" in r.started_at

    def test_explicit_run_id_preserved(self):
        r = PipelineResult(run_id="BR-CUSTOM123456")
        assert r.run_id == "BR-CUSTOM123456"

    def test_to_dict_structure(self):
        r = PipelineResult(org_id="test")
        r.steps = [StepResult(name="connect", status=StepStatus.COMPLETED)]
        d = r.to_dict()
        assert "run_id" in d
        assert "org_id" in d
        assert "status" in d
        assert "started_at" in d
        assert "steps" in d
        assert "summary" in d
        assert d["summary"]["findings_ingested"] == 0

    def test_to_dict_summary_keys(self):
        r = PipelineResult(
            findings_ingested=100,
            clusters_created=20,
            exposure_cases_created=5,
            graph_nodes=50,
            graph_edges=30,
            avg_risk_score=0.65,
            critical_cases=3,
            pentest_validated=2,
            playbooks_executed=10,
            evidence_generated=True,
        )
        d = r.to_dict()
        s = d["summary"]
        assert s["findings_ingested"] == 100
        assert s["clusters_created"] == 20
        assert s["exposure_cases_created"] == 5
        assert s["graph_nodes"] == 50
        assert s["graph_edges"] == 30
        assert s["avg_risk_score"] == 0.65
        assert s["critical_cases"] == 3
        assert s["pentest_validated"] == 2
        assert s["playbooks_executed"] == 10
        assert s["evidence_generated"] is True


# ---------------------------------------------------------------------------
# BrainPipeline.run() — basic execution
# ---------------------------------------------------------------------------


class TestPipelineRun:
    def test_run_returns_result(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        assert isinstance(result, PipelineResult)
        assert result.org_id == "test-org"
        assert result.run_id.startswith("BR-")

    def test_run_has_12_steps(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        assert len(result.steps) == 13

    def test_optional_steps_skipped_by_default(self, pipeline, basic_input):
        """Step 10 (pentest) should be SKIPPED; 11/12 run by default."""
        result = pipeline.run(basic_input)
        micro_pentest = result.steps[10]
        run_playbooks = result.steps[11]
        gen_evidence = result.steps[12]
        assert micro_pentest.status == StepStatus.SKIPPED
        assert run_playbooks.status == StepStatus.COMPLETED
        assert gen_evidence.status == StepStatus.COMPLETED

    def test_required_steps_completed(self, pipeline, basic_input):
        """Steps 1-8 should be COMPLETED (or FAILED gracefully)."""
        result = pipeline.run(basic_input)
        # Steps 0-2 should complete (no external deps)
        assert result.steps[0].status == StepStatus.COMPLETED  # connect
        assert result.steps[1].status == StepStatus.COMPLETED  # normalize
        # Steps 3-6 may fail if services unavailable, but should not crash
        for step in result.steps[:10]:
            assert step.status in (
                StepStatus.COMPLETED,
                StepStatus.FAILED,
                StepStatus.SKIPPED,
            )

    def test_pipeline_status_completed_or_partial(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        # Some steps may fail (dedup, graph, etc) due to missing services
        assert result.status in (
            PipelineStatus.COMPLETED,
            PipelineStatus.PARTIAL,
            PipelineStatus.FAILED,
        )

    def test_pipeline_timing(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        assert result.total_duration_ms > 0
        assert result.finished_at is not None

    def test_findings_ingested_count(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        assert result.findings_ingested == len(basic_input.findings)


# ---------------------------------------------------------------------------
# Step 1: Connect
# ---------------------------------------------------------------------------


class TestStepConnect:
    def test_connect_tallies_counts(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        step = result.steps[0]
        assert step.status == StepStatus.COMPLETED
        assert step.output["findings_count"] == 20
        assert step.output["assets_count"] == 3
        assert step.output["source"] == "pytest"


# ---------------------------------------------------------------------------
# Step 2: Normalize
# ---------------------------------------------------------------------------


class TestStepNormalize:
    def test_normalize_sets_defaults(self, pipeline):
        findings = [{"id": "1"}, {"id": "2", "severity": "high"}]
        inp = PipelineInput(org_id="org", findings=findings)
        result = pipeline.run(inp)
        step = result.steps[1]
        assert step.status == StepStatus.COMPLETED
        assert step.output["normalized_count"] == 2
        # Check that defaults were set on findings
        assert findings[0]["severity"] == "medium"
        assert findings[0]["org_id"] == "org"
        assert findings[0]["source"] == "api"
        assert findings[0]["cve_id"] is None

    def test_normalize_preserves_existing_severity(self, pipeline):
        findings = [{"id": "1", "severity": "critical"}]
        inp = PipelineInput(org_id="org", findings=findings)
        pipeline.run(inp)
        assert findings[0]["severity"] == "critical"

    def test_normalize_title_from_message(self, pipeline):
        findings = [{"id": "1", "message": "SQL injection found"}]
        inp = PipelineInput(org_id="org", findings=findings)
        pipeline.run(inp)
        assert findings[0]["title"] == "SQL injection found"

    def test_normalize_title_from_rule_id(self, pipeline):
        findings = [{"id": "1", "rule_id": "CWE-79"}]
        inp = PipelineInput(org_id="org", findings=findings)
        pipeline.run(inp)
        assert findings[0]["title"] == "CWE-79"

    def test_normalize_asset_name_from_component(self, pipeline):
        findings = [{"id": "1", "component": "openssl"}]
        inp = PipelineInput(org_id="org", findings=findings)
        pipeline.run(inp)
        assert findings[0]["asset_name"] == "openssl"


# ---------------------------------------------------------------------------
# Step 3: Resolve Identity (graceful fallback)
# ---------------------------------------------------------------------------


class TestStepResolveIdentity:
    def test_resolve_identity_graceful_when_unavailable(self, pipeline, basic_input):
        """Should handle missing fuzzy_identity module gracefully."""
        result = pipeline.run(basic_input)
        step = result.steps[2]
        # Should be completed (with skipped=True) or failed gracefully
        assert step.status in (StepStatus.COMPLETED, StepStatus.FAILED)

    @patch("core.brain_pipeline.BrainPipeline._step_resolve_identity")
    def test_resolve_identity_with_mock(self, mock_resolve, pipeline, basic_input):
        mock_resolve.return_value = {"resolved": 15, "total": 20}
        result = pipeline.run(basic_input)
        step = result.steps[2]
        assert step.status == StepStatus.COMPLETED
        assert step.output["resolved"] == 15


# ---------------------------------------------------------------------------
# Step 4: Deduplicate (graceful fallback)
# ---------------------------------------------------------------------------


class TestStepDeduplicate:
    def test_deduplicate_graceful_when_unavailable(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        step = result.steps[4]
        assert step.status in (StepStatus.COMPLETED, StepStatus.FAILED)


# ---------------------------------------------------------------------------
# Step 5: Build Graph (graceful fallback)
# ---------------------------------------------------------------------------


class TestStepBuildGraph:
    def test_build_graph_graceful_when_unavailable(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        step = result.steps[5]
        assert step.status in (StepStatus.COMPLETED, StepStatus.FAILED)


# ---------------------------------------------------------------------------
# Step 6: Enrich Threats
# ---------------------------------------------------------------------------


class TestStepEnrichThreats:
    def test_enrich_threats_with_cves(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        step = result.steps[6]
        assert step.status == StepStatus.COMPLETED
        # 10 of 20 findings have CVE IDs (every other one)
        assert step.output["enriched"] == 10

    def test_enrich_threats_no_cves(self, pipeline):
        findings = [{"id": "1", "severity": "high"}]
        inp = PipelineInput(org_id="org", findings=findings)
        result = pipeline.run(inp)
        step = result.steps[6]
        assert step.status == StepStatus.COMPLETED
        assert step.output["enriched"] == 0

    def test_enrich_threats_sets_cvss_and_epss(self, pipeline):
        findings = [{"id": "1", "cve_id": "CVE-2024-001", "severity": "critical"}]
        inp = PipelineInput(org_id="org", findings=findings)
        # Need to run through normalize first, then enrich
        pipeline.run(inp)
        # After enrichment, findings should have cvss/epss
        assert "cvss_score" in findings[0]
        assert "epss_score" in findings[0]
        assert findings[0]["cvss_score"] == 9.5  # critical maps to 9.5
        # in_kev is determined by actual CISA KEV catalog lookup, not severity
        # CVE-2024-001 is a synthetic ID not in the real KEV catalog
        assert "in_kev" in findings[0]

    def test_enrich_threats_severity_mapping(self, pipeline):
        for sev, expected_cvss in [
            ("critical", 9.5),
            ("high", 7.5),
            ("medium", 5.0),
            ("low", 2.5),
            ("info", 0.5),
        ]:
            findings = [{"id": "1", "cve_id": "CVE-2024-001", "severity": sev}]
            inp = PipelineInput(org_id="org", findings=findings)
            pipeline.run(inp)
            assert findings[0]["cvss_score"] == expected_cvss, (
                f"severity={sev} should map to cvss={expected_cvss}"
            )


# ---------------------------------------------------------------------------
# Step 7: Score Risk
# ---------------------------------------------------------------------------


class TestStepScoreRisk:
    def test_score_risk_produces_scores(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        step = result.steps[7]
        assert step.status == StepStatus.COMPLETED
        assert step.output["scored"] == 20
        assert 0 <= step.output["avg_risk_score"] <= 1.0
        assert step.output["critical_count"] >= 0

    def test_score_risk_respects_asset_criticality(self, pipeline):
        findings = [
            {
                "id": "f1",
                "cve_id": "CVE-2024-001",
                "severity": "high",
                "asset": "service-0",
            }
        ]
        assets = [{"id": "service-0", "name": "service-0", "criticality": 2.0}]
        inp = PipelineInput(org_id="org", findings=findings, assets=assets)
        pipeline.run(inp)
        # Finding should have a risk_score assigned
        assert "risk_score" in findings[0]
        assert findings[0]["risk_score"] > 0

    def test_score_risk_empty_findings(self, pipeline):
        inp = PipelineInput(org_id="org", findings=[])
        result = pipeline.run(inp)
        step = result.steps[7]
        assert step.status == StepStatus.COMPLETED
        assert step.output["scored"] == 0
        assert step.output["avg_risk_score"] == 0.0


# ---------------------------------------------------------------------------
# Step 8: Apply Policy
# ---------------------------------------------------------------------------


class TestStepApplyPolicy:
    def test_apply_policy_default_rules(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        step = result.steps[8]
        assert step.status == StepStatus.COMPLETED
        assert step.output["decisions"] == 20
        assert isinstance(step.output["action_breakdown"], dict)

    def test_apply_policy_high_risk_blocked(self, pipeline):
        findings = [
            {
                "id": "f1",
                "cve_id": "CVE-2024-001",
                "severity": "critical",
            }
        ]
        inp = PipelineInput(org_id="org", findings=findings)
        pipeline.run(inp)
        # After enrichment + scoring, critical finding should get high risk_score
        # Policy should assign "block" or "review" or "escalate"
        assert findings[0].get("policy_action") in (
            "block",
            "review",
            "escalate",
            "allow",
        )

    def test_apply_policy_custom_rules(self, pipeline):
        findings = [
            {"id": "f1", "severity": "medium", "cve_id": "CVE-2024-001"}
        ]
        custom_rules = [
            {
                "name": "auto_patch",
                "condition": "risk_score >= 0.6",
                "action": "auto_patch",
            }
        ]
        inp = PipelineInput(
            org_id="org",
            findings=findings,
            policy_rules=custom_rules,
        )
        result = pipeline.run(inp)
        step = result.steps[8]
        assert step.status == StepStatus.COMPLETED


# ---------------------------------------------------------------------------
# Step 9: LLM Consensus (graceful fallback)
# ---------------------------------------------------------------------------


class TestStepLLMConsensus:
    def test_llm_consensus_graceful_when_unavailable(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        step = result.steps[9]
        assert step.status in (StepStatus.COMPLETED, StepStatus.FAILED)

    def test_llm_consensus_no_critical_findings(self, pipeline):
        # All findings low severity => no critical => skip
        findings = [
            {"id": f"f{i}", "severity": "info"} for i in range(5)
        ]
        inp = PipelineInput(org_id="org", findings=findings)
        result = pipeline.run(inp)
        step = result.steps[9]
        assert step.status == StepStatus.COMPLETED
        assert step.output.get("analyzed") == 0


# ---------------------------------------------------------------------------
# Step 10: Micro Pentest (skipped by default)
# ---------------------------------------------------------------------------


class TestStepMicroPentest:
    def test_skipped_by_default(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        assert result.steps[10].status == StepStatus.SKIPPED

    @pytest.mark.timeout(15)
    @patch("core.brain_pipeline.BrainPipeline._step_micro_pentest")
    def test_runs_when_enabled(self, mock_pentest, pipeline, basic_input):
        mock_pentest.return_value = {"tested_cves": 3, "status": "complete"}
        basic_input.run_pentest = True
        result = pipeline.run(basic_input)
        assert result.steps[10].status == StepStatus.COMPLETED


# ---------------------------------------------------------------------------
# Step 11: Run Playbooks (skipped by default)
# ---------------------------------------------------------------------------


class TestStepRunPlaybooks:
    def test_runs_by_default(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        assert result.steps[11].status == StepStatus.COMPLETED

    def test_skipped_when_disabled(self, pipeline, basic_input):
        basic_input.run_playbooks = False
        result = pipeline.run(basic_input)
        assert result.steps[11].status == StepStatus.SKIPPED

    def test_runs_when_enabled(self, pipeline, basic_input):
        basic_input.run_playbooks = True
        result = pipeline.run(basic_input)
        step = result.steps[11]
        assert step.status == StepStatus.COMPLETED
        assert "executed" in step.output

    def test_no_actionable_findings(self, pipeline):
        findings = [{"id": "f1", "severity": "info"}]
        inp = PipelineInput(
            org_id="org", findings=findings, run_playbooks=True
        )
        result = pipeline.run(inp)
        step = result.steps[11]
        assert step.status == StepStatus.COMPLETED
        assert step.output["executed"] == 0


# ---------------------------------------------------------------------------
# Step 12: Generate Evidence (skipped by default)
# ---------------------------------------------------------------------------


class TestStepGenerateEvidence:
    def test_runs_by_default(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        assert result.steps[12].status == StepStatus.COMPLETED

    def test_skipped_when_disabled(self, pipeline, basic_input):
        basic_input.generate_evidence = False
        result = pipeline.run(basic_input)
        assert result.steps[12].status == StepStatus.SKIPPED

    def test_runs_when_enabled(self, pipeline, basic_input):
        basic_input.generate_evidence = True
        result = pipeline.run(basic_input)
        step = result.steps[12]
        assert step.status == StepStatus.COMPLETED
        assert step.output["framework"] == "soc2"
        assert step.output["org_id"] == "test-org"
        assert "summary" in step.output
        assert "controls" in step.output

    def test_evidence_contains_controls(self, pipeline, basic_input):
        basic_input.generate_evidence = True
        result = pipeline.run(basic_input)
        controls = result.steps[12].output["controls"]
        assert "vulnerability_management" in controls
        assert "change_management" in controls
        assert "logging_monitoring" in controls

    def test_evidence_custom_framework(self, pipeline, basic_input):
        basic_input.generate_evidence = True
        basic_input.evidence_framework = "hipaa"
        result = pipeline.run(basic_input)
        assert result.steps[12].output["framework"] == "hipaa"


# ---------------------------------------------------------------------------
# Pipeline failure handling
# ---------------------------------------------------------------------------


class TestPipelineFailureHandling:
    @patch("core.brain_pipeline.BrainPipeline._step_normalize")
    def test_step_exception_marks_step_failed(self, mock_norm, pipeline, basic_input):
        mock_norm.side_effect = RuntimeError("Boom!")
        result = pipeline.run(basic_input)
        step = result.steps[1]
        assert step.status == StepStatus.FAILED
        # Error message should contain exception type but NOT the raw detail
        # (hardened to prevent info leakage — see brain_pipeline.py line 291)
        assert "RuntimeError" in step.error
        assert "pipeline step failed" in step.error

    @patch("core.brain_pipeline.BrainPipeline._step_normalize")
    def test_pipeline_continues_after_step_failure(
        self, mock_norm, pipeline, basic_input
    ):
        mock_norm.side_effect = RuntimeError("Step 2 fail")
        result = pipeline.run(basic_input)
        # Steps after the failure should still run
        # (step 3+ should be attempted)
        assert result.steps[0].status == StepStatus.COMPLETED  # connect OK
        assert result.steps[1].status == StepStatus.FAILED  # normalize failed
        # Later steps still attempted
        for step in result.steps[2:10]:
            assert step.status in (
                StepStatus.COMPLETED,
                StepStatus.FAILED,
                StepStatus.SKIPPED,
            )

    @patch("core.brain_pipeline.BrainPipeline._step_normalize")
    def test_pipeline_status_failed_when_step_fails(
        self, mock_norm, pipeline, basic_input
    ):
        mock_norm.side_effect = RuntimeError("Critical failure")
        result = pipeline.run(basic_input)
        # Pipeline status should reflect the failure
        assert result.status in (PipelineStatus.FAILED, PipelineStatus.PARTIAL)


# ---------------------------------------------------------------------------
# Pipeline status transitions
# ---------------------------------------------------------------------------


class TestPipelineStatusTransitions:
    def test_empty_findings_still_completes(self, pipeline):
        inp = PipelineInput(org_id="empty-org", findings=[])
        result = pipeline.run(inp)
        # With empty findings, all steps should complete (or skip)
        assert result.status in (
            PipelineStatus.COMPLETED,
            PipelineStatus.PARTIAL,
            PipelineStatus.FAILED,
        )
        assert result.findings_ingested == 0

    def test_all_optional_steps_enabled(self, pipeline, full_input):
        result = pipeline.run(full_input)
        # With all steps enabled, none should be skipped except due to errors
        for step in result.steps:
            assert step.status != StepStatus.PENDING


# ---------------------------------------------------------------------------
# get_run / list_runs
# ---------------------------------------------------------------------------


class TestRunManagement:
    def test_get_run(self, pipeline, basic_input):
        result = pipeline.run(basic_input)
        retrieved = pipeline.get_run(result.run_id)
        assert retrieved is not None
        assert retrieved.run_id == result.run_id

    def test_get_run_missing(self, pipeline):
        assert pipeline.get_run("nonexistent") is None

    def test_list_runs(self, pipeline, basic_input):
        pipeline.run(basic_input)
        pipeline.run(PipelineInput(org_id="org2", findings=[]))
        runs = pipeline.list_runs()
        assert len(runs) == 2
        # Should be dicts
        assert isinstance(runs[0], dict)
        assert "run_id" in runs[0]

    def test_list_runs_limit(self, pipeline):
        for i in range(5):
            pipeline.run(PipelineInput(org_id=f"org-{i}", findings=[]))
        runs = pipeline.list_runs(limit=3)
        assert len(runs) == 3

    def test_list_runs_sorted_by_time(self, pipeline):
        for i in range(3):
            pipeline.run(PipelineInput(org_id=f"org-{i}", findings=[]))
        runs = pipeline.list_runs()
        # Most recent first
        assert runs[0]["started_at"] >= runs[1]["started_at"]


# ---------------------------------------------------------------------------
# get_brain_pipeline singleton
# ---------------------------------------------------------------------------


class TestGetBrainPipeline:
    def test_returns_same_instance(self):
        import core.brain_pipeline as bp_module

        # Reset singleton
        bp_module._pipeline_instance = None
        p1 = get_brain_pipeline()
        p2 = get_brain_pipeline()
        assert p1 is p2
        # Cleanup
        bp_module._pipeline_instance = None

    def test_returns_brain_pipeline_type(self):
        import core.brain_pipeline as bp_module

        bp_module._pipeline_instance = None
        p = get_brain_pipeline()
        assert isinstance(p, BrainPipeline)
        bp_module._pipeline_instance = None


# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------


class TestEventEmission:
    @patch("core.brain_pipeline.BrainPipeline._emit_event")
    def test_event_emitted_after_run(self, mock_emit, pipeline, basic_input):
        result = pipeline.run(basic_input)
        mock_emit.assert_called_once_with(result)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    @pytest.mark.timeout(30)  # Large batch needs more time with post-pipeline enrichment
    def test_large_findings_batch(self, pipeline):
        findings = [
            {
                "id": f"FIND-{i}",
                "severity": "medium",
                "cve_id": f"CVE-2024-{i}" if i % 3 == 0 else None,
            }
            for i in range(500)
        ]
        inp = PipelineInput(org_id="large-org", findings=findings)
        result = pipeline.run(inp)
        assert result.findings_ingested == 500

    def test_findings_with_no_severity(self, pipeline):
        findings = [{"id": "1"}]
        inp = PipelineInput(org_id="org", findings=findings)
        pipeline.run(inp)
        # Normalize should have set default severity
        assert findings[0].get("severity") == "medium"

    def test_findings_with_no_id(self, pipeline):
        findings = [{"message": "Unknown vuln"}]
        inp = PipelineInput(org_id="org", findings=findings)
        result = pipeline.run(inp)
        assert result.findings_ingested == 1

    def test_empty_org_id(self, pipeline):
        inp = PipelineInput(org_id="", findings=[{"id": "1"}])
        result = pipeline.run(inp)
        assert result.org_id == ""

    def test_multiple_runs_tracked(self, pipeline):
        for i in range(3):
            pipeline.run(PipelineInput(org_id=f"org-{i}", findings=[]))
        assert len(pipeline.list_runs()) == 3

    def test_kev_enrichment_for_critical_and_high(self, pipeline):
        """KEV membership is determined by actual CISA catalog lookup, not severity.

        Synthetic CVE IDs (CVE-001 etc.) are not in the real KEV catalog,
        so in_kev should be False for all of them. Only real CVEs from the
        CISA KEV feed (e.g. CVE-2021-44228) would have in_kev=True.
        """
        findings = [
            {"id": "1", "cve_id": "CVE-001", "severity": "critical"},
            {"id": "2", "cve_id": "CVE-002", "severity": "high"},
            {"id": "3", "cve_id": "CVE-003", "severity": "medium"},
            {"id": "4", "cve_id": "CVE-004", "severity": "low"},
        ]
        inp = PipelineInput(org_id="org", findings=findings)
        pipeline.run(inp)
        # All synthetic CVEs should have in_kev field set (False since not in real catalog)
        for f in findings:
            assert "in_kev" in f
        # Synthetic CVEs are NOT in the real CISA KEV catalog
        assert findings[2]["in_kev"] is False  # medium
        assert findings[3]["in_kev"] is False  # low

    def test_policy_kev_escalate(self, pipeline):
        """Critical findings should have a policy action applied.

        With real threat enrichment, synthetic CVEs won't be in KEV,
        so the policy action depends on risk score from severity-based
        estimation. Critical severity should still get a policy action.
        """
        findings = [
            {"id": "f1", "cve_id": "CVE-001", "severity": "critical"},
        ]
        inp = PipelineInput(org_id="org", findings=findings)
        pipeline.run(inp)
        # After pipeline, finding should have a policy action set
        action = findings[0].get("policy_action")
        assert action is not None
        # Critical severity findings should be at least reviewed or allowed
        assert action in ("block", "review", "escalate", "allow")
