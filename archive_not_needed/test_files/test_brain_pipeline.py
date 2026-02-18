"""Tests for the Brain Pipeline Orchestrator (Phase 9.5.3)."""
import os
import sys
import tempfile
import unittest

# Ensure suite-core is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "suite-core"))

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


class TestPipelineDataTypes(unittest.TestCase):
    def test_step_names_count(self):
        self.assertEqual(len(STEP_NAMES), 12)

    def test_step_result_defaults(self):
        sr = StepResult(name="connect")
        self.assertEqual(sr.status, StepStatus.PENDING)
        self.assertIsNone(sr.error)

    def test_pipeline_result_auto_id(self):
        r = PipelineResult(org_id="acme")
        self.assertTrue(r.run_id.startswith("BR-"))
        self.assertEqual(r.status, PipelineStatus.PENDING)

    def test_pipeline_result_to_dict(self):
        r = PipelineResult(org_id="acme")
        d = r.to_dict()
        self.assertIn("run_id", d)
        self.assertIn("summary", d)
        self.assertEqual(d["summary"]["findings_ingested"], 0)

    def test_pipeline_input_defaults(self):
        inp = PipelineInput(org_id="acme")
        self.assertFalse(inp.run_pentest)
        self.assertFalse(inp.run_playbooks)
        self.assertFalse(inp.generate_evidence)


class TestBrainPipelineCoreSteps(unittest.TestCase):
    """Test the pipeline with core steps (1-9), optional steps skipped."""

    def setUp(self):
        self.pipeline = BrainPipeline()
        self.findings = [
            {
                "id": "f1",
                "cve_id": "CVE-2024-1234",
                "severity": "critical",
                "asset_name": "payments-api-prod",
                "title": "SQL Injection",
            },
            {
                "id": "f2",
                "cve_id": "CVE-2024-5678",
                "severity": "high",
                "asset_name": "auth-service",
                "title": "XSS in login",
            },
            {
                "id": "f3",
                "cve_id": "CVE-2024-9999",
                "severity": "medium",
                "asset_name": "payments_prod_api",
                "title": "Missing CSRF",
            },
        ]
        self.assets = [
            {"id": "payments-api", "name": "payments-api-prod", "criticality": 1.5},
            {"id": "auth-svc", "name": "auth-service", "criticality": 1.3},
        ]

    def test_run_core_pipeline(self):
        result = self.pipeline.run(
            PipelineInput(
                org_id="test-org",
                findings=self.findings,
                assets=self.assets,
            )
        )
        self.assertIn(result.status, (PipelineStatus.COMPLETED, PipelineStatus.PARTIAL))
        self.assertEqual(result.findings_ingested, 3)
        self.assertTrue(result.run_id.startswith("BR-"))
        self.assertIsNotNone(result.finished_at)
        self.assertGreater(result.total_duration_ms, 0)

    def test_step1_connect(self):
        result = self.pipeline.run(
            PipelineInput(
                org_id="acme",
                findings=self.findings,
                assets=self.assets,
            )
        )
        step = result.steps[0]
        self.assertEqual(step.name, "connect")
        self.assertEqual(step.status, StepStatus.COMPLETED)
        self.assertEqual(step.output["findings_count"], 3)
        self.assertEqual(step.output["assets_count"], 2)

    def test_step2_normalize(self):
        result = self.pipeline.run(
            PipelineInput(
                org_id="acme",
                findings=self.findings,
                assets=self.assets,
            )
        )
        step = result.steps[1]
        self.assertEqual(step.name, "normalize")
        self.assertEqual(step.status, StepStatus.COMPLETED)
        self.assertEqual(step.output["normalized_count"], 3)

    def test_step6_enrich_threats(self):
        result = self.pipeline.run(
            PipelineInput(
                org_id="acme",
                findings=self.findings,
                assets=self.assets,
            )
        )
        step = result.steps[5]
        self.assertEqual(step.name, "enrich_threats")
        self.assertIn(step.status, (StepStatus.COMPLETED, StepStatus.FAILED))
        if step.status == StepStatus.COMPLETED:
            self.assertGreater(step.output.get("enriched", 0), 0)

    def test_step7_score_risk(self):
        result = self.pipeline.run(
            PipelineInput(
                org_id="acme",
                findings=self.findings,
                assets=self.assets,
            )
        )
        step = result.steps[6]
        self.assertEqual(step.name, "score_risk")
        if step.status == StepStatus.COMPLETED:
            self.assertGreater(step.output.get("scored", 0), 0)
            self.assertGreater(step.output.get("avg_risk_score", 0), 0)

    def test_step8_apply_policy(self):
        result = self.pipeline.run(
            PipelineInput(
                org_id="acme",
                findings=self.findings,
                assets=self.assets,
            )
        )
        step = result.steps[7]
        self.assertEqual(step.name, "apply_policy")
        if step.status == StepStatus.COMPLETED:
            self.assertIn("action_breakdown", step.output)

    def test_optional_steps_skipped(self):
        result = self.pipeline.run(
            PipelineInput(
                org_id="acme",
                findings=self.findings,
                assets=self.assets,
            )
        )
        # Steps 10-12 should be skipped when not requested
        self.assertEqual(result.steps[9].name, "micro_pentest")
        self.assertEqual(result.steps[9].status, StepStatus.SKIPPED)
        self.assertEqual(result.steps[10].name, "run_playbooks")
        self.assertEqual(result.steps[10].status, StepStatus.SKIPPED)
        self.assertEqual(result.steps[11].name, "generate_evidence")
        self.assertEqual(result.steps[11].status, StepStatus.SKIPPED)

    def test_get_run_and_list(self):
        result = self.pipeline.run(
            PipelineInput(
                org_id="acme",
                findings=self.findings,
                assets=self.assets,
            )
        )
        fetched = self.pipeline.get_run(result.run_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.run_id, result.run_id)
        runs = self.pipeline.list_runs()
        self.assertGreater(len(runs), 0)

    def test_to_dict(self):
        result = self.pipeline.run(
            PipelineInput(
                org_id="acme",
                findings=self.findings,
                assets=self.assets,
            )
        )
        d = result.to_dict()
        self.assertEqual(d["org_id"], "acme")
        self.assertEqual(len(d["steps"]), 12)
        self.assertIn("summary", d)


class TestBrainPipelineEdgeCases(unittest.TestCase):
    def test_empty_findings(self):
        pipeline = BrainPipeline()
        result = pipeline.run(PipelineInput(org_id="empty-org"))
        self.assertEqual(result.findings_ingested, 0)
        self.assertIn(result.status, (PipelineStatus.COMPLETED, PipelineStatus.PARTIAL))

    def test_singleton(self):
        p1 = get_brain_pipeline()
        p2 = get_brain_pipeline()
        self.assertIs(p1, p2)


if __name__ == "__main__":
    unittest.main()
