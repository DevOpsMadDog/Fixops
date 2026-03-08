"""Coverage tests for core.ssdlc — SSDLCEvaluator."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from unittest.mock import MagicMock
from core.ssdlc import SSDLCEvaluator, RequirementResult, StageResult


class TestSSDLCEvaluator:
    def test_instantiation(self):
        ev = SSDLCEvaluator(settings={"strict": False})
        assert ev is not None

    def test_evaluate_with_minimal_inputs(self):
        ev = SSDLCEvaluator(settings={})
        sbom = MagicMock()
        sbom.components = []
        sarif = MagicMock()
        sarif.results = []
        cve = MagicMock()
        cve.entries = []
        overlay = MagicMock()
        overlay.overrides = {}

        result = ev.evaluate(
            design_rows=[],
            sbom=sbom,
            sarif=sarif,
            cve=cve,
            pipeline_result={"status": "clean"},
            context_summary=None,
            compliance_status=None,
            policy_summary=None,
            overlay=overlay,
        )
        assert result is not None
        assert isinstance(result, dict)


class TestRequirementResult:
    def test_creation(self):
        rr = RequirementResult(
            key="REQ-001",
            title="Input Validation",
            status="pass",
            details="All input paths validated",
        )
        assert rr.key == "REQ-001"
        assert rr.status == "pass"

    def test_fail_status(self):
        rr = RequirementResult(
            key="REQ-002",
            title="Auth Check",
            status="fail",
            details="Missing auth on /admin endpoint",
        )
        assert rr.status == "fail"


class TestStageResult:
    def test_creation(self):
        sr = StageResult(
            identifier="STAGE-001",
            name="Design Review",
            description="Architecture security review",
            status="pass",
            requirements=[],
        )
        assert sr.name == "Design Review"
        assert sr.status == "pass"

    def test_with_requirements(self):
        rr = RequirementResult(key="R1", title="T1", status="pass", details="OK")
        sr = StageResult(
            identifier="STAGE-002",
            name="Code Review",
            description="Source code analysis",
            status="pass",
            requirements=[rr],
        )
        assert len(sr.requirements) == 1
