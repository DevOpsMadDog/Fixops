"""Tests for core.compliance — ComplianceEvaluator and requirement checking."""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.compliance import ComplianceEvaluator  # noqa: E402


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestComplianceEvaluatorInit:
    def test_empty_settings(self):
        evaluator = ComplianceEvaluator({})
        assert evaluator.frameworks == []

    def test_none_settings(self):
        evaluator = ComplianceEvaluator(None)
        assert evaluator.frameworks == []

    def test_frameworks_loaded(self):
        evaluator = ComplianceEvaluator({
            "frameworks": [
                {"name": "SOC2", "controls": []},
                {"name": "ISO27001", "controls": []},
            ]
        })
        assert len(evaluator.frameworks) == 2
        assert evaluator.frameworks[0]["name"] == "SOC2"

    def test_non_mapping_frameworks_filtered(self):
        evaluator = ComplianceEvaluator({
            "frameworks": [
                {"name": "SOC2", "controls": []},
                "invalid",
                42,
                None,
            ]
        })
        assert len(evaluator.frameworks) == 1


# ---------------------------------------------------------------------------
# _check_requirement
# ---------------------------------------------------------------------------


class TestCheckRequirement:
    def setup_method(self):
        self.evaluator = ComplianceEvaluator({})

    def test_design_satisfied(self):
        pipeline = {"design_summary": {"row_count": 10}}
        assert self.evaluator._check_requirement("design", pipeline, None) is True

    def test_design_not_satisfied(self):
        pipeline = {"design_summary": {"row_count": 0}}
        assert self.evaluator._check_requirement("design", pipeline, None) is False

    def test_design_missing(self):
        assert self.evaluator._check_requirement("design", {}, None) is False

    def test_sbom_satisfied(self):
        pipeline = {"sbom_summary": {"component_count": 42}}
        assert self.evaluator._check_requirement("sbom", pipeline, None) is True

    def test_sbom_satisfied_alt_key(self):
        pipeline = {"sbom_summary": {"componentCount": 42}}
        assert self.evaluator._check_requirement("sbom", pipeline, None) is True

    def test_sbom_not_satisfied(self):
        pipeline = {"sbom_summary": {}}
        assert self.evaluator._check_requirement("sbom", pipeline, None) is False

    def test_sarif_satisfied(self):
        pipeline = {"sarif_summary": {"finding_count": 5}}
        assert self.evaluator._check_requirement("sarif", pipeline, None) is True

    def test_sarif_not_satisfied(self):
        pipeline = {"sarif_summary": {}}
        assert self.evaluator._check_requirement("sarif", pipeline, None) is False

    def test_cve_satisfied_exploited(self):
        pipeline = {"cve_summary": {"exploited_count": 1}}
        assert self.evaluator._check_requirement("cve", pipeline, None) is True

    def test_cve_satisfied_records(self):
        pipeline = {"cve_summary": {"record_count": 10}}
        assert self.evaluator._check_requirement("cve", pipeline, None) is True

    def test_cve_not_satisfied(self):
        pipeline = {"cve_summary": {}}
        assert self.evaluator._check_requirement("cve", pipeline, None) is False

    def test_context_satisfied(self):
        context = {"summary": {"components_evaluated": 3}}
        assert self.evaluator._check_requirement("context", {}, context) is True

    def test_context_not_satisfied_none(self):
        assert self.evaluator._check_requirement("context", {}, None) is False

    def test_context_not_satisfied_empty(self):
        assert self.evaluator._check_requirement("context", {}, {"summary": {}}) is False

    def test_guardrails_satisfied(self):
        pipeline = {"guardrail_evaluation": {"status": "passed"}}
        assert self.evaluator._check_requirement("guardrails", pipeline, None) is True

    def test_guardrails_not_satisfied(self):
        pipeline = {"guardrail_evaluation": {}}
        assert self.evaluator._check_requirement("guardrails", pipeline, None) is False

    def test_evidence_satisfied(self):
        pipeline = {"evidence_bundle": {"id": "EB-123"}}
        assert self.evaluator._check_requirement("evidence", pipeline, None) is True

    def test_evidence_not_satisfied(self):
        assert self.evaluator._check_requirement("evidence", {}, None) is False

    def test_policy_satisfied(self):
        pipeline = {
            "policy_automation": {
                "actions": [{"type": "jira_ticket"}],
                "execution": {"dispatched_count": 1, "status": "completed"},
            }
        }
        assert self.evaluator._check_requirement("policy", pipeline, None) is True

    def test_policy_not_satisfied_no_actions(self):
        pipeline = {
            "policy_automation": {
                "actions": [],
                "execution": {"dispatched_count": 1, "status": "completed"},
            }
        }
        assert self.evaluator._check_requirement("policy", pipeline, None) is False

    def test_policy_not_satisfied_no_dispatch(self):
        pipeline = {
            "policy_automation": {
                "actions": [{"type": "ticket"}],
                "execution": {"dispatched_count": 0, "status": "completed"},
            }
        }
        assert self.evaluator._check_requirement("policy", pipeline, None) is False

    def test_policy_not_satisfied_bad_status(self):
        pipeline = {
            "policy_automation": {
                "actions": [{"type": "ticket"}],
                "execution": {"dispatched_count": 1, "status": "failed"},
            }
        }
        assert self.evaluator._check_requirement("policy", pipeline, None) is False

    def test_policy_partial_status(self):
        pipeline = {
            "policy_automation": {
                "actions": [{"type": "ticket"}],
                "execution": {"dispatched_count": 2, "status": "partial"},
            }
        }
        assert self.evaluator._check_requirement("policy", pipeline, None) is True

    def test_policy_non_mapping_payload(self):
        pipeline = {"policy_automation": "not a dict"}
        assert self.evaluator._check_requirement("policy", pipeline, None) is False

    def test_unknown_requirement(self):
        assert self.evaluator._check_requirement("unknown_req", {}, None) is False


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------


class TestEvaluate:
    def test_no_frameworks(self):
        evaluator = ComplianceEvaluator({})
        result = evaluator.evaluate({}, None)
        assert result["frameworks"] == []
        assert result["gaps"] == []

    def test_all_satisfied(self):
        evaluator = ComplianceEvaluator({
            "frameworks": [{
                "name": "SOC2",
                "controls": [
                    {"id": "CC1", "title": "Design", "requires": ["design"]},
                    {"id": "CC2", "title": "SBOM", "requires": ["sbom"]},
                ],
            }]
        })
        pipeline = {
            "design_summary": {"row_count": 5},
            "sbom_summary": {"component_count": 10},
        }
        result = evaluator.evaluate(pipeline, None)
        assert result["frameworks"][0]["status"] == "satisfied"
        assert result["gaps"] == []
        assert all(c["status"] == "satisfied" for c in result["frameworks"][0]["controls"])

    def test_gaps_reported(self):
        evaluator = ComplianceEvaluator({
            "frameworks": [{
                "name": "ISO27001",
                "controls": [
                    {"id": "A5", "title": "Asset Mgmt", "requires": ["sbom", "design"]},
                ],
            }]
        })
        pipeline = {"design_summary": {"row_count": 5}}  # sbom missing
        result = evaluator.evaluate(pipeline, None)
        assert result["frameworks"][0]["status"] == "in_progress"
        assert len(result["gaps"]) == 1
        assert "sbom" in result["gaps"][0]

    def test_multiple_frameworks(self):
        evaluator = ComplianceEvaluator({
            "frameworks": [
                {"name": "SOC2", "controls": [
                    {"id": "CC1", "title": "T", "requires": ["design"]},
                ]},
                {"name": "PCI-DSS", "controls": [
                    {"id": "R1", "title": "T", "requires": ["sarif"]},
                ]},
            ]
        })
        pipeline = {"design_summary": {"row_count": 1}}
        result = evaluator.evaluate(pipeline, None)
        assert result["frameworks"][0]["status"] == "satisfied"
        assert result["frameworks"][1]["status"] == "in_progress"

    def test_non_mapping_controls_skipped(self):
        evaluator = ComplianceEvaluator({
            "frameworks": [{
                "name": "Test",
                "controls": [
                    {"id": "C1", "title": "T", "requires": ["design"]},
                    "invalid_control",
                    42,
                ],
            }]
        })
        pipeline = {"design_summary": {"row_count": 1}}
        result = evaluator.evaluate(pipeline, None)
        assert len(result["frameworks"][0]["controls"]) == 1
