"""Coverage tests for core.iac — IaCPostureEvaluator."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.iac import IACTarget, IaCPostureEvaluator


class TestIACTarget:
    def test_creation(self):
        target = IACTarget(
            identifier="terraform-aws",
            display_name="Terraform AWS",
            match_keywords={"terraform", "aws"},
            required_artifacts=["main.tf", "variables.tf"],
            recommended_controls=["encryption", "logging"],
            environments={"production", "staging"},
        )
        assert target.identifier == "terraform-aws"
        assert "terraform" in target.match_keywords

    def test_from_mapping(self):
        data = {
            "id": "k8s",
            "name": "Kubernetes",
            "keywords": ["kubernetes", "k8s"],
            "required_artifacts": ["deployment.yaml"],
            "recommended_controls": ["network-policy"],
            "environments": ["production"],
        }
        target = IACTarget.from_mapping(data)
        assert target.identifier == "k8s"

    def test_from_mapping_no_id_raises(self):
        with pytest.raises(ValueError, match="requires an identifier"):
            IACTarget.from_mapping({})


class TestIaCPostureEvaluator:
    def test_instantiation(self):
        evaluator = IaCPostureEvaluator(settings={})
        assert evaluator is not None

    def test_evaluate_empty(self):
        evaluator = IaCPostureEvaluator(settings={})
        result = evaluator.evaluate(
            design_rows=[],
            crosswalk=[],
            pipeline_result={},
        )
        # Can return None or dict
        assert result is None or isinstance(result, dict)

    def test_evaluate_with_data(self):
        evaluator = IaCPostureEvaluator(settings={})
        result = evaluator.evaluate(
            design_rows=[
                {"id": "DR-001", "type": "terraform", "status": "reviewed"},
            ],
            crosswalk=[
                {"control": "encryption-at-rest", "status": "compliant"},
            ],
            pipeline_result={"stage": "iac-review", "status": "completed"},
        )
        assert result is None or isinstance(result, dict)
