"""Coverage tests for core.stage_runner — InputNormalizer, StageRunner."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from unittest.mock import MagicMock
from core.stage_runner import InputNormalizer, StageRunner, NormalizedSARIF, NormalizedSBOM


class TestInputNormalizer:
    def test_instantiation(self):
        norm = InputNormalizer()
        assert norm is not None

    def test_with_sbom_type(self):
        norm = InputNormalizer(sbom_type="cyclonedx")
        assert norm is not None

    def test_load_sarif_minimal(self):
        norm = InputNormalizer()
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "TestTool", "version": "1.0"}},
                "results": [],
            }],
        }
        result = norm.load_sarif(sarif_data)
        assert isinstance(result, NormalizedSARIF)

    def test_load_sbom_minimal(self):
        norm = InputNormalizer()
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [],
        }
        result = norm.load_sbom(sbom_data)
        assert isinstance(result, NormalizedSBOM)

    def test_load_sarif_with_results(self):
        norm = InputNormalizer()
        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Semgrep", "version": "1.0"}},
                "results": [
                    {
                        "ruleId": "sql-injection",
                        "level": "error",
                        "message": {"text": "SQL injection detected"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app.py"},
                                "region": {"startLine": 42},
                            }
                        }],
                    }
                ],
            }],
        }
        result = norm.load_sarif(sarif_data)
        assert isinstance(result, NormalizedSARIF)


class TestStageRunner:
    def test_instantiation(self):
        registry = MagicMock()
        allocator = MagicMock()
        signer = MagicMock()
        runner = StageRunner(registry, allocator, signer)
        assert runner is not None

    def test_with_normalizer(self):
        registry = MagicMock()
        allocator = MagicMock()
        signer = MagicMock()
        normalizer = InputNormalizer()
        runner = StageRunner(registry, allocator, signer, normalizer=normalizer)
        assert runner is not None
