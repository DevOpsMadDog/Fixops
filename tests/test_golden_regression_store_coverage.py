"""Tests for GoldenRegressionStore — regression case loading, lookup, and validation."""
import json

import pytest

from core.services.enterprise.golden_regression_store import (
    RegressionCase,
    RegressionCaseResult,
    GoldenRegressionStore,
)


class TestRegressionCase:
    def test_create_basic(self):
        case = RegressionCase(
            case_id="test-001",
            service_name="auth-service",
            cve_id="CVE-2024-1234",
            decision="pass",
            confidence=0.95,
        )
        assert case.case_id == "test-001"
        assert case.service_name == "auth-service"
        assert case.decision == "pass"
        assert case.confidence == 0.95

    def test_create_with_metadata(self):
        case = RegressionCase(
            case_id="test-002",
            service_name="api-gateway",
            cve_id=None,
            decision="fail",
            confidence=0.5,
            timestamp="2024-01-01T00:00:00Z",
            metadata={"scanner": "snyk"},
        )
        assert case.metadata["scanner"] == "snyk"
        assert case.timestamp is not None

    def test_from_dict_pass(self):
        data = {
            "case_id": "case-001",
            "service_name": "auth",
            "cve_id": "CVE-2024-001",
            "decision": "pass",
            "confidence": 0.9,
        }
        case = RegressionCase.from_dict(data)
        assert case.decision == "pass"
        assert case.confidence == 0.9

    def test_from_dict_allow_mapped_to_pass(self):
        data = {
            "case_id": "case-002",
            "service_name": "api",
            "decision": "allow",
            "confidence": 0.8,
        }
        case = RegressionCase.from_dict(data)
        assert case.decision == "pass"

    def test_from_dict_block_mapped_to_fail(self):
        data = {
            "case_id": "case-003",
            "service_name": "web",
            "decision": "block",
            "confidence": 0.7,
        }
        case = RegressionCase.from_dict(data)
        assert case.decision == "fail"

    def test_from_dict_reject_mapped_to_fail(self):
        data = {
            "case_id": "case-004",
            "service_name": "web",
            "decision": "reject",
            "confidence": 0.6,
        }
        case = RegressionCase.from_dict(data)
        assert case.decision == "fail"

    def test_from_dict_defer_mapped_to_fail(self):
        data = {
            "case_id": "case-005",
            "service_name": "web",
            "decision": "defer",
            "confidence": 0.5,
        }
        case = RegressionCase.from_dict(data)
        assert case.decision == "fail"

    def test_from_dict_context_fallback(self):
        data = {
            "case_id": "case-006",
            "context": {"service_name": "billing"},
            "decision": "pass",
            "confidence": 0.85,
        }
        case = RegressionCase.from_dict(data)
        assert case.service_name == "billing"

    def test_from_dict_expected_fallback(self):
        data = {
            "case_id": "case-007",
            "service_name": "auth",
            "expected": {"decision": "approve", "confidence": 0.75},
        }
        case = RegressionCase.from_dict(data)
        assert case.decision == "pass"
        assert case.confidence == 0.75

    def test_from_dict_missing_case_id_raises(self):
        with pytest.raises(ValueError, match="case_id"):
            RegressionCase.from_dict({"service_name": "x", "decision": "pass"})

    def test_from_dict_missing_service_name_raises(self):
        with pytest.raises(ValueError, match="service_name"):
            RegressionCase.from_dict({"case_id": "x", "decision": "pass"})

    def test_from_dict_missing_decision_raises(self):
        with pytest.raises(ValueError, match="decision"):
            RegressionCase.from_dict({"case_id": "x", "service_name": "y"})

    def test_from_dict_unsupported_decision_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            RegressionCase.from_dict(
                {"case_id": "x", "service_name": "y", "decision": "banana"}
            )

    def test_to_response(self):
        case = RegressionCase(
            case_id="r-001",
            service_name="auth",
            cve_id="CVE-2024-001",
            decision="pass",
            confidence=0.9,
        )
        resp = case.to_response()
        assert resp["case_id"] == "r-001"
        assert resp["decision"] == "pass"
        assert "metadata" not in resp  # empty metadata omitted

    def test_to_response_with_metadata(self):
        case = RegressionCase(
            case_id="r-002",
            service_name="api",
            cve_id=None,
            decision="fail",
            confidence=0.5,
            metadata={"scanner": "sast"},
        )
        resp = case.to_response()
        assert resp["metadata"]["scanner"] == "sast"

    def test_from_dict_original_decision_in_metadata(self):
        data = {
            "case_id": "case-010",
            "service_name": "svc",
            "decision": "allow",
            "confidence": 0.9,
        }
        case = RegressionCase.from_dict(data)
        # "allow" maps to "pass", so original_decision should be stored
        assert case.metadata.get("original_decision") == "allow"


class TestRegressionCaseResult:
    def test_create(self):
        result = RegressionCaseResult(
            case_id="r-001",
            cve_id="CVE-2024-001",
            expected={"decision": "pass", "confidence": 0.9},
            actual={"decision": "pass", "confidence": 0.85},
            match=True,
            delta={"confidence": -0.05},
            metadata={},
        )
        assert result.match is True
        assert result.delta["confidence"] == -0.05

    def test_to_dict(self):
        result = RegressionCaseResult(
            case_id="r-002",
            cve_id=None,
            expected={"decision": "fail"},
            actual={"decision": "pass"},
            match=False,
            delta={"decision": "mismatch"},
            metadata={"note": "regression"},
        )
        d = result.to_dict()
        assert d["case_id"] == "r-002"
        assert d["match"] is False
        assert d["metadata"]["note"] == "regression"


class TestGoldenRegressionStore:
    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        GoldenRegressionStore.reset_instance()
        yield
        GoldenRegressionStore.reset_instance()

    def test_empty_dataset(self, tmp_path):
        dataset_file = tmp_path / "golden_regression.json"
        dataset_file.write_text("[]")
        store = GoldenRegressionStore(dataset_path=dataset_file)
        result = store.lookup_cases(service_name="any")
        assert isinstance(result, dict)

    def test_load_valid_dataset(self, tmp_path):
        dataset_file = tmp_path / "golden_regression.json"
        data = [
            {
                "case_id": "case-001",
                "service_name": "auth",
                "cve_id": "CVE-2024-1234",
                "decision": "pass",
                "confidence": 0.9,
            },
            {
                "case_id": "case-002",
                "service_name": "api",
                "cve_id": "CVE-2024-5678",
                "decision": "block",
                "confidence": 0.8,
            },
        ]
        dataset_file.write_text(json.dumps(data))
        store = GoldenRegressionStore(dataset_path=dataset_file)
        assert len(store._cases_by_id) == 2

    def test_lookup_by_service(self, tmp_path):
        dataset_file = tmp_path / "golden_regression.json"
        data = [
            {
                "case_id": "case-001",
                "service_name": "auth-service",
                "decision": "pass",
                "confidence": 0.9,
            },
        ]
        dataset_file.write_text(json.dumps(data))
        store = GoldenRegressionStore(dataset_path=dataset_file)
        result = store.lookup_cases(service_name="auth-service")
        assert isinstance(result, dict)

    def test_singleton_pattern(self, tmp_path):
        dataset_file = tmp_path / "golden_regression.json"
        dataset_file.write_text("[]")
        s1 = GoldenRegressionStore.get_instance(dataset_path=dataset_file)
        s2 = GoldenRegressionStore.get_instance(dataset_path=dataset_file)
        assert s1 is s2

    def test_singleton_reset(self, tmp_path):
        dataset_file = tmp_path / "golden_regression.json"
        dataset_file.write_text("[]")
        s1 = GoldenRegressionStore.get_instance(dataset_path=dataset_file)
        GoldenRegressionStore.reset_instance()
        s2 = GoldenRegressionStore.get_instance(dataset_path=dataset_file)
        assert s1 is not s2

    def test_missing_dataset_file(self, tmp_path):
        dataset_file = tmp_path / "nonexistent.json"
        store = GoldenRegressionStore(dataset_path=dataset_file)
        assert len(store._cases_by_id) == 0
