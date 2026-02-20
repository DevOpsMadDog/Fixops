"""Integration test for Golden Regression Store functionality."""

import json
import sys
from pathlib import Path

import pytest

ENTERPRISE_LEGACY_ROOT = (
    Path(__file__).resolve().parents[1] / "WIP" / "code" / "enterprise_legacy"
)
if str(ENTERPRISE_LEGACY_ROOT) not in sys.path:
    sys.path.insert(0, str(ENTERPRISE_LEGACY_ROOT))

import types

if "structlog" not in sys.modules:
    structlog_stub = types.ModuleType("structlog")

    class _Logger:
        def __getattr__(self, _name):
            def _noop(*_args, **_kwargs):
                return None

            return _noop

    def get_logger(*_args, **_kwargs):
        return _Logger()

    structlog_stub.get_logger = get_logger
    sys.modules["structlog"] = structlog_stub

from core.services.enterprise.golden_regression_store import (
    GoldenRegressionStore,
    RegressionCase,
)


@pytest.fixture(autouse=True)
def reset_store():
    """Reset the golden regression store before each test."""
    GoldenRegressionStore.reset_instance()
    yield
    GoldenRegressionStore.reset_instance()


def test_golden_regression_store_loads_dataset():
    """Test that the golden regression store loads the demo dataset."""
    store = GoldenRegressionStore.get_instance()

    assert len(store._cases_by_id) > 0, "No cases loaded from dataset"

    assert "payment-2024-01" in store._cases_by_id
    assert "log4shell-2021-12" in store._cases_by_id

    print(f"✅ Loaded {len(store._cases_by_id)} golden regression cases")


def test_lookup_by_service_name():
    """Test looking up cases by service name."""
    store = GoldenRegressionStore.get_instance()

    lookup = store.lookup_cases(service_name="payment-service")

    assert (
        lookup["service_matches"] >= 2
    ), "Should find at least 2 payment-service cases"

    case_ids = {case["case_id"] for case in lookup["cases"]}
    assert "payment-2024-01" in case_ids
    assert "payment-2024-02" in case_ids

    print(f"✅ Found {lookup['service_matches']} cases for payment-service")


def test_lookup_by_cve():
    """Test looking up cases by CVE ID."""
    store = GoldenRegressionStore.get_instance()

    lookup = store.lookup_cases(cve_ids=["CVE-2021-44228"])

    assert lookup["cve_matches"]["CVE-2021-44228"] >= 1, "Should find Log4Shell case"

    case_ids = {case["case_id"] for case in lookup["cases"]}
    assert "log4shell-2021-12" in case_ids

    log4shell_case = next(
        c for c in lookup["cases"] if c["case_id"] == "log4shell-2021-12"
    )
    assert log4shell_case["decision"] == "fail"
    assert log4shell_case["confidence"] >= 0.95

    print(
        f"✅ Found Log4Shell case with decision={log4shell_case['decision']}, confidence={log4shell_case['confidence']}"
    )


def test_lookup_by_service_and_cve():
    """Test looking up cases by both service name and CVE."""
    store = GoldenRegressionStore.get_instance()

    lookup = store.lookup_cases(
        service_name="payment-service", cve_ids=["CVE-2024-1111"]
    )

    assert lookup["service_matches"] >= 2, "Should find payment-service cases"
    assert lookup["cve_matches"]["CVE-2024-1111"] >= 1, "Should find CVE-2024-1111 case"

    case = next(c for c in lookup["cases"] if c["case_id"] == "payment-2024-01")
    match_types = {m["type"] for m in case["match_context"]}
    assert "service" in match_types
    assert "cve" in match_types

    print("✅ Found case matching both service and CVE")


def test_regression_case_from_dict():
    """Test creating RegressionCase from dictionary."""
    payload = {
        "case_id": "test-case-001",
        "service_name": "test-service",
        "cve_id": "CVE-2024-9999",
        "decision": "BLOCK",
        "confidence": 0.95,
        "timestamp": "2024-01-01T00:00:00Z",
        "context": {"service_name": "test-service", "environment": "production"},
        "expected": {"decision": "BLOCK", "confidence": 0.95},
    }

    case = RegressionCase.from_dict(payload)

    assert case.case_id == "test-case-001"
    assert case.service_name == "test-service"
    assert case.cve_id == "CVE-2024-9999"
    assert case.decision == "fail"  # "BLOCK" normalized to "fail"
    assert case.confidence == 0.95

    print(f"✅ Created RegressionCase from dict: {case.case_id}")


def test_demo_dataset_structure():
    """Test that the demo dataset has the expected structure."""
    dataset_path = (
        Path(__file__).resolve().parents[1] / "data" / "golden_regression_cases.json"
    )

    assert dataset_path.exists(), f"Demo dataset not found at {dataset_path}"

    with open(dataset_path) as f:
        data = json.load(f)

    assert "cases" in data, "Dataset should have 'cases' key"
    assert len(data["cases"]) >= 5, "Dataset should have at least 5 cases"

    case = data["cases"][0]
    required_fields = ["case_id", "service_name", "decision", "confidence"]
    for field in required_fields:
        assert field in case, f"Case missing required field: {field}"

    print(f"✅ Demo dataset has {len(data['cases'])} cases with correct structure")


def test_no_coverage_scenario():
    """Test behavior when no historical cases match."""
    store = GoldenRegressionStore.get_instance()

    lookup = store.lookup_cases(
        service_name="nonexistent-service", cve_ids=["CVE-0000-0000"]
    )

    assert lookup["service_matches"] == 0
    assert lookup["cve_matches"]["CVE-0000-0000"] == 0
    assert len(lookup["cases"]) == 0

    print("✅ Correctly handled no-coverage scenario")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
