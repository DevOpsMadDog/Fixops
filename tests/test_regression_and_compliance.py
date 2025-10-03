from pathlib import Path
import sys
import types

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "fixops-blended-enterprise"))

if "structlog" not in sys.modules:
    structlog_stub = types.ModuleType("structlog")

    class _Logger:
        def bind(self, **kwargs):
            return self

        def info(self, *args, **kwargs):
            return None

        def warning(self, *args, **kwargs):
            return None

        def error(self, *args, **kwargs):
            return None

    structlog_stub.get_logger = lambda *args, **kwargs: _Logger()
    sys.modules["structlog"] = structlog_stub

from src.services.golden_regression_store import GoldenRegressionStore
from src.services.compliance_engine import ComplianceEvaluator


def _sample_finding(**overrides):
    payload = {
        "cve": "CVE-2024-3094",
        "severity": "CRITICAL",
        "kev_flag": True,
        "epss_score": 0.98,
        "fix_available": True,
    }
    payload.update(overrides)
    return payload


def test_golden_regression_store_matches_expected_cases():
    store = GoldenRegressionStore()
    findings = [
        _sample_finding(),
        _sample_finding(cve="CVE-2024-3400", epss_score=0.95),
    ]
    results = store.evaluate("payment-api", "production", findings)

    assert results["status"] in {"validated", "partial"}
    assert results["matched_cases"] >= 1
    assert results["total_cases"] >= results["matched_cases"]
    assert results["confidence"] >= 0.3


def test_golden_regression_store_flags_missing_cases():
    store = GoldenRegressionStore()
    findings = [_sample_finding(cve="CVE-2024-9999", kev_flag=False, epss_score=0.1)]
    results = store.evaluate("identity-service", "production", findings)

    assert results["status"] in {"missing_inputs", "partial"}
    assert results["matched_cases"] <= results["total_cases"]
    assert isinstance(results["failures"], list)


def test_compliance_evaluator_flags_high_risk():
    evaluator = ComplianceEvaluator()
    frameworks = ["PCI-DSS", "SOC2"]
    business_context = {
        "deployment_frequency": "daily",
        "data_classification": "restricted",
        "customer_impact": "high",
    }
    findings = [_sample_finding()]
    regression_results = {"validation_passed": True}

    results = evaluator.evaluate(frameworks, business_context, findings, regression_results)

    assert results["status"] == "evaluated"
    assert not results["overall_compliant"]
    assert "PCI-DSS" in results["frameworks"]
    assert results["frameworks"]["PCI-DSS"]["status"] == "fail"


def test_compliance_evaluator_passes_low_risk():
    evaluator = ComplianceEvaluator()
    frameworks = ["SOC2"]
    business_context = {
        "deployment_frequency": "monthly",
        "data_classification": "internal",
        "customer_impact": "low",
    }
    findings = [
        _sample_finding(
            cve="CVE-2024-1234",
            severity="LOW",
            kev_flag=False,
            epss_score=0.01,
            fix_available=True,
        )
    ]
    regression_results = {"validation_passed": True}

    results = evaluator.evaluate(frameworks, business_context, findings, regression_results)

    assert results["overall_compliant"]
    assert results["frameworks"]["SOC2"]["status"] == "pass"
