import sys
from pathlib import Path

import pytest
import types

if "structlog" not in sys.modules:
    class _StubLogger:
        def info(self, *args, **kwargs):
            pass

        def warning(self, *args, **kwargs):
            pass

        def error(self, *args, **kwargs):
            pass

        def debug(self, *args, **kwargs):
            pass

    sys.modules["structlog"] = types.SimpleNamespace(get_logger=lambda: _StubLogger())

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXOPS_ROOT = REPO_ROOT / "fixops-blended-enterprise"
if str(FIXOPS_ROOT) not in sys.path:
    sys.path.insert(0, str(FIXOPS_ROOT))

from src.services.risk_scorer import ContextualRiskScorer  # noqa: E402
from src.services.compliance_engine import ComplianceEngine  # noqa: E402


@pytest.fixture()
def scorer() -> ContextualRiskScorer:
    return ContextualRiskScorer()


def test_contextual_risk_scorer_downgrades_low_impact(scorer: ContextualRiskScorer) -> None:
    findings = [
        {
            "id": "CVE-LOW-1",
            "severity": "critical",
        }
    ]
    business_context = {
        "customer_impact": "low",
        "data_classification": ["public"],
        "deployment_frequency": "quarterly",
    }

    adjusted = scorer.apply(findings, business_context)
    assert adjusted[0]["scanner_severity"] == "CRITICAL"
    assert adjusted[0]["fixops_severity"] == "HIGH"
    assert adjusted[0]["risk_adjustment"] == -1


def test_contextual_risk_scorer_upgrades_high_impact(scorer: ContextualRiskScorer) -> None:
    findings = [
        {
            "id": "CVE-HIGH-1",
            "severity": "medium",
        }
    ]
    business_context = {
        "customer_impact": "mission_critical",
        "data_classification": ["pii", "financial"],
        "deployment_frequency": "continuous",
    }

    adjusted = scorer.apply(findings, business_context)
    assert adjusted[0]["scanner_severity"] == "MEDIUM"
    assert adjusted[0]["fixops_severity"] == "HIGH"
    assert adjusted[0]["risk_adjustment"] == 1


def test_compliance_engine_uses_adjusted_severity() -> None:
    engine = ComplianceEngine()
    findings = [
        {
            "id": "CVE-0001",
            "scanner_severity": "low",
            "fixops_severity": "critical",
            "risk_adjustment": 2,
        }
    ]

    result = engine._evaluate_framework("pci_dss", findings, {})
    assert result["status"] == "non_compliant"
    assert result["highest_scanner_severity"] == "LOW"
    assert result["highest_fixops_severity"] == "CRITICAL"
    assert result["findings"][0]["scanner_severity"] == "LOW"
    assert result["findings"][0]["fixops_severity"] == "CRITICAL"
