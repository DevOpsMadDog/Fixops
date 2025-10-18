# ruff: noqa: E402

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = ROOT / "enterprise"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from src.services.golden_regression_store import GoldenRegressionStore


class FakeDecisionEngine:
    def __init__(self, outcomes: dict[str, tuple[str, float]]) -> None:
        self.outcomes = outcomes
        self.seen_case_ids: list[str] = []
        self.initialized = False

    async def initialize(self) -> None:
        self.initialized = True

    async def make_decision(self, context):
        case_id = context.business_context.get("regression_case_id")
        self.seen_case_ids.append(case_id)
        outcome, confidence = self.outcomes[case_id]
        from types import SimpleNamespace

        return SimpleNamespace(
            decision=outcome,
            confidence_score=confidence,
            consensus_details={"mock": outcome},
            evidence_id=f"EVID-{case_id}",
            reasoning=f"mock reasoning for {case_id}",
            validation_results={"mock": True},
        )


def test_evaluate_with_mock_engine(tmp_path: Path) -> None:
    dataset = tmp_path / "cases.json"
    cases = [
        {
            "id": "case-block",
            "cve_id": "CVE-TEST-0001",
            "expected": {"decision": "BLOCK", "confidence": 0.9},
            "context": {
                "service_name": "payments-service",
                "environment": "production",
                "business_context": {"service_tier": "tier-0"},
                "security_findings": [{"source": "scanner", "severity": "CRITICAL"}],
            },
        },
        {
            "id": "case-allow",
            "cve_id": "CVE-TEST-0002",
            "expected": {"decision": "ALLOW", "confidence": 0.75},
            "context": {
                "service_name": "inventory-service",
                "environment": "staging",
                "business_context": {"service_tier": "tier-2"},
                "security_findings": [{"source": "sbom", "severity": "MEDIUM"}],
            },
        },
        {
            "id": "case-defer",
            "cve_id": "CVE-TEST-0003",
            "expected": {"decision": "BLOCK", "confidence": 0.85},
            "context": {
                "service_name": "auth-service",
                "environment": "production",
                "business_context": {"service_tier": "tier-1"},
                "security_findings": [{"source": "vendor", "severity": "HIGH"}],
            },
        },
    ]
    dataset.write_text(json.dumps(cases))

    store = GoldenRegressionStore(dataset_path=dataset)
    engine = FakeDecisionEngine(
        {
            "case-block": ("BLOCK", 0.95),
            "case-allow": ("ALLOW", 0.78),
            "case-defer": ("DEFER", 0.55),
        }
    )

    report = asyncio.run(store.evaluate(engine, initialize_engine=True))

    assert engine.initialized is True
    assert engine.seen_case_ids == ["case-block", "case-allow", "case-defer"]

    summary = report["summary"]
    assert summary["total_cases"] == 3
    assert summary["matches"] == 2
    assert summary["mismatches"] == 1

    cases_by_id = {case["case_id"]: case for case in report["cases"]}
    assert cases_by_id["case-block"]["match"] is True
    assert cases_by_id["case-allow"]["match"] is True

    defer_case = cases_by_id["case-defer"]
    assert defer_case["match"] is False
    assert defer_case["actual"]["decision"] == "DEFER"
    assert defer_case["expected"]["decision"] == "BLOCK"
    assert defer_case["delta"]["decision_changed"] is True
    assert defer_case["delta"]["confidence_delta"] == pytest.approx(-0.30, abs=1e-2)
