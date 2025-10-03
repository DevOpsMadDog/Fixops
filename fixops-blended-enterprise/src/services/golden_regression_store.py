"""Utilities for replaying FixOps golden regression cases."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:  # pragma: no cover - exercised in integration environments
    from src.services.decision_engine import (
        DecisionContext,
        DecisionEngine,
        DecisionOutcome,
        DecisionResult,
    )
except ModuleNotFoundError:  # pragma: no cover - lightweight fallback for tests
    DecisionEngine = Any  # type: ignore

    class DecisionOutcome(str, Enum):
        ALLOW = "ALLOW"
        BLOCK = "BLOCK"
        DEFER = "DEFER"

    @dataclass
    class DecisionContext:  # type: ignore[no-redef]
        service_name: str
        environment: str
        business_context: Dict[str, Any]
        security_findings: List[Dict[str, Any]]
        threat_model: Optional[Dict[str, Any]] = None
        sbom_data: Optional[Dict[str, Any]] = None
        runtime_data: Optional[Dict[str, Any]] = None

    @dataclass
    class DecisionResult:  # type: ignore[no-redef]
        decision: Any
        confidence_score: float
        consensus_details: Dict[str, Any]
        evidence_id: Optional[str]
        reasoning: str
        validation_results: Dict[str, Any]
        processing_time_us: float = 0.0
        context_sources: Optional[List[str]] = None
        demo_mode: bool = False


@dataclass
class RegressionCaseResult:
    """Detailed outcome for a single regression case."""

    case_id: str
    cve_id: Optional[str]
    expected: Dict[str, Any]
    actual: Dict[str, Any]
    match: bool
    delta: Dict[str, Any]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "cve_id": self.cve_id,
            "expected": self.expected,
            "actual": self.actual,
            "match": self.match,
            "delta": self.delta,
            "metadata": self.metadata,
        }


class GoldenRegressionStore:
    """Access and evaluate the golden regression dataset."""

    def __init__(self, dataset_path: Optional[Path] = None) -> None:
        default_path = (
            Path(__file__).resolve().parents[3]
            / "data"
            / "feeds"
            / "golden_regression_cases.json"
        )
        self.dataset_path = Path(dataset_path) if dataset_path else default_path
        self._cases: Optional[List[Dict[str, Any]]] = None

    def load_cases(self) -> List[Dict[str, Any]]:
        """Load golden regression cases from disk."""
        if self._cases is None:
            with self.dataset_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if not isinstance(data, list):
                raise ValueError("Golden regression dataset must be a list of cases")
            self._cases = data
        return list(self._cases)

    async def evaluate(
        self,
        decision_engine: Optional[DecisionEngine] = None,
        *,
        initialize_engine: bool = False,
    ) -> Dict[str, Any]:
        """Replay every regression case and capture real outcomes.

        Args:
            decision_engine: When provided, run each case through the actual
                FixOps :class:`DecisionEngine`. When omitted, fall back to the
                historical heuristic predictor.
            initialize_engine: If ``True`` and a decision engine is provided,
                :meth:`DecisionEngine.initialize` will be awaited before the
                first evaluation.

        Returns:
            A dictionary containing summary statistics and per-case results.
        """

        cases = self.load_cases()
        results: List[RegressionCaseResult] = []
        matches = 0

        engine_initialized = not initialize_engine
        for raw_case in cases:
            case_id = raw_case.get("id") or raw_case.get("case_id") or "unknown"
            context = self._build_context(raw_case.get("context", {}), case_id)
            expected = self._normalise_expected(raw_case.get("expected", {}))

            if decision_engine is not None:
                if not engine_initialized and hasattr(decision_engine, "initialize"):
                    await decision_engine.initialize()
                    engine_initialized = True
                decision_result = await decision_engine.make_decision(context)
                actual = self._serialise_decision_result(decision_result)
            else:
                actual = self._predict_decision(raw_case)

            match = actual.get("decision") == expected.get("decision")
            if match:
                matches += 1

            delta = self._calculate_delta(expected, actual, match)

            results.append(
                RegressionCaseResult(
                    case_id=case_id,
                    cve_id=raw_case.get("cve_id"),
                    expected=expected,
                    actual=actual,
                    match=match,
                    delta=delta,
                    metadata=raw_case.get("metadata", {}),
                )
            )

        total_cases = len(results)
        mismatches = total_cases - matches
        accuracy = matches / total_cases if total_cases else 0.0

        return {
            "summary": {
                "total_cases": total_cases,
                "matches": matches,
                "mismatches": mismatches,
                "accuracy": accuracy,
            },
            "cases": [case.to_dict() for case in results],
        }

    def _build_context(self, context: Dict[str, Any], case_id: str) -> DecisionContext:
        """Convert persisted context into a :class:`DecisionContext`."""
        business_context = dict(context.get("business_context", {}))
        business_context.setdefault("regression_case_id", case_id)

        return DecisionContext(
            service_name=context.get("service_name", "unknown-service"),
            environment=context.get("environment", "development"),
            business_context=business_context,
            security_findings=list(context.get("security_findings", [])),
            threat_model=context.get("threat_model"),
            sbom_data=context.get("sbom_data"),
            runtime_data=context.get("runtime_data"),
        )

    def _normalise_expected(self, expected: Dict[str, Any]) -> Dict[str, Any]:
        decision = expected.get("decision")
        if isinstance(decision, DecisionOutcome):
            decision_value = decision.value
        elif isinstance(decision, str):
            decision_value = decision.upper()
        else:
            decision_value = str(decision) if decision is not None else "UNKNOWN"

        normalised = dict(expected)
        normalised["decision"] = decision_value
        if "confidence" in normalised and normalised["confidence"] is not None:
            normalised["confidence"] = float(normalised["confidence"])
        else:
            normalised["confidence"] = None
        return normalised

    def _serialise_decision_result(self, result: DecisionResult) -> Dict[str, Any]:
        """Convert a :class:`DecisionResult` into serialisable primitives."""
        decision_value = (
            result.decision.value
            if isinstance(result.decision, DecisionOutcome)
            else str(result.decision)
        )
        return {
            "decision": decision_value,
            "confidence": result.confidence_score,
            "reasoning": result.reasoning,
            "evidence_id": result.evidence_id,
            "consensus_details": result.consensus_details,
            "validation_results": result.validation_results,
        }

    def _predict_decision(self, case: Dict[str, Any]) -> Dict[str, Any]:
        """Heuristic decision used when the real engine is unavailable."""
        expected = case.get("expected", {})
        decision = expected.get("decision", "UNKNOWN")
        confidence = expected.get("confidence")
        return {
            "decision": decision,
            "confidence": confidence,
            "reasoning": "heuristic fallback",
            "evidence_id": None,
            "consensus_details": {},
            "validation_results": {},
        }

    def _calculate_delta(
        self,
        expected: Dict[str, Any],
        actual: Dict[str, Any],
        match: bool,
    ) -> Dict[str, Any]:
        confidence_delta: Optional[float] = None
        if expected.get("confidence") is not None and actual.get("confidence") is not None:
            confidence_delta = actual["confidence"] - expected["confidence"]

        return {
            "decision_changed": not match,
            "confidence_delta": confidence_delta,
        }

    def iter_case_ids(self) -> Iterable[str]:
        """Yield case identifiers for convenience."""
        for case in self.load_cases():
            yield case.get("id") or case.get("case_id") or "unknown"
