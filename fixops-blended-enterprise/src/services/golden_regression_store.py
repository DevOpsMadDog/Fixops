"""Golden regression dataset loader for historical validation results."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class RegressionCase:
    """Represents a single historical regression validation case."""

    case_id: str
    service_name: str
    cve_id: Optional[str]
    decision: str
    confidence: float
    timestamp: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "RegressionCase":
        """Create a regression case from a raw payload."""
        base_fields = {
            "case_id",
            "service_name",
            "cve_id",
            "decision",
            "confidence",
            "timestamp",
        }

        missing = [field for field in ("case_id", "service_name", "decision") if not payload.get(field)]
        if missing:
            raise ValueError(f"Regression case missing required fields: {', '.join(missing)}")

        decision = str(payload.get("decision", "")).strip().lower()
        if decision not in {"pass", "fail"}:
            raise ValueError(f"Unsupported regression decision '{decision}'")

        metadata = {k: v for k, v in payload.items() if k not in base_fields}
        confidence = float(payload.get("confidence", 0.0))
        return cls(
            case_id=str(payload.get("case_id")),
            service_name=str(payload.get("service_name")),
            cve_id=payload.get("cve_id"),
            decision=decision,
            confidence=confidence,
            timestamp=payload.get("timestamp"),
            metadata=metadata,
        )

    def to_response(self) -> Dict[str, Any]:
        """Convert to a serializable representation for API responses."""
        return {
            "case_id": self.case_id,
            "service_name": self.service_name,
            "cve_id": self.cve_id,
            "decision": self.decision,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
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
    """Loads and queries historical regression validation cases."""

    _instance: Optional["GoldenRegressionStore"] = None
    _lock: Lock = Lock()

    def __init__(self, dataset_path: Optional[Path] = None) -> None:
        self.dataset_path = Path(dataset_path) if dataset_path else self._default_dataset_path()
        self._cases_by_id: Dict[str, RegressionCase] = {}
        self._cases_by_service: Dict[str, List[RegressionCase]] = {}
        self._cases_by_cve: Dict[str, List[RegressionCase]] = {}
        self._load_dataset()

    @classmethod
    def get_instance(cls, dataset_path: Optional[Path] = None) -> "GoldenRegressionStore":
        """Return a singleton instance, reloading if a new dataset path is provided."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(dataset_path)
            elif dataset_path and Path(dataset_path) != cls._instance.dataset_path:
                cls._instance = cls(dataset_path)
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (useful for tests)."""
        with cls._lock:
            cls._instance = None

    def lookup_cases(
        self,
        service_name: Optional[str] = None,
        cve_ids: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Return cases that match the provided service or CVE identifiers."""
        matched_cases: Dict[str, Dict[str, Any]] = {}
        service_match_count = 0
        cve_match_counts: Dict[str, int] = {}

        def _add_case(case: RegressionCase, match_type: str, match_value: str) -> None:
            context = {"type": match_type, "value": match_value}
            existing = matched_cases.get(case.case_id)
            if not existing:
                record = case.to_response()
                record["match_context"] = [context]
                matched_cases[case.case_id] = record
            else:
                contexts = existing.setdefault("match_context", [])
                if context not in contexts:
                    contexts.append(context)

        if service_name:
            key = service_name.strip().lower()
            for case in self._cases_by_service.get(key, []):
                service_match_count += 1
                _add_case(case, "service", service_name)

        if cve_ids:
            for cve in cve_ids:
                if not cve:
                    continue
                normalized = cve.strip().lower()
                cases = self._cases_by_cve.get(normalized, [])
                cve_match_counts[cve] = len(cases)
                for case in cases:
                    _add_case(case, "cve", cve)

        return {
            "cases": list(matched_cases.values()),
            "service_matches": service_match_count,
            "cve_matches": cve_match_counts,
        }

    def _load_dataset(self) -> None:
        """Load regression cases from the dataset file."""
        self._cases_by_id.clear()
        self._cases_by_service.clear()
        self._cases_by_cve.clear()

        if not self.dataset_path.exists():
            logger.warning(
                "Golden regression dataset not found; regression validation will have no coverage",
                path=str(self.dataset_path),
            )
            return

        try:
            with self.dataset_path.open("r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except Exception as exc:
            logger.error("Failed to load golden regression dataset", error=str(exc))
            return

        cases_payload = raw.get("cases") if isinstance(raw, dict) else raw
        if not isinstance(cases_payload, list):
            logger.error("Golden regression dataset is malformed", path=str(self.dataset_path))
            return

        for entry in cases_payload:
            try:
                case = RegressionCase.from_dict(entry)
            except Exception as exc:
                logger.warning("Skipping invalid regression case", error=str(exc), entry=entry)
                continue

            self._cases_by_id[case.case_id] = case

            service_key = case.service_name.strip().lower()
            self._cases_by_service.setdefault(service_key, []).append(case)

            if case.cve_id:
                cve_key = str(case.cve_id).strip().lower()
                self._cases_by_cve.setdefault(cve_key, []).append(case)

        logger.info(
            "Golden regression dataset loaded",
            path=str(self.dataset_path),
            cases=len(self._cases_by_id),
            services=len(self._cases_by_service),
            cves=len(self._cases_by_cve),
        )

    @staticmethod
    def _default_dataset_path() -> Path:
        return Path(__file__).resolve().parents[2] / "data" / "golden_regression_cases.json"


__all__ = ["GoldenRegressionStore", "RegressionCase"]
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
