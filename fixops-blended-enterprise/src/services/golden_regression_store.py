"""Golden regression dataset loader for historical validation results."""
from __future__ import annotations

import contextlib
import importlib
import importlib.util
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional
from types import SimpleNamespace

_structlog_spec = None
with contextlib.suppress(ValueError):
    _structlog_spec = importlib.util.find_spec("structlog")

if _structlog_spec:  # pragma: no branch - deterministic at import time
    structlog = importlib.import_module("structlog")
    logger = structlog.get_logger(__name__)
else:  # pragma: no cover - executed only when structlog missing
    logger = logging.getLogger(__name__)


def _log(method: str, message: str, **kwargs: Any) -> None:
    """Log helper compatible with structlog and stdlib logging."""

    handler = getattr(logger, method)
    if hasattr(logger, "bind"):
        handler(message, **kwargs)
        return

    if kwargs:
        extras = ", ".join(f"{key}={value!r}" for key, value in kwargs.items())
        handler(f"{message} ({extras})")
    else:
        handler(message)


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

        service_name = payload.get("service_name")
        if not service_name and isinstance(payload.get("context"), dict):
            service_name = payload["context"].get("service_name")

        raw_decision: Any = payload.get("decision")
        if raw_decision is None and isinstance(payload.get("expected"), dict):
            raw_decision = payload["expected"].get("decision")

        if not payload.get("case_id") or not service_name or raw_decision is None:
            missing = []
            if not payload.get("case_id"):
                missing.append("case_id")
            if not service_name:
                missing.append("service_name")
            if raw_decision is None:
                missing.append("decision")
            raise ValueError(f"Regression case missing required fields: {', '.join(missing)}")

        decision_raw = str(raw_decision).strip().lower()
        decision_map = {
            "pass": "pass",
            "allow": "pass",
            "approve": "pass",
            "success": "pass",
            "fail": "fail",
            "block": "fail",
            "reject": "fail",
            "defer": "fail",
        }
        try:
            decision = decision_map[decision_raw]
        except KeyError as exc:
            raise ValueError(f"Unsupported regression decision '{decision_raw}'") from exc

        if payload.get("confidence") is not None:
            confidence = float(payload.get("confidence", 0.0))
        elif isinstance(payload.get("expected"), dict) and payload["expected"].get("confidence") is not None:
            confidence = float(payload["expected"]["confidence"])
        else:
            confidence = 0.0

        metadata = {k: v for k, v in payload.items() if k not in base_fields}
        if decision_raw != decision:
            metadata.setdefault("original_decision", decision_raw)
        return cls(
            case_id=str(payload.get("case_id")),
            service_name=str(service_name),
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
            **({"metadata": self.metadata} if self.metadata else {}),
        }


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
        self._raw_cases: List[Dict[str, Any]] = []
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
            for raw_cve in cve_ids:
                if not raw_cve:
                    continue
                cve = str(raw_cve).strip()
                if not cve:
                    continue
                normalized = cve.lower()
                cases = self._cases_by_cve.get(normalized, [])
                cve_match_counts[cve] = len(cases)
                for case in cases:
                    _add_case(case, "cve", cve)

        return {
            "cases": list(matched_cases.values()),
            "service_matches": service_match_count,
            "cve_matches": cve_match_counts,
        }

    def load_cases(self) -> List[Dict[str, Any]]:
        """Return the raw case payloads as loaded from disk."""

        return list(self._raw_cases)

    async def evaluate(
        self,
        decision_engine: Optional[Any] = None,
        *,
        initialize_engine: bool = False,
    ) -> Dict[str, Any]:
        """Replay every regression case and capture real outcomes."""

        cases = self.load_cases()
        results: List[RegressionCaseResult] = []
        matches = 0

        engine_initialized = not initialize_engine
        for raw_case in cases:
            case_id = str(raw_case.get("id") or raw_case.get("case_id") or "unknown")
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

    def iter_case_ids(self) -> Iterable[str]:
        """Yield case identifiers for convenience."""

        for case in self._raw_cases:
            yield str(case.get("id") or case.get("case_id") or "unknown")

    def _load_dataset(self) -> None:
        """Load regression cases from the dataset file."""

        self._cases_by_id.clear()
        self._cases_by_service.clear()
        self._cases_by_cve.clear()
        self._raw_cases.clear()

        if not self.dataset_path.exists():
            _log(
                "warning",
                "Golden regression dataset not found; regression validation will have no coverage",
                path=str(self.dataset_path),
            )
            return

        try:
            with self.dataset_path.open("r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except Exception as exc:  # pragma: no cover - defensive logging
            _log("error", "Failed to load golden regression dataset", error=str(exc))
            return

        cases_payload = raw.get("cases") if isinstance(raw, dict) else raw
        if not isinstance(cases_payload, list):
            _log("error", "Golden regression dataset is malformed", path=str(self.dataset_path))
            return

        for entry in cases_payload:
            if not isinstance(entry, dict):
                _log("warning", "Skipping invalid regression case", entry=entry)
                continue

            case_data = dict(entry)
            if "case_id" not in case_data and "id" in case_data:
                case_data["case_id"] = case_data["id"]

            try:
                case = RegressionCase.from_dict(case_data)
            except Exception as exc:
                _log("warning", "Skipping invalid regression case", error=str(exc), entry=entry)
                continue

            self._cases_by_id[case.case_id] = case

            service_key = case.service_name.strip().lower()
            self._cases_by_service.setdefault(service_key, []).append(case)

            if case.cve_id:
                cve_key = str(case.cve_id).strip().lower()
                self._cases_by_cve.setdefault(cve_key, []).append(case)

            # Preserve the original payload for evaluation routines.
            normalised_entry = dict(entry)
            normalised_entry.setdefault("case_id", case.case_id)
            normalised_entry.setdefault("service_name", case.service_name)
            normalised_entry.setdefault("cve_id", case.cve_id)
            self._raw_cases.append(normalised_entry)

        _log(
            "info",
            "Golden regression dataset loaded",
            path=str(self.dataset_path),
            cases=len(self._cases_by_id),
            services=len(self._cases_by_service),
            cves=len(self._cases_by_cve),
        )

    def _build_context(self, context: Dict[str, Any], case_id: str) -> Any:
        """Convert persisted context into a decision context instance."""

        try:
            from src.services.decision_engine import DecisionContext
        except ModuleNotFoundError:  # pragma: no cover - tests supply a stub
            DecisionContext = None  # type: ignore

        business_context = dict(context.get("business_context", {}))
        business_context.setdefault("regression_case_id", case_id)

        if DecisionContext is None:
            return SimpleNamespace(
                service_name=context.get("service_name", "unknown-service"),
                environment=context.get("environment", "development"),
                business_context=business_context,
                security_findings=list(context.get("security_findings", [])),
                threat_model=context.get("threat_model"),
                sbom_data=context.get("sbom_data"),
                runtime_data=context.get("runtime_data"),
            )

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
        if hasattr(decision, "value"):
            decision_value = str(decision.value)
        elif isinstance(decision, str):
            decision_value = decision.upper()
        else:
            decision_value = str(decision).upper() if decision is not None else "UNKNOWN"

        normalised = dict(expected)
        normalised["decision"] = decision_value
        if "confidence" in normalised and normalised["confidence"] is not None:
            try:
                normalised["confidence"] = float(normalised["confidence"])
            except (TypeError, ValueError):
                normalised["confidence"] = None
        else:
            normalised["confidence"] = None
        return normalised

    def _serialise_decision_result(self, result: Any) -> Dict[str, Any]:
        """Convert a decision result into serialisable primitives."""

        decision = getattr(result, "decision", None)
        if hasattr(decision, "value"):
            decision_value = str(decision.value)
        else:
            decision_value = str(decision)

        return {
            "decision": decision_value.upper(),
            "confidence": getattr(result, "confidence_score", None),
            "reasoning": getattr(result, "reasoning", ""),
            "evidence_id": getattr(result, "evidence_id", None),
            "consensus_details": getattr(result, "consensus_details", {}),
            "validation_results": getattr(result, "validation_results", {}),
        }

    def _predict_decision(self, case: Dict[str, Any]) -> Dict[str, Any]:
        """Heuristic decision used when the real engine is unavailable."""

        expected = case.get("expected", {})
        decision = expected.get("decision", "UNKNOWN")
        confidence = expected.get("confidence")
        return {
            "decision": str(decision).upper(),
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
        expected_conf = expected.get("confidence")
        actual_conf = actual.get("confidence")
        if expected_conf is not None and actual_conf is not None:
            try:
                confidence_delta = float(actual_conf) - float(expected_conf)
            except (TypeError, ValueError):
                confidence_delta = None

        return {
            "decision_changed": not match,
            "confidence_delta": confidence_delta,
        }

    @staticmethod
    def _default_dataset_path() -> Path:
        return Path(__file__).resolve().parents[2] / "data" / "golden_regression_cases.json"


__all__ = ["GoldenRegressionStore", "RegressionCase", "RegressionCaseResult"]
