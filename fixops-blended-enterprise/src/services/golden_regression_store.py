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
