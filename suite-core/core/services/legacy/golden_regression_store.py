"""Golden regression dataset loader for regression validation tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional

try:  # pragma: no cover - structlog is optional in tests
    import structlog

    logger = structlog.get_logger(__name__)
except ModuleNotFoundError:  # pragma: no cover
    import logging

    logger = logging.getLogger(__name__)


@dataclass
class RegressionCase:
    case_id: str
    service_name: str
    cve_id: Optional[str]
    decision: str
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "RegressionCase":
        service_name = payload.get("service_name") or payload.get("context", {}).get(
            "service_name"
        )
        decision = payload.get("decision") or payload.get("expected", {}).get(
            "decision"
        )
        if not payload.get("case_id") or not service_name or decision is None:
            raise ValueError("Regression case missing required fields")

        decision_value = str(decision).strip().lower()
        decision_map = {
            "pass": "pass",
            "allow": "pass",
            "fail": "fail",
            "block": "fail",
            "reject": "fail",
            "defer": "fail",
        }
        try:
            normalised_decision = decision_map[decision_value]
        except KeyError as exc:
            raise ValueError(
                f"Unsupported regression decision '{decision_value}'"
            ) from exc

        confidence = float(payload.get("confidence") or 0.0)
        metadata = {
            key: value
            for key, value in payload.items()
            if key
            not in {
                "case_id",
                "service_name",
                "cve_id",
                "decision",
                "confidence",
                "timestamp",
            }
        }
        return cls(
            case_id=str(payload.get("case_id")),
            service_name=str(service_name),
            cve_id=payload.get("cve_id"),
            decision=normalised_decision,
            confidence=confidence,
            metadata=metadata,
        )

    def to_response(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "service_name": self.service_name,
            "cve_id": self.cve_id,
            "decision": self.decision,
            "confidence": self.confidence,
            **({"metadata": self.metadata} if self.metadata else {}),
        }


class GoldenRegressionStore:
    """Loads and indexes historical regression validation cases."""

    _instance: Optional["GoldenRegressionStore"] = None
    _lock: Lock = Lock()

    def __init__(self, dataset_path: Optional[Path] = None) -> None:
        self.dataset_path = dataset_path or self._default_dataset_path()
        self._cases_by_service: Dict[str, List[RegressionCase]] = {}
        self._cases_by_cve: Dict[str, List[RegressionCase]] = {}
        self._load_dataset()

    @classmethod
    def get_instance(
        cls, dataset_path: Optional[Path] = None
    ) -> "GoldenRegressionStore":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(dataset_path)
            elif dataset_path and Path(dataset_path) != cls._instance.dataset_path:
                cls._instance = cls(dataset_path)
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        with cls._lock:
            cls._instance = None

    def lookup_cases(
        self,
        service_name: Optional[str] = None,
        cve_ids: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        matched_cases: Dict[str, Dict[str, Any]] = {}
        service_match_count = 0
        cve_match_counts: Dict[str, int] = {}

        def _add_case(case: RegressionCase, match_type: str, match_value: str) -> None:
            context = {"type": match_type, "value": match_value}
            existing = matched_cases.get(case.case_id)
            if existing is None:
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

    def _load_dataset(self) -> None:
        self._cases_by_service.clear()
        self._cases_by_cve.clear()

        if not self.dataset_path.exists():
            logger.warning(
                "Golden regression dataset not found; coverage will be empty",
                path=str(self.dataset_path),
            )
            return

        try:
            raw = json.loads(self.dataset_path.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.error("Failed to load golden regression dataset", exc_info=exc)
            return

        cases_payload = raw.get("cases") if isinstance(raw, dict) else raw
        if not isinstance(cases_payload, list):
            logger.error(
                "Golden regression dataset is malformed", path=str(self.dataset_path)
            )
            return

        for entry in cases_payload:
            if not isinstance(entry, dict):
                continue
            case_data = dict(entry)
            case_data.setdefault("case_id", case_data.get("id"))
            try:
                case = RegressionCase.from_dict(case_data)
            except Exception:
                continue

            service_key = case.service_name.strip().lower()
            self._cases_by_service.setdefault(service_key, []).append(case)

            if case.cve_id:
                cve_key = str(case.cve_id).strip().lower()
                self._cases_by_cve.setdefault(cve_key, []).append(case)

        logger.info(
            "Golden regression dataset loaded",
            path=str(self.dataset_path),
            cases=sum(len(v) for v in self._cases_by_service.values()),
        )

    @staticmethod
    def _default_dataset_path() -> Path:
        repo_root = Path(__file__).resolve().parents[3]
        return repo_root / "data" / "golden_regression_cases.json"


__all__ = ["GoldenRegressionStore", "RegressionCase"]
