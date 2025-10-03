"""Golden regression lookup and evaluation utilities."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import structlog

logger = structlog.get_logger()


@dataclass
class RegressionCase:
    """A historic exploit scenario captured in the golden regression suite."""

    service: str
    environment: str
    cve_id: str
    expected_decision: str
    expected_confidence: float
    regression_suite: str
    exploit_window: str
    summary: str
    signals: Dict[str, Any]

    @property
    def key(self) -> Tuple[str, str]:
        return (self.service.lower(), self.environment.lower())


class GoldenRegressionStore:
    """Load and query golden regression cases for regression validation."""

    def __init__(self, dataset_path: Optional[Path] = None) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        default_path = repo_root / "data" / "feeds" / "golden_regression_cases.json"
        self._dataset_path = dataset_path or default_path
        self._cases: List[RegressionCase] = []
        self._index: Dict[Tuple[str, str], List[RegressionCase]] = {}
        self._load_dataset()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def evaluate(self, service_name: str, environment: str, findings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        """Return coverage metrics for the supplied context."""

        key = (service_name.lower(), environment.lower())
        cases = list(self._index.get(key, []))
        if not cases:
            return {
                "status": "no_coverage",
                "validation_passed": False,
                "confidence": 0.0,
                "total_cases": 0,
                "matched_cases": 0,
                "passed": 0,
                "failed": 0,
                "coverage_pct": 0.0,
                "failures": [
                    {
                        "reason": "no_golden_regression_cases",
                        "details": f"No regression cases available for {service_name} ({environment})",
                    }
                ],
            }

        findings_by_cve = self._index_findings(findings)
        matched_details: List[Dict[str, Any]] = []
        failures: List[Dict[str, Any]] = []
        passes = 0

        for case in cases:
            finding = findings_by_cve.get(case.cve_id.upper())
            if not finding:
                failures.append(
                    {
                        "reason": "missing_in_regression_input",
                        "cve_id": case.cve_id,
                        "regression_suite": case.regression_suite,
                        "summary": case.summary,
                    }
                )
                continue

            predicted_decision, score = self._predict_decision(finding)
            passed = predicted_decision == case.expected_decision.upper()
            if passed:
                passes += 1
            else:
                failures.append(
                    {
                        "reason": "decision_mismatch",
                        "cve_id": case.cve_id,
                        "expected": case.expected_decision,
                        "predicted": predicted_decision,
                        "heuristic_score": score,
                        "regression_suite": case.regression_suite,
                    }
                )

            matched_details.append(
                {
                    "cve_id": case.cve_id,
                    "expected": case.expected_decision,
                    "predicted": predicted_decision,
                    "heuristic_score": score,
                    "regression_suite": case.regression_suite,
                    "summary": case.summary,
                    "signals": case.signals,
                }
            )

        matched_cases = len(matched_details)
        total_cases = len(cases)
        coverage_pct = (matched_cases / total_cases * 100.0) if total_cases else 0.0
        validation_passed = passes == matched_cases and matched_cases > 0
        confidence = min(0.99, (passes / total_cases) if total_cases else 0.0)

        status = "validated" if validation_passed else "partial"
        if not matched_cases:
            status = "missing_inputs"

        return {
            "status": status,
            "validation_passed": validation_passed,
            "confidence": round(confidence, 2),
            "total_cases": total_cases,
            "matched_cases": matched_cases,
            "coverage_pct": round(coverage_pct, 1),
            "passed": passes,
            "failed": len(failures),
            "failures": failures,
            "matched_details": matched_details,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _load_dataset(self) -> None:
        if not self._dataset_path.exists():
            logger.warning("Golden regression dataset missing", path=str(self._dataset_path))
            return

        try:
            payload = json.loads(self._dataset_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive branch
            logger.error("Failed to parse golden regression dataset", error=str(exc))
            return

        raw_cases = payload.get("cases", [])
        for item in raw_cases:
            try:
                case = RegressionCase(
                    service=item["service"],
                    environment=item["environment"],
                    cve_id=item["cve_id"],
                    expected_decision=item.get("expected_decision", "BLOCK"),
                    expected_confidence=float(item.get("expected_confidence", 0.85)),
                    regression_suite=item.get("regression_suite", "unknown"),
                    exploit_window=item.get("exploit_window", "unknown"),
                    summary=item.get("summary", ""),
                    signals=item.get("signals", {}),
                )
            except KeyError as exc:  # pragma: no cover - dataset hygiene
                logger.warning("Skipping malformed regression case", missing=str(exc), raw=item)
                continue

            self._cases.append(case)
            self._index.setdefault(case.key, []).append(case)

        logger.info(
            "Loaded golden regression dataset",
            cases=len(self._cases),
            services=len({case.key for case in self._cases}),
        )

    @staticmethod
    def _index_findings(findings: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        index: Dict[str, Dict[str, Any]] = {}
        for finding in findings:
            cve = finding.get("cve") or finding.get("cve_id")
            if not cve:
                continue
            index[cve.upper()] = finding
        return index

    @staticmethod
    def _predict_decision(finding: Dict[str, Any]) -> Tuple[str, float]:
        """Derive a heuristic decision to compare against historical expectations."""

        severity = (finding.get("severity") or "medium").upper()
        kev = bool(finding.get("kev_flag") or finding.get("kev"))
        epss = float(finding.get("epss_score") or 0.0)
        fix_available = bool(finding.get("fix_available"))
        exploit_maturity = finding.get("exploit_maturity", "active")

        score = 0.0
        if severity in {"CRITICAL", "HIGH"}:
            score += 0.4
        if kev:
            score += 0.3
        if epss >= 0.5:
            score += 0.2
        if fix_available:
            score += 0.05
        if str(exploit_maturity).lower() in {"active", "widespread"}:
            score += 0.05

        decision = "BLOCK" if score >= 0.5 else "DEFER" if score >= 0.35 else "ALLOW"
        return decision, round(score, 2)


__all__ = ["GoldenRegressionStore", "RegressionCase"]
