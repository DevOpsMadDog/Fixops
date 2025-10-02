"""Integration layer for SARIF risk tooling."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

import structlog

logger = structlog.get_logger()


class SarifToolingAdapter:
    """Delegate clustering and scoring to SARIF utilities.

    The production environment relies on the ``sarif-toolkit`` package.  During
    tests we reuse a deterministic fallback that applies a light-weight scoring
    heuristic mirroring our previous in-house logic.
    """

    def __init__(self) -> None:
        self._tooling = self._load_tooling()

    def cluster_results(self, results: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return self._tooling.cluster_results(list(results))

    def score_cluster(self, cluster: Dict[str, Any]) -> float:
        return float(self._tooling.score_cluster(cluster))

    def score_finding(self, finding: Dict[str, Any]) -> float:
        return float(self._tooling.score_finding(finding))

    def _load_tooling(self):
        try:
            from sarif_toolkit import RiskToolkit  # type: ignore

            logger.info("✅ Loaded SARIF risk toolkit")
            return RiskToolkit()
        except Exception as exc:  # pragma: no cover - fallback used in tests
            logger.warning("SARIF toolkit unavailable, using fallback", exc_info=exc)
            return _FallbackSarifToolkit()


class _FallbackSarifToolkit:
    """Deterministic SARIF scoring heuristic used in tests."""

    def cluster_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        clusters: Dict[str, Dict[str, Any]] = {}
        for result in results:
            cwe = (result.get("cwe_id") or result.get("ruleId") or "uncategorised").lower()
            cluster = clusters.setdefault(
                cwe,
                {
                    "cluster_id": cwe,
                    "cwe_id": result.get("cwe_id"),
                    "findings": [],
                },
            )
            cluster["findings"].append(result)
        return list(clusters.values())

    def score_cluster(self, cluster: Dict[str, Any]) -> float:
        findings = cluster.get("findings", [])
        if not findings:
            return 0.0
        scores = [self.score_finding(finding) for finding in findings]
        return sum(scores) / len(scores)

    def score_finding(self, finding: Dict[str, Any]) -> float:
        base = {
            "error": 0.7,
            "warning": 0.5,
            "note": 0.3,
        }.get(str(finding.get("level", "warning")).lower(), 0.4)

        severity = str(finding.get("severity", "medium")).upper()
        severity_boost = {
            "CRITICAL": 0.9,
            "HIGH": 0.75,
            "MEDIUM": 0.55,
            "LOW": 0.35,
            "INFO": 0.2,
        }.get(severity, base)

        if finding.get("cve"):
            severity_boost += 0.05
        elif finding.get("cwe_id") or finding.get("owasp_category"):
            severity_boost += 0.1

        confidence = float(finding.get("confidence", 0.6))
        score = min(max((base + severity_boost) / 2 * confidence, 0.0), 1.0)
        return score

