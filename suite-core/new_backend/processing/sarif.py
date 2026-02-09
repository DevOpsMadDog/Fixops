"""SARIF analyzer for security scan results."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List


class SarifAnalyzer:
    """Analyzer for SARIF format security scan results."""

    def __init__(self) -> None:
        pass

    def _generate_result_id(self, result: Dict[str, Any], run_index: int) -> str:
        """Generate a unique ID for a result."""
        rule_id = result.get("ruleId", "unknown")
        message = result.get("message", {}).get("text", "")
        locations = result.get("locations", [])
        location_str = ""
        if locations:
            loc = locations[0].get("physicalLocation", {})
            artifact = loc.get("artifactLocation", {}).get("uri", "")
            region = loc.get("region", {})
            line = region.get("startLine", 0)
            location_str = f"{artifact}:{line}"

        hash_input = f"{run_index}:{rule_id}:{message}:{location_str}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    def _calculate_probability(
        self, result: Dict[str, Any], run: Dict[str, Any]
    ) -> float:
        """Calculate exploitation probability for a result."""
        try:
            from sarif.sarif_file_utils import read_result_severity

            severity = read_result_severity(result, run)
        except ImportError:
            severity = result.get("level", "warning")

        severity_scores = {
            "error": 0.8,
            "warning": 0.5,
            "note": 0.3,
            "none": 0.1,
        }
        return severity_scores.get(severity, 0.5)

    def analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a SARIF payload.

        Args:
            payload: SARIF format payload with runs and results

        Returns:
            Analysis report with clusters, severity breakdown, and probabilities
        """
        runs = payload.get("runs", [])
        all_results = []
        severity_breakdown: Dict[str, int] = {}
        clusters: List[Dict[str, Any]] = []
        probabilities: Dict[str, float] = {}

        for run_index, run in enumerate(runs):
            results = run.get("results", [])
            for result in results:
                result_id = self._generate_result_id(result, run_index)

                # Get severity
                try:
                    from sarif.sarif_file_utils import read_result_severity

                    severity = read_result_severity(result, run)
                except ImportError:
                    severity = result.get("level", "warning")

                severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1

                # Calculate probability
                prob = self._calculate_probability(result, run)
                probabilities[result_id] = prob

                # Extract location info
                locations = result.get("locations", [])
                location_info = {}
                if locations:
                    loc = locations[0].get("physicalLocation", {})
                    location_info = {
                        "uri": loc.get("artifactLocation", {}).get("uri", ""),
                        "line": loc.get("region", {}).get("startLine", 0),
                    }

                result_entry = {
                    "id": result_id,
                    "rule_id": result.get("ruleId", "unknown"),
                    "severity": severity,
                    "message": result.get("message", {}).get("text", ""),
                    "location": location_info,
                }
                all_results.append(result_entry)

        # Cluster results by rule_id
        rule_clusters: Dict[str, List[Dict[str, Any]]] = {}
        for result in all_results:
            rule_id = result["rule_id"]
            if rule_id not in rule_clusters:
                rule_clusters[rule_id] = []
            rule_clusters[rule_id].append(result)

        for rule_id, results in rule_clusters.items():
            clusters.append(
                {
                    "rule_id": rule_id,
                    "count": len(results),
                    "results": results,
                }
            )

        return {
            "result_count": len(all_results),
            "severity_breakdown": severity_breakdown,
            "clusters": clusters,
            "probabilities": probabilities,
        }


__all__ = ["SarifAnalyzer"]
