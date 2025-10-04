"""SARIF analysis utilities using sarif-om and sarif-tools."""

from __future__ import annotations

import importlib
import json
import logging
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)


class SarifAnalysisError(RuntimeError):
    """Raised when SARIF processing fails."""


def _import_sarif_utils() -> Any:
    try:
        return importlib.import_module("sarif.sarif_file_utils")
    except ModuleNotFoundError as exc:  # pragma: no cover - helpful message in real runtimes
        raise SarifAnalysisError("sarif-tools is not installed") from exc


class SarifAnalyzer:
    """High-level SARIF analysis pipeline leveraging ecosystem utilities."""

    def __init__(
        self,
        *,
        loader: Optional[Callable[[Any], Any]] = None,
        clusterer: Optional[Callable[[Sequence[Dict[str, Any]]], Sequence[Dict[str, Any]]]] = None,
        probability_estimator: Optional[Callable[[Sequence[Dict[str, Any]]], Mapping[str, float]]] = None,
    ) -> None:
        self._loader = loader or self._default_loader
        self._clusterer = clusterer or self._default_clusterer
        self._probability_estimator = probability_estimator or self._default_probability_estimator

    def analyse(self, sarif_payload: Any) -> Dict[str, Any]:
        """Parse, cluster and score SARIF findings."""

        log_object = self._load_log(sarif_payload)
        results = self._extract_results(log_object)
        clusters = list(self._clusterer(results))
        probability_map = dict(self._probability_estimator(results))
        severity_breakdown = self._severity_breakdown(results)
        return {
            "result_count": len(results),
            "clusters": clusters,
            "probabilities": probability_map,
            "severity_breakdown": severity_breakdown,
        }

    def analyze(self, sarif_payload: Any) -> Dict[str, Any]:
        """US English alias for :meth:`analyse`."""

        return self.analyse(sarif_payload)

    # ------------------------------------------------------------------
    # Loader utilities
    # ------------------------------------------------------------------
    def _default_loader(self, payload: Any) -> Any:
        if hasattr(payload, "read"):
            payload = payload.read()
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8")
        if isinstance(payload, str):
            try:
                candidate = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise SarifAnalysisError("SARIF payload is not valid JSON") from exc
        else:
            candidate = payload

        if isinstance(candidate, Mapping):
            return candidate

        sarif_om = importlib.import_module("sarif_om")
        if hasattr(candidate, "__class__") and candidate.__class__.__name__ == "SarifLog":
            return candidate
        if isinstance(candidate, Mapping):  # pragma: no cover - handled earlier
            return candidate
        if hasattr(sarif_om, "SarifLog") and hasattr(sarif_om.SarifLog, "from_dict"):
            return sarif_om.SarifLog.from_dict(candidate)
        raise SarifAnalysisError("Unsupported SARIF payload type")

    def _load_log(self, payload: Any) -> Any:
        try:
            return self._loader(payload)
        except SarifAnalysisError:
            raise
        except Exception as exc:  # pragma: no cover - defensive guard
            raise SarifAnalysisError("Failed to load SARIF payload") from exc

    # ------------------------------------------------------------------
    # Result extraction
    # ------------------------------------------------------------------
    def _extract_results(self, log_object: Any) -> List[Dict[str, Any]]:
        log_dict = self._to_dict(log_object)
        utils_module = _import_sarif_utils()
        runs = log_dict.get("runs", [])
        normalised: List[Dict[str, Any]] = []
        for run_index, run in enumerate(runs):
            run_dict = self._ensure_dict(run)
            for result_index, result in enumerate(run_dict.get("results", []) or []):
                result_dict = self._ensure_dict(result)
                severity = utils_module.read_result_severity(result_dict, run_dict)
                rule_id = result_dict.get("ruleId") or result_dict.get("rule", {}).get("id")
                location = self._normalise_location(result_dict)
                message = self._extract_message(result_dict)
                result_id = self._resolve_result_identifier(result_dict, run_index, result_index)
                normalised.append(
                    {
                        "id": result_id,
                        "rule_id": rule_id,
                        "severity": severity,
                        "location": location,
                        "description": message,
                        "raw_result": result_dict,
                        "run": run_dict,
                    }
                )
        return normalised

    def _to_dict(self, payload: Any) -> Dict[str, Any]:
        if isinstance(payload, Mapping):
            return dict(payload)
        if hasattr(payload, "to_dict") and callable(payload.to_dict):
            return payload.to_dict()
        if hasattr(payload, "__dict__"):
            return json.loads(json.dumps(payload, default=lambda obj: getattr(obj, "__dict__", str(obj))))
        raise SarifAnalysisError("Unable to convert SARIF log to dictionary")

    def _ensure_dict(self, value: Any) -> Dict[str, Any]:
        if isinstance(value, Mapping):
            return dict(value)
        if hasattr(value, "to_dict") and callable(value.to_dict):
            return value.to_dict()
        if hasattr(value, "__dict__"):
            extracted: Dict[str, Any] = {}
            for key in dir(value):
                if key.startswith("_"):
                    continue
                try:
                    attr_value = getattr(value, key)
                except AttributeError:  # pragma: no cover - defensive guard
                    continue
                if callable(attr_value):
                    continue
                extracted[key] = attr_value
            return extracted
        raise SarifAnalysisError("Expected mapping-like SARIF structure")

    def _normalise_location(self, result: Mapping[str, Any]) -> Optional[str]:
        locations = result.get("locations") or []
        if not locations:
            return None
        location = self._ensure_dict(locations[0])
        physical = self._ensure_dict(location.get("physicalLocation", {}))
        artifact = self._ensure_dict(physical.get("artifactLocation", {}))
        region = self._ensure_dict(physical.get("region", {}))
        file_path = artifact.get("uri") or artifact.get("uriBaseId")
        start_line = region.get("startLine")
        if file_path and start_line:
            return f"{file_path}:{start_line}"
        return file_path or None

    def _extract_message(self, result: Mapping[str, Any]) -> Optional[str]:
        message = result.get("message")
        if isinstance(message, Mapping):
            for key in ("text", "markdown", "id"):
                if key in message:
                    return str(message[key])
        if isinstance(message, str):
            return message
        return None

    def _resolve_result_identifier(
        self, result: Mapping[str, Any], run_index: int, result_index: int
    ) -> str:
        fingerprints = result.get("fingerprints")
        if isinstance(fingerprints, Mapping):
            for key in ("primary", "unique", "stable"):
                if key in fingerprints:
                    return str(fingerprints[key])
        partial_fingerprint = result.get("partialFingerprints")
        if isinstance(partial_fingerprint, Mapping):
            for value in partial_fingerprint.values():
                return str(value)
        return f"run-{run_index}-result-{result_index}"

    # ------------------------------------------------------------------
    # Clustering and probability inference
    # ------------------------------------------------------------------
    def _default_clusterer(self, results: Sequence[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
        utils_module = _import_sarif_utils()
        clusters: Dict[str, Dict[str, Any]] = {}
        for result in results:
            rule_id = result.get("rule_id", "unknown") or "unknown"
            description = result.get("description") or ""
            cluster_key = utils_module.combine_code_and_description(rule_id, description)
            cluster = clusters.setdefault(
                cluster_key,
                {"key": cluster_key, "rule_id": rule_id, "results": []},
            )
            cluster["results"].append(result)
        return clusters.values()

    def _default_probability_estimator(
        self, results: Sequence[Dict[str, Any]]
    ) -> Mapping[str, float]:
        utils_module = _import_sarif_utils()
        severities = list(getattr(utils_module, "SARIF_SEVERITIES_WITH_NONE", ["error", "warning", "note", "none"]))
        severity_weights = {
            severity: (len(severities) - index) / float(len(severities))
            for index, severity in enumerate(severities)
        }
        probability: Dict[str, float] = {}
        for result in results:
            severity = result.get("severity", "none")
            weight = severity_weights.get(severity, 0.1)
            location_bonus = 0.1 if result.get("location") else 0.0
            description_bonus = 0.1 if result.get("description") else 0.0
            probability[result["id"]] = min(1.0, weight + location_bonus + description_bonus)
        return probability

    def _severity_breakdown(self, results: Sequence[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for result in results:
            severity = result.get("severity", "none")
            counts[severity] = counts.get(severity, 0) + 1
        return counts
