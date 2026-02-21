"""LLM hallucination guards for enhanced decision engine."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)


def validate_input_citation(
    llm_response: str,
    input_context: Mapping[str, Any],
    required_fields: Optional[List[str]] = None,
) -> tuple[bool, List[str]]:
    """Validate that LLM response cites input fields correctly.

    Parameters
    ----------
    llm_response:
        LLM response text.
    input_context:
        Input context provided to LLM.
    required_fields:
        Optional list of required fields that must be cited.

    Returns
    -------
    tuple[bool, List[str]]
        Validation result and list of issues found.
    """
    issues: List[str] = []
    required_fields = required_fields or []

    for field in required_fields:
        field_value = input_context.get(field)
        if field_value is None:
            continue

        field_str = str(field_value)

        if field_str not in llm_response and field not in llm_response:
            issues.append(f"Required field '{field}' not cited in response")

    response_numbers = re.findall(r"\b\d+\.?\d*\b", llm_response)
    input_numbers = set()
    for value in _flatten_dict(input_context):
        if isinstance(value, (int, float)):
            input_numbers.add(str(value))
        elif isinstance(value, str):
            input_numbers.update(re.findall(r"\b\d+\.?\d*\b", value))

    for num in response_numbers:
        if num not in input_numbers:
            if num not in ("0", "1", "100", "0.0", "1.0"):
                issues.append(f"Numeric value '{num}' in response not found in input")

    is_valid = len(issues) == 0
    return is_valid, issues


def validate_cross_model_agreement(
    analyses: Sequence[Mapping[str, Any]],
    disagreement_threshold: float = 0.3,
) -> tuple[bool, float, List[str]]:
    """Validate cross-model agreement to detect hallucinations.

    Parameters
    ----------
    analyses:
        List of individual model analyses.
    disagreement_threshold:
        Maximum allowed disagreement ratio (0.0 to 1.0).

    Returns
    -------
    tuple[bool, float, List[str]]
        Validation result, disagreement score, and list of issues.
    """
    issues: List[str] = []

    if len(analyses) < 2:
        return True, 0.0, []

    actions = [
        str(analysis.get("recommended_action", "")).lower()
        for analysis in analyses
        if isinstance(analysis, Mapping)
    ]
    action_counts: Dict[str, int] = {}
    for action in actions:
        action_counts[action] = action_counts.get(action, 0) + 1

    if len(action_counts) > 1:
        max_count = max(action_counts.values())
        disagreement_ratio = 1.0 - (max_count / len(actions))

        if disagreement_ratio > disagreement_threshold:
            issues.append(
                f"High action disagreement: {disagreement_ratio:.2f} "
                f"(threshold: {disagreement_threshold})"
            )

    confidences = [
        float(analysis.get("confidence", 0))
        for analysis in analyses
        if isinstance(analysis, Mapping) and analysis.get("confidence") is not None
    ]

    if len(confidences) >= 2:
        max_conf = max(confidences)
        min_conf = min(confidences)
        conf_spread = max_conf - min_conf

        if conf_spread > 0.3:
            issues.append(
                f"High confidence spread: {conf_spread:.2f} "
                f"(max: {max_conf:.2f}, min: {min_conf:.2f})"
            )

    disagreement_score = 0.0
    if len(action_counts) > 1:
        max_count = max(action_counts.values())
        disagreement_score = 1.0 - (max_count / len(actions))

    is_valid = len(issues) == 0
    return is_valid, disagreement_score, issues


def validate_numeric_consistency(
    llm_response: str,
    computed_values: Mapping[str, float],
    tolerance: float = 0.05,
) -> tuple[bool, List[str]]:
    """Validate numeric consistency between LLM response and computed values.

    Parameters
    ----------
    llm_response:
        LLM response text.
    computed_values:
        Mapping of metric names to computed values.
    tolerance:
        Tolerance for numeric differences (0.0 to 1.0).

    Returns
    -------
    tuple[bool, List[str]]
        Validation result and list of issues found.
    """
    issues: List[str] = []

    for metric_name, computed_value in computed_values.items():
        if metric_name not in llm_response:
            continue

        pattern = rf"{re.escape(metric_name)}[:\s]+(\d+\.?\d*)"
        matches = re.findall(pattern, llm_response, re.IGNORECASE)

        for match in matches:
            try:
                response_value = float(match)
                diff = abs(response_value - computed_value)
                relative_diff = diff / max(computed_value, 0.01)

                if relative_diff > tolerance:
                    issues.append(
                        f"Numeric inconsistency for '{metric_name}': "
                        f"response={response_value}, computed={computed_value:.3f}, "
                        f"diff={relative_diff:.2%}"
                    )
            except ValueError:
                continue

    is_valid = len(issues) == 0
    return is_valid, issues


def apply_hallucination_guards(
    llm_result: Mapping[str, Any],
    input_context: Mapping[str, Any],
    computed_metrics: Optional[Mapping[str, float]] = None,
    config: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Apply all hallucination guards to LLM result.

    Parameters
    ----------
    llm_result:
        LLM analysis result.
    input_context:
        Input context provided to LLM.
    computed_metrics:
        Optional computed metrics for validation.
    config:
        Optional configuration for guard thresholds.

    Returns
    -------
    Dict[str, Any]
        Validation results with confidence adjustments.
    """
    config = config or {}
    computed_metrics = computed_metrics or {}

    disagreement_threshold = float(config.get("disagreement_threshold", 0.3))
    numeric_tolerance = float(config.get("numeric_tolerance", 0.05))
    confidence_penalty = float(config.get("confidence_penalty", 0.15))

    result: Dict[str, Any] = {
        "original_confidence": llm_result.get("consensus_confidence", 0.0),
        "adjusted_confidence": llm_result.get("consensus_confidence", 0.0),
        "guards_applied": [],
        "issues_found": [],
        "validation_passed": True,
    }

    summary = llm_result.get("summary", "")
    required_fields = ["highest_severity", "service_name"]
    citation_valid, citation_issues = validate_input_citation(
        summary,
        input_context,
        required_fields,
    )

    result["guards_applied"].append("input_citation")
    if not citation_valid:
        result["issues_found"].extend(citation_issues)
        result["validation_passed"] = False
        result["adjusted_confidence"] *= 1.0 - confidence_penalty
        logger.warning(
            "Input citation validation failed: %d issues found",
            len(citation_issues),
        )

    analyses = llm_result.get("individual_analyses", [])
    (
        agreement_valid,
        disagreement_score,
        agreement_issues,
    ) = validate_cross_model_agreement(
        analyses,
        disagreement_threshold,
    )

    result["guards_applied"].append("cross_model_agreement")
    result["disagreement_score"] = disagreement_score
    if not agreement_valid:
        result["issues_found"].extend(agreement_issues)
        result["validation_passed"] = False

        if disagreement_threshold == 0.0:
            if disagreement_score > 0:
                penalty = confidence_penalty
            else:
                penalty = 0.0
        else:
            penalty = confidence_penalty * (disagreement_score / disagreement_threshold)

        result["adjusted_confidence"] *= 1.0 - penalty
        logger.warning(
            "Cross-model agreement validation failed: disagreement=%.2f",
            disagreement_score,
        )

    if computed_metrics:
        numeric_valid, numeric_issues = validate_numeric_consistency(
            summary,
            computed_metrics,
            numeric_tolerance,
        )

        result["guards_applied"].append("numeric_consistency")
        if not numeric_valid:
            result["issues_found"].extend(numeric_issues)
            result["validation_passed"] = False
            result["adjusted_confidence"] *= 1.0 - confidence_penalty
            logger.warning(
                "Numeric consistency validation failed: %d issues found",
                len(numeric_issues),
            )

    result["adjusted_confidence"] = max(0.0, min(1.0, result["adjusted_confidence"]))

    if result["validation_passed"]:
        logger.info(
            "All hallucination guards passed: confidence=%.3f",
            result["adjusted_confidence"],
        )
    else:
        logger.warning(
            "Hallucination guards detected issues: %d total, confidence adjusted %.3f -> %.3f",
            len(result["issues_found"]),
            result["original_confidence"],
            result["adjusted_confidence"],
        )

    return result


def _flatten_dict(d: Mapping[str, Any], parent_key: str = "") -> List[Any]:
    """Flatten nested dictionary to list of values."""
    items: List[Any] = []
    for k, v in d.items():
        if isinstance(v, Mapping):
            items.extend(_flatten_dict(v, f"{parent_key}.{k}"))
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, Mapping):
                    items.extend(_flatten_dict(item, f"{parent_key}.{k}"))
                else:
                    items.append(item)
        else:
            items.append(v)
    return items


__all__ = [
    "validate_input_citation",
    "validate_cross_model_agreement",
    "validate_numeric_consistency",
    "apply_hallucination_guards",
]
