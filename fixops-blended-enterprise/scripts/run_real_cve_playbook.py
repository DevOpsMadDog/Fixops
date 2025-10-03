#!/usr/bin/env python3
"""Render FixOps CVE playbook results with compliance and regression insights."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class PlaybookRun:
    """Lightweight representation of a playbook execution."""

    cve_id: str
    service_name: str
    environment: str
    decision: Dict[str, Any]
    consensus_details: Dict[str, Any]
    validation_results: Dict[str, Any]

    @classmethod
    def from_mapping(cls, payload: Dict[str, Any]) -> "PlaybookRun":
        return cls(
            cve_id=payload.get("cve_id", "unknown"),
            service_name=payload.get("service_name", "unknown"),
            environment=payload.get("environment", "unknown"),
            decision=payload.get("decision", {}),
            consensus_details=payload.get("consensus_details", {}),
            validation_results=payload.get("validation_results", {}),
        )


def _load_sample_payload() -> List[Dict[str, Any]]:
    """Provide representative CVE scenarios used for CLI previews/tests."""

    sample_file = Path(__file__).with_name("sample_cve_runs.json")
    if sample_file.exists():
        return json.loads(sample_file.read_text())

    # Embedded fallback mirrors DecisionResult.validation_results structure
    return [
        {
            "cve_id": "CVE-2024-1050",
            "service_name": "payment-gateway",
            "environment": "production",
            "decision": {
                "verdict": "BLOCK",
                "confidence": 0.58,
                "reasoning": "Critical PCI gaps detected."
            },
            "consensus_details": {
                "confidence": 0.58,
                "threshold_met": False,
                "component_scores": {
                    "vector_db": 0.45,
                    "golden_regression": 0.62,
                    "policy_engine": 0.30,
                    "criticality": 0.20
                }
            },
            "validation_results": {
                "golden_regression": {
                    "confidence": 0.62,
                    "validation_passed": False,
                    "similar_cases": 4
                },
                "compliance": {
                    "frameworks": {
                        "PCI DSS": {
                            "decision": "block",
                            "rationale": "1 critical finding(s) violate PCI DSS mandatory controls",
                            "severity_breakdown": {
                                "critical": 1,
                                "high": 0,
                                "medium": 2,
                                "low": 0
                            }
                        },
                        "SOC2": {
                            "decision": "defer",
                            "rationale": "1 high severity finding(s) require remediation before SOC2 attestation",
                            "severity_breakdown": {
                                "critical": 1,
                                "high": 1,
                                "medium": 2,
                                "low": 0
                            }
                        }
                    },
                    "failed_frameworks": ["PCI DSS", "SOC2"],
                    "overall_decision": "block",
                    "summary": "PCI DSS: BLOCK (1 critical finding(s) violate PCI DSS mandatory controls) | SOC2: DEFER (1 high severity finding(s) require remediation before SOC2 attestation)",
                    "status": "evaluated"
                }
            }
        },
        {
            "cve_id": "CVE-2024-2230",
            "service_name": "feature-flags",
            "environment": "staging",
            "decision": {
                "verdict": "ALLOW",
                "confidence": 0.82,
                "reasoning": "Coverage acceptable for pre-production rollout."
            },
            "consensus_details": {
                "confidence": 0.82,
                "threshold_met": True,
                "component_scores": {
                    "vector_db": 0.79,
                    "golden_regression": 0.88,
                    "policy_engine": 0.92,
                    "criticality": 0.69
                }
            },
            "validation_results": {
                "golden_regression": {
                    "confidence": 0.88,
                    "validation_passed": True,
                    "similar_cases": 18
                },
                "compliance": {
                    "frameworks": {
                        "NIST SSDF": {
                            "decision": "allow",
                            "rationale": "NIST SSDF tolerances met with 0 tracked finding(s)",
                            "severity_breakdown": {
                                "critical": 0,
                                "high": 0,
                                "medium": 1,
                                "low": 2
                            }
                        },
                        "ISO27001": {
                            "decision": "allow",
                            "rationale": "ISO27001 tolerances met with 0 tracked finding(s)",
                            "severity_breakdown": {
                                "critical": 0,
                                "high": 0,
                                "medium": 1,
                                "low": 2
                            }
                        }
                    },
                    "failed_frameworks": [],
                    "overall_decision": "allow",
                    "summary": "NIST SSDF: ALLOW (NIST SSDF tolerances met with 0 tracked finding(s)) | ISO27001: ALLOW (ISO27001 tolerances met with 0 tracked finding(s))",
                    "status": "evaluated"
                }
            }
        }
    ]


def _format_stage_summary(run: PlaybookRun) -> str:
    confidence = run.consensus_details.get("confidence")
    threshold_met = run.consensus_details.get("threshold_met")
    if confidence is None:
        return "Stage Summary: unavailable"
    status = "met" if threshold_met else "missed"
    return f"Stage Summary: consensus {confidence:.1%} (threshold {status})"


def _format_regression(validation_results: Dict[str, Any]) -> str:
    regression = validation_results.get("golden_regression", {})
    confidence = regression.get("confidence")
    similar_cases = regression.get("similar_cases")
    passed = regression.get("validation_passed")
    if confidence is None:
        return "Regression Confidence: n/a"
    status = "passed" if passed else "failed"
    if similar_cases is not None:
        return f"Regression Confidence: {confidence:.1%} ({status}, {similar_cases} similar cases)"
    return f"Regression Confidence: {confidence:.1%} ({status})"


def _format_compliance(validation_results: Dict[str, Any]) -> List[str]:
    compliance = validation_results.get("compliance") or {}
    frameworks = compliance.get("frameworks") or {}
    if not frameworks:
        return ["Compliance Coverage: n/a (no frameworks provided)"]

    total = len(frameworks)
    allowed = sum(1 for data in frameworks.values() if data.get("decision") == "allow")
    coverage_pct = (allowed / total) * 100 if total else 0.0
    failed_frameworks = [name for name, data in frameworks.items() if data.get("decision") != "allow"]
    lines = [f"Compliance Coverage: {coverage_pct:.1f}% ({allowed}/{total} frameworks)"]

    if failed_frameworks:
        lines.append("Failed Frameworks: " + ", ".join(failed_frameworks))
    else:
        lines.append("Failed Frameworks: none")
    return lines


def render_playbook_report(runs: Iterable[PlaybookRun]) -> str:
    """Render a textual report for CLI display."""

    lines: List[str] = ["🚀 FixOps Real CVE Playbook", "=========================="]
    for run in runs:
        decision = run.decision
        verdict = decision.get("verdict", "UNKNOWN")
        confidence = decision.get("confidence")
        header = f"▶ {run.cve_id} | {run.service_name} ({run.environment})"
        lines.append("\n" + header)
        lines.append("-" * len(header))
        if confidence is not None:
            lines.append(f"Decision: {verdict} ({confidence:.1%})")
        else:
            lines.append(f"Decision: {verdict}")
        reasoning = decision.get("reasoning")
        if reasoning:
            lines.append(f"Reason: {reasoning}")

        lines.append(_format_stage_summary(run))
        lines.append(_format_regression(run.validation_results))
        lines.extend(_format_compliance(run.validation_results))

    return "\n".join(lines)


def generate_playbook_runs(payload: Optional[Iterable[Dict[str, Any]]] = None) -> List[PlaybookRun]:
    """Create PlaybookRun entries from payload or bundled sample data."""

    raw_payload = list(payload) if payload is not None else _load_sample_payload()
    return [PlaybookRun.from_mapping(item) for item in raw_payload]


def main() -> None:
    runs = generate_playbook_runs()
    report = render_playbook_report(runs)
    print(report)


if __name__ == "__main__":
    main()
