#!/usr/bin/env python3
"""Run a FixOps CVE playbook and highlight severity reclassification."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from rich.console import Console
from rich.table import Table

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "enterprise") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "enterprise"))

from core.services.enterprise.compliance_engine import ComplianceEngine  # noqa: E402
from core.services.enterprise.risk_scorer import ContextualRiskScorer  # noqa: E402

DEFAULT_CONTEXT = {
    "service_name": "payment-service",
    "environment": "production",
    "business_context": {
        "customer_impact": "critical",
        "data_classification": ["pii", "financial"],
        "deployment_frequency": "continuous",
    },
    "security_findings": [
        {
            "id": "CVE-2024-12345",
            "title": "OpenSSL buffer overflow",
            "severity": "medium",
            "cve": "CVE-2024-12345",
        },
        {
            "id": "CVE-2023-9876",
            "title": "Old ORM SQL injection",
            "severity": "critical",
            "cve": "CVE-2023-9876",
        },
    ],
    "compliance_requirements": ["pci_dss", "sox"],
}


def load_context(path: Path | None) -> Dict[str, Any]:
    if not path:
        return DEFAULT_CONTEXT
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_table(findings: List[Dict[str, Any]]) -> Table:
    table = Table(title="FixOps Severity Reclassification", expand=True)
    table.add_column("Finding", style="cyan", overflow="fold")
    table.add_column("Scanner Severity", style="yellow")
    table.add_column("FixOps Severity", style="magenta")
    table.add_column("Risk Factors", style="green")

    for finding in findings:
        name = (
            finding.get("id")
            or finding.get("title")
            or finding.get("cve")
            or finding.get("rule_id")
            or "Unknown"
        )
        risk_factors = ", ".join(finding.get("risk_factors", [])) or "-"
        table.add_row(
            name,
            finding.get("scanner_severity", finding.get("severity", "UNKNOWN")),
            finding.get("fixops_severity", finding.get("risk_tier", "UNKNOWN")),
            risk_factors,
        )

    return table


def print_compliance_results(
    console: Console, context: Dict[str, Any], findings: List[Dict[str, Any]]
) -> None:
    engine = ComplianceEngine()
    frameworks = context.get("compliance_requirements", [])
    if not frameworks:
        return

    results = [
        engine._evaluate_framework(framework, findings, context.get("business_context"))
        for framework in frameworks
    ]
    for result in results:
        console.print(
            f"[bold]{result['framework'].upper()}[/bold] status: {result['status']} "
            f"(scanner {result['highest_scanner_severity']} → FixOps {result['highest_fixops_severity']})"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--context",
        type=Path,
        help="Path to a JSON payload with business_context and security_findings",
    )
    args = parser.parse_args()

    context = load_context(args.context)
    business_context = context.get("business_context", {})
    findings = context.get("security_findings", [])

    scorer = ContextualRiskScorer()
    adjusted_findings = scorer.apply(findings, business_context)

    console = Console()
    console.print("[bold underline]FixOps Real CVE Playbook[/bold underline]\n")
    console.print(build_table(adjusted_findings))
    console.print("")

    print_compliance_results(console, context, adjusted_findings)


if __name__ == "__main__":
    main()
