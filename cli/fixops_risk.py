"""CLI helpers for FixOps risk scoring."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

from risk.feeds.epss import load_epss_scores
from risk.feeds.kev import load_kev_catalog
from risk.scoring import write_risk_report

DEFAULT_SBOM_INPUT = Path("artifacts/sbom/normalized.json")
DEFAULT_RISK_OUTPUT = Path("artifacts/risk.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fixops-risk",
        description="Compute FixOps composite risk scores for SBOM components.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    score_parser = subparsers.add_parser(
        "score", help="Generate risk scores for components in a normalized SBOM"
    )
    score_parser.add_argument(
        "--sbom",
        dest="sbom",
        default=str(DEFAULT_SBOM_INPUT),
        help="Path to the normalized SBOM JSON",
    )
    score_parser.add_argument(
        "--out",
        dest="output",
        default=str(DEFAULT_RISK_OUTPUT),
        help="Destination for the risk report JSON",
    )
    score_parser.add_argument(
        "--epss",
        dest="epss",
        default=None,
        help="Optional override path for a cached EPSS CSV",
    )
    score_parser.add_argument(
        "--kev",
        dest="kev",
        default=None,
        help="Optional override path for a cached KEV JSON",
    )

    return parser


def _handle_score(sbom: str, output: str, epss: str | None, kev: str | None) -> int:
    try:
        epss_scores = load_epss_scores(path=epss) if epss else load_epss_scores()
        kev_catalog = load_kev_catalog(path=kev) if kev else load_kev_catalog()
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    report = write_risk_report(sbom, output, epss_scores, kev_catalog)
    component_count = len(report.get("components", []))
    weights = report.get("weights", {})
    summary = report.get("summary", {})
    print(f"Wrote risk profile for {component_count} components to {output}")
    if weights:
        weight_breakdown = ", ".join(
            f"{name}={value}" for name, value in sorted(weights.items())
        )
        print(f"Risk weight breakdown: {weight_breakdown}")
    if summary:
        print(
            "Summary: highest risk component="
            f"{summary.get('highest_risk_component')} (score="
            f"{summary.get('max_risk_score')})"
        )
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "score":
        return _handle_score(args.sbom, args.output, args.epss, args.kev)

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
