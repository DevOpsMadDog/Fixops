"""CLI helpers for SBOM normalization and quality reporting."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

from lib4sbom.normalizer import build_and_write_quality_outputs, write_normalized_sbom

DEFAULT_NORMALIZED_OUTPUT = Path("artifacts/sbom/normalized.json")
DEFAULT_JSON_REPORT = Path("analysis/sbom_quality_report.json")
DEFAULT_HTML_REPORT = Path("reports/sbom_quality_report.html")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fixops-sbom",
        description="Normalize SBOM inputs and calculate quality metrics.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize_parser = subparsers.add_parser(
        "normalize", help="Normalize SBOM files into a single canonical document"
    )
    normalize_parser.add_argument(
        "--in",
        dest="inputs",
        nargs="+",
        required=True,
        help="Input SBOM file paths (CycloneDX or SPDX JSON)",
    )
    normalize_parser.add_argument(
        "--out",
        dest="output",
        default=str(DEFAULT_NORMALIZED_OUTPUT),
        help="Destination for the normalized SBOM JSON",
    )

    quality_parser = subparsers.add_parser(
        "quality", help="Generate SBOM quality metrics and HTML report"
    )
    quality_parser.add_argument(
        "--in",
        dest="normalized",
        required=True,
        help="Path to a normalized SBOM JSON file",
    )
    quality_parser.add_argument(
        "--html",
        dest="html",
        default=str(DEFAULT_HTML_REPORT),
        help="Destination for the rendered HTML report",
    )
    quality_parser.add_argument(
        "--json",
        dest="json_path",
        default=str(DEFAULT_JSON_REPORT),
        help="Destination for the JSON quality report",
    )

    return parser


def _handle_normalize(inputs: Iterable[str], output: str) -> int:
    normalized = write_normalized_sbom(inputs, output)
    print(f"Normalized {len(normalized.get('components', []))} components to {output}")
    return 0


def _handle_quality(normalized_path: str, html_path: str, json_path: str) -> int:
    path = Path(normalized_path)
    with path.open("r", encoding="utf-8") as handle:
        normalized = json.load(handle)
    build_and_write_quality_outputs(normalized, json_path, html_path)
    print(f"Wrote quality report to {json_path} and HTML to {html_path}")
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "normalize":
        return _handle_normalize(args.inputs, args.output)
    if args.command == "quality":
        return _handle_quality(args.normalized, args.html, args.json_path)

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
