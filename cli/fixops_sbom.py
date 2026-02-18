"""CLI helpers for SBOM normalization and quality reporting."""

from __future__ import annotations

import argparse
import json
import sys
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
    normalize_parser.add_argument(
        "--strict-schema",
        dest="strict_schema",
        action="store_true",
        help="Enable strict schema validation (fail on missing required fields)",
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


def _handle_normalize(
    inputs: Iterable[str], output: str, strict_schema: bool = False
) -> int:
    """Normalize SBOM files into a single canonical document."""
    try:
        normalized = write_normalized_sbom(inputs, output, strict_schema=strict_schema)
        component_count = len(normalized.get("components", []))
        print(f"Normalized {component_count} components to {output}")
        if strict_schema:
            print("Strict schema validation: PASSED")
        validation_errors = normalized.get("metadata", {}).get("validation_errors", [])
        if validation_errors:
            print(
                f"Warning: {len(validation_errors)} components have validation errors",
                file=sys.stderr,
            )
        return 0
    except FileNotFoundError as e:
        print(f"Error: Input file not found: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error during normalization: {e}", file=sys.stderr)
        return 1


def _handle_quality(normalized_path: str, html_path: str, json_path: str) -> int:
    """Generate SBOM quality metrics and HTML report."""
    try:
        path = Path(normalized_path)
        if not path.exists():
            print(
                f"Error: Normalized SBOM file not found: {normalized_path}",
                file=sys.stderr,
            )
            return 1
        with path.open("r", encoding="utf-8") as handle:
            normalized = json.load(handle)
        build_and_write_quality_outputs(normalized, json_path, html_path)
        print(f"Wrote quality report to {json_path} and HTML to {html_path}")
        return 0
    except FileNotFoundError:
        print(f"Error: File not found: {normalized_path}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {normalized_path}: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(
            f"Unexpected error during quality report generation: {e}", file=sys.stderr
        )
        return 1


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "normalize":
        return _handle_normalize(args.inputs, args.output, args.strict_schema)
    if args.command == "quality":
        return _handle_quality(args.normalized, args.html, args.json_path)

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
