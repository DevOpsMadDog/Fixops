"""Execute the FixOps demo pipeline with bundled fixtures."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from core.demo_runner import run_demo_pipeline


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the FixOps demo pipeline for the requested overlay profile.",
    )
    parser.add_argument(
        "--mode",
        choices=["demo", "enterprise"],
        default="demo",
        help="Overlay profile to execute (demo or enterprise).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to persist the raw JSON result.",
    )
    parser.add_argument(
        "--pretty",
        dest="pretty",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Pretty-print the JSON output when --output is supplied (default: enabled).",
    )
    parser.add_argument(
        "--summary",
        dest="summary",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Display the human readable summary after the pipeline runs (default: enabled).",
    )
    parser.add_argument(
        "--app",
        default="life-claims-portal",
        help="Reserved for compatibility with historical scripts; no longer required.",
    )
    return parser


def _run(mode: str, output: Optional[Path], pretty: bool, summary: bool) -> None:
    run_demo_pipeline(
        mode=mode, output_path=output, pretty=pretty, include_summary=summary
    )


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    _run(args.mode, args.output, args.pretty, args.summary)


if __name__ == "__main__":
    main()
