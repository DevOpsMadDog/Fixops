"""Entry point for the unified FixOps stage runner CLI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable


def _ensure_enterprise_src() -> Path:
    """Ensure the enterprise runtime package is importable."""

    repo_root = Path(__file__).resolve().parents[2]
    enterprise_src = repo_root / "fixops-enterprise"
    if enterprise_src.exists():
        candidate = str(enterprise_src)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)
    return enterprise_src


_ = _ensure_enterprise_src()


from core.services.enterprise import id_allocator, signing  # noqa: E402
from core.services.enterprise.run_registry import RunRegistry  # noqa: E402
from core.stage_runner import StageRunner  # noqa: E402  (import after path tweak)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fixops", description="Canonical stage runner for the FixOps platform"
    )
    subparsers = parser.add_subparsers(dest="command")

    stage_parser = subparsers.add_parser(
        "stage-run",
        help="Normalise a single stage input and materialise canonical outputs",
    )
    stage_parser.add_argument(
        "--stage",
        required=True,
        choices=[
            "requirements",
            "design",
            "build",
            "test",
            "deploy",
            "operate",
            "decision",
        ],
        help="Stage to execute",
    )
    stage_parser.add_argument(
        "--input",
        type=Path,
        help="Path to the stage input artefact",
    )
    stage_parser.add_argument(
        "--app",
        dest="app_name",
        help="Logical application name used for artefact grouping",
    )
    stage_parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to copy the canonical output to",
    )
    stage_parser.add_argument(
        "--mode",
        choices=["demo", "enterprise"],
        default="demo",
        help="Processing mode hint (affects scoring heuristics)",
    )
    stage_parser.add_argument(
        "--sign",
        action="store_true",
        help="Sign canonical outputs when signing keys are configured",
    )
    stage_parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify signatures after writing canonical outputs",
    )
    stage_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print verbose run metadata",
    )
    stage_parser.set_defaults(handler=_handle_stage_run)

    return parser


def _handle_stage_run(args: argparse.Namespace) -> int:
    runner = StageRunner(RunRegistry(), id_allocator, signing)
    input_path = args.input.resolve() if isinstance(args.input, Path) else None
    output_path = args.output.resolve() if isinstance(args.output, Path) else None

    result = runner.run_stage(
        args.stage,
        input_path,
        app_name=args.app_name,
        mode=args.mode,
        sign=args.sign,
        verify=args.verify,
        output_path=output_path,
        verbose=args.verbose,
    )

    details: list[str] = []
    if result.signatures:
        details.append(
            "signed: " + ", ".join(str(path.name) for path in result.signatures)
        )
    if result.transparency_index:
        details.append(f"transparency: {result.transparency_index.name}")
    if result.verified is not None:
        verdict = "passed" if result.verified else "failed"
        details.append(f"verification {verdict}")

    suffix = f" ({'; '.join(details)})" if details else ""
    print(f"✅ Stage {result.stage} complete → {result.output_file}{suffix}")
    return 0


def _dispatch(parser: argparse.ArgumentParser, argv: Iterable[str]) -> int:
    args = parser.parse_args(list(argv))
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 1
    return handler(args)


def main(argv: Iterable[str] | None = None) -> int:
    parser = _build_parser()
    selected = sys.argv[1:] if argv is None else list(argv)
    return _dispatch(parser, selected)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
