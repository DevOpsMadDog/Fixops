from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable

from services.repro.verifier import run_verification

DEFAULT_PLAN = Path("build/plan.yaml")
DEFAULT_OUTPUT = Path("artifacts/repro/attestations")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fixops-repro",
        description="Verify reproducible builds against reference digests or attestations.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser(
        "verify",
        help="Execute a reproducible build plan and emit an attestation report.",
    )
    verify_parser.add_argument(
        "--tag",
        required=True,
        help="Release tag or identifier to verify.",
    )
    verify_parser.add_argument(
        "--plan",
        default=str(DEFAULT_PLAN),
        help="Path to the build plan YAML (defaults to build/plan.yaml).",
    )
    verify_parser.add_argument(
        "--out",
        dest="output",
        default=str(DEFAULT_OUTPUT),
        help="Directory to store reproducibility attestations.",
    )
    verify_parser.add_argument(
        "--repo",
        dest="repo",
        default=".",
        help="Repository root containing sources and reference artefacts.",
    )

    return parser


def _handle_verify(tag: str, plan: str, output: str, repo: str) -> int:
    try:
        result = run_verification(plan, tag, output_dir=output, repo_root=repo)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    digest = result.generated_digest.get("sha256")
    status = "SUCCESS" if result.match else "MISMATCH"
    print(f"[{status}] {tag} sha256={digest}")
    if result.attestation_path:
        print(f"Attestation written to {result.attestation_path}")
    return 0 if result.match else 3


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "verify":
        return _handle_verify(args.tag, args.plan, args.output, args.repo)

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
