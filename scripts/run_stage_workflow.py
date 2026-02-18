#!/usr/bin/env python3
"""Run the staged FixOps workflow using the bundled fixtures."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
ENTERPRISE_SRC = REPO_ROOT / "fixops-enterprise"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(ENTERPRISE_SRC) not in sys.path:
    sys.path.insert(0, str(ENTERPRISE_SRC))

from src.services import id_allocator, signing
from src.services.run_registry import RunRegistry

from apps.api.normalizers import InputNormalizer
from core.stage_runner import StageRunner

STAGE_SEQUENCE: list[tuple[str, str | None]] = [
    ("requirements", "requirements/requirements-input.csv"),
    ("design", "design/design-input.json"),
    ("build", "build/sbom.json"),
    ("test", "test/scanner.sarif"),
    ("deploy", "deploy/tfplan.json"),
    ("operate", "operate/ops-telemetry.json"),
    ("decision", "decision/decision-input.json"),
]


def _load_input(fixtures_root: Path, relative_path: Optional[str]) -> Optional[Path]:
    if relative_path is None:
        return None
    candidate = fixtures_root / relative_path
    if not candidate.exists():
        raise FileNotFoundError(f"Fixture input not found: {candidate}")
    return candidate


def _describe_summary(summary) -> dict[str, object]:
    payload = {
        "stage": summary.stage,
        "app_id": summary.app_id,
        "run_id": summary.run_id,
        "output": str(summary.output_file),
    }
    if summary.bundle is not None:
        payload["evidence_bundle"] = str(summary.bundle)
    if summary.transparency_index is not None:
        payload["transparency_index"] = str(summary.transparency_index)
    if summary.signatures:
        payload["signatures"] = [str(entry) for entry in summary.signatures]
    if summary.verified is not None:
        payload["verified"] = summary.verified
    return payload


def _set_env(var: str, value: Optional[str]) -> None:
    if value is None:
        return
    os.environ[var] = value


def run_workflow(
    fixtures_root: Path,
    artefacts_root: Path,
    *,
    app: str,
    mode: str,
    run_id_seed: Optional[str],
    fake_now: Optional[str],
    sign: bool,
    verify: bool,
) -> list[dict[str, object]]:
    artefacts_root.mkdir(parents=True, exist_ok=True)
    registry = RunRegistry(root=artefacts_root)
    normalizer = InputNormalizer()
    runner = StageRunner(registry, id_allocator, signing, normalizer=normalizer)

    if run_id_seed:
        _set_env("FIXOPS_RUN_ID_SEED", run_id_seed)
    if fake_now:
        _set_env("FIXOPS_FAKE_NOW", fake_now)
    summaries = []
    for stage, relative_path in STAGE_SEQUENCE:
        input_path = _load_input(fixtures_root, relative_path)
        summary = runner.run_stage(
            stage,
            input_path,
            app_name=app,
            mode=mode,
            sign=sign,
            verify=verify,
        )
        summaries.append(_describe_summary(summary))
    return summaries


def _parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=REPO_ROOT / "fixtures" / "sample_inputs",
        help="Directory containing stage fixture inputs",
    )
    parser.add_argument(
        "--artefacts",
        type=Path,
        default=REPO_ROOT / "artefacts",
        help="Destination for generated artefacts",
    )
    parser.add_argument(
        "--app", default="life-claims-portal", help="Application name for the run"
    )
    parser.add_argument(
        "--mode", default="demo", help="Stage runner mode (demo or enterprise)"
    )
    parser.add_argument(
        "--run-id-seed",
        help="Optional deterministic run identifier seed (sets FIXOPS_RUN_ID_SEED)",
    )
    parser.add_argument(
        "--fake-now",
        help="Override timestamp used in manifests and bundles (sets FIXOPS_FAKE_NOW)",
    )
    parser.add_argument(
        "--sign", action="store_true", help="Request manifest signing if configured"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify manifest signatures when signing is enabled",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        help="Write a JSON summary of stage outputs to this file",
    )
    return parser.parse_args(list(argv))


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    summaries = run_workflow(
        args.fixtures,
        args.artefacts,
        app=args.app,
        mode=args.mode,
        run_id_seed=args.run_id_seed,
        fake_now=args.fake_now,
        sign=args.sign,
        verify=args.verify,
    )
    for entry in summaries:
        print(f"✅ {entry['stage']} → {entry['output']}")
    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summaries, indent=2), encoding="utf-8")
        print(f"Summary written to {args.summary}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
