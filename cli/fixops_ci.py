from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List

from cli.fixops_provenance import main as provenance_main
from cli.fixops_repro import main as repro_main
from cli.fixops_risk import main as risk_main
from cli.fixops_sbom import main as sbom_main
from evidence.packager import BundleInputs, create_bundle

DEFAULT_NORMALIZED = Path("artifacts/sbom/normalized.json")
DEFAULT_QUALITY_JSON = Path("analysis/sbom_quality_report.json")
DEFAULT_QUALITY_HTML = Path("reports/sbom_quality_report.html")
DEFAULT_RISK = Path("artifacts/risk.json")
DEFAULT_PROVENANCE_DIR = Path("artifacts/attestations")
DEFAULT_REPRO_DIR = Path("artifacts/repro/attestations")
DEFAULT_POLICY = Path("config/policy.yml")
DEFAULT_EVIDENCE_OUT = Path("evidence")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fixops-ci",
        description="One-stop CLI for FixOps secure supply chain workflows.",
    )
    subparsers = parser.add_subparsers(dest="group", required=True)

    sbom_parser = subparsers.add_parser(
        "sbom",
        help="Proxy to fixops-sbom for normalization and quality reporting.",
    )
    sbom_parser.add_argument("args", nargs=argparse.REMAINDER)

    risk_parser = subparsers.add_parser(
        "risk",
        help="Proxy to fixops-risk for composite scoring.",
    )
    risk_parser.add_argument("args", nargs=argparse.REMAINDER)

    provenance_parser = subparsers.add_parser(
        "provenance",
        help="Proxy to fixops-provenance for attest/verify operations.",
    )
    provenance_parser.add_argument("args", nargs=argparse.REMAINDER)

    repro_parser = subparsers.add_parser(
        "repro",
        help="Proxy to fixops-repro for reproducible build verification.",
    )
    repro_parser.add_argument("args", nargs=argparse.REMAINDER)

    evidence_parser = subparsers.add_parser(
        "evidence",
        help="Evidence bundle packaging and policy evaluation.",
    )
    evidence_sub = evidence_parser.add_subparsers(dest="action", required=True)
    bundle_parser = evidence_sub.add_parser(
        "bundle",
        help="Assemble and optionally sign an evidence bundle for a release tag.",
    )
    bundle_parser.add_argument("--tag", required=True, help="Release tag to package.")
    bundle_parser.add_argument(
        "--normalized",
        default=str(DEFAULT_NORMALIZED),
        help="Path to normalized SBOM JSON.",
    )
    bundle_parser.add_argument(
        "--quality-json",
        default=str(DEFAULT_QUALITY_JSON),
        help="Path to SBOM quality JSON report.",
    )
    bundle_parser.add_argument(
        "--quality-html",
        default=str(DEFAULT_QUALITY_HTML),
        help="Path to SBOM quality HTML report (optional).",
    )
    bundle_parser.add_argument(
        "--risk",
        default=str(DEFAULT_RISK),
        help="Path to risk scoring JSON report.",
    )
    bundle_parser.add_argument(
        "--provenance-dir",
        default=str(DEFAULT_PROVENANCE_DIR),
        help="Directory containing provenance attestations.",
    )
    bundle_parser.add_argument(
        "--repro-dir",
        default=str(DEFAULT_REPRO_DIR),
        help="Directory containing reproducibility attestations.",
    )
    bundle_parser.add_argument(
        "--policy",
        default=str(DEFAULT_POLICY),
        help="Policy definition YAML for pass/warn/fail thresholds.",
    )
    bundle_parser.add_argument(
        "--out",
        default=str(DEFAULT_EVIDENCE_OUT),
        help="Root directory for evidence bundles and manifests.",
    )
    bundle_parser.add_argument(
        "--extra",
        action="append",
        default=[],
        help="Additional files or directories to include (repeatable).",
    )
    bundle_parser.add_argument(
        "--sign-key",
        default=None,
        help="Optional cosign private key used to sign MANIFEST.yaml.",
    )

    return parser


def _proxy(callback, arguments: List[str]) -> int:
    if not arguments:
        return callback(["--help"])
    return callback(arguments)


def _handle_bundle(args: argparse.Namespace) -> int:
    tag = args.tag
    repro_attestation = Path(args.repro_dir) / f"{tag}.json"
    inputs = BundleInputs(
        tag=tag,
        normalized_sbom=Path(args.normalized),
        sbom_quality_json=Path(args.quality_json),
        sbom_quality_html=Path(args.quality_html) if args.quality_html else None,
        risk_report=Path(args.risk),
        provenance_dir=Path(args.provenance_dir),
        repro_attestation=repro_attestation,
        policy_path=Path(args.policy) if args.policy else None,
        output_dir=Path(args.out),
        extra_paths=[Path(item) for item in args.extra],
        sign_key=Path(args.sign_key) if args.sign_key else None,
    )
    try:
        manifest = create_bundle(inputs)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"cosign signing failed: {exc}", file=sys.stderr)
        return 2

    overall = manifest.get("evaluations", {}).get("overall", "unknown")
    bundle_path = manifest.get("bundle_path")
    print(f"Evidence bundle created at {bundle_path}")
    print(f"Overall policy status: {overall}")
    if overall == "fail":
        return 4
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.group == "sbom":
        return _proxy(sbom_main, list(args.args))
    if args.group == "risk":
        return _proxy(risk_main, list(args.args))
    if args.group == "provenance":
        return _proxy(provenance_main, list(args.args))
    if args.group == "repro":
        return _proxy(repro_main, list(args.args))
    if args.group == "evidence" and args.action == "bundle":
        return _handle_bundle(args)

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
