"""Command-line helpers for running FixOps pipelines locally."""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from backend.normalizers import InputNormalizer, NormalizedCVEFeed, NormalizedSARIF, NormalizedSBOM
from backend.pipeline import PipelineOrchestrator
from fixops.configuration import OverlayConfig, load_overlay
from fixops.paths import ensure_secure_directory
from fixops.storage import ArtefactArchive


def _apply_env_overrides(pairs: Iterable[str]) -> None:
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(f"Environment override '{pair}' must be in KEY=VALUE format")
        key, value = pair.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError("Environment override requires a non-empty key")
        os.environ[key] = value


def _load_design(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = [row for row in reader if any((value or "").strip() for value in row.values())]
    if not rows:
        raise ValueError(f"Design CSV '{path}' contained no usable rows")
    return {"columns": reader.fieldnames or [], "rows": rows}


def _load_file(path: Optional[Path]) -> Optional[bytes]:
    if path is None:
        return None
    return path.read_bytes()


def _load_inputs(
    normalizer: InputNormalizer,
    design_path: Optional[Path],
    sbom_path: Optional[Path],
    sarif_path: Optional[Path],
    cve_path: Optional[Path],
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}

    if design_path is not None:
        payload["design"] = _load_design(design_path)

    if sbom_path is not None:
        payload["sbom"] = normalizer.load_sbom(_load_file(sbom_path) or b"")

    if sarif_path is not None:
        payload["sarif"] = normalizer.load_sarif(_load_file(sarif_path) or b"")

    if cve_path is not None:
        payload["cve"] = normalizer.load_cve_feed(_load_file(cve_path) or b"")

    return payload


def _ensure_inputs(
    overlay: OverlayConfig,
    inputs: Dict[str, Any],
    design_path: Optional[Path],
    sbom_path: Optional[Path],
    sarif_path: Optional[Path],
    cve_path: Optional[Path],
) -> Dict[str, Any]:
    required = overlay.required_inputs
    missing: list[str] = []
    mapping = {
        "design": design_path,
        "sbom": sbom_path,
        "sarif": sarif_path,
        "cve": cve_path,
    }
    for stage in required:
        if stage not in inputs:
            missing.append(stage)
        elif mapping.get(stage) is None:
            missing.append(stage)
    if missing:
        raise ValueError(
            "Overlay requires artefacts that were not provided: " + ", ".join(sorted(set(missing)))
        )

    sbom: NormalizedSBOM = inputs["sbom"]
    sarif: NormalizedSARIF = inputs["sarif"]
    cve: NormalizedCVEFeed = inputs["cve"]
    design_dataset = inputs.get("design", {"columns": [], "rows": []})
    return {
        "design_dataset": design_dataset,
        "sbom": sbom,
        "sarif": sarif,
        "cve": cve,
    }


def _set_module_enabled(overlay: OverlayConfig, module: str, enabled: bool) -> None:
    current = overlay.modules.get(module)
    if isinstance(current, dict):
        current["enabled"] = enabled
    else:
        overlay.modules[module] = {"enabled": enabled}


def _copy_evidence(result: Dict[str, Any], destination: Optional[Path]) -> Optional[Path]:
    if destination is None:
        return None
    files = result.get("evidence_bundle", {}).get("files") if isinstance(result.get("evidence_bundle"), dict) else {}
    if not isinstance(files, dict):
        return None
    bundle = files.get("bundle")
    if not bundle:
        return None
    bundle_path = Path(bundle)
    ensure_secure_directory(destination)
    target = destination / bundle_path.name
    target.write_bytes(bundle_path.read_bytes())
    return target


def _print_summary(result: Dict[str, Any], output: Optional[Path], evidence_path: Optional[Path]) -> None:
    severity_overview = result.get("severity_overview", {})
    guardrail = result.get("guardrail_evaluation", {})
    compliance = result.get("compliance_status", {})
    pricing = result.get("pricing_summary", {})
    modules = result.get("modules", {})
    analytics = result.get("analytics", {})
    performance = result.get("performance_profile", {})
    tenancy = result.get("tenant_lifecycle", {})

    highest = severity_overview.get("highest", "unknown")
    guardrail_status = guardrail.get("status", "n/a")
    frameworks = compliance.get("frameworks") or []
    executed = modules.get("executed") or []

    print("FixOps pipeline summary:")
    print(f"  Highest severity: {highest}")
    print(f"  Guardrail status: {guardrail_status}")
    if frameworks:
        joined = ", ".join(sorted({framework.get("id", "framework") for framework in frameworks if isinstance(framework, dict)}))
        print(f"  Compliance frameworks satisfied: {joined}")
    pricing_plan = pricing.get("plan")
    if pricing_plan:
        print(f"  Pricing plan: {pricing_plan}")
    if executed:
        print(f"  Modules executed: {', '.join(executed)}")
    roi_overview = analytics.get("overview") if isinstance(analytics, dict) else None
    if isinstance(roi_overview, dict):
        currency = roi_overview.get("currency", "USD")
        estimated_value = roi_overview.get("estimated_value")
        if estimated_value is not None:
            print(f"  Estimated ROI: {currency} {estimated_value}")
    perf_summary = performance.get("summary") if isinstance(performance, dict) else None
    if isinstance(perf_summary, dict):
        status = perf_summary.get("status")
        total_latency = perf_summary.get("total_estimated_latency_ms")
        if status and total_latency is not None:
            print(
                f"  Performance status: {status} (approx {total_latency} ms per run)"
            )
    tenancy_summary = tenancy.get("summary") if isinstance(tenancy, dict) else None
    if isinstance(tenancy_summary, dict):
        total_tenants = tenancy_summary.get("total_tenants")
        if total_tenants:
            print(f"  Tenants tracked: {total_tenants}")
    if output is not None:
        print(f"  Result saved to: {output}")
    if evidence_path is not None:
        print(f"  Evidence bundle copied to: {evidence_path}")
    elif result.get("evidence_bundle"):
        bundle_file = result["evidence_bundle"].get("files", {}).get("bundle")
        if bundle_file:
            print(f"  Evidence bundle generated at: {bundle_file}")


def _handle_run(args: argparse.Namespace) -> int:
    if args.env:
        _apply_env_overrides(args.env)

    overlay = load_overlay(args.overlay)
    if args.disable_modules:
        for module in args.disable_modules:
            _set_module_enabled(overlay, module, False)
    if args.enable_modules:
        for module in args.enable_modules:
            _set_module_enabled(overlay, module, True)
    if args.offline:
        auto_refresh = overlay.exploit_signals.get("auto_refresh")
        if isinstance(auto_refresh, dict):
            auto_refresh["enabled"] = False
    for directory in overlay.data_directories.values():
        ensure_secure_directory(directory)

    archive_dir = overlay.data_directories.get("archive_dir")
    if archive_dir is None:
        root = (
            overlay.allowed_data_roots[0]
            if overlay.allowed_data_roots
            else Path("data").resolve()
        )
        archive_dir = (root / "archive" / overlay.mode).resolve()
    archive = ArtefactArchive(archive_dir)

    normalizer = InputNormalizer()
    inputs = _load_inputs(
        normalizer=normalizer,
        design_path=args.design,
        sbom_path=args.sbom,
        sarif_path=args.sarif,
        cve_path=args.cve,
    )
    orchestrator = PipelineOrchestrator()
    prepared = _ensure_inputs(
        overlay=overlay,
        inputs=inputs,
        design_path=args.design,
        sbom_path=args.sbom,
        sarif_path=args.sarif,
        cve_path=args.cve,
    )

    archive_records: Dict[str, Dict[str, Any]] = {}
    try:
        if args.design is not None and "design" in inputs:
            archive_records["design"] = archive.persist(
                "design",
                prepared["design_dataset"],
                original_filename=args.design.name,
                raw_bytes=args.design.read_bytes(),
            )
        if args.sbom is not None:
            archive_records["sbom"] = archive.persist(
                "sbom",
                prepared["sbom"],
                original_filename=args.sbom.name,
                raw_bytes=args.sbom.read_bytes(),
            )
        if args.sarif is not None:
            archive_records["sarif"] = archive.persist(
                "sarif",
                prepared["sarif"],
                original_filename=args.sarif.name,
                raw_bytes=args.sarif.read_bytes(),
            )
        if args.cve is not None:
            archive_records["cve"] = archive.persist(
                "cve",
                prepared["cve"],
                original_filename=args.cve.name,
                raw_bytes=args.cve.read_bytes(),
            )
    except Exception as exc:  # pragma: no cover - archival should not abort CLI runs
        print(f"Warning: failed to persist artefacts locally: {exc}", file=sys.stderr)

    result = orchestrator.run(overlay=overlay, **prepared)
    if args.include_overlay:
        result["overlay"] = overlay.to_sanitised_dict()

    if archive_records:
        result["artifact_archive"] = ArtefactArchive.summarise(archive_records)

    output_path: Optional[Path] = args.output
    if output_path:
        ensure_secure_directory(output_path.parent)
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2 if args.pretty else None)
            if args.pretty:
                handle.write("\n")

    copied_bundle = _copy_evidence(result, args.evidence_dir)

    if not args.quiet:
        _print_summary(result, output_path, copied_bundle)

    return 0


def _handle_show_overlay(args: argparse.Namespace) -> int:
    if args.env:
        _apply_env_overrides(args.env)
    overlay = load_overlay(args.overlay)
    payload = overlay.to_sanitised_dict()
    text = json.dumps(payload, indent=2 if args.pretty else None)
    print(text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="FixOps local orchestration helpers")
    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser("run", help="Execute the FixOps pipeline locally")
    run_parser.add_argument("--overlay", type=Path, default=None, help="Path to an overlay file (defaults to repository overlay)")
    run_parser.add_argument("--design", type=Path, help="Path to design CSV artefact")
    run_parser.add_argument("--sbom", type=Path, required=True, help="Path to SBOM JSON artefact")
    run_parser.add_argument("--sarif", type=Path, required=True, help="Path to SARIF JSON artefact")
    run_parser.add_argument("--cve", type=Path, required=True, help="Path to CVE/KEV JSON artefact")
    run_parser.add_argument("--output", type=Path, help="Location to write the pipeline result JSON")
    run_parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output when saving to disk")
    run_parser.add_argument("--include-overlay", action="store_true", help="Attach the sanitised overlay to the result payload")
    run_parser.add_argument(
        "--disable",
        dest="disable_modules",
        action="append",
        default=[],
        metavar="MODULE",
        help="Disable a module for this run (e.g. exploit_signals)",
    )
    run_parser.add_argument(
        "--enable",
        dest="enable_modules",
        action="append",
        default=[],
        metavar="MODULE",
        help="Force-enable a module for this run",
    )
    run_parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set environment variables before loading the overlay",
    )
    run_parser.add_argument(
        "--offline",
        action="store_true",
        help="Disable exploit feed auto-refresh to avoid network calls",
    )
    run_parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="Directory to copy the generated evidence bundle into",
    )
    run_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the human-readable summary output",
    )
    run_parser.set_defaults(func=_handle_run)

    overlay_parser = subparsers.add_parser("show-overlay", help="Print the sanitised overlay configuration")
    overlay_parser.add_argument("--overlay", type=Path, default=None, help="Path to an overlay file")
    overlay_parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set environment variables before loading the overlay",
    )
    overlay_parser.add_argument("--pretty", action="store_true", help="Pretty-print the overlay JSON")
    overlay_parser.set_defaults(func=_handle_show_overlay)

    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
