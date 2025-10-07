"""Command-line helpers for running FixOps pipelines locally."""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

from backend.normalizers import InputNormalizer, NormalizedCVEFeed, NormalizedSARIF, NormalizedSBOM
from backend.pipeline import PipelineOrchestrator
from fixops.configuration import OverlayConfig, load_overlay
from fixops.demo_runner import generate_showcase, run_demo_pipeline
from fixops.paths import ensure_secure_directory, verify_allowlisted_path
from fixops.storage import ArtefactArchive
from fixops.probabilistic import ProbabilisticForecastEngine


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


def _load_incident_history(path: Path) -> Sequence[Dict[str, Any]]:
    raw_text = path.read_text(encoding="utf-8")
    payload = json.loads(raw_text)
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        candidates = (
            payload.get("incidents")
            or payload.get("records")
            or payload.get("data")
            or payload.get("history")
        )
        if isinstance(candidates, list):
            records = candidates
        else:
            records = [payload]
    else:
        raise ValueError("Incident history must be a JSON list or object")
    incidents = [record for record in records if isinstance(record, dict)]
    if not incidents:
        raise ValueError("Incident history file did not contain any usable records")
    return incidents


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
    allowlist = overlay.allowed_data_roots or (Path("data").resolve(),)
    for directory in overlay.data_directories.values():
        secure_path = verify_allowlisted_path(directory, allowlist)
        ensure_secure_directory(secure_path)

    archive_dir = overlay.data_directories.get("archive_dir")
    if archive_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        archive_dir = (root / "archive" / overlay.mode).resolve()
    archive_dir = verify_allowlisted_path(archive_dir, allowlist)
    archive = ArtefactArchive(archive_dir, allowlist=allowlist)

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


def _handle_train_forecast(args: argparse.Namespace) -> int:
    config_payload: Dict[str, Any] = {}
    if args.config:
        config_payload = json.loads(args.config.read_text(encoding="utf-8"))
        if not isinstance(config_payload, Mapping):
            raise ValueError("Forecast configuration must be a JSON object")
    incidents = _load_incident_history(args.incidents)
    engine = ProbabilisticForecastEngine(config_payload)
    result = engine.calibrate(incidents, enforce_validation=args.enforce_validation)
    payload = result.to_dict()

    if args.output:
        ensure_secure_directory(args.output.parent)
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2 if args.pretty else None)
            if args.pretty:
                handle.write("\n")

    if not args.quiet:
        metrics = payload["metrics"]
        validation = metrics.get("validation", {})
        print("Probabilistic calibration complete:")
        print(f"  Incidents processed: {metrics.get('incidents')}")
        print(f"  Transition samples: {metrics.get('transition_observations')}")
        print(
            "  Transition matrix validation: "
            + ("passed" if validation.get("valid") else "needs review")
        )

    return 0


def _handle_demo(args: argparse.Namespace) -> int:
    _result, summary_lines = run_demo_pipeline(
        mode=args.mode,
        output_path=args.output,
        pretty=args.pretty,
        include_summary=False,
    )
    if not args.quiet:
        for line in summary_lines:
            print(line)
    if args.output is not None and not args.output.exists():
        raise FileNotFoundError(f"Failed to persist demo output to {args.output}")
    return 0


def _format_table_row(label: str, value: Any, indent: int = 2) -> None:
    prefix = " " * indent
    print(f"{prefix}- {label}: {value}")


def _print_showcase_report(snapshot: Mapping[str, Any]) -> None:
    mode = str(snapshot.get("mode", "demo")).title()
    print(f"FixOps {mode} showcase")

    summary_lines = snapshot.get("summary_lines", [])
    if isinstance(summary_lines, Iterable):
        for line in summary_lines:
            print(f"  {line}")

    print("\n[1] Ingestion & normalisation")
    inputs = snapshot.get("inputs", {})
    if isinstance(inputs, Mapping):
        for key in ("design", "sbom", "sarif", "cve"):
            stage = inputs.get(key, {})
            if not isinstance(stage, Mapping):
                continue
            print(f"- {key.upper()}")
            source = stage.get("source_path")
            if source:
                _format_table_row("source", source)
            metrics = stage.get("metrics", {})
            if isinstance(metrics, Mapping):
                for metric, value in metrics.items():
                    _format_table_row(metric, value)
            preview_key = "preview_rows" if key == "design" else f"sample_{'components' if key == 'sbom' else 'findings' if key == 'sarif' else 'records'}"
            preview = stage.get(preview_key, [])
            if preview:
                _format_table_row("sample", json.dumps(preview, indent=2) if len(str(preview)) < 400 else json.dumps(preview[:1], indent=2))

    print("\n[2] Pipeline stage highlights")
    pipeline = snapshot.get("pipeline", {})
    if isinstance(pipeline, Mapping):
        severity = pipeline.get("severity_overview", {})
        if severity:
            _format_table_row("highest severity", severity.get("highest"))
            _format_table_row("severity counts", severity.get("counts"))
        guardrail = pipeline.get("guardrail_evaluation", {})
        if isinstance(guardrail, Mapping):
            _format_table_row("guardrail status", guardrail.get("status"))
            rationale = guardrail.get("rationale")
            if rationale:
                _format_table_row("rationale", rationale)
        compliance = pipeline.get("compliance_status", {})
        if isinstance(compliance, Mapping):
            frameworks = compliance.get("frameworks")
            if frameworks:
                ids = sorted({framework.get("id", "framework") for framework in frameworks if isinstance(framework, Mapping)})
                _format_table_row("frameworks", ids)
        modules = pipeline.get("modules", {})
        if isinstance(modules, Mapping):
            _format_table_row("modules executed", modules.get("executed"))
            skipped = modules.get("skipped")
            if skipped:
                _format_table_row("modules skipped", skipped)
        analytics = pipeline.get("analytics", {})
        if isinstance(analytics, Mapping):
            overview = analytics.get("overview", {})
            if isinstance(overview, Mapping):
                _format_table_row("ROI (currency)", overview.get("currency"))
                _format_table_row("Estimated value", overview.get("estimated_value"))
        performance = pipeline.get("performance_profile", {})
        if isinstance(performance, Mapping):
            summary = performance.get("summary", {})
            if isinstance(summary, Mapping):
                _format_table_row("Performance status", summary.get("status"))
                _format_table_row("Run latency (ms)", summary.get("total_estimated_latency_ms"))
        forecast = pipeline.get("probabilistic_forecast", {})
        if isinstance(forecast, Mapping):
            _format_table_row("Forecast next state", forecast.get("next_state"))

    print("\n[3] Automation & evidence integrations")
    integrations = snapshot.get("integrations", {})
    if isinstance(integrations, Mapping):
        policy = integrations.get("policy_automation", {})
        if isinstance(policy, Mapping):
            _format_table_row("Policy status", policy.get("status"))
            _format_table_row("Automation actions", policy.get("action_count"))
            if policy.get("sample_actions"):
                _format_table_row("Sample actions", policy.get("sample_actions"))
            if policy.get("delivery_notes"):
                _format_table_row("Delivery notes", policy.get("delivery_notes"))
        bundle = integrations.get("evidence_bundle", {})
        if isinstance(bundle, Mapping):
            _format_table_row("Evidence bundle", bundle.get("path"))
            _format_table_row("Bundle size (bytes)", bundle.get("size_bytes"))
        pricing = integrations.get("pricing_summary", {})
        if isinstance(pricing, Mapping):
            _format_table_row("Pricing plan", pricing.get("plan"))
        onboarding = integrations.get("onboarding", {})
        if isinstance(onboarding, Mapping):
            _format_table_row("Onboarding steps", len(onboarding.get("steps", [])))


def _handle_showcase(args: argparse.Namespace) -> int:
    include_raw = args.save_result is not None
    snapshot = generate_showcase(mode=args.mode, include_raw_result=include_raw)

    raw_result: Optional[Dict[str, Any]] = None
    if include_raw:
        raw_result = snapshot.pop("raw_result", None)

    if args.save_result:
        if raw_result is None:
            raise ValueError("Failed to capture raw pipeline result for showcase export")
        ensure_secure_directory(args.save_result.parent)
        with args.save_result.open("w", encoding="utf-8") as handle:
            json.dump(raw_result, handle, indent=2 if args.pretty else None)
            if args.pretty:
                handle.write("\n")

    if args.output:
        ensure_secure_directory(args.output.parent)
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(snapshot, handle, indent=2 if args.pretty else None)
            if args.pretty:
                handle.write("\n")

    if args.json:
        text = json.dumps(snapshot, indent=2 if args.pretty else None)
        print(text)
    else:
        _print_showcase_report(snapshot)

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

    train_parser = subparsers.add_parser(
        "train-forecast",
        help="Calibrate the probabilistic severity forecast engine using incident history",
    )
    train_parser.add_argument(
        "--incidents",
        type=Path,
        required=True,
        help="Path to a JSON file containing historical incident records",
    )
    train_parser.add_argument(
        "--config",
        type=Path,
        help="Optional JSON file providing the base forecast configuration",
    )
    train_parser.add_argument(
        "--output",
        type=Path,
        help="File to write the calibrated priors and transitions to",
    )
    train_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output when saving calibration results",
    )
    train_parser.add_argument(
        "--enforce-validation",
        action="store_true",
        help="Fail the calibration if the transition matrix does not validate",
    )
    train_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the calibration summary",
    )
    train_parser.set_defaults(func=_handle_train_forecast)

    demo_parser = subparsers.add_parser(
        "demo",
        help="Run the FixOps pipeline with bundled demo or enterprise fixtures",
    )
    demo_parser.add_argument(
        "--mode",
        choices=["demo", "enterprise"],
        default="demo",
        help="Overlay profile to apply when running the bundled fixtures",
    )
    demo_parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write the pipeline response JSON",
    )
    demo_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output when saving to disk",
    )
    demo_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the demo summary",
    )
    demo_parser.set_defaults(func=_handle_demo)

    showcase_parser = subparsers.add_parser(
        "showcase",
        help="Simulate each pipeline stage and surface representative inputs/outputs",
    )
    showcase_parser.add_argument(
        "--mode",
        choices=["demo", "enterprise"],
        default="demo",
        help="Overlay profile to use when generating the showcase snapshot",
    )
    showcase_parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON file capturing the structured showcase snapshot",
    )
    showcase_parser.add_argument(
        "--save-result",
        type=Path,
        help="Optional JSON file containing the full pipeline response for inspection",
    )
    showcase_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the showcase snapshot as JSON instead of the formatted report",
    )
    showcase_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON when using --json, --output, or --save-result",
    )
    showcase_parser.set_defaults(func=_handle_showcase)

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
