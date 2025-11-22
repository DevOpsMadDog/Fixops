"""Command-line helpers for running FixOps pipelines locally."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path

ENTERPRISE_SRC = Path(__file__).resolve().parent.parent / "fixops-enterprise"
if ENTERPRISE_SRC.exists():
    enterprise_path = str(ENTERPRISE_SRC)
    if enterprise_path not in sys.path:
        sys.path.insert(0, enterprise_path)
from typing import TYPE_CHECKING, Any, Dict, Iterable, Mapping, Optional, Sequence

if TYPE_CHECKING:
    from src.services import id_allocator, signing  # noqa: F401
    from src.services.run_registry import RunRegistry  # noqa: F401
    from apps.api.normalizers import (  # noqa: F401
        InputNormalizer,
        NormalizedCVEFeed,
        NormalizedSARIF,
        NormalizedSBOM,
    )
    from apps.api.pipeline import PipelineOrchestrator  # noqa: F401
    from core.configuration import OverlayConfig  # noqa: F401
    from core.demo_runner import run_demo_pipeline  # noqa: F401
    from core.evidence import EvidenceHub  # noqa: F401
    from core.probabilistic import ProbabilisticForecastEngine  # noqa: F401
    from core.processing_layer import ProcessingLayer  # noqa: F401
    from core.stage_runner import StageRunner  # noqa: F401
    from core.storage import ArtefactArchive  # noqa: F401

from core.overlay_runtime import prepare_overlay
from core.paths import (
    ensure_output_directory,
    ensure_secure_directory,
    verify_allowlisted_path,
)


def _apply_env_overrides(pairs: Iterable[str]) -> None:
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(
                f"Environment override '{pair}' must be in KEY=VALUE format"
            )
        key, value = pair.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError("Environment override requires a non-empty key")
        if not key.replace("_", "").isalnum():
            raise ValueError(
                f"Environment variable name '{key}' contains invalid characters"
            )
        os.environ[key] = value


def _load_design(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = [
            row
            for row in reader
            if any((value or "").strip() for value in row.values())
        ]
    if not rows:
        raise ValueError(f"Design CSV '{path}' contained no usable rows")
    return {"columns": reader.fieldnames or [], "rows": rows}


def _load_file(path: Optional[Path]) -> Optional[bytes]:
    if path is None:
        return None
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")
    return path.read_bytes()


def _load_inputs(
    normalizer: InputNormalizer,
    design_path: Optional[Path],
    sbom_path: Optional[Path],
    sarif_path: Optional[Path],
    cve_path: Optional[Path],
    vex_path: Optional[Path],
    cnapp_path: Optional[Path],
    context_path: Optional[Path],
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

    if vex_path is not None:
        payload["vex"] = normalizer.load_vex(_load_file(vex_path) or b"")

    if cnapp_path is not None:
        payload["cnapp"] = normalizer.load_cnapp(_load_file(cnapp_path) or b"")

    if context_path is not None:
        raw_bytes = _load_file(context_path) or b""
        payload["context"] = normalizer.load_business_context(
            raw_bytes, content_type=None
        )

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
            "Overlay requires artefacts that were not provided: "
            + ", ".join(sorted(set(missing)))
        )

    sbom: NormalizedSBOM = inputs["sbom"]
    sarif: NormalizedSARIF = inputs["sarif"]
    cve: NormalizedCVEFeed = inputs["cve"]
    design_dataset = inputs.get("design", {"columns": [], "rows": []})
    prepared: Dict[str, Any] = {
        "design_dataset": design_dataset,
        "sbom": sbom,
        "sarif": sarif,
        "cve": cve,
    }
    if "vex" in inputs:
        prepared["vex"] = inputs["vex"]
    if "cnapp" in inputs:
        prepared["cnapp"] = inputs["cnapp"]
    if "context" in inputs:
        prepared["context"] = inputs["context"]
    return prepared


def _set_module_enabled(overlay: OverlayConfig, module: str, enabled: bool) -> None:
    current = overlay.modules.get(module)
    if isinstance(current, dict):
        current["enabled"] = enabled
    else:
        overlay.modules[module] = {"enabled": enabled}


def _copy_evidence(
    result: Dict[str, Any], destination: Optional[Path]
) -> Optional[Path]:
    if destination is None:
        return None
    evidence_bundle = result.get("evidence_bundle")
    if not isinstance(evidence_bundle, dict):
        return None
    files = evidence_bundle.get("files")
    if not isinstance(files, dict):
        return None
    bundle = files.get("bundle")
    if not bundle:
        return None
    bundle_path = Path(bundle)

    bundle_id = evidence_bundle.get("bundle_id")
    if bundle_id:
        target_dir = destination / str(bundle_id)
    else:
        target_dir = destination

    ensure_secure_directory(target_dir)

    target = target_dir / bundle_path.name
    target.write_bytes(bundle_path.read_bytes())

    manifest = files.get("manifest")
    if manifest:
        manifest_path = Path(manifest)
        if manifest_path.exists():
            manifest_target = target_dir / "manifest.json"
            manifest_target.write_bytes(manifest_path.read_bytes())

    return target


def _build_pipeline_result(args: argparse.Namespace) -> Dict[str, Any]:
    from apps.api.normalizers import InputNormalizer  # noqa: F811
    from apps.api.pipeline import PipelineOrchestrator  # noqa: F811
    from core.storage import ArtefactArchive  # noqa: F811

    if getattr(args, "env", None):
        _apply_env_overrides(args.env)

    if getattr(args, "signing_provider", None):
        os.environ["SIGNING_PROVIDER"] = args.signing_provider
    if getattr(args, "signing_key_id", None):
        os.environ["KEY_ID"] = args.signing_key_id
    if getattr(args, "signing_region", None):
        os.environ["AWS_REGION"] = args.signing_region
    if getattr(args, "azure_vault_url", None):
        os.environ["AZURE_VAULT_URL"] = args.azure_vault_url
    if getattr(args, "rotation_sla_days", None) is not None:
        os.environ["SIGNING_ROTATION_SLA_DAYS"] = str(args.rotation_sla_days)
    if getattr(args, "opa_url", None):
        os.environ["OPA_SERVER_URL"] = args.opa_url
    if getattr(args, "opa_token", None):
        os.environ["OPA_AUTH_TOKEN"] = args.opa_token
    if getattr(args, "opa_package", None):
        os.environ["OPA_POLICY_PACKAGE"] = args.opa_package
    if getattr(args, "opa_health_path", None):
        os.environ["OPA_HEALTH_PATH"] = args.opa_health_path
    if getattr(args, "opa_bundle_status_path", None):
        os.environ["OPA_BUNDLE_STATUS_PATH"] = args.opa_bundle_status_path
    if getattr(args, "opa_timeout", None) is not None:
        os.environ["OPA_REQUEST_TIMEOUT"] = str(args.opa_timeout)
    if getattr(args, "enable_rl", False):
        os.environ["ENABLE_RL_EXPERIMENTS"] = "true"
    if getattr(args, "enable_shap", False):
        os.environ["ENABLE_SHAP_EXPERIMENTS"] = "true"

    overlay = prepare_overlay(path=args.overlay, ensure_directories=False)
    if getattr(args, "disable_modules", None):
        for module in args.disable_modules:
            _set_module_enabled(overlay, module, False)
    if getattr(args, "enable_modules", None):
        for module in args.enable_modules:
            _set_module_enabled(overlay, module, True)
    if getattr(args, "offline", False):
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
        vex_path=args.vex,
        cnapp_path=getattr(args, "cnapp", None),
        context_path=getattr(args, "context", None),
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
            archive_records["design"] = archive.persist(  # type: ignore[assignment]
                "design",
                prepared["design_dataset"],
                original_filename=args.design.name,
                raw_bytes=args.design.read_bytes(),
            )
        if args.sbom is not None:
            archive_records["sbom"] = archive.persist(  # type: ignore[assignment]
                "sbom",
                prepared["sbom"],
                original_filename=args.sbom.name,
                raw_bytes=args.sbom.read_bytes(),
            )
        if args.sarif is not None:
            archive_records["sarif"] = archive.persist(  # type: ignore[assignment]
                "sarif",
                prepared["sarif"],
                original_filename=args.sarif.name,
                raw_bytes=args.sarif.read_bytes(),
            )
        if args.cve is not None:
            archive_records["cve"] = archive.persist(  # type: ignore[assignment]
                "cve",
                prepared["cve"],
                original_filename=args.cve.name,
                raw_bytes=args.cve.read_bytes(),
            )
        if getattr(args, "vex", None) is not None and "vex" in prepared:
            archive_records["vex"] = archive.persist(  # type: ignore[assignment]
                "vex",
                prepared["vex"],
                original_filename=args.vex.name,
                raw_bytes=args.vex.read_bytes(),
            )
        if getattr(args, "cnapp", None) is not None and "cnapp" in prepared:
            archive_records["cnapp"] = archive.persist(  # type: ignore[assignment]
                "cnapp",
                prepared["cnapp"],
                original_filename=args.cnapp.name,
                raw_bytes=args.cnapp.read_bytes(),
            )
        if getattr(args, "context", None) is not None and "context" in prepared:
            archive_records["context"] = archive.persist(  # type: ignore[assignment]
                "context",
                prepared["context"],
                original_filename=args.context.name,
                raw_bytes=args.context.read_bytes(),
            )
    except Exception as exc:  # pragma: no cover - archival should not abort CLI runs
        print(f"Warning: failed to persist artefacts locally: {exc}", file=sys.stderr)

    result = orchestrator.run(
        overlay=overlay,
        vex=prepared.get("vex"),
        cnapp=prepared.get("cnapp"),
        context=prepared.get("context"),
        **{
            key: value
            for key, value in prepared.items()
            if key not in {"vex", "cnapp", "context"}
        },
    )
    if getattr(args, "include_overlay", False):
        result["overlay"] = overlay.to_sanitised_dict()

    if archive_records:
        result["artifact_archive"] = ArtefactArchive.summarise(archive_records)

    return result


def _write_output(path: Path, payload: Mapping[str, Any], *, pretty: bool) -> None:
    ensure_output_directory(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2 if pretty else None)
        if pretty:
            handle.write("\n")


def _handle_ingest(args: argparse.Namespace) -> int:
    result = _build_pipeline_result(args)

    output_path: Optional[Path] = getattr(args, "output", None)
    if output_path is not None:
        output_path = output_path.expanduser().resolve()
        _write_output(output_path, result, pretty=getattr(args, "pretty", False))
    else:
        payload = json.dumps(
            result, indent=2 if getattr(args, "pretty", False) else None
        )
        print(payload)

    _copy_evidence(result, getattr(args, "evidence_dir", None))
    return 0


def _derive_decision_exit(result: Mapping[str, Any]) -> tuple[str, int]:
    decision = (
        str(result.get("enhanced_decision", {}).get("final_decision") or "")
        .strip()
        .lower()
    )
    if not decision:
        decision = str(
            result.get("guardrail_evaluation", {}).get("status") or "defer"
        ).lower()

    if not decision:
        decision = "unknown"

    mapping = {
        "allow": 0,
        "pass": 0,
        "ok": 0,
        "block": 1,
        "fail": 1,
        "defer": 2,
        "warn": 2,
        "unknown": 2,
    }
    exit_code = mapping.get(decision, 2)

    if decision not in mapping:
        print(
            f"Warning: Unknown decision value '{decision}', defaulting to exit code 2 (defer)",
            file=sys.stderr,
        )

    return decision, exit_code


def _handle_make_decision(args: argparse.Namespace) -> int:
    result = _build_pipeline_result(args)
    decision, exit_code = _derive_decision_exit(result)

    output_path: Optional[Path] = getattr(args, "output", None)
    if output_path is not None:
        output_path = output_path.expanduser().resolve()
        _write_output(output_path, result, pretty=getattr(args, "pretty", False))

    _copy_evidence(result, getattr(args, "evidence_dir", None))

    summary = {
        "decision": decision,
        "exit_code": exit_code,
        "confidence": result.get("enhanced_decision", {}).get("consensus_confidence"),
        "severity": result.get("severity_overview", {}).get("highest"),
        "guardrail": result.get("guardrail_evaluation", {}).get("status"),
    }
    print(json.dumps(summary, indent=2 if getattr(args, "pretty", False) else None))
    return exit_code


def _handle_analyze(args: argparse.Namespace) -> int:
    """Handle analyze command with flexible input requirements."""
    import tempfile

    temp_files = []

    if not hasattr(args, "design") or args.design is None:
        dummy_design = tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        )
        dummy_design.write(
            "component_name,component_type,criticality,internet_facing,authentication_required\n"
        )
        dummy_design.write("default-service,service,medium,false,false\n")
        dummy_design.close()
        args.design = Path(dummy_design.name)
        temp_files.append(dummy_design.name)

    if not hasattr(args, "sbom") or args.sbom is None:
        dummy_sbom = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        dummy_sbom.write(
            '{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}'
        )
        dummy_sbom.close()
        args.sbom = Path(dummy_sbom.name)
        temp_files.append(dummy_sbom.name)

    if not hasattr(args, "cve") or args.cve is None:
        dummy_cve = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        dummy_cve.write('{"vulnerabilities":[]}')
        dummy_cve.close()
        args.cve = Path(dummy_cve.name)
        temp_files.append(dummy_cve.name)

    try:
        result = _build_pipeline_result(args)
    finally:
        for temp_file in temp_files:
            try:
                Path(temp_file).unlink()
            except Exception:
                pass
    decision, exit_code = _derive_decision_exit(result)

    output_path: Optional[Path] = getattr(args, "output", None)
    if output_path is not None:
        output_path = output_path.expanduser().resolve()
        _write_output(output_path, result, pretty=getattr(args, "pretty", False))

    _copy_evidence(result, getattr(args, "evidence_dir", None))

    enhanced_decision = result.get("enhanced_decision", {})
    telemetry = enhanced_decision.get("telemetry", {})
    summary = {
        "verdict": decision,
        "confidence": enhanced_decision.get("consensus_confidence"),
        "severity": result.get("severity_overview", {}).get("highest"),
        "guardrail": result.get("guardrail_evaluation", {}).get("status"),
        "decision_strategy": telemetry.get("decision_strategy"),
        "raw_risk": telemetry.get("raw_risk"),
        "adjusted_risk": telemetry.get("adjusted_risk"),
        "exposure_multiplier": telemetry.get("exposure_multiplier"),
    }

    format_type = getattr(args, "format", "json")
    if format_type == "json":
        print(json.dumps(summary, indent=2 if getattr(args, "pretty", False) else None))
    else:
        print(f"Verdict: {decision}")
        print(f"Confidence: {summary.get('confidence')}")
        print(f"Severity: {summary.get('severity')}")

    return exit_code


def _handle_health(args: argparse.Namespace) -> int:
    from core.evidence import EvidenceHub  # noqa: F811
    from core.processing_layer import ProcessingLayer  # noqa: F811

    overlay = prepare_overlay(path=args.overlay, ensure_directories=False)
    processing = ProcessingLayer()
    health: Dict[str, Any] = {
        "overlay_mode": overlay.mode,
        "pgmpy_available": processing.pgmpy_available,
        "pomegranate_available": processing.pomegranate_available,
        "mchmm_available": processing.mchmm_available,
    }
    try:
        evidence = EvidenceHub(overlay)
    except Exception as exc:
        health["evidence_ready"] = False
        health["evidence_error"] = str(exc)
    else:
        health["evidence_ready"] = True
        health["evidence_retention_days"] = getattr(evidence, "retention_days", None)
    opa_settings = (
        overlay.policy_settings.get("opa")
        if isinstance(overlay.policy_settings, Mapping)
        else {}
    )
    health["opa_configured"] = bool(opa_settings and opa_settings.get("url"))
    print(
        json.dumps(
            {"status": "ok", "checks": health}, indent=2 if args.pretty else None
        )
    )
    return 0


def _handle_get_evidence(args: argparse.Namespace) -> int:
    result_path: Path = args.result.expanduser().resolve()
    if not result_path.exists():
        print(f"Error: result file {result_path} not found", file=sys.stderr)
        return 1
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    bundle_section = payload.get("evidence_bundle")
    if not isinstance(bundle_section, Mapping):
        print("Error: evidence bundle not available in result", file=sys.stderr)
        return 1
    files_section = bundle_section.get("files")
    if not isinstance(files_section, Mapping):
        print("Error: evidence bundle files missing", file=sys.stderr)
        return 1
    bundle_path = files_section.get("bundle")
    if not bundle_path:
        print("Error: bundle path missing", file=sys.stderr)
        return 1
    source = Path(bundle_path).expanduser().resolve()
    if not source.exists():
        print(f"Error: bundle {source} does not exist", file=sys.stderr)
        return 1
    destination = (
        args.destination.expanduser().resolve() if args.destination else Path.cwd()
    )
    ensure_secure_directory(destination)
    target = destination / source.name
    target.write_bytes(source.read_bytes())
    print(
        json.dumps(
            {"status": "ok", "bundle": str(target)}, indent=2 if args.pretty else None
        )
    )
    return 0


def _handle_stage_run(args: argparse.Namespace) -> int:
    from src.services import id_allocator, signing  # noqa: F811
    from src.services.run_registry import RunRegistry  # noqa: F811

    from core.stage_runner import StageRunner  # noqa: F811

    input_path: Optional[Path] = args.input
    if input_path is not None:
        input_path = input_path.expanduser().resolve()
        if not input_path.exists():
            raise FileNotFoundError(input_path)

    output_path: Optional[Path] = args.output
    if output_path is not None:
        output_path = output_path.expanduser().resolve()

    if args.sign and not (
        os.environ.get("FIXOPS_SIGNING_KEY") and os.environ.get("FIXOPS_SIGNING_KID")
    ):
        print(
            "Signing requested but FIXOPS_SIGNING_KEY/FIXOPS_SIGNING_KID not set; proceeding without signatures."
        )

    registry = RunRegistry()
    runner = StageRunner(registry, id_allocator, signing)
    summary = runner.run_stage(
        args.stage,
        input_path,
        app_name=args.app,
        app_id=None,
        output_path=output_path,
        mode=args.mode,
        sign=args.sign,
        verify=args.verify,
        verbose=args.verbose,
    )

    try:
        output_relative = summary.output_file.relative_to(Path.cwd())
    except ValueError:
        output_relative = summary.output_file
    print(f"✅ Stage {summary.stage} complete → wrote {output_relative}")
    print(f"   app_id={summary.app_id} run_id={summary.run_id}")
    if output_path is not None:
        print(f"   Copied output to: {output_path}")
    if summary.signatures:
        joined = ", ".join(path.name for path in summary.signatures)
        print(f"   Signed manifests: {joined}")
    if summary.transparency_index:
        print(f"   Transparency index: {summary.transparency_index}")
    if summary.verified is not None:
        status = "passed" if summary.verified else "failed"
        print(f"   Signature verification {status}")
    if summary.bundle:
        print(f"   Evidence bundle: {summary.bundle}")

    return 0


def _configure_pipeline_parser(
    parser: argparse.ArgumentParser,
    *,
    include_quiet: bool = False,
    include_overlay_flag: bool = True,
) -> None:
    parser.add_argument(
        "--overlay",
        type=Path,
        default=None,
        help="Path to an overlay file (defaults to repository overlay)",
    )
    parser.add_argument("--design", type=Path, help="Path to design CSV artefact")
    parser.add_argument(
        "--sbom", type=Path, required=True, help="Path to SBOM JSON artefact"
    )
    parser.add_argument(
        "--sarif", type=Path, required=True, help="Path to SARIF JSON artefact"
    )
    parser.add_argument(
        "--cve", type=Path, required=True, help="Path to CVE/KEV JSON artefact"
    )
    parser.add_argument(
        "--vex",
        type=Path,
        help="Optional path to a CycloneDX VEX document used for noise reduction",
    )
    parser.add_argument(
        "--cnapp",
        type=Path,
        help="Optional path to CNAPP findings JSON for threat-path enrichment",
    )
    parser.add_argument(
        "--context",
        type=Path,
        help="Optional FixOps.yaml, OTM.json, or SSVC YAML business context artefact",
    )
    parser.add_argument(
        "--output", type=Path, help="Location to write the pipeline result JSON"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output when saving to disk",
    )
    if include_overlay_flag:
        parser.add_argument(
            "--include-overlay",
            action="store_true",
            help="Attach the sanitised overlay to the result payload",
        )
    parser.add_argument(
        "--disable",
        dest="disable_modules",
        action="append",
        default=[],
        metavar="MODULE",
        help="Disable a module for this run (e.g. exploit_signals)",
    )
    parser.add_argument(
        "--enable",
        dest="enable_modules",
        action="append",
        default=[],
        metavar="MODULE",
        help="Force-enable a module for this run",
    )
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set environment variables before loading the overlay",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Disable exploit feed auto-refresh to avoid network calls",
    )
    parser.add_argument(
        "--signing-provider",
        choices=["env", "aws_kms", "azure_key_vault"],
        help="Override the signing backend provider for this run",
    )
    parser.add_argument(
        "--signing-key-id",
        help="Signing key alias or identifier when using remote providers",
    )
    parser.add_argument("--signing-region", help="AWS region to use when invoking KMS")
    parser.add_argument(
        "--azure-vault-url", help="Azure Key Vault URL for remote signing"
    )
    parser.add_argument(
        "--rotation-sla-days",
        type=int,
        help="Override the signing key rotation SLA in days",
    )
    parser.add_argument(
        "--opa-url", help="Override the OPA server URL for remote policy checks"
    )
    parser.add_argument(
        "--opa-token", help="Bearer token for authenticating with the OPA server"
    )
    parser.add_argument(
        "--opa-package", help="OPA policy package to query (e.g. core.policies)"
    )
    parser.add_argument("--opa-health-path", help="Custom OPA health endpoint path")
    parser.add_argument(
        "--opa-bundle-status-path",
        help="OPA bundle status endpoint for readiness checks",
    )
    parser.add_argument(
        "--opa-timeout", type=int, help="Timeout in seconds for OPA requests"
    )
    parser.add_argument(
        "--enable-rl",
        action="store_true",
        help="Enable reinforcement learning experiments for this run",
    )
    parser.add_argument(
        "--enable-shap",
        action="store_true",
        help="Enable SHAP explainability experiments for this run",
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="Directory to copy the generated evidence bundle into",
    )
    if include_quiet:
        parser.add_argument(
            "--quiet",
            action="store_true",
            help="Suppress the human-readable summary output",
        )


def _print_summary(
    result: Dict[str, Any], output: Optional[Path], evidence_path: Optional[Path]
) -> None:
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

    product_name = "FixOps"
    branding = result.get("branding")
    if isinstance(branding, dict):
        product_name = branding.get("product_name", "FixOps")

    print(f"{product_name} pipeline summary:")
    print(f"  Highest severity: {highest}")
    print(f"  Guardrail status: {guardrail_status}")
    if frameworks:
        joined = ", ".join(
            sorted(
                {
                    framework.get("id", "framework")
                    for framework in frameworks
                    if isinstance(framework, dict)
                }
            )
        )
        print(f"  Compliance frameworks satisfied: {joined}")
    pricing_plan = pricing.get("plan")
    if pricing_plan:
        print(f"  Pricing plan: {pricing_plan}")
    if executed:
        print(f"  Modules executed: {', '.join(executed)}")
    noise_reduction = result.get("noise_reduction")
    if isinstance(noise_reduction, Mapping):
        suppressed_total = noise_reduction.get("suppressed_total")
        if suppressed_total:
            print(f"  VEX noise reduction suppressed {suppressed_total} findings")
    cnapp_summary = result.get("cnapp_summary")
    if isinstance(cnapp_summary, Mapping):
        added = cnapp_summary.get("added_severity")
        if isinstance(added, Mapping):
            added_total = sum(int(value) for value in added.values())
            if added_total:
                print(f"  CNAPP findings added: {added_total}")
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
            print(f"  Performance status: {status} (approx {total_latency} ms per run)")
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
    runtime_warnings = result.get("runtime_warnings")
    if isinstance(runtime_warnings, Sequence) and runtime_warnings:
        print("  Runtime warnings:")
        for warning in runtime_warnings:
            print(f"    - {warning}")


def _handle_run(args: argparse.Namespace) -> int:
    result = _build_pipeline_result(args)

    output_path: Optional[Path] = args.output
    if output_path:
        _write_output(output_path, result, pretty=args.pretty)

    copied_bundle = _copy_evidence(result, getattr(args, "evidence_dir", None))

    if not getattr(args, "quiet", False):
        _print_summary(result, output_path, copied_bundle)

    return 0


def _handle_show_overlay(args: argparse.Namespace) -> int:
    if args.env:
        _apply_env_overrides(args.env)
    overlay = prepare_overlay(path=args.overlay, ensure_directories=False)
    metadata = getattr(overlay, "metadata", {}) or {}
    warnings = metadata.get("runtime_warnings")
    if isinstance(warnings, Sequence) and warnings:
        for warning in warnings:
            print(f"Warning: {warning}", file=sys.stderr)
    payload = overlay.to_sanitised_dict()
    text = json.dumps(payload, indent=2 if args.pretty else None)
    print(text)
    return 0


def _handle_train_forecast(args: argparse.Namespace) -> int:
    from core.probabilistic import ProbabilisticForecastEngine  # noqa: F811

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
        ensure_output_directory(args.output.parent)
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
    from core.demo_runner import run_demo_pipeline  # noqa: F811

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


def _handle_train_bn_lr(args: argparse.Namespace) -> int:
    import numpy as np
    import pandas as pd

    from core.bn_lr import save_model, train

    data_path = args.data
    if not data_path.exists():
        raise FileNotFoundError(f"Training data not found: {data_path}")

    df = pd.read_csv(data_path)

    required_columns = [
        "bn_p_low",
        "bn_p_medium",
        "bn_p_high",
        "bn_p_critical",
        "label",
    ]
    missing = set(required_columns) - set(df.columns)
    if missing:
        raise ValueError(f"Training data missing required columns: {missing}")

    X = df[["bn_p_low", "bn_p_medium", "bn_p_high", "bn_p_critical"]].values
    y = df["label"].values

    if not args.quiet:
        print(f"Training BN-LR model on {len(X)} samples...")
        print(f"  Positive samples: {np.sum(y)}")
        print(f"  Negative samples: {len(y) - np.sum(y)}")

    model, metadata = train(X, y)

    output_path = args.output
    save_model(model, metadata, output_path)

    if not args.quiet:
        print(f"Model saved to {output_path}")
        print(f"  BN CPD hash: {metadata['bn_cpd_hash'][:16]}...")
        print(f"  Calibration: {metadata['calibration_method']}")
        print(f"  Trained at: {metadata['trained_at']}")

    return 0


def _handle_predict_bn_lr(args: argparse.Namespace) -> int:
    from core.bn_lr import extract_bn_posteriors, load_model, predict_proba

    model_path = args.model
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")

    context_path = args.context
    if not context_path.exists():
        raise FileNotFoundError(f"Context file not found: {context_path}")

    with open(context_path, "r") as f:
        context = json.load(f)

    model, metadata = load_model(model_path, verify_cpd_hash=not args.allow_skew)

    features = extract_bn_posteriors(context)
    probability = predict_proba(model, features)

    result = {
        "risk_probability": probability,
        "bn_posteriors": {
            "low": features[0],
            "medium": features[1],
            "high": features[2],
            "critical": features[3],
        },
        "model_metadata": {
            "bn_cpd_hash": metadata["bn_cpd_hash"],
            "trained_at": metadata["trained_at"],
            "calibration_method": metadata["calibration_method"],
        },
    }

    if args.output:
        ensure_output_directory(args.output.parent)
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2 if args.pretty else None)
            if args.pretty:
                handle.write("\n")

    if not args.quiet:
        print(f"Risk probability: {probability:.4f}")
        print(
            f"BN posteriors: low={features[0]:.3f}, med={features[1]:.3f}, "
            f"high={features[2]:.3f}, crit={features[3]:.3f}"
        )

    return 0


def _handle_backtest_bn_lr(args: argparse.Namespace) -> int:
    import pandas as pd

    from core.bn_lr import backtest, load_model

    model_path = args.model
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")

    data_path = args.data
    if not data_path.exists():
        raise FileNotFoundError(f"Test data not found: {data_path}")

    model, metadata = load_model(model_path, verify_cpd_hash=not args.allow_skew)

    df = pd.read_csv(data_path)
    required_columns = [
        "bn_p_low",
        "bn_p_medium",
        "bn_p_high",
        "bn_p_critical",
        "label",
    ]
    missing = set(required_columns) - set(df.columns)
    if missing:
        raise ValueError(f"Test data missing required columns: {missing}")

    X_test = df[["bn_p_low", "bn_p_medium", "bn_p_high", "bn_p_critical"]].values
    y_test = df["label"].values

    thresholds = (
        [0.6, 0.85]
        if not args.thresholds
        else [float(t) for t in args.thresholds.split(",")]
    )

    metrics = backtest(model, X_test, y_test, thresholds=thresholds)

    if args.output:
        ensure_output_directory(args.output.parent)
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(metrics, handle, indent=2 if args.pretty else None)
            if args.pretty:
                handle.write("\n")

    if not args.quiet:
        print(f"Backtest results on {metrics['n_samples']} samples:")
        print(f"  Accuracy: {metrics['accuracy']:.4f}")
        print(f"  ROC-AUC: {metrics['roc_auc']:.4f}")
        print(f"  Positive samples: {metrics['n_positive']}")
        print(f"  Negative samples: {metrics['n_negative']}")
        print("  Threshold metrics:")
        for threshold, threshold_metrics in metrics["thresholds"].items():
            print(
                f"    {threshold}: precision={threshold_metrics['precision']:.4f}, "
                f"recall={threshold_metrics['recall']:.4f}"
            )

    return 0


def _handle_users(args):
    """Handle user management commands."""
    import json

    from core.user_db import UserDB
    from core.user_models import User, UserRole, UserStatus

    db = UserDB()

    if args.user_command == "list":
        users = db.list_users(limit=args.limit, offset=args.offset)
        if args.format == "json":
            print(json.dumps([u.to_dict() for u in users], indent=2))
        else:
            print(f"{'ID':<40} {'Email':<30} {'Role':<20} {'Status':<12}")
            print("-" * 110)
            for user in users:
                print(
                    f"{user.id:<40} {user.email:<30} {user.role.value:<20} {user.status.value:<12}"
                )

    elif args.user_command == "create":
        user = User(
            id="",
            email=args.email,
            password_hash=db.hash_password(args.password),
            first_name=args.first_name,
            last_name=args.last_name,
            role=UserRole(args.role),
            status=UserStatus.ACTIVE,
            department=args.department,
        )
        created = db.create_user(user)
        print(f"✅ Created user: {created.id}")
        print(json.dumps(created.to_dict(), indent=2))

    elif args.user_command == "get":
        user = db.get_user(args.id)
        if not user:
            print(f"❌ User not found: {args.id}")
            return 1
        print(json.dumps(user.to_dict(), indent=2))

    elif args.user_command == "update":
        user = db.get_user(args.id)
        if not user:
            print(f"❌ User not found: {args.id}")
            return 1

        if args.first_name:
            user.first_name = args.first_name
        if args.last_name:
            user.last_name = args.last_name
        if args.role:
            user.role = UserRole(args.role)
        if args.status:
            user.status = UserStatus(args.status)

        updated = db.update_user(user)
        print(f"✅ Updated user: {updated.id}")
        print(json.dumps(updated.to_dict(), indent=2))

    elif args.user_command == "delete":
        if not args.confirm:
            print("❌ Please use --confirm to delete")
            return 1
        if db.delete_user(args.id):
            print(f"✅ Deleted user: {args.id}")
        else:
            print(f"❌ Failed to delete user: {args.id}")
            return 1

    return 0


def _handle_teams(args):
    """Handle team management commands."""
    import json

    from core.user_db import UserDB
    from core.user_models import Team

    db = UserDB()

    if args.team_command == "list":
        teams = db.list_teams(limit=args.limit, offset=args.offset)
        if args.format == "json":
            print(json.dumps([t.to_dict() for t in teams], indent=2))
        else:
            print(f"{'ID':<40} {'Name':<30} {'Description':<50}")
            print("-" * 125)
            for team in teams:
                desc = (
                    team.description[:47] + "..."
                    if len(team.description) > 50
                    else team.description
                )
                print(f"{team.id:<40} {team.name:<30} {desc:<50}")

    elif args.team_command == "create":
        team = Team(id="", name=args.name, description=args.description)
        created = db.create_team(team)
        print(f"✅ Created team: {created.id}")
        print(json.dumps(created.to_dict(), indent=2))

    elif args.team_command == "get":
        team = db.get_team(args.id)
        if not team:
            print(f"❌ Team not found: {args.id}")
            return 1
        print(json.dumps(team.to_dict(), indent=2))

    elif args.team_command == "update":
        team = db.get_team(args.id)
        if not team:
            print(f"❌ Team not found: {args.id}")
            return 1

        if args.name:
            team.name = args.name
        if args.description:
            team.description = args.description

        updated = db.update_team(team)
        print(f"✅ Updated team: {updated.id}")
        print(json.dumps(updated.to_dict(), indent=2))

    elif args.team_command == "delete":
        if not args.confirm:
            print("❌ Please use --confirm to delete")
            return 1
        if db.delete_team(args.id):
            print(f"✅ Deleted team: {args.id}")
        else:
            print(f"❌ Failed to delete team: {args.id}")
            return 1

    elif args.team_command == "members":
        members = db.list_team_members(args.id)
        print(json.dumps(members, indent=2))

    elif args.team_command == "add-member":
        member = db.add_team_member(args.id, args.user_id, args.role)
        print(f"✅ Added user {args.user_id} to team {args.id}")
        print(json.dumps(member.to_dict(), indent=2))

    elif args.team_command == "remove-member":
        if db.remove_team_member(args.id, args.user_id):
            print(f"✅ Removed user {args.user_id} from team {args.id}")
        else:
            print("❌ Failed to remove user from team")
            return 1

    return 0


def _handle_policies(args):
    """Handle policy management commands."""
    import json

    from core.policy_db import PolicyDB
    from core.policy_models import Policy, PolicyStatus

    db = PolicyDB()

    if args.policy_command == "list":
        policies = db.list_policies(
            policy_type=args.type, limit=args.limit, offset=args.offset
        )
        if args.format == "json":
            print(json.dumps([p.to_dict() for p in policies], indent=2))
        else:
            print(f"{'ID':<40} {'Name':<30} {'Type':<15} {'Status':<12}")
            print("-" * 105)
            for policy in policies:
                print(
                    f"{policy.id:<40} {policy.name:<30} {policy.policy_type:<15} {policy.status.value:<12}"
                )

    elif args.policy_command == "create":
        policy = Policy(
            id="",
            name=args.name,
            description=args.description,
            policy_type=args.type,
            status=PolicyStatus(args.status),
            rules=json.loads(args.rules) if args.rules else {},
        )
        created = db.create_policy(policy)
        print(f"✅ Created policy: {created.id}")
        print(json.dumps(created.to_dict(), indent=2))

    elif args.policy_command == "get":
        policy = db.get_policy(args.id)
        if not policy:
            print(f"❌ Policy not found: {args.id}")
            return 1
        print(json.dumps(policy.to_dict(), indent=2))

    elif args.policy_command == "update":
        policy = db.get_policy(args.id)
        if not policy:
            print(f"❌ Policy not found: {args.id}")
            return 1

        if args.name:
            policy.name = args.name
        if args.description:
            policy.description = args.description
        if args.type:
            policy.policy_type = args.type
        if args.status:
            policy.status = PolicyStatus(args.status)

        updated = db.update_policy(policy)
        print(f"✅ Updated policy: {updated.id}")
        print(json.dumps(updated.to_dict(), indent=2))

    elif args.policy_command == "delete":
        if not args.confirm:
            print("❌ Please use --confirm to delete")
            return 1
        if db.delete_policy(args.id):
            print(f"✅ Deleted policy: {args.id}")
        else:
            print(f"❌ Failed to delete policy: {args.id}")
            return 1

    return 0


def _handle_inventory(args):
    """Handle inventory management commands."""
    import json

    from core.inventory_db import InventoryDB
    from core.inventory_models import (
        Application,
        ApplicationCriticality,
        ApplicationStatus,
    )

    db = InventoryDB()

    if args.inventory_command == "list":
        apps = db.list_applications(limit=args.limit, offset=args.offset)
        if args.format == "json":
            print(json.dumps([app.to_dict() for app in apps], indent=2))
        else:
            print(f"{'ID':<40} {'Name':<30} {'Criticality':<12} {'Status':<12}")
            print("-" * 100)
            for app in apps:
                print(
                    f"{app.id:<40} {app.name:<30} {app.criticality.value:<12} {app.status.value:<12}"
                )

    elif args.inventory_command == "create":
        app = Application(
            id="",
            name=args.name,
            description=args.description,
            criticality=ApplicationCriticality(args.criticality),
            status=ApplicationStatus.ACTIVE,
            environment=args.environment,
            owner_team=args.owner_team,
            repository_url=args.repo_url,
        )
        created = db.create_application(app)
        print(f"✅ Created application: {created.id}")
        print(json.dumps(created.to_dict(), indent=2))

    elif args.inventory_command == "get":
        app = db.get_application(args.id)
        if not app:
            print(f"❌ Application not found: {args.id}")
            return 1
        if args.format == "json":
            print(json.dumps(app.to_dict(), indent=2))
        else:
            print(f"ID: {app.id}")
            print(f"Name: {app.name}")
            print(f"Description: {app.description}")
            print(f"Criticality: {app.criticality.value}")
            print(f"Status: {app.status.value}")
            print(f"Environment: {app.environment}")

    elif args.inventory_command == "update":
        app = db.get_application(args.id)
        if not app:
            print(f"❌ Application not found: {args.id}")
            return 1

        if args.name:
            app.name = args.name
        if args.description:
            app.description = args.description
        if args.criticality:
            app.criticality = ApplicationCriticality(args.criticality)
        if args.status:
            app.status = ApplicationStatus(args.status)

        updated = db.update_application(app)
        print(f"✅ Updated application: {updated.id}")
        print(json.dumps(updated.to_dict(), indent=2))

    elif args.inventory_command == "delete":
        if not args.confirm:
            print("❌ Please use --confirm to delete")
            return 1
        if db.delete_application(args.id):
            print(f"✅ Deleted application: {args.id}")
        else:
            print(f"❌ Failed to delete application: {args.id}")
            return 1

    elif args.inventory_command == "search":
        results = db.search_inventory(args.query, limit=args.limit)
        print(json.dumps(results, indent=2))

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="FixOps local orchestration helpers")
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
        help="Application identifier",
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
        help="Optional hint influencing local processing (reserved)",
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
        help="Print verbose stage processing information",
    )
    stage_parser.set_defaults(func=_handle_stage_run)

    run_parser = subparsers.add_parser(
        "run", help="Execute the FixOps pipeline locally"
    )
    _configure_pipeline_parser(
        run_parser, include_quiet=True, include_overlay_flag=True
    )
    run_parser.set_defaults(func=_handle_run)

    ingest_parser = subparsers.add_parser(
        "ingest", help="Normalise artefacts and print the pipeline response"
    )
    _configure_pipeline_parser(
        ingest_parser, include_quiet=False, include_overlay_flag=True
    )
    ingest_parser.set_defaults(func=_handle_ingest)

    decision_parser = subparsers.add_parser(
        "make-decision",
        help="Execute the pipeline and use the decision as the exit code",
    )
    _configure_pipeline_parser(
        decision_parser, include_quiet=False, include_overlay_flag=True
    )
    decision_parser.set_defaults(func=_handle_make_decision)

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze security findings and output verdict",
    )
    analyze_parser.add_argument(
        "--overlay",
        type=Path,
        default=None,
        help="Path to an overlay file (defaults to repository overlay)",
    )
    analyze_parser.add_argument(
        "--design", type=Path, help="Path to design CSV artefact"
    )
    analyze_parser.add_argument("--sbom", type=Path, help="Path to SBOM JSON artefact")
    analyze_parser.add_argument(
        "--sarif", type=Path, help="Path to SARIF JSON artefact"
    )
    analyze_parser.add_argument(
        "--sast",
        type=Path,
        dest="sarif",
        help="Path to SAST/SARIF JSON artefact (alias for --sarif)",
    )
    analyze_parser.add_argument(
        "--cve", type=Path, help="Path to CVE/KEV JSON artefact"
    )
    analyze_parser.add_argument(
        "--vex",
        type=Path,
        help="Optional path to a CycloneDX VEX document used for noise reduction",
    )
    analyze_parser.add_argument(
        "--cnapp",
        type=Path,
        help="Optional path to CNAPP findings JSON for threat-path enrichment",
    )
    analyze_parser.add_argument(
        "--context",
        type=Path,
        help="Optional FixOps.yaml, OTM.json, or SSVC YAML business context artefact",
    )
    analyze_parser.add_argument(
        "--output", type=Path, help="Location to write the pipeline result JSON"
    )
    analyze_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output when saving to disk",
    )
    analyze_parser.add_argument(
        "--include-overlay",
        action="store_true",
        help="Attach the sanitised overlay to the result payload",
    )
    analyze_parser.add_argument(
        "--disable",
        dest="disable_modules",
        action="append",
        default=[],
        metavar="MODULE",
        help="Disable a module for this run (e.g. exploit_signals)",
    )
    analyze_parser.add_argument(
        "--enable",
        dest="enable_modules",
        action="append",
        default=[],
        metavar="MODULE",
        help="Force-enable a module for this run",
    )
    analyze_parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set environment variables before loading the overlay",
    )
    analyze_parser.add_argument(
        "--offline",
        action="store_true",
        help="Disable exploit feed auto-refresh to avoid network calls",
    )
    analyze_parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="Directory to copy the generated evidence bundle into",
    )
    analyze_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)",
    )
    analyze_parser.set_defaults(func=_handle_analyze)

    health_parser = subparsers.add_parser(
        "health", help="Check integration readiness for local runs"
    )
    health_parser.add_argument(
        "--overlay", type=Path, default=None, help="Path to an overlay file"
    )
    health_parser.add_argument(
        "--pretty", action="store_true", help="Pretty-print JSON output"
    )
    health_parser.set_defaults(func=_handle_health)

    evidence_parser = subparsers.add_parser(
        "get-evidence", help="Copy the evidence bundle referenced in a pipeline result"
    )
    evidence_parser.add_argument(
        "--result", type=Path, required=True, help="Path to a pipeline result JSON file"
    )
    evidence_parser.add_argument(
        "--destination",
        type=Path,
        help="Directory to copy the bundle into (defaults to CWD)",
    )
    evidence_parser.add_argument(
        "--pretty", action="store_true", help="Pretty-print JSON output"
    )
    evidence_parser.set_defaults(func=_handle_get_evidence)

    overlay_parser = subparsers.add_parser(
        "show-overlay", help="Print the sanitised overlay configuration"
    )
    overlay_parser.add_argument(
        "--overlay", type=Path, default=None, help="Path to an overlay file"
    )
    overlay_parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set environment variables before loading the overlay",
    )
    overlay_parser.add_argument(
        "--pretty", action="store_true", help="Pretty-print the overlay JSON"
    )
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

    train_bn_lr_parser = subparsers.add_parser(
        "train-bn-lr",
        help="Train BN-LR hybrid model using Bayesian Network posteriors and Logistic Regression",
    )
    train_bn_lr_parser.add_argument(
        "--data",
        type=Path,
        required=True,
        help="Path to CSV file with training data (columns: bn_p_low, bn_p_medium, bn_p_high, bn_p_critical, label)",
    )
    train_bn_lr_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Directory to save trained model artifacts",
    )
    train_bn_lr_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress training summary",
    )
    train_bn_lr_parser.set_defaults(func=_handle_train_bn_lr)

    predict_bn_lr_parser = subparsers.add_parser(
        "predict-bn-lr",
        help="Predict exploitation risk using trained BN-LR model",
    )
    predict_bn_lr_parser.add_argument(
        "--model",
        type=Path,
        required=True,
        help="Path to trained model directory",
    )
    predict_bn_lr_parser.add_argument(
        "--context",
        type=Path,
        required=True,
        help="Path to JSON file with context (exploitation, exposure, utility, etc.)",
    )
    predict_bn_lr_parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write prediction result JSON",
    )
    predict_bn_lr_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    predict_bn_lr_parser.add_argument(
        "--allow-skew",
        action="store_true",
        help="Allow BN CPD hash mismatch (skip training/serving skew check)",
    )
    predict_bn_lr_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress prediction output",
    )
    predict_bn_lr_parser.set_defaults(func=_handle_predict_bn_lr)

    backtest_bn_lr_parser = subparsers.add_parser(
        "backtest-bn-lr",
        help="Backtest trained BN-LR model on labeled test data",
    )
    backtest_bn_lr_parser.add_argument(
        "--model",
        type=Path,
        required=True,
        help="Path to trained model directory",
    )
    backtest_bn_lr_parser.add_argument(
        "--data",
        type=Path,
        required=True,
        help="Path to CSV file with test data (same format as training data)",
    )
    backtest_bn_lr_parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write backtest metrics JSON",
    )
    backtest_bn_lr_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    backtest_bn_lr_parser.add_argument(
        "--thresholds",
        type=str,
        help="Comma-separated decision thresholds to evaluate (default: 0.6,0.85)",
    )
    backtest_bn_lr_parser.add_argument(
        "--allow-skew",
        action="store_true",
        help="Allow BN CPD hash mismatch (skip training/serving skew check)",
    )
    backtest_bn_lr_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress backtest summary",
    )
    backtest_bn_lr_parser.set_defaults(func=_handle_backtest_bn_lr)

    inventory_parser = subparsers.add_parser(
        "inventory", help="Manage application and service inventory"
    )
    inventory_subparsers = inventory_parser.add_subparsers(dest="inventory_command")

    list_apps = inventory_subparsers.add_parser("list", help="List applications")
    list_apps.add_argument("--limit", type=int, default=100, help="Results per page")
    list_apps.add_argument("--offset", type=int, default=0, help="Pagination offset")
    list_apps.add_argument("--format", choices=["table", "json"], default="table")

    create_app = inventory_subparsers.add_parser("create", help="Create application")
    create_app.add_argument("--name", required=True, help="Application name")
    create_app.add_argument("--description", required=True, help="Description")
    create_app.add_argument(
        "--criticality", required=True, choices=["critical", "high", "medium", "low"]
    )
    create_app.add_argument("--environment", default="production")
    create_app.add_argument("--owner-team", help="Owning team")
    create_app.add_argument("--repo-url", help="Repository URL")

    get_app = inventory_subparsers.add_parser("get", help="Get application details")
    get_app.add_argument("id", help="Application ID")
    get_app.add_argument("--format", choices=["table", "json"], default="json")

    update_app = inventory_subparsers.add_parser("update", help="Update application")
    update_app.add_argument("id", help="Application ID")
    update_app.add_argument("--name", help="Application name")
    update_app.add_argument("--description", help="Description")
    update_app.add_argument(
        "--criticality", choices=["critical", "high", "medium", "low"]
    )
    update_app.add_argument("--status", choices=["active", "deprecated", "archived"])

    delete_app = inventory_subparsers.add_parser("delete", help="Delete application")
    delete_app.add_argument("id", help="Application ID")
    delete_app.add_argument("--confirm", action="store_true", help="Confirm deletion")

    search_inv = inventory_subparsers.add_parser("search", help="Search inventory")
    search_inv.add_argument("query", help="Search query")
    search_inv.add_argument("--limit", type=int, default=100)

    inventory_parser.set_defaults(func=_handle_inventory)

    users_parser = subparsers.add_parser(
        "users", help="Manage users and authentication"
    )
    users_subparsers = users_parser.add_subparsers(dest="user_command")

    list_users = users_subparsers.add_parser("list", help="List users")
    list_users.add_argument("--limit", type=int, default=100)
    list_users.add_argument("--offset", type=int, default=0)
    list_users.add_argument("--format", choices=["table", "json"], default="table")

    create_user = users_subparsers.add_parser("create", help="Create user")
    create_user.add_argument("--email", required=True)
    create_user.add_argument("--password", required=True)
    create_user.add_argument("--first-name", required=True)
    create_user.add_argument("--last-name", required=True)
    create_user.add_argument(
        "--role",
        required=True,
        choices=["admin", "security_analyst", "developer", "viewer"],
    )
    create_user.add_argument("--department")

    get_user = users_subparsers.add_parser("get", help="Get user details")
    get_user.add_argument("id", help="User ID")

    update_user = users_subparsers.add_parser("update", help="Update user")
    update_user.add_argument("id", help="User ID")
    update_user.add_argument("--first-name")
    update_user.add_argument("--last-name")
    update_user.add_argument(
        "--role", choices=["admin", "security_analyst", "developer", "viewer"]
    )
    update_user.add_argument("--status", choices=["active", "inactive", "suspended"])

    delete_user = users_subparsers.add_parser("delete", help="Delete user")
    delete_user.add_argument("id", help="User ID")
    delete_user.add_argument("--confirm", action="store_true")

    users_parser.set_defaults(func=_handle_users)

    teams_parser = subparsers.add_parser("teams", help="Manage teams")
    teams_subparsers = teams_parser.add_subparsers(dest="team_command")

    list_teams = teams_subparsers.add_parser("list", help="List teams")
    list_teams.add_argument("--limit", type=int, default=100)
    list_teams.add_argument("--offset", type=int, default=0)
    list_teams.add_argument("--format", choices=["table", "json"], default="table")

    create_team = teams_subparsers.add_parser("create", help="Create team")
    create_team.add_argument("--name", required=True)
    create_team.add_argument("--description", required=True)

    get_team = teams_subparsers.add_parser("get", help="Get team details")
    get_team.add_argument("id", help="Team ID")

    update_team = teams_subparsers.add_parser("update", help="Update team")
    update_team.add_argument("id", help="Team ID")
    update_team.add_argument("--name")
    update_team.add_argument("--description")

    delete_team = teams_subparsers.add_parser("delete", help="Delete team")
    delete_team.add_argument("id", help="Team ID")
    delete_team.add_argument("--confirm", action="store_true")

    members_team = teams_subparsers.add_parser("members", help="List team members")
    members_team.add_argument("id", help="Team ID")

    add_member = teams_subparsers.add_parser("add-member", help="Add user to team")
    add_member.add_argument("id", help="Team ID")
    add_member.add_argument("--user-id", required=True)
    add_member.add_argument("--role", default="member")

    remove_member = teams_subparsers.add_parser(
        "remove-member", help="Remove user from team"
    )
    remove_member.add_argument("id", help="Team ID")
    remove_member.add_argument("--user-id", required=True)

    teams_parser.set_defaults(func=_handle_teams)

    policies_parser = subparsers.add_parser("policies", help="Manage security policies")
    policies_subparsers = policies_parser.add_subparsers(dest="policy_command")

    list_policies = policies_subparsers.add_parser("list", help="List policies")
    list_policies.add_argument("--type", help="Filter by policy type")
    list_policies.add_argument("--limit", type=int, default=100)
    list_policies.add_argument("--offset", type=int, default=0)
    list_policies.add_argument("--format", choices=["table", "json"], default="table")

    create_policy = policies_subparsers.add_parser("create", help="Create policy")
    create_policy.add_argument("--name", required=True)
    create_policy.add_argument("--description", required=True)
    create_policy.add_argument(
        "--type", required=True, help="Policy type (guardrail, compliance, custom)"
    )
    create_policy.add_argument(
        "--status", default="draft", choices=["active", "draft", "archived"]
    )
    create_policy.add_argument("--rules", help="JSON string of policy rules")

    get_policy = policies_subparsers.add_parser("get", help="Get policy details")
    get_policy.add_argument("id", help="Policy ID")

    update_policy = policies_subparsers.add_parser("update", help="Update policy")
    update_policy.add_argument("id", help="Policy ID")
    update_policy.add_argument("--name")
    update_policy.add_argument("--description")
    update_policy.add_argument("--type")
    update_policy.add_argument("--status", choices=["active", "draft", "archived"])

    delete_policy = policies_subparsers.add_parser("delete", help="Delete policy")
    delete_policy.add_argument("id", help="Policy ID")
    delete_policy.add_argument("--confirm", action="store_true")

    policies_parser.set_defaults(func=_handle_policies)

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
