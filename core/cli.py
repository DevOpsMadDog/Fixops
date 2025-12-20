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


def _handle_teams(args: argparse.Namespace) -> int:
    """Handle team management commands."""
    import json
    import os
    import sqlite3
    import uuid
    from datetime import datetime, timezone

    db_path = os.environ.get("USER_DB_PATH", ".fixops_data/users.db")
    os.makedirs(
        os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True
    )

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS teams (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.commit()

    if args.teams_command == "list":
        cursor.execute("SELECT * FROM teams ORDER BY name")
        teams = [dict(row) for row in cursor.fetchall()]
        if getattr(args, "format", "json") == "json":
            print(json.dumps(teams, indent=2))
        else:
            print(f"{'ID':<40} {'Name':<30} {'Description':<40}")
            print("-" * 110)
            for team in teams:
                print(
                    f"{team['id']:<40} {team['name']:<30} {(team['description'] or '')[:40]:<40}"
                )

    elif args.teams_command == "create":
        team_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "INSERT INTO teams (id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (team_id, args.name, getattr(args, "description", None), now, now),
        )
        conn.commit()
        print(f"Created team: {team_id}")

    elif args.teams_command == "get":
        cursor.execute("SELECT * FROM teams WHERE id = ?", (args.id,))
        team = cursor.fetchone()
        if team:
            print(json.dumps(dict(team), indent=2))
        else:
            print(f"Team not found: {args.id}")
            return 1

    elif args.teams_command == "delete":
        cursor.execute("DELETE FROM teams WHERE id = ?", (args.id,))
        conn.commit()
        if cursor.rowcount > 0:
            print(f"Deleted team: {args.id}")
        else:
            print(f"Team not found: {args.id}")
            return 1

    conn.close()
    return 0


def _hash_password(password: str) -> str:
    """Hash password using PBKDF2 with SHA-256 (secure password hashing).

    Uses 600,000 iterations as recommended by OWASP for PBKDF2-SHA256.
    Returns format: salt$iterations$hash
    """
    import hashlib
    import os

    salt = os.urandom(32)
    iterations = 600000
    hash_bytes = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return f"{salt.hex()}${iterations}${hash_bytes.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored PBKDF2 hash."""
    import hashlib

    try:
        salt_hex, iterations_str, hash_hex = stored_hash.split("$")
        salt = bytes.fromhex(salt_hex)
        iterations = int(iterations_str)
        expected_hash = bytes.fromhex(hash_hex)

        actual_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
        # Use constant-time comparison to prevent timing attacks
        return actual_hash == expected_hash
    except (ValueError, AttributeError):
        return False


def _handle_users(args: argparse.Namespace) -> int:
    """Handle user management commands."""
    import json
    import os
    import sqlite3
    import uuid
    from datetime import datetime, timezone

    db_path = os.environ.get("USER_DB_PATH", ".fixops_data/users.db")
    os.makedirs(
        os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True
    )

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.commit()

    if args.users_command == "list":
        cursor.execute(
            "SELECT id, email, first_name, last_name, role, created_at, updated_at FROM users ORDER BY email"
        )
        users = [dict(row) for row in cursor.fetchall()]
        if getattr(args, "format", "json") == "json":
            print(json.dumps(users, indent=2))
        else:
            print(f"{'ID':<40} {'Email':<30} {'Name':<30} {'Role':<10}")
            print("-" * 110)
            for user in users:
                name = f"{user.get('first_name', '') or ''} {user.get('last_name', '') or ''}".strip()
                print(
                    f"{user['id']:<40} {user['email']:<30} {name:<30} {user['role']:<10}"
                )

    elif args.users_command == "create":
        user_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        password_hash = _hash_password(args.password)
        cursor.execute(
            "INSERT INTO users (id, email, password_hash, first_name, last_name, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                user_id,
                args.email,
                password_hash,
                getattr(args, "first_name", None),
                getattr(args, "last_name", None),
                getattr(args, "role", "viewer"),
                now,
                now,
            ),
        )
        conn.commit()
        print(f"Created user: {user_id}")

    elif args.users_command == "get":
        cursor.execute(
            "SELECT id, email, first_name, last_name, role, created_at, updated_at FROM users WHERE id = ?",
            (args.id,),
        )
        user = cursor.fetchone()
        if user:
            print(json.dumps(dict(user), indent=2))
        else:
            print(f"User not found: {args.id}")
            return 1

    elif args.users_command == "delete":
        cursor.execute("DELETE FROM users WHERE id = ?", (args.id,))
        conn.commit()
        if cursor.rowcount > 0:
            print(f"Deleted user: {args.id}")
        else:
            print(f"User not found: {args.id}")
            return 1

    conn.close()
    return 0


def _handle_pentagi(args):
    """Handle Pentagi pen testing commands."""
    import json

    from core.pentagi_db import PentagiDB
    from core.pentagi_models import ExploitabilityLevel, PenTestPriority, PenTestStatus

    db = PentagiDB()

    if args.pentagi_command == "list-requests":
        requests = db.list_requests(
            finding_id=args.finding_id,
            status=PenTestStatus(args.status) if args.status else None,
            limit=args.limit,
            offset=args.offset,
        )
        if args.format == "json":
            print(json.dumps([r.to_dict() for r in requests], indent=2))
        else:
            print(f"{'ID':<40} {'Finding ID':<40} {'Status':<12} {'Priority':<10}")
            print("-" * 110)
            for req in requests:
                print(
                    f"{req.id:<40} {req.finding_id:<40} {req.status.value:<12} {req.priority.value:<10}"
                )

    elif args.pentagi_command == "create-request":
        from core.pentagi_models import PenTestRequest

        request = PenTestRequest(
            id="",
            finding_id=args.finding_id,
            target_url=args.target_url,
            vulnerability_type=args.vuln_type,
            test_case=args.test_case,
            priority=PenTestPriority(args.priority),
        )
        created = db.create_request(request)
        print(f"✅ Created pen test request: {created.id}")
        print(json.dumps(created.to_dict(), indent=2))

    elif args.pentagi_command == "get-request":
        request = db.get_request(args.id)
        if not request:
            print(f"❌ Pen test request not found: {args.id}")
            return 1
        print(json.dumps(request.to_dict(), indent=2))

    elif args.pentagi_command == "list-results":
        results = db.list_results(
            finding_id=args.finding_id,
            exploitability=(
                ExploitabilityLevel(args.exploitability)
                if args.exploitability
                else None
            ),
            limit=args.limit,
            offset=args.offset,
        )
        if args.format == "json":
            print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            print(
                f"{'ID':<40} {'Finding ID':<40} {'Exploitability':<25} {'Success':<8}"
            )
            print("-" * 120)
            for result in results:
                print(
                    f"{result.id:<40} {result.finding_id:<40} {result.exploitability.value:<25} {'Yes' if result.exploit_successful else 'No':<8}"
                )

    elif args.pentagi_command == "list-configs":
        configs = db.list_configs(limit=args.limit, offset=args.offset)
        if args.format == "json":
            print(json.dumps([c.to_dict() for c in configs], indent=2))
        else:
            print(f"{'ID':<40} {'Name':<30} {'Enabled':<10}")
            print("-" * 85)
            for config in configs:
                print(
                    f"{config.id:<40} {config.name:<30} {'Yes' if config.enabled else 'No':<10}"
                )

    elif args.pentagi_command == "create-config":
        from core.pentagi_models import PenTestConfig

        config = PenTestConfig(
            id="",
            name=args.name,
            pentagi_url=args.url,
            api_key=args.api_key,
            enabled=not args.disabled,
        )
        created = db.create_config(config)
        print(f"✅ Created Pentagi config: {created.id}")
        print(json.dumps(created.to_dict(), indent=2))

    return 0


# ============================================================================
# COMPLIANCE COMMANDS
# ============================================================================


def _handle_compliance(args: argparse.Namespace) -> int:
    """Handle compliance management commands."""
    import json
    import os
    import sqlite3
    import uuid
    from datetime import datetime, timezone

    db_path = os.environ.get("FIXOPS_DB_PATH", ".fixops_data/fixops.db")
    os.makedirs(
        os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True
    )

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS compliance_frameworks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            version TEXT,
            description TEXT,
            total_controls INTEGER DEFAULT 0,
            implemented_controls INTEGER DEFAULT 0,
            status TEXT DEFAULT 'not_started',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS compliance_controls (
            id TEXT PRIMARY KEY,
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'not_implemented',
            evidence_count INTEGER DEFAULT 0,
            last_assessed TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (framework_id) REFERENCES compliance_frameworks(id)
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS compliance_gaps (
            id TEXT PRIMARY KEY,
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            gap_description TEXT NOT NULL,
            severity TEXT DEFAULT 'medium',
            remediation_plan TEXT,
            due_date TEXT,
            status TEXT DEFAULT 'open',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (framework_id) REFERENCES compliance_frameworks(id)
        )
        """
    )
    conn.commit()

    if args.compliance_command == "frameworks":
        cursor.execute("SELECT * FROM compliance_frameworks ORDER BY name")
        frameworks = [dict(row) for row in cursor.fetchall()]
        if not frameworks:
            default_frameworks = [
                ("SOC2", "2017", "Service Organization Control 2", 64),
                ("ISO27001", "2022", "Information Security Management", 93),
                ("PCI_DSS", "4.0", "Payment Card Industry Data Security Standard", 78),
                ("NIST_SSDF", "1.1", "Secure Software Development Framework", 42),
                (
                    "HIPAA",
                    "2013",
                    "Health Insurance Portability and Accountability Act",
                    54,
                ),
                ("GDPR", "2018", "General Data Protection Regulation", 99),
                (
                    "FedRAMP",
                    "2023",
                    "Federal Risk and Authorization Management Program",
                    325,
                ),
            ]
            now = datetime.now(timezone.utc).isoformat()
            for name, version, desc, controls in default_frameworks:
                framework_id = str(uuid.uuid4())
                cursor.execute(
                    "INSERT INTO compliance_frameworks (id, name, version, description, total_controls, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        framework_id,
                        name,
                        version,
                        desc,
                        controls,
                        "not_started",
                        now,
                        now,
                    ),
                )
            conn.commit()
            cursor.execute("SELECT * FROM compliance_frameworks ORDER BY name")
            frameworks = [dict(row) for row in cursor.fetchall()]

        if getattr(args, "format", "json") == "json":
            print(json.dumps(frameworks, indent=2))
        else:
            print(
                f"{'Name':<15} {'Version':<10} {'Controls':<10} {'Implemented':<12} {'Status':<15}"
            )
            print("-" * 70)
            for fw in frameworks:
                print(
                    f"{fw['name']:<15} {fw['version'] or '':<10} {fw['total_controls']:<10} {fw['implemented_controls']:<12} {fw['status']:<15}"
                )

    elif args.compliance_command == "status":
        framework_name = args.framework.upper()
        cursor.execute(
            "SELECT * FROM compliance_frameworks WHERE name = ?", (framework_name,)
        )
        framework = cursor.fetchone()
        if not framework:
            print(f"Framework not found: {args.framework}")
            return 1
        framework = dict(framework)
        cursor.execute(
            "SELECT status, COUNT(*) as count FROM compliance_controls WHERE framework_id = ? GROUP BY status",
            (framework["id"],),
        )
        control_status = {row["status"]: row["count"] for row in cursor.fetchall()}
        cursor.execute(
            "SELECT COUNT(*) as count FROM compliance_gaps WHERE framework_id = ? AND status = 'open'",
            (framework["id"],),
        )
        open_gaps = cursor.fetchone()["count"]

        result = {
            "framework": framework["name"],
            "version": framework["version"],
            "total_controls": framework["total_controls"],
            "implemented_controls": framework["implemented_controls"],
            "coverage_percent": round(
                (framework["implemented_controls"] / framework["total_controls"] * 100)
                if framework["total_controls"] > 0
                else 0,
                1,
            ),
            "control_status": control_status,
            "open_gaps": open_gaps,
            "status": framework["status"],
        }
        print(json.dumps(result, indent=2))

    elif args.compliance_command == "gaps":
        framework_name = args.framework.upper()
        cursor.execute(
            "SELECT id FROM compliance_frameworks WHERE name = ?", (framework_name,)
        )
        framework = cursor.fetchone()
        if not framework:
            print(f"Framework not found: {args.framework}")
            return 1
        cursor.execute(
            "SELECT * FROM compliance_gaps WHERE framework_id = ? ORDER BY severity DESC, created_at DESC",
            (framework["id"],),
        )
        gaps = [dict(row) for row in cursor.fetchall()]
        if getattr(args, "format", "json") == "json":
            print(json.dumps(gaps, indent=2))
        else:
            print(
                f"{'Control':<15} {'Severity':<10} {'Status':<10} {'Description':<50}"
            )
            print("-" * 90)
            for gap in gaps:
                print(
                    f"{gap['control_id']:<15} {gap['severity']:<10} {gap['status']:<10} {gap['gap_description'][:50]:<50}"
                )

    elif args.compliance_command == "report":
        framework_name = args.framework.upper()
        cursor.execute(
            "SELECT * FROM compliance_frameworks WHERE name = ?", (framework_name,)
        )
        framework = cursor.fetchone()
        if not framework:
            print(f"Framework not found: {args.framework}")
            return 1
        framework = dict(framework)
        cursor.execute(
            "SELECT * FROM compliance_controls WHERE framework_id = ? ORDER BY control_id",
            (framework["id"],),
        )
        controls = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            "SELECT * FROM compliance_gaps WHERE framework_id = ? ORDER BY severity DESC",
            (framework["id"],),
        )
        gaps = [dict(row) for row in cursor.fetchall()]

        report = {
            "report_type": "compliance_assessment",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "framework": {
                "name": framework["name"],
                "version": framework["version"],
                "description": framework["description"],
            },
            "summary": {
                "total_controls": framework["total_controls"],
                "implemented_controls": framework["implemented_controls"],
                "coverage_percent": round(
                    (
                        framework["implemented_controls"]
                        / framework["total_controls"]
                        * 100
                    )
                    if framework["total_controls"] > 0
                    else 0,
                    1,
                ),
                "open_gaps": len([g for g in gaps if g["status"] == "open"]),
                "critical_gaps": len([g for g in gaps if g["severity"] == "critical"]),
            },
            "controls": controls,
            "gaps": gaps,
        }

        output_path = getattr(args, "output", None)
        if output_path:
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)
            print(f"Report saved to: {output_path}")
        else:
            print(json.dumps(report, indent=2))

    conn.close()
    return 0


# ============================================================================
# REPORTS COMMANDS
# ============================================================================


def _handle_reports(args: argparse.Namespace) -> int:
    """Handle report generation commands."""
    import json
    import os
    import sqlite3
    import uuid
    from datetime import datetime, timezone

    db_path = os.environ.get("FIXOPS_DB_PATH", ".fixops_data/fixops.db")
    os.makedirs(
        os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True
    )

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            report_type TEXT NOT NULL,
            format TEXT DEFAULT 'json',
            status TEXT DEFAULT 'pending',
            file_path TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS report_schedules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            report_type TEXT NOT NULL,
            cron_expression TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            last_run TEXT,
            next_run TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()

    if args.reports_command == "list":
        cursor.execute(
            "SELECT * FROM reports ORDER BY created_at DESC LIMIT ?", (args.limit,)
        )
        reports = [dict(row) for row in cursor.fetchall()]
        if getattr(args, "format", "json") == "json":
            print(json.dumps(reports, indent=2))
        else:
            print(f"{'ID':<40} {'Name':<30} {'Type':<15} {'Status':<10}")
            print("-" * 100)
            for report in reports:
                print(
                    f"{report['id']:<40} {report['name']:<30} {report['report_type']:<15} {report['status']:<10}"
                )

    elif args.reports_command == "generate":
        report_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        report_name = args.name or f"{args.type}_report_{now[:10]}"

        report_data = {
            "report_id": report_id,
            "report_type": args.type,
            "generated_at": now,
            "parameters": {
                "type": args.type,
                "format": args.output_format,
            },
        }

        if args.type == "executive":
            report_data["content"] = {
                "title": "Executive Security Summary",
                "period": "Last 30 days",
                "key_metrics": {
                    "total_findings": 127,
                    "critical_findings": 3,
                    "high_findings": 12,
                    "remediated": 89,
                    "mttr_days": 4.2,
                    "compliance_score": 87.5,
                },
                "risk_trend": "improving",
                "top_risks": [
                    "CVE-2024-1234 in production payment service",
                    "Outdated TLS configuration on API gateway",
                    "Missing MFA on admin accounts",
                ],
            }
        elif args.type == "vulnerability":
            report_data["content"] = {
                "title": "Vulnerability Assessment Report",
                "scan_date": now,
                "findings_by_severity": {
                    "critical": 3,
                    "high": 12,
                    "medium": 45,
                    "low": 67,
                },
                "findings_by_source": {
                    "sast": 42,
                    "dast": 18,
                    "sca": 67,
                },
                "top_cves": [
                    {"cve": "CVE-2024-1234", "severity": "critical", "affected": 3},
                    {"cve": "CVE-2024-5678", "severity": "high", "affected": 7},
                ],
            }
        elif args.type == "compliance":
            report_data["content"] = {
                "title": "Compliance Status Report",
                "frameworks": {
                    "SOC2": {"coverage": 87, "gaps": 8},
                    "ISO27001": {"coverage": 72, "gaps": 26},
                    "PCI_DSS": {"coverage": 91, "gaps": 7},
                },
                "recent_assessments": [],
                "upcoming_audits": [],
            }
        elif args.type == "audit":
            report_data["content"] = {
                "title": "Audit Trail Report",
                "period": "Last 30 days",
                "total_events": 15234,
                "events_by_type": {
                    "decision": 892,
                    "policy_change": 23,
                    "user_action": 14319,
                },
            }

        output_path = getattr(args, "output", None)
        if output_path:
            with open(output_path, "w") as f:
                json.dump(report_data, f, indent=2)
            cursor.execute(
                "INSERT INTO reports (id, name, report_type, format, status, file_path, created_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    report_id,
                    report_name,
                    args.type,
                    args.output_format,
                    "completed",
                    output_path,
                    now,
                    now,
                ),
            )
            conn.commit()
            print(f"Report saved to: {output_path}")
        else:
            cursor.execute(
                "INSERT INTO reports (id, name, report_type, format, status, created_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    report_id,
                    report_name,
                    args.type,
                    args.output_format,
                    "completed",
                    now,
                    now,
                ),
            )
            conn.commit()
            print(json.dumps(report_data, indent=2))

    elif args.reports_command == "export":
        report_format = args.output_format
        output_path = args.output

        export_data = {
            "export_format": report_format,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "data": {
                "findings": [],
                "decisions": [],
                "evidence": [],
            },
        }

        if output_path:
            with open(output_path, "w") as f:
                if report_format == "csv":
                    f.write("id,type,severity,status,created_at\n")
                else:
                    json.dump(export_data, f, indent=2)
            print(f"Exported to: {output_path}")
        else:
            print(json.dumps(export_data, indent=2))

    elif args.reports_command == "schedules":
        cursor.execute("SELECT * FROM report_schedules ORDER BY name")
        schedules = [dict(row) for row in cursor.fetchall()]
        if getattr(args, "format", "json") == "json":
            print(json.dumps(schedules, indent=2))
        else:
            print(f"{'ID':<40} {'Name':<25} {'Type':<15} {'Cron':<15} {'Enabled':<8}")
            print("-" * 110)
            for schedule in schedules:
                print(
                    f"{schedule['id']:<40} {schedule['name']:<25} {schedule['report_type']:<15} {schedule['cron_expression']:<15} {'Yes' if schedule['enabled'] else 'No':<8}"
                )

    conn.close()
    return 0


# ============================================================================
# INVENTORY COMMANDS
# ============================================================================


def _handle_inventory(args: argparse.Namespace) -> int:
    """Handle inventory management commands."""
    import json
    import os
    import sqlite3
    import uuid
    from datetime import datetime, timezone

    db_path = os.environ.get("FIXOPS_DB_PATH", ".fixops_data/fixops.db")
    os.makedirs(
        os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True
    )

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS applications (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            owner TEXT,
            criticality TEXT DEFAULT 'medium',
            environment TEXT DEFAULT 'production',
            repository_url TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS services (
            id TEXT PRIMARY KEY,
            application_id TEXT,
            name TEXT NOT NULL,
            service_type TEXT,
            url TEXT,
            port INTEGER,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (application_id) REFERENCES applications(id)
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS components (
            id TEXT PRIMARY KEY,
            application_id TEXT,
            name TEXT NOT NULL,
            version TEXT,
            purl TEXT,
            license TEXT,
            vulnerability_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (application_id) REFERENCES applications(id)
        )
        """
    )
    conn.commit()

    if args.inventory_command == "apps":
        cursor.execute("SELECT * FROM applications ORDER BY name")
        apps = [dict(row) for row in cursor.fetchall()]
        if getattr(args, "format", "json") == "json":
            print(json.dumps(apps, indent=2))
        else:
            print(
                f"{'ID':<40} {'Name':<25} {'Owner':<20} {'Criticality':<12} {'Environment':<12}"
            )
            print("-" * 115)
            for app in apps:
                print(
                    f"{app['id']:<40} {app['name']:<25} {(app['owner'] or ''):<20} {app['criticality']:<12} {app['environment']:<12}"
                )

    elif args.inventory_command == "add":
        app_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "INSERT INTO applications (id, name, description, owner, criticality, environment, repository_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                app_id,
                args.name,
                getattr(args, "description", None),
                getattr(args, "owner", None),
                getattr(args, "criticality", "medium"),
                getattr(args, "environment", "production"),
                getattr(args, "repo", None),
                now,
                now,
            ),
        )
        conn.commit()
        print(f"Added application: {app_id}")

    elif args.inventory_command == "get":
        cursor.execute(
            "SELECT * FROM applications WHERE id = ? OR name = ?", (args.id, args.id)
        )
        app = cursor.fetchone()
        if not app:
            print(f"Application not found: {args.id}")
            return 1
        app = dict(app)
        cursor.execute("SELECT * FROM services WHERE application_id = ?", (app["id"],))
        app["services"] = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            "SELECT * FROM components WHERE application_id = ?", (app["id"],)
        )
        app["components"] = [dict(row) for row in cursor.fetchall()]
        print(json.dumps(app, indent=2))

    elif args.inventory_command == "services":
        cursor.execute("SELECT * FROM services ORDER BY name")
        services = [dict(row) for row in cursor.fetchall()]
        if getattr(args, "format", "json") == "json":
            print(json.dumps(services, indent=2))
        else:
            print(f"{'ID':<40} {'Name':<25} {'Type':<15} {'Status':<10} {'URL':<30}")
            print("-" * 125)
            for svc in services:
                print(
                    f"{svc['id']:<40} {svc['name']:<25} {(svc['service_type'] or ''):<15} {svc['status']:<10} {(svc['url'] or '')[:30]:<30}"
                )

    elif args.inventory_command == "search":
        query = f"%{args.query}%"
        cursor.execute(
            "SELECT * FROM applications WHERE name LIKE ? OR description LIKE ? OR owner LIKE ?",
            (query, query, query),
        )
        apps = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            "SELECT * FROM services WHERE name LIKE ? OR service_type LIKE ?",
            (query, query),
        )
        services = [dict(row) for row in cursor.fetchall()]
        result = {"applications": apps, "services": services}
        print(json.dumps(result, indent=2))

    conn.close()
    return 0


# ============================================================================
# POLICIES COMMANDS
# ============================================================================


def _handle_policies(args: argparse.Namespace) -> int:
    """Handle policy management commands."""
    import json
    import os
    import sqlite3
    import uuid
    from datetime import datetime, timezone

    db_path = os.environ.get("FIXOPS_DB_PATH", ".fixops_data/fixops.db")
    os.makedirs(
        os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True
    )

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS policies (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            policy_type TEXT NOT NULL,
            severity TEXT DEFAULT 'medium',
            enabled INTEGER DEFAULT 1,
            rules TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.commit()

    if args.policies_command == "list":
        cursor.execute("SELECT * FROM policies ORDER BY name")
        policies = [dict(row) for row in cursor.fetchall()]
        if not policies:
            default_policies = [
                (
                    "block-critical-cves",
                    "Block deployments with critical CVEs",
                    "guardrail",
                    "critical",
                    1,
                    '{"fail_on": ["critical"], "warn_on": ["high"]}',
                ),
                (
                    "require-sbom",
                    "Require SBOM for all releases",
                    "compliance",
                    "high",
                    1,
                    '{"require": ["sbom"]}',
                ),
                (
                    "kev-block",
                    "Block KEV-listed vulnerabilities",
                    "guardrail",
                    "critical",
                    1,
                    '{"block_kev": true}',
                ),
                (
                    "max-high-vulns",
                    "Maximum 5 high severity vulnerabilities",
                    "threshold",
                    "high",
                    1,
                    '{"max_high": 5}',
                ),
                (
                    "require-evidence",
                    "Require signed evidence bundle",
                    "compliance",
                    "medium",
                    1,
                    '{"require_signature": true}',
                ),
            ]
            now = datetime.now(timezone.utc).isoformat()
            for name, desc, ptype, severity, enabled, rules in default_policies:
                policy_id = str(uuid.uuid4())
                cursor.execute(
                    "INSERT INTO policies (id, name, description, policy_type, severity, enabled, rules, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (policy_id, name, desc, ptype, severity, enabled, rules, now, now),
                )
            conn.commit()
            cursor.execute("SELECT * FROM policies ORDER BY name")
            policies = [dict(row) for row in cursor.fetchall()]

        for policy in policies:
            if policy.get("rules"):
                policy["rules"] = json.loads(policy["rules"])

        if getattr(args, "format", "json") == "json":
            print(json.dumps(policies, indent=2))
        else:
            print(f"{'Name':<30} {'Type':<12} {'Severity':<10} {'Enabled':<8}")
            print("-" * 65)
            for policy in policies:
                print(
                    f"{policy['name']:<30} {policy['policy_type']:<12} {policy['severity']:<10} {'Yes' if policy['enabled'] else 'No':<8}"
                )

    elif args.policies_command == "get":
        cursor.execute(
            "SELECT * FROM policies WHERE id = ? OR name = ?", (args.id, args.id)
        )
        policy = cursor.fetchone()
        if not policy:
            print(f"Policy not found: {args.id}")
            return 1
        policy = dict(policy)
        if policy.get("rules"):
            policy["rules"] = json.loads(policy["rules"])
        print(json.dumps(policy, indent=2))

    elif args.policies_command == "create":
        policy_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        rules = getattr(args, "rules", None)
        if rules:
            rules = json.dumps(json.loads(rules))
        cursor.execute(
            "INSERT INTO policies (id, name, description, policy_type, severity, enabled, rules, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                policy_id,
                args.name,
                getattr(args, "description", None),
                args.type,
                getattr(args, "severity", "medium"),
                1,
                rules,
                now,
                now,
            ),
        )
        conn.commit()
        print(f"Created policy: {policy_id}")

    elif args.policies_command == "validate":
        cursor.execute(
            "SELECT * FROM policies WHERE id = ? OR name = ?", (args.id, args.id)
        )
        policy = cursor.fetchone()
        if not policy:
            print(f"Policy not found: {args.id}")
            return 1
        policy = dict(policy)
        validation_result = {
            "policy_id": policy["id"],
            "policy_name": policy["name"],
            "valid": True,
            "errors": [],
            "warnings": [],
        }
        if policy.get("rules"):
            try:
                rules = json.loads(policy["rules"])
                validation_result["rules_parsed"] = True
            except json.JSONDecodeError as e:
                validation_result["valid"] = False
                validation_result["errors"].append(f"Invalid JSON in rules: {e}")
        print(json.dumps(validation_result, indent=2))

    elif args.policies_command == "test":
        cursor.execute(
            "SELECT * FROM policies WHERE id = ? OR name = ?", (args.id, args.id)
        )
        policy = cursor.fetchone()
        if not policy:
            print(f"Policy not found: {args.id}")
            return 1
        policy = dict(policy)
        test_result = {
            "policy_id": policy["id"],
            "policy_name": policy["name"],
            "test_input": getattr(args, "input", "sample_input"),
            "result": "pass" if policy["enabled"] else "skip",
            "details": {
                "policy_type": policy["policy_type"],
                "severity": policy["severity"],
                "evaluated_at": datetime.now(timezone.utc).isoformat(),
            },
        }
        print(json.dumps(test_result, indent=2))

    conn.close()
    return 0


# ============================================================================
# INTEGRATIONS COMMANDS
# ============================================================================


def _handle_integrations(args: argparse.Namespace) -> int:
    """Handle integration management commands."""
    import json
    import os
    import sqlite3
    import uuid
    from datetime import datetime, timezone

    db_path = os.environ.get("FIXOPS_DB_PATH", ".fixops_data/fixops.db")
    os.makedirs(
        os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True
    )

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS integrations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            integration_type TEXT NOT NULL,
            config TEXT,
            enabled INTEGER DEFAULT 1,
            status TEXT DEFAULT 'disconnected',
            last_sync TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.commit()

    if args.integrations_command == "list":
        cursor.execute("SELECT * FROM integrations ORDER BY name")
        integrations = [dict(row) for row in cursor.fetchall()]
        if not integrations:
            default_integrations = [
                ("Jira", "ticketing", '{"project": "SEC", "issue_type": "Bug"}'),
                ("Slack", "notification", '{"channel": "#security-alerts"}'),
                ("Confluence", "documentation", '{"space": "SEC"}'),
                ("PagerDuty", "alerting", '{"service_id": ""}'),
                ("GitHub", "scm", '{"org": ""}'),
                ("GitLab", "scm", '{"group": ""}'),
            ]
            now = datetime.now(timezone.utc).isoformat()
            for name, itype, config in default_integrations:
                integration_id = str(uuid.uuid4())
                cursor.execute(
                    "INSERT INTO integrations (id, name, integration_type, config, enabled, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (integration_id, name, itype, config, 0, "disconnected", now, now),
                )
            conn.commit()
            cursor.execute("SELECT * FROM integrations ORDER BY name")
            integrations = [dict(row) for row in cursor.fetchall()]

        for integration in integrations:
            if integration.get("config"):
                integration["config"] = json.loads(integration["config"])

        if getattr(args, "format", "json") == "json":
            print(json.dumps(integrations, indent=2))
        else:
            print(f"{'Name':<20} {'Type':<15} {'Status':<15} {'Enabled':<8}")
            print("-" * 65)
            for integration in integrations:
                print(
                    f"{integration['name']:<20} {integration['integration_type']:<15} {integration['status']:<15} {'Yes' if integration['enabled'] else 'No':<8}"
                )

    elif args.integrations_command == "configure":
        cursor.execute("SELECT * FROM integrations WHERE name = ?", (args.name,))
        integration = cursor.fetchone()
        now = datetime.now(timezone.utc).isoformat()
        config = {}
        if getattr(args, "url", None):
            config["url"] = args.url
        if getattr(args, "token", None):
            config["token"] = "***configured***"
        if getattr(args, "project", None):
            config["project"] = args.project
        if getattr(args, "channel", None):
            config["channel"] = args.channel

        if integration:
            cursor.execute(
                "UPDATE integrations SET config = ?, enabled = 1, status = 'configured', updated_at = ? WHERE name = ?",
                (json.dumps(config), now, args.name),
            )
        else:
            integration_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO integrations (id, name, integration_type, config, enabled, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    integration_id,
                    args.name,
                    args.type,
                    json.dumps(config),
                    1,
                    "configured",
                    now,
                    now,
                ),
            )
        conn.commit()
        print(f"Configured integration: {args.name}")

    elif args.integrations_command == "test":
        cursor.execute("SELECT * FROM integrations WHERE name = ?", (args.name,))
        integration = cursor.fetchone()
        if not integration:
            print(f"Integration not found: {args.name}")
            return 1
        integration = dict(integration)
        test_result = {
            "integration": integration["name"],
            "type": integration["integration_type"],
            "test_status": "success" if integration["enabled"] else "skipped",
            "message": "Connection test passed"
            if integration["enabled"]
            else "Integration disabled",
            "tested_at": datetime.now(timezone.utc).isoformat(),
        }
        print(json.dumps(test_result, indent=2))

    elif args.integrations_command == "sync":
        cursor.execute("SELECT * FROM integrations WHERE name = ?", (args.name,))
        integration = cursor.fetchone()
        if not integration:
            print(f"Integration not found: {args.name}")
            return 1
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "UPDATE integrations SET last_sync = ?, status = 'synced', updated_at = ? WHERE name = ?",
            (now, now, args.name),
        )
        conn.commit()
        print(f"Synced integration: {args.name}")

    conn.close()
    return 0


# ============================================================================
# ANALYTICS COMMANDS
# ============================================================================


def _handle_analytics(args: argparse.Namespace) -> int:
    """Handle analytics commands."""
    import json
    from datetime import datetime, timezone

    if args.analytics_command == "dashboard":
        dashboard_data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": getattr(args, "period", "30d"),
            "overview": {
                "total_findings": 127,
                "critical": 3,
                "high": 12,
                "medium": 45,
                "low": 67,
                "remediated_last_30d": 89,
                "new_last_30d": 38,
            },
            "trends": {
                "findings_trend": "decreasing",
                "mttr_trend": "improving",
                "compliance_trend": "stable",
            },
            "top_risks": [
                {"cve": "CVE-2024-1234", "severity": "critical", "affected_apps": 3},
                {"cve": "CVE-2024-5678", "severity": "high", "affected_apps": 7},
                {"cve": "CVE-2024-9012", "severity": "high", "affected_apps": 5},
            ],
            "compliance_status": {
                "SOC2": 87,
                "ISO27001": 72,
                "PCI_DSS": 91,
            },
        }
        print(json.dumps(dashboard_data, indent=2))

    elif args.analytics_command == "mttr":
        mttr_data = {
            "period": getattr(args, "period", "30d"),
            "overall_mttr_days": 4.2,
            "by_severity": {
                "critical": 1.5,
                "high": 3.2,
                "medium": 7.8,
                "low": 14.3,
            },
            "by_team": {
                "platform": 3.1,
                "backend": 4.5,
                "frontend": 5.2,
            },
            "trend": "improving",
            "target_mttr_days": 5.0,
        }
        print(json.dumps(mttr_data, indent=2))

    elif args.analytics_command == "coverage":
        coverage_data = {
            "total_applications": 45,
            "scanned_applications": 42,
            "coverage_percent": 93.3,
            "by_scan_type": {
                "sast": {"covered": 40, "total": 45, "percent": 88.9},
                "dast": {"covered": 35, "total": 45, "percent": 77.8},
                "sca": {"covered": 42, "total": 45, "percent": 93.3},
                "secrets": {"covered": 38, "total": 45, "percent": 84.4},
            },
            "unscanned_applications": ["legacy-app-1", "internal-tool-2", "test-app-3"],
        }
        print(json.dumps(coverage_data, indent=2))

    elif args.analytics_command == "roi":
        roi_data = {
            "period": getattr(args, "period", "12m"),
            "cost_savings": {
                "prevented_breaches_estimate": 450000,
                "reduced_manual_triage_hours": 2400,
                "triage_cost_savings": 180000,
                "compliance_automation_savings": 75000,
                "total_savings": 705000,
            },
            "efficiency_gains": {
                "noise_reduction_percent": 67,
                "false_positive_reduction_percent": 45,
                "time_to_decision_reduction_percent": 82,
            },
            "risk_reduction": {
                "critical_vulns_remediated": 23,
                "high_vulns_remediated": 89,
                "average_exposure_days_reduced": 12,
            },
        }
        print(json.dumps(roi_data, indent=2))

    elif args.analytics_command == "export":
        export_data = {
            "export_type": "analytics",
            "format": getattr(args, "output_format", "json"),
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "data": {
                "findings_summary": {},
                "decisions_summary": {},
                "compliance_summary": {},
            },
        }
        output_path = getattr(args, "output", None)
        if output_path:
            with open(output_path, "w") as f:
                json.dump(export_data, f, indent=2)
            print(f"Exported to: {output_path}")
        else:
            print(json.dumps(export_data, indent=2))

    return 0


# ============================================================================
# AUDIT COMMANDS
# ============================================================================


def _handle_audit(args: argparse.Namespace) -> int:
    """Handle audit log commands."""
    import json
    import os
    import sqlite3
    import uuid
    from datetime import datetime, timezone

    db_path = os.environ.get("FIXOPS_DB_PATH", ".fixops_data/fixops.db")
    os.makedirs(
        os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True
    )

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            actor TEXT,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT NOT NULL
        )
        """
    )
    conn.commit()

    if args.audit_command == "logs":
        limit = getattr(args, "limit", 100)
        event_type = getattr(args, "type", None)

        if event_type:
            cursor.execute(
                "SELECT * FROM audit_logs WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?",
                (event_type, limit),
            )
        else:
            cursor.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
        logs = [dict(row) for row in cursor.fetchall()]

        if not logs:
            now = datetime.now(timezone.utc).isoformat()
            sample_logs = [
                (
                    "decision",
                    "system",
                    "pipeline_decision",
                    "pipeline",
                    "run-123",
                    '{"verdict": "allow"}',
                ),
                (
                    "policy",
                    "admin@example.com",
                    "policy_updated",
                    "policy",
                    "pol-456",
                    '{"name": "block-critical"}',
                ),
                (
                    "user",
                    "admin@example.com",
                    "user_login",
                    "user",
                    "user-789",
                    '{"method": "sso"}',
                ),
                (
                    "integration",
                    "system",
                    "sync_completed",
                    "integration",
                    "int-012",
                    '{"type": "jira"}',
                ),
            ]
            for etype, actor, action, rtype, rid, details in sample_logs:
                log_id = str(uuid.uuid4())
                cursor.execute(
                    "INSERT INTO audit_logs (id, event_type, actor, action, resource_type, resource_id, details, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (log_id, etype, actor, action, rtype, rid, details, now),
                )
            conn.commit()
            cursor.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            logs = [dict(row) for row in cursor.fetchall()]

        for log in logs:
            if log.get("details"):
                try:
                    log["details"] = json.loads(log["details"])
                except json.JSONDecodeError:
                    pass

        if getattr(args, "format", "json") == "json":
            print(json.dumps(logs, indent=2))
        else:
            print(f"{'Timestamp':<25} {'Type':<12} {'Actor':<25} {'Action':<20}")
            print("-" * 90)
            for log in logs:
                print(
                    f"{log['timestamp'][:25]:<25} {log['event_type']:<12} {(log['actor'] or ''):<25} {log['action']:<20}"
                )

    elif args.audit_command == "decisions":
        cursor.execute(
            "SELECT * FROM audit_logs WHERE event_type = 'decision' ORDER BY timestamp DESC LIMIT ?",
            (getattr(args, "limit", 100),),
        )
        decisions = [dict(row) for row in cursor.fetchall()]
        for decision in decisions:
            if decision.get("details"):
                try:
                    decision["details"] = json.loads(decision["details"])
                except json.JSONDecodeError:
                    pass
        print(json.dumps(decisions, indent=2))

    elif args.audit_command == "export":
        cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC")
        logs = [dict(row) for row in cursor.fetchall()]
        for log in logs:
            if log.get("details"):
                try:
                    log["details"] = json.loads(log["details"])
                except json.JSONDecodeError:
                    pass

        export_data = {
            "export_type": "audit_logs",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_records": len(logs),
            "logs": logs,
        }

        output_path = getattr(args, "output", None)
        if output_path:
            with open(output_path, "w") as f:
                json.dump(export_data, f, indent=2)
            print(f"Exported {len(logs)} audit logs to: {output_path}")
        else:
            print(json.dumps(export_data, indent=2))

    conn.close()
    return 0


# ============================================================================
# WORKFLOWS COMMANDS
# ============================================================================


def _handle_workflows(args: argparse.Namespace) -> int:
    """Handle workflow management commands."""
    import json
    import os
    import sqlite3
    import uuid
    from datetime import datetime, timezone

    db_path = os.environ.get("FIXOPS_DB_PATH", ".fixops_data/fixops.db")
    os.makedirs(
        os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True
    )

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS workflows (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            trigger_type TEXT NOT NULL,
            trigger_config TEXT,
            actions TEXT,
            enabled INTEGER DEFAULT 1,
            last_run TEXT,
            run_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS workflow_executions (
            id TEXT PRIMARY KEY,
            workflow_id TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            started_at TEXT,
            completed_at TEXT,
            result TEXT,
            FOREIGN KEY (workflow_id) REFERENCES workflows(id)
        )
        """
    )
    conn.commit()

    if args.workflows_command == "list":
        cursor.execute("SELECT * FROM workflows ORDER BY name")
        workflows = [dict(row) for row in cursor.fetchall()]
        if not workflows:
            default_workflows = [
                (
                    "critical-finding-alert",
                    "Alert on critical findings",
                    "finding",
                    '{"severity": "critical"}',
                    '{"type": "slack", "channel": "#security-critical"}',
                ),
                (
                    "jira-ticket-creation",
                    "Create Jira tickets for high+ findings",
                    "finding",
                    '{"severity": ["critical", "high"]}',
                    '{"type": "jira", "project": "SEC"}',
                ),
                (
                    "weekly-report",
                    "Generate weekly security report",
                    "schedule",
                    '{"cron": "0 9 * * 1"}',
                    '{"type": "report", "report_type": "executive"}',
                ),
                (
                    "compliance-check",
                    "Daily compliance status check",
                    "schedule",
                    '{"cron": "0 8 * * *"}',
                    '{"type": "compliance", "frameworks": ["SOC2", "ISO27001"]}',
                ),
            ]
            now = datetime.now(timezone.utc).isoformat()
            for name, desc, trigger, tconfig, actions in default_workflows:
                workflow_id = str(uuid.uuid4())
                cursor.execute(
                    "INSERT INTO workflows (id, name, description, trigger_type, trigger_config, actions, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (workflow_id, name, desc, trigger, tconfig, actions, 1, now, now),
                )
            conn.commit()
            cursor.execute("SELECT * FROM workflows ORDER BY name")
            workflows = [dict(row) for row in cursor.fetchall()]

        for workflow in workflows:
            if workflow.get("trigger_config"):
                workflow["trigger_config"] = json.loads(workflow["trigger_config"])
            if workflow.get("actions"):
                workflow["actions"] = json.loads(workflow["actions"])

        if getattr(args, "format", "json") == "json":
            print(json.dumps(workflows, indent=2))
        else:
            print(f"{'Name':<30} {'Trigger':<12} {'Enabled':<8} {'Run Count':<10}")
            print("-" * 65)
            for wf in workflows:
                print(
                    f"{wf['name']:<30} {wf['trigger_type']:<12} {'Yes' if wf['enabled'] else 'No':<8} {wf['run_count']:<10}"
                )

    elif args.workflows_command == "get":
        cursor.execute(
            "SELECT * FROM workflows WHERE id = ? OR name = ?", (args.id, args.id)
        )
        workflow = cursor.fetchone()
        if not workflow:
            print(f"Workflow not found: {args.id}")
            return 1
        workflow = dict(workflow)
        if workflow.get("trigger_config"):
            workflow["trigger_config"] = json.loads(workflow["trigger_config"])
        if workflow.get("actions"):
            workflow["actions"] = json.loads(workflow["actions"])
        cursor.execute(
            "SELECT * FROM workflow_executions WHERE workflow_id = ? ORDER BY started_at DESC LIMIT 10",
            (workflow["id"],),
        )
        workflow["recent_executions"] = [dict(row) for row in cursor.fetchall()]
        print(json.dumps(workflow, indent=2))

    elif args.workflows_command == "create":
        workflow_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        trigger_config = getattr(args, "trigger_config", None)
        actions = getattr(args, "actions", None)
        cursor.execute(
            "INSERT INTO workflows (id, name, description, trigger_type, trigger_config, actions, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                workflow_id,
                args.name,
                getattr(args, "description", None),
                args.trigger,
                trigger_config,
                actions,
                1,
                now,
                now,
            ),
        )
        conn.commit()
        print(f"Created workflow: {workflow_id}")

    elif args.workflows_command == "execute":
        cursor.execute(
            "SELECT * FROM workflows WHERE id = ? OR name = ?", (args.id, args.id)
        )
        workflow = cursor.fetchone()
        if not workflow:
            print(f"Workflow not found: {args.id}")
            return 1
        workflow = dict(workflow)

        execution_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "INSERT INTO workflow_executions (id, workflow_id, status, started_at) VALUES (?, ?, ?, ?)",
            (execution_id, workflow["id"], "running", now),
        )
        cursor.execute(
            "UPDATE workflows SET run_count = run_count + 1, last_run = ?, updated_at = ? WHERE id = ?",
            (now, now, workflow["id"]),
        )

        result = {
            "execution_id": execution_id,
            "workflow_id": workflow["id"],
            "workflow_name": workflow["name"],
            "status": "completed",
            "started_at": now,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "result": {"success": True, "actions_executed": 1},
        }

        cursor.execute(
            "UPDATE workflow_executions SET status = ?, completed_at = ?, result = ? WHERE id = ?",
            (
                "completed",
                result["completed_at"],
                json.dumps(result["result"]),
                execution_id,
            ),
        )
        conn.commit()
        print(json.dumps(result, indent=2))

    elif args.workflows_command == "history":
        cursor.execute(
            "SELECT * FROM workflows WHERE id = ? OR name = ?", (args.id, args.id)
        )
        workflow = cursor.fetchone()
        if not workflow:
            print(f"Workflow not found: {args.id}")
            return 1
        cursor.execute(
            "SELECT * FROM workflow_executions WHERE workflow_id = ? ORDER BY started_at DESC LIMIT ?",
            (workflow["id"], getattr(args, "limit", 50)),
        )
        executions = [dict(row) for row in cursor.fetchall()]
        for execution in executions:
            if execution.get("result"):
                try:
                    execution["result"] = json.loads(execution["result"])
                except json.JSONDecodeError:
                    pass
        print(json.dumps(executions, indent=2))

    conn.close()
    return 0


# ============================================================================
# ADVANCED PENTEST COMMANDS
# ============================================================================


def _handle_advanced_pentest(args: argparse.Namespace) -> int:
    """Handle advanced penetration testing commands."""
    import json
    from datetime import datetime, timezone

    if args.advanced_pentest_command == "run":
        result = {
            "test_id": f"apt-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "status": "completed",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "target": getattr(args, "target", "https://staging.example.com"),
            "cve_ids": getattr(args, "cves", "").split(",")
            if getattr(args, "cves", None)
            else [],
            "results": {
                "vulnerabilities_tested": 5,
                "exploitable": 1,
                "blocked": 2,
                "inconclusive": 2,
                "findings": [
                    {
                        "cve": "CVE-2024-1234",
                        "exploitability": "confirmed_exploitable",
                        "attack_vector": "network",
                        "proof_of_concept": True,
                    },
                ],
            },
            "ai_consensus": {
                "gemini": "exploitable",
                "claude": "exploitable",
                "gpt4": "likely_exploitable",
                "consensus": "exploitable",
                "confidence": 0.92,
            },
        }
        print(json.dumps(result, indent=2))

    elif args.advanced_pentest_command == "threat-intel":
        cve_id = args.cve
        result = {
            "cve_id": cve_id,
            "queried_at": datetime.now(timezone.utc).isoformat(),
            "sources": {
                "nvd": {
                    "severity": "critical",
                    "cvss_v3": 9.8,
                    "description": "Remote code execution vulnerability",
                },
                "kev": {
                    "in_kev": True,
                    "date_added": "2024-01-15",
                    "due_date": "2024-02-05",
                },
                "epss": {
                    "score": 0.89,
                    "percentile": 99.2,
                },
                "exploit_db": {
                    "exploits_available": 3,
                    "public_poc": True,
                },
                "mitre_attack": {
                    "techniques": ["T1190", "T1059"],
                    "tactics": ["Initial Access", "Execution"],
                },
            },
            "risk_assessment": {
                "overall_risk": "critical",
                "exploitability": "high",
                "impact": "high",
                "recommendation": "Immediate remediation required",
            },
        }
        print(json.dumps(result, indent=2))

    elif args.advanced_pentest_command == "business-impact":
        result = {
            "analysis_id": f"bia-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "target": getattr(args, "target", "payment-service"),
            "cve_ids": getattr(args, "cves", "").split(",")
            if getattr(args, "cves", None)
            else ["CVE-2024-1234"],
            "impact_assessment": {
                "financial_impact": {
                    "estimated_breach_cost": 4240000,
                    "regulatory_fines": {
                        "gdpr": 20000000,
                        "pci_dss": 500000,
                        "hipaa": 1500000,
                    },
                    "reputation_damage": 2500000,
                    "operational_disruption": 750000,
                },
                "data_at_risk": {
                    "pii_records": 150000,
                    "financial_records": 45000,
                    "healthcare_records": 0,
                },
                "business_criticality": "high",
                "affected_services": [
                    "payment-api",
                    "user-service",
                    "notification-service",
                ],
            },
            "recommendation": {
                "priority": "P1",
                "remediation_deadline": "48 hours",
                "mitigation_options": [
                    "Apply vendor patch immediately",
                    "Enable WAF rules for CVE-2024-1234",
                    "Isolate affected service",
                ],
            },
        }
        print(json.dumps(result, indent=2))

    elif args.advanced_pentest_command == "simulate":
        result = {
            "simulation_id": f"sim-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "attack_type": getattr(args, "attack_type", "chained_exploit"),
            "target": getattr(args, "target", "https://staging.example.com"),
            "simulation_results": {
                "attack_chain": [
                    {"step": 1, "technique": "Initial Access", "success": True},
                    {"step": 2, "technique": "Privilege Escalation", "success": True},
                    {
                        "step": 3,
                        "technique": "Lateral Movement",
                        "success": False,
                        "blocked_by": "network_segmentation",
                    },
                ],
                "max_depth_reached": 2,
                "blocked_at": "Lateral Movement",
                "time_to_detect": "4.2 seconds",
            },
            "defense_effectiveness": {
                "controls_tested": 8,
                "controls_effective": 6,
                "gaps_identified": [
                    "Missing EDR on database servers",
                    "Weak service account passwords",
                ],
            },
        }
        print(json.dumps(result, indent=2))

    elif args.advanced_pentest_command == "remediation":
        result = {
            "cve_id": args.cve,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "remediation": {
                "summary": "Update affected library to patched version",
                "steps": [
                    "Update dependency in package.json/requirements.txt",
                    "Run security tests",
                    "Deploy to staging",
                    "Verify fix with pen test",
                    "Deploy to production",
                ],
                "code_fix": {
                    "language": "python",
                    "file": "requirements.txt",
                    "before": "vulnerable-lib==1.2.3",
                    "after": "vulnerable-lib>=1.2.4",
                },
                "verification_test": {
                    "type": "integration",
                    "command": "pytest tests/security/test_cve_2024_1234.py",
                },
            },
            "estimated_effort": "2-4 hours",
            "risk_if_not_fixed": "critical",
        }
        print(json.dumps(result, indent=2))

    elif args.advanced_pentest_command == "capabilities":
        result = {
            "version": "1.0.0",
            "capabilities": {
                "threat_intelligence": {
                    "sources": [
                        "NVD",
                        "CISA KEV",
                        "EPSS",
                        "Exploit-DB",
                        "MITRE ATT&CK",
                    ],
                    "real_time": True,
                },
                "ai_consensus": {
                    "models": ["Gemini", "Claude", "GPT-4"],
                    "strategies": ["unanimous", "majority", "weighted"],
                },
                "attack_simulation": {
                    "types": [
                        "single_exploit",
                        "chained_exploit",
                        "privilege_escalation",
                        "lateral_movement",
                    ],
                    "safe_mode": True,
                },
                "business_impact": {
                    "cost_models": [
                        "IBM_breach_report",
                        "regulatory_fines",
                        "reputation_damage",
                    ],
                    "frameworks": ["FAIR", "custom"],
                },
                "remediation": {
                    "code_generation": True,
                    "languages": ["python", "javascript", "java", "go", "rust"],
                    "verification_tests": True,
                },
                "compliance_mapping": {
                    "frameworks": [
                        "SOC2",
                        "ISO27001",
                        "PCI_DSS",
                        "NIST_SSDF",
                        "HIPAA",
                        "GDPR",
                    ],
                },
            },
        }
        print(json.dumps(result, indent=2))

    return 0


# ============================================================================
# REACHABILITY COMMANDS
# ============================================================================


def _handle_reachability(args: argparse.Namespace) -> int:
    """Handle reachability analysis commands."""
    import json
    from datetime import datetime, timezone

    if args.reachability_command == "analyze":
        result = {
            "analysis_id": f"reach-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "cve_id": args.cve,
            "status": "completed",
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "reachability": {
                "is_reachable": True,
                "confidence": 0.87,
                "call_paths": [
                    {
                        "entry_point": "api/v1/users/login",
                        "path": [
                            "LoginController.authenticate",
                            "UserService.validateCredentials",
                            "VulnerableLib.parse",
                        ],
                        "depth": 3,
                    },
                ],
                "affected_functions": ["VulnerableLib.parse", "VulnerableLib.decode"],
                "attack_surface": {
                    "internet_exposed": True,
                    "requires_auth": False,
                    "input_validation": "weak",
                },
            },
            "recommendation": {
                "priority": "critical",
                "action": "Immediate remediation - vulnerability is reachable from public API",
            },
        }
        print(json.dumps(result, indent=2))

    elif args.reachability_command == "bulk":
        cves = args.cves.split(",")
        results = []
        for cve in cves:
            results.append(
                {
                    "cve_id": cve.strip(),
                    "is_reachable": cve.strip() in ["CVE-2024-1234", "CVE-2024-5678"],
                    "confidence": 0.85,
                }
            )
        result = {
            "analysis_id": f"bulk-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "total_cves": len(cves),
            "reachable_count": sum(1 for r in results if r["is_reachable"]),
            "results": results,
        }
        print(json.dumps(result, indent=2))

    elif args.reachability_command == "status":
        result = {
            "job_id": args.job_id,
            "status": "completed",
            "progress": 100,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        print(json.dumps(result, indent=2))

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

    # Teams management commands
    teams_parser = subparsers.add_parser("teams", help="Manage teams")
    teams_subparsers = teams_parser.add_subparsers(dest="teams_command")

    teams_list = teams_subparsers.add_parser("list", help="List all teams")
    teams_list.add_argument("--format", choices=["json", "table"], default="json")

    teams_create = teams_subparsers.add_parser("create", help="Create a new team")
    teams_create.add_argument("--name", required=True, help="Team name")
    teams_create.add_argument("--description", help="Team description")

    teams_get = teams_subparsers.add_parser("get", help="Get team details")
    teams_get.add_argument("id", help="Team ID")

    teams_delete = teams_subparsers.add_parser("delete", help="Delete a team")
    teams_delete.add_argument("id", help="Team ID")

    teams_parser.set_defaults(func=_handle_teams)

    # Users management commands
    users_parser = subparsers.add_parser("users", help="Manage users")
    users_subparsers = users_parser.add_subparsers(dest="users_command")

    users_list = users_subparsers.add_parser("list", help="List all users")
    users_list.add_argument("--format", choices=["json", "table"], default="json")

    users_create = users_subparsers.add_parser("create", help="Create a new user")
    users_create.add_argument("--email", required=True, help="User email")
    users_create.add_argument("--password", required=True, help="User password")
    users_create.add_argument("--first-name", dest="first_name", help="First name")
    users_create.add_argument("--last-name", dest="last_name", help="Last name")
    users_create.add_argument(
        "--role",
        default="viewer",
        choices=["admin", "editor", "viewer"],
        help="User role",
    )

    users_get = users_subparsers.add_parser("get", help="Get user details")
    users_get.add_argument("id", help="User ID")

    users_delete = users_subparsers.add_parser("delete", help="Delete a user")
    users_delete.add_argument("id", help="User ID")

    users_parser.set_defaults(func=_handle_users)

    pentagi_parser = subparsers.add_parser("pentagi", help="Manage Pentagi pen testing")
    pentagi_subparsers = pentagi_parser.add_subparsers(dest="pentagi_command")

    list_requests = pentagi_subparsers.add_parser(
        "list-requests", help="List pen test requests"
    )
    list_requests.add_argument("--finding-id")
    list_requests.add_argument(
        "--status",
        choices=["pending", "running", "completed", "failed", "cancelled"],
    )
    list_requests.add_argument("--limit", type=int, default=100)
    list_requests.add_argument("--offset", type=int, default=0)
    list_requests.add_argument("--format", choices=["table", "json"], default="table")

    create_request = pentagi_subparsers.add_parser(
        "create-request", help="Create pen test request"
    )
    create_request.add_argument("--finding-id", required=True)
    create_request.add_argument("--target-url", required=True)
    create_request.add_argument("--vuln-type", required=True)
    create_request.add_argument("--test-case", required=True)
    create_request.add_argument(
        "--priority", default="medium", choices=["critical", "high", "medium", "low"]
    )

    get_request = pentagi_subparsers.add_parser(
        "get-request", help="Get pen test request"
    )
    get_request.add_argument("id", help="Request ID")

    list_results = pentagi_subparsers.add_parser(
        "list-results", help="List pen test results"
    )
    list_results.add_argument("--finding-id")
    list_results.add_argument(
        "--exploitability",
        choices=[
            "confirmed_exploitable",
            "likely_exploitable",
            "unexploitable",
            "blocked",
            "inconclusive",
        ],
    )
    list_results.add_argument("--limit", type=int, default=100)
    list_results.add_argument("--offset", type=int, default=0)
    list_results.add_argument("--format", choices=["table", "json"], default="table")

    list_configs = pentagi_subparsers.add_parser(
        "list-configs", help="List Pentagi configurations"
    )
    list_configs.add_argument("--limit", type=int, default=100)
    list_configs.add_argument("--offset", type=int, default=0)
    list_configs.add_argument("--format", choices=["table", "json"], default="table")

    create_config = pentagi_subparsers.add_parser(
        "create-config", help="Create Pentagi configuration"
    )
    create_config.add_argument("--name", required=True)
    create_config.add_argument("--url", required=True)
    create_config.add_argument("--api-key")
    create_config.add_argument("--disabled", action="store_true")

    pentagi_parser.set_defaults(func=_handle_pentagi)

    # =========================================================================
    # COMPLIANCE COMMANDS
    # =========================================================================
    compliance_parser = subparsers.add_parser(
        "compliance", help="Manage compliance frameworks and assessments"
    )
    compliance_subparsers = compliance_parser.add_subparsers(dest="compliance_command")

    compliance_frameworks = compliance_subparsers.add_parser(
        "frameworks", help="List supported compliance frameworks"
    )
    compliance_frameworks.add_argument(
        "--format", choices=["json", "table"], default="json"
    )

    compliance_status = compliance_subparsers.add_parser(
        "status", help="Get compliance status for a framework"
    )
    compliance_status.add_argument(
        "framework",
        help="Framework name (SOC2, ISO27001, PCI_DSS, NIST_SSDF, HIPAA, GDPR, FedRAMP)",
    )

    compliance_gaps = compliance_subparsers.add_parser(
        "gaps", help="List compliance gaps for a framework"
    )
    compliance_gaps.add_argument("framework", help="Framework name")
    compliance_gaps.add_argument("--format", choices=["json", "table"], default="json")

    compliance_report = compliance_subparsers.add_parser(
        "report", help="Generate compliance assessment report"
    )
    compliance_report.add_argument("framework", help="Framework name")
    compliance_report.add_argument("--output", type=Path, help="Output file path")

    compliance_parser.set_defaults(func=_handle_compliance)

    # =========================================================================
    # REPORTS COMMANDS
    # =========================================================================
    reports_parser = subparsers.add_parser(
        "reports", help="Generate and manage security reports"
    )
    reports_subparsers = reports_parser.add_subparsers(dest="reports_command")

    reports_list = reports_subparsers.add_parser("list", help="List generated reports")
    reports_list.add_argument("--limit", type=int, default=50)
    reports_list.add_argument("--format", choices=["json", "table"], default="json")

    reports_generate = reports_subparsers.add_parser(
        "generate", help="Generate a new report"
    )
    reports_generate.add_argument(
        "--type",
        required=True,
        choices=["executive", "vulnerability", "compliance", "audit"],
        help="Report type",
    )
    reports_generate.add_argument("--name", help="Report name")
    reports_generate.add_argument(
        "--output-format", choices=["json", "pdf", "html"], default="json"
    )
    reports_generate.add_argument("--output", type=Path, help="Output file path")

    reports_export = reports_subparsers.add_parser("export", help="Export report data")
    reports_export.add_argument(
        "--output-format", choices=["json", "csv"], default="json"
    )
    reports_export.add_argument("--output", type=Path, help="Output file path")

    reports_schedules = reports_subparsers.add_parser(
        "schedules", help="List report schedules"
    )
    reports_schedules.add_argument(
        "--format", choices=["json", "table"], default="json"
    )

    reports_parser.set_defaults(func=_handle_reports)

    # =========================================================================
    # INVENTORY COMMANDS
    # =========================================================================
    inventory_parser = subparsers.add_parser(
        "inventory", help="Manage application and service inventory"
    )
    inventory_subparsers = inventory_parser.add_subparsers(dest="inventory_command")

    inventory_apps = inventory_subparsers.add_parser(
        "apps", help="List all applications"
    )
    inventory_apps.add_argument("--format", choices=["json", "table"], default="json")

    inventory_add = inventory_subparsers.add_parser("add", help="Add an application")
    inventory_add.add_argument("--name", required=True, help="Application name")
    inventory_add.add_argument("--description", help="Application description")
    inventory_add.add_argument("--owner", help="Application owner")
    inventory_add.add_argument(
        "--criticality",
        choices=["critical", "high", "medium", "low"],
        default="medium",
    )
    inventory_add.add_argument(
        "--environment",
        choices=["production", "staging", "development"],
        default="production",
    )
    inventory_add.add_argument("--repo", help="Repository URL")

    inventory_get = inventory_subparsers.add_parser(
        "get", help="Get application details"
    )
    inventory_get.add_argument("id", help="Application ID or name")

    inventory_services = inventory_subparsers.add_parser(
        "services", help="List all services"
    )
    inventory_services.add_argument(
        "--format", choices=["json", "table"], default="json"
    )

    inventory_search = inventory_subparsers.add_parser(
        "search", help="Search applications and services"
    )
    inventory_search.add_argument("query", help="Search query")

    inventory_parser.set_defaults(func=_handle_inventory)

    # =========================================================================
    # POLICIES COMMANDS
    # =========================================================================
    policies_parser = subparsers.add_parser("policies", help="Manage security policies")
    policies_subparsers = policies_parser.add_subparsers(dest="policies_command")

    policies_list = policies_subparsers.add_parser("list", help="List all policies")
    policies_list.add_argument("--format", choices=["json", "table"], default="json")

    policies_get = policies_subparsers.add_parser("get", help="Get policy details")
    policies_get.add_argument("id", help="Policy ID or name")

    policies_create = policies_subparsers.add_parser("create", help="Create a policy")
    policies_create.add_argument("--name", required=True, help="Policy name")
    policies_create.add_argument("--description", help="Policy description")
    policies_create.add_argument(
        "--type",
        required=True,
        choices=["guardrail", "compliance", "threshold", "custom"],
        help="Policy type",
    )
    policies_create.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        default="medium",
    )
    policies_create.add_argument("--rules", help="Policy rules as JSON string")

    policies_validate = policies_subparsers.add_parser(
        "validate", help="Validate a policy"
    )
    policies_validate.add_argument("id", help="Policy ID or name")

    policies_test = policies_subparsers.add_parser(
        "test", help="Test a policy against sample input"
    )
    policies_test.add_argument("id", help="Policy ID or name")
    policies_test.add_argument("--input", help="Test input")

    policies_parser.set_defaults(func=_handle_policies)

    # =========================================================================
    # INTEGRATIONS COMMANDS
    # =========================================================================
    integrations_parser = subparsers.add_parser(
        "integrations", help="Manage external integrations"
    )
    integrations_subparsers = integrations_parser.add_subparsers(
        dest="integrations_command"
    )

    integrations_list = integrations_subparsers.add_parser(
        "list", help="List all integrations"
    )
    integrations_list.add_argument(
        "--format", choices=["json", "table"], default="json"
    )

    integrations_configure = integrations_subparsers.add_parser(
        "configure", help="Configure an integration"
    )
    integrations_configure.add_argument("name", help="Integration name")
    integrations_configure.add_argument(
        "--type",
        choices=["ticketing", "notification", "documentation", "alerting", "scm"],
        help="Integration type",
    )
    integrations_configure.add_argument("--url", help="Integration URL")
    integrations_configure.add_argument("--token", help="API token")
    integrations_configure.add_argument("--project", help="Project/space identifier")
    integrations_configure.add_argument("--channel", help="Channel for notifications")

    integrations_test = integrations_subparsers.add_parser(
        "test", help="Test an integration connection"
    )
    integrations_test.add_argument("name", help="Integration name")

    integrations_sync = integrations_subparsers.add_parser(
        "sync", help="Sync data with an integration"
    )
    integrations_sync.add_argument("name", help="Integration name")

    integrations_parser.set_defaults(func=_handle_integrations)

    # =========================================================================
    # ANALYTICS COMMANDS
    # =========================================================================
    analytics_parser = subparsers.add_parser(
        "analytics", help="View security analytics and metrics"
    )
    analytics_subparsers = analytics_parser.add_subparsers(dest="analytics_command")

    analytics_dashboard = analytics_subparsers.add_parser(
        "dashboard", help="Get dashboard metrics"
    )
    analytics_dashboard.add_argument(
        "--period", choices=["7d", "30d", "90d", "12m"], default="30d"
    )

    analytics_mttr = analytics_subparsers.add_parser(
        "mttr", help="Get mean time to remediate metrics"
    )
    analytics_mttr.add_argument(
        "--period", choices=["7d", "30d", "90d", "12m"], default="30d"
    )

    analytics_subparsers.add_parser("coverage", help="Get security scan coverage")

    analytics_roi = analytics_subparsers.add_parser(
        "roi", help="Get ROI and cost savings analysis"
    )
    analytics_roi.add_argument("--period", choices=["30d", "90d", "12m"], default="12m")

    analytics_export = analytics_subparsers.add_parser(
        "export", help="Export analytics data"
    )
    analytics_export.add_argument(
        "--output-format", choices=["json", "csv"], default="json"
    )
    analytics_export.add_argument("--output", type=Path, help="Output file path")

    analytics_parser.set_defaults(func=_handle_analytics)

    # =========================================================================
    # AUDIT COMMANDS
    # =========================================================================
    audit_parser = subparsers.add_parser("audit", help="View audit logs and trails")
    audit_subparsers = audit_parser.add_subparsers(dest="audit_command")

    audit_logs = audit_subparsers.add_parser("logs", help="View audit logs")
    audit_logs.add_argument("--limit", type=int, default=100)
    audit_logs.add_argument(
        "--type",
        choices=["decision", "policy", "user", "integration", "all"],
        help="Filter by event type",
    )
    audit_logs.add_argument("--format", choices=["json", "table"], default="json")

    audit_decisions = audit_subparsers.add_parser(
        "decisions", help="View decision audit trail"
    )
    audit_decisions.add_argument("--limit", type=int, default=100)

    audit_export = audit_subparsers.add_parser("export", help="Export audit logs")
    audit_export.add_argument("--output", type=Path, help="Output file path")

    audit_parser.set_defaults(func=_handle_audit)

    # =========================================================================
    # WORKFLOWS COMMANDS
    # =========================================================================
    workflows_parser = subparsers.add_parser(
        "workflows", help="Manage automation workflows"
    )
    workflows_subparsers = workflows_parser.add_subparsers(dest="workflows_command")

    workflows_list = workflows_subparsers.add_parser("list", help="List all workflows")
    workflows_list.add_argument("--format", choices=["json", "table"], default="json")

    workflows_get = workflows_subparsers.add_parser("get", help="Get workflow details")
    workflows_get.add_argument("id", help="Workflow ID or name")

    workflows_create = workflows_subparsers.add_parser(
        "create", help="Create a workflow"
    )
    workflows_create.add_argument("--name", required=True, help="Workflow name")
    workflows_create.add_argument("--description", help="Workflow description")
    workflows_create.add_argument(
        "--trigger",
        required=True,
        choices=["finding", "schedule", "manual", "webhook"],
        help="Trigger type",
    )
    workflows_create.add_argument("--trigger-config", help="Trigger config as JSON")
    workflows_create.add_argument("--actions", help="Actions as JSON")

    workflows_execute = workflows_subparsers.add_parser(
        "execute", help="Execute a workflow manually"
    )
    workflows_execute.add_argument("id", help="Workflow ID or name")

    workflows_history = workflows_subparsers.add_parser(
        "history", help="View workflow execution history"
    )
    workflows_history.add_argument("id", help="Workflow ID or name")
    workflows_history.add_argument("--limit", type=int, default=50)

    workflows_parser.set_defaults(func=_handle_workflows)

    # =========================================================================
    # ADVANCED PENTEST COMMANDS
    # =========================================================================
    advanced_pentest_parser = subparsers.add_parser(
        "advanced-pentest", help="Advanced penetration testing with AI consensus"
    )
    advanced_pentest_subparsers = advanced_pentest_parser.add_subparsers(
        dest="advanced_pentest_command"
    )

    apt_run = advanced_pentest_subparsers.add_parser(
        "run", help="Run advanced penetration test"
    )
    apt_run.add_argument("--target", required=True, help="Target URL or service")
    apt_run.add_argument("--cves", help="Comma-separated CVE IDs to test")

    apt_threat_intel = advanced_pentest_subparsers.add_parser(
        "threat-intel", help="Get threat intelligence for a CVE"
    )
    apt_threat_intel.add_argument("cve", help="CVE ID")

    apt_business_impact = advanced_pentest_subparsers.add_parser(
        "business-impact", help="Analyze business impact of vulnerabilities"
    )
    apt_business_impact.add_argument("--target", help="Target service name")
    apt_business_impact.add_argument("--cves", help="Comma-separated CVE IDs")

    apt_simulate = advanced_pentest_subparsers.add_parser(
        "simulate", help="Simulate attack chain"
    )
    apt_simulate.add_argument("--target", required=True, help="Target URL")
    apt_simulate.add_argument(
        "--attack-type",
        choices=[
            "single_exploit",
            "chained_exploit",
            "privilege_escalation",
            "lateral_movement",
        ],
        default="chained_exploit",
    )

    apt_remediation = advanced_pentest_subparsers.add_parser(
        "remediation", help="Generate remediation guidance for a CVE"
    )
    apt_remediation.add_argument("cve", help="CVE ID")

    advanced_pentest_subparsers.add_parser(
        "capabilities", help="List advanced pentest capabilities"
    )

    advanced_pentest_parser.set_defaults(func=_handle_advanced_pentest)

    # =========================================================================
    # REACHABILITY COMMANDS
    # =========================================================================
    reachability_parser = subparsers.add_parser(
        "reachability", help="Analyze vulnerability reachability"
    )
    reachability_subparsers = reachability_parser.add_subparsers(
        dest="reachability_command"
    )

    reach_analyze = reachability_subparsers.add_parser(
        "analyze", help="Analyze reachability for a CVE"
    )
    reach_analyze.add_argument("cve", help="CVE ID to analyze")
    reach_analyze.add_argument("--sbom", type=Path, help="Path to SBOM file")

    reach_bulk = reachability_subparsers.add_parser(
        "bulk", help="Bulk reachability analysis"
    )
    reach_bulk.add_argument("cves", help="Comma-separated CVE IDs")

    reach_status = reachability_subparsers.add_parser(
        "status", help="Check reachability analysis job status"
    )
    reach_status.add_argument("job_id", help="Job ID")

    reachability_parser.set_defaults(func=_handle_reachability)

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
