"""Utilities for running the FixOps pipeline with bundled demo fixtures."""
from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from backend.normalizers import InputNormalizer, NormalizedCVEFeed, NormalizedSARIF, NormalizedSBOM
from backend.pipeline import PipelineOrchestrator
from fixops.configuration import OverlayConfig, load_overlay
from fixops.evidence import Fernet  # type: ignore
from fixops.paths import ensure_secure_directory

_DEMO_ENV_DEFAULTS: Dict[str, str] = {
    "FIXOPS_API_TOKEN": "demo-api-token",
    "FIXOPS_JIRA_TOKEN": "demo-jira-token",
    "FIXOPS_CONFLUENCE_TOKEN": "demo-confluence-token",
    "FIXOPS_EVIDENCE_KEY": "Zz6A0n4P3skS8F6edSxE2xe50Tzw9uQWGWp9JYG1ChE=",
}

_FIXTURE_DIR = Path(__file__).resolve().parent.parent / "demo" / "fixtures"


def _ensure_env_defaults() -> None:
    for key, value in _DEMO_ENV_DEFAULTS.items():
        os.environ.setdefault(key, value)


def _read_design(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = [row for row in reader if any((value or "").strip() for value in row.values())]
    return {"columns": reader.fieldnames or [], "rows": rows}


@dataclass
class DemoInputs:
    """Container capturing raw and normalised fixture content for showcases."""

    design_path: Path
    design_dataset: Dict[str, Any]
    sbom_path: Path
    sbom: NormalizedSBOM
    sarif_path: Path
    sarif: NormalizedSARIF
    cve_path: Path
    cve: NormalizedCVEFeed


def _fixture_path(filename: str) -> Path:
    candidate = _FIXTURE_DIR / filename
    if not candidate.exists():
        raise FileNotFoundError(f"Demo fixture '{filename}' is missing at {candidate}")
    return candidate


def _load_demo_inputs() -> DemoInputs:
    """Load bundled fixtures and return their parsed representations."""

    normalizer = InputNormalizer()

    design_path = _fixture_path("sample.design.csv")
    design_dataset = _read_design(design_path)

    sbom_path = _fixture_path("sample.sbom.json")
    sbom = normalizer.load_sbom(sbom_path.read_bytes())

    sarif_path = _fixture_path("sample.sarif.json")
    sarif = normalizer.load_sarif(sarif_path.read_bytes())

    cve_path = _fixture_path("sample.cve.json")
    cve = normalizer.load_cve_feed(cve_path.read_bytes())

    return DemoInputs(
        design_path=design_path,
        design_dataset=design_dataset,
        sbom_path=sbom_path,
        sbom=sbom,
        sarif_path=sarif_path,
        sarif=sarif,
        cve_path=cve_path,
        cve=cve,
    )


def _bundle_path(result: Mapping[str, Any]) -> Optional[Path]:
    bundle = (
        result.get("evidence_bundle", {})
        if isinstance(result.get("evidence_bundle"), Mapping)
        else {}
    )
    if not isinstance(bundle, Mapping):
        return None
    files = bundle.get("files")
    if not isinstance(files, Mapping):
        return None
    path = files.get("bundle")
    if not isinstance(path, str) or not path:
        return None
    return Path(path)


def _format_summary(
    result: Mapping[str, Any],
    *,
    mode: str,
    output_path: Optional[Path],
    evidence_path: Optional[Path],
) -> List[str]:
    severity = (
        result.get("severity_overview", {}).get("highest")
        if isinstance(result.get("severity_overview"), Mapping)
        else None
    )
    guardrail = (
        result.get("guardrail_evaluation", {}).get("status")
        if isinstance(result.get("guardrail_evaluation"), Mapping)
        else None
    )
    compliance = result.get("compliance_status", {})
    frameworks: Sequence[str] = []
    if isinstance(compliance, Mapping):
        raw_frameworks = compliance.get("frameworks")
        if isinstance(raw_frameworks, Iterable):
            frameworks = [
                str(item.get("id", "framework"))
                for item in raw_frameworks
                if isinstance(item, Mapping)
            ]
    modules = result.get("modules", {})
    executed: Sequence[str] = []
    if isinstance(modules, Mapping):
        executed_raw = modules.get("executed")
        if isinstance(executed_raw, Iterable):
            executed = [str(module) for module in executed_raw]
    lines = [f"FixOps {mode.title()} mode summary:"]
    if severity:
        lines.append(f"  Highest severity: {severity}")
    if guardrail:
        lines.append(f"  Guardrail status: {guardrail}")
    if frameworks:
        lines.append(f"  Compliance frameworks: {', '.join(sorted(set(frameworks)))}")
    if executed:
        lines.append(f"  Modules executed: {', '.join(executed)}")
    pricing = result.get("pricing_summary", {})
    if isinstance(pricing, Mapping):
        active = pricing.get("active_plan")
        if isinstance(active, Mapping):
            plan_name = active.get("name")
            if plan_name:
                lines.append(f"  Active pricing plan: {plan_name}")
    if output_path:
        lines.append(f"  Result saved to: {output_path}")
    if evidence_path:
        lines.append(f"  Evidence bundle: {evidence_path}")
    return lines


def _prepare_overlay(mode: str) -> OverlayConfig:
    _ensure_env_defaults()
    overlay = load_overlay(mode_override=mode)
    evidence_limits = overlay.limits.setdefault("evidence", {}) if isinstance(overlay.limits, dict) else {}
    if evidence_limits.get("encrypt") and Fernet is None:
        evidence_limits["encrypt"] = False
    for directory in overlay.data_directories.values():
        ensure_secure_directory(directory)
    return overlay


def run_demo_pipeline(
    mode: str = "demo",
    *,
    output_path: Optional[Path] = None,
    pretty: bool = True,
    include_summary: bool = True,
) -> Tuple[Dict[str, Any], List[str]]:
    """Execute the pipeline using bundled demo artefacts.

    Parameters
    ----------
    mode:
        Overlay profile to load (``"demo"`` or ``"enterprise"``).
    output_path:
        Optional file to persist the raw pipeline response as JSON.
    pretty:
        When persisting to ``output_path``, control whether the JSON is
        pretty-printed.
    include_summary:
        Print a short human-readable summary when ``True``.
    """

    selected_mode = mode.lower().strip() or "demo"
    overlay = _prepare_overlay(selected_mode)

    normalizer = InputNormalizer()
    sbom = normalizer.load_sbom(_fixture_path("sample.sbom.json").read_bytes())
    sarif = normalizer.load_sarif(_fixture_path("sample.sarif.json").read_bytes())
    cve = normalizer.load_cve_feed(_fixture_path("sample.cve.json").read_bytes())
    design = _read_design(_fixture_path("sample.design.csv"))

    orchestrator = PipelineOrchestrator()
    result = orchestrator.run(
        design_dataset=design,
        sbom=sbom,
        sarif=sarif,
        cve=cve,
        overlay=overlay,
    )

    if output_path:
        ensure_secure_directory(output_path.parent)
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2 if pretty else None)
            if pretty:
                handle.write("\n")

    evidence_path = _bundle_path(result)
    summary_lines = _format_summary(
        result,
        mode=selected_mode,
        output_path=output_path,
        evidence_path=evidence_path,
    )

    if include_summary:
        for line in summary_lines:
            print(line)

    return result, summary_lines


def generate_showcase(
    mode: str = "demo",
    *,
    include_raw_result: bool = False,
) -> Dict[str, Any]:
    """Return a structured summary of demo inputs, pipeline stages, and integrations.

    The snapshot powers CLI walkthroughs and documentation that need to
    illustrate what goes into (and comes out of) each pipeline stage without
    requiring developers to manually inspect large JSON payloads.
    """

    selected_mode = mode.lower().strip() or "demo"
    inputs = _load_demo_inputs()
    result, summary_lines = run_demo_pipeline(
        selected_mode,
        include_summary=False,
    )

    def _sample_rows(rows: Sequence[Mapping[str, Any]], limit: int = 2) -> List[Mapping[str, Any]]:
        return [dict(row) for row in rows[:limit]]

    sbom_components = [component.to_dict() for component in inputs.sbom.components[:3]]
    fallback_components: List[Dict[str, Any]] = []
    if not sbom_components:
        document = getattr(inputs.sbom, "document", {})
        if isinstance(document, Mapping):
            manifests = document.get("detectedManifests", {})
            if isinstance(manifests, Mapping):
                for manifest in manifests.values():
                    resolved = manifest.get("resolved") if isinstance(manifest, Mapping) else None
                    if not isinstance(resolved, Mapping):
                        continue
                    for name, meta in resolved.items():
                        if not isinstance(meta, Mapping):
                            continue
                        fallback_components.append(
                            {
                                "name": meta.get("name") or name,
                                "version": meta.get("version"),
                                "purl": meta.get("packageUrl"),
                                "licenses": meta.get("licenses"),
                            }
                        )
                        if len(fallback_components) >= 3:
                            break
                    if len(fallback_components) >= 3:
                        break
    if not sbom_components and fallback_components:
        sbom_components = fallback_components

    component_count = len(inputs.sbom.components)
    if component_count == 0 and fallback_components:
        component_count = len(fallback_components)
    sarif_findings = [finding.to_dict() for finding in inputs.sarif.findings[:3]]
    cve_records = [
        {
            "cve_id": record.cve_id,
            "title": record.title,
            "severity": record.severity,
            "exploited": record.exploited,
        }
        for record in inputs.cve.records[:3]
    ]

    severity = result.get("severity_overview", {}) if isinstance(result, Mapping) else {}
    guardrail = result.get("guardrail_evaluation", {}) if isinstance(result, Mapping) else {}
    modules = result.get("modules", {}) if isinstance(result, Mapping) else {}
    compliance = result.get("compliance_status", {}) if isinstance(result, Mapping) else {}

    evidence_bundle = result.get("evidence_bundle", {}) if isinstance(result, Mapping) else {}
    bundle_path: Optional[Path] = None
    bundle_size: Optional[int] = None
    if isinstance(evidence_bundle, Mapping):
        files = evidence_bundle.get("files")
        if isinstance(files, Mapping):
            bundle_location = files.get("bundle")
            if isinstance(bundle_location, str) and bundle_location:
                bundle_path = Path(bundle_location)
                try:
                    bundle_size = bundle_path.stat().st_size
                except FileNotFoundError:
                    bundle_path = None
                    bundle_size = None

    policy_automation = result.get("policy_automation", {}) if isinstance(result, Mapping) else {}
    actions: List[Mapping[str, Any]] = []
    if isinstance(policy_automation, Mapping):
        raw_actions = policy_automation.get("actions", [])
        if isinstance(raw_actions, Iterable):
            for entry in list(raw_actions)[:3]:
                if isinstance(entry, Mapping):
                    actions.append(
                        {
                            "type": entry.get("type"),
                            "summary": entry.get("summary"),
                            "destination": entry.get("channel") or entry.get("project_key"),
                        }
                    )

    execution_status: Optional[str] = None
    delivery_reasons: List[str] = []
    if isinstance(policy_automation, Mapping):
        execution = policy_automation.get("execution")
        if isinstance(execution, Mapping):
            execution_status = str(execution.get("status")) if execution.get("status") is not None else None
            delivery_results = execution.get("delivery_results", [])
            if isinstance(delivery_results, Iterable):
                for item in list(delivery_results)[:3]:
                    if isinstance(item, Mapping):
                        reason = item.get("reason")
                        status = item.get("status")
                        if reason and status:
                            delivery_reasons.append(f"{status}: {reason}")

    snapshot: Dict[str, Any] = {
        "mode": selected_mode,
        "summary_lines": summary_lines,
        "inputs": {
            "design": {
                "source_path": str(inputs.design_path),
                "metrics": {
                    "columns": inputs.design_dataset.get("columns", []),
                    "row_count": len(inputs.design_dataset.get("rows", [])),
                },
                "preview_rows": _sample_rows(inputs.design_dataset.get("rows", [])),
            },
            "sbom": {
                "source_path": str(inputs.sbom_path),
                "metrics": {
                    "format": inputs.sbom.format,
                    "component_count": component_count,
                },
                "sample_components": sbom_components,
            },
            "sarif": {
                "source_path": str(inputs.sarif_path),
                "metrics": {
                    "tool_names": inputs.sarif.tool_names,
                    "finding_count": len(inputs.sarif.findings),
                },
                "sample_findings": sarif_findings,
            },
            "cve": {
                "source_path": str(inputs.cve_path),
                "metrics": {
                    "record_count": len(inputs.cve.records),
                    "exploited_records": sum(1 for record in inputs.cve.records if record.exploited),
                    "errors": inputs.cve.errors,
                },
                "sample_records": cve_records,
            },
        },
        "pipeline": {
            "severity_overview": severity,
            "guardrail_evaluation": {
                "status": guardrail.get("status"),
                "rationale": list(guardrail.get("rationale", [])[:3]) if isinstance(guardrail.get("rationale"), list) else [],
            },
            "context_summary": result.get("context_summary", {}),
            "compliance_status": compliance,
            "modules": {
                "executed": list(modules.get("executed", [])[:10]) if isinstance(modules.get("executed"), Iterable) else [],
                "skipped": list(modules.get("skipped", [])[:10]) if isinstance(modules.get("skipped"), Iterable) else [],
            },
            "ssdlc_assessment": result.get("ssdlc_assessment", {}),
            "exploitability_insights": result.get("exploitability_insights", {}),
            "iac_posture": result.get("iac_posture", {}),
            "probabilistic_forecast": result.get("probabilistic_forecast", {}),
            "performance_profile": result.get("performance_profile", {}),
            "analytics": result.get("analytics", {}),
            "tenant_lifecycle": result.get("tenant_lifecycle", {}),
        },
        "integrations": {
            "policy_automation": {
                "status": policy_automation.get("status"),
                "action_count": len(policy_automation.get("actions", [])) if isinstance(policy_automation.get("actions"), Iterable) else 0,
                "sample_actions": actions,
                "execution_status": execution_status,
                "delivery_notes": delivery_reasons,
            },
            "evidence_bundle": {
                "path": str(bundle_path) if bundle_path else None,
                "size_bytes": bundle_size,
            },
            "onboarding": result.get("onboarding", {}),
            "pricing_summary": result.get("pricing_summary", {}),
        },
    }

    if include_raw_result:
        snapshot["raw_result"] = result

    return snapshot


__all__ = ["run_demo_pipeline", "generate_showcase"]
