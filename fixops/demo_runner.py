"""Utilities for running the FixOps pipeline with bundled demo fixtures."""
from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from backend.normalizers import InputNormalizer
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


def _fixture_path(filename: str) -> Path:
    candidate = _FIXTURE_DIR / filename
    if not candidate.exists():
        raise FileNotFoundError(f"Demo fixture '{filename}' is missing at {candidate}")
    return candidate


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


__all__ = ["run_demo_pipeline"]
