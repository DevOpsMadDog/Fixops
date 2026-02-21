from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, MutableMapping, Optional

from apps.api.normalizers import (
    CVERecordSummary,
    NormalizedCVEFeed,
    NormalizedSARIF,
    NormalizedSBOM,
    SarifFinding,
    SBOMComponent,
)
from apps.api.pipeline import PipelineOrchestrator
from core.configuration import DEFAULT_OVERLAY_PATH, OverlayConfig
from core.configuration import _deep_merge as _merge_overlay  # type: ignore
from core.configuration import _parse_overlay as _parse_overlay_config  # type: ignore
from core.configuration import _read_text as _read_overlay_text  # type: ignore
from core.configuration import load_overlay

# Import the contextual risk scorer from the blended enterprise package.
# The repository ships with the module but it is not installed as a package,
# so we add it to ``sys.path`` on demand.


def _resolve_risk_scorer():
    try:
        from src.services.risk_scorer import ContextualRiskScorer  # type: ignore

        return ContextualRiskScorer
    except ModuleNotFoundError:  # pragma: no cover - defensive path
        repo_root = Path(__file__).resolve().parents[2]
        candidate = repo_root / "enterprise"
        if candidate.exists() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
        from src.services.risk_scorer import ContextualRiskScorer  # type: ignore
    return ContextualRiskScorer()


CVE_SOURCE_URL = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"


@dataclass(frozen=True)
class RunResult:
    """Outcome of executing the CVE simulation."""

    mode: str
    score_path: Path
    evidence_path: Path
    adjusted_severity: str
    risk_adjustment: int
    justification: str
    guardrail_status: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "score_path": str(self.score_path),
            "evidence_path": str(self.evidence_path),
            "adjusted_severity": self.adjusted_severity,
            "risk_adjustment": self.risk_adjustment,
            "justification": self.justification,
            "guardrail_status": self.guardrail_status,
        }


def _load_contexts() -> Dict[str, Any]:
    contexts_path = Path(__file__).with_name("contexts.json")
    return json.loads(contexts_path.read_text(encoding="utf-8"))


def _build_artifacts() -> tuple[NormalizedSBOM, NormalizedSARIF, NormalizedCVEFeed]:
    component = SBOMComponent(
        name="logging-service",
        version="2.17.1",
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
        licenses=["Apache-2.0"],
        supplier="Apache Software Foundation",
        raw={
            "name": "logging-service",
            "package_url": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
            "description": "Service embedding Log4j for structured logging",
        },
    )

    sbom = NormalizedSBOM(
        format="cyclonedx",
        document={"name": "observability-sbom", "version": "1.0"},
        components=[component],
        relationships=[],
        services=[],
        vulnerabilities=[],
        metadata={"component_count": 1},
    )

    finding = SarifFinding(
        rule_id="JAVA-LOG4J-REMOTE-CODE-EXECUTION",
        message="Dependency org.apache.logging.log4j:log4j-core vulnerable to CVE-2021-44228",
        level="error",
        file="services/logging-service/pom.xml",
        line=42,
        raw={"analysisTarget": {"uri": "logging-service"}},
    )

    sarif = NormalizedSARIF(
        version="2.1.0",
        schema_uri="https://json.schemastore.org/sarif-2.1.0.json",
        tool_names=["SCA-Scanner"],
        findings=[finding],
        metadata={"run_count": 1, "finding_count": 1},
    )

    cve_record = CVERecordSummary(
        cve_id="CVE-2021-44228",
        title="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints",
        severity="HIGH",
        exploited=True,
        raw={
            "cve": {
                "cveId": "CVE-2021-44228",
                "references": [CVE_SOURCE_URL],
            },
            "cvssV3Severity": "CRITICAL",
            "cvssV3Score": 10.0,
            "affected_component": "logging-service",
            "knownExploited": True,
            "epss": 0.73,
        },
    )

    cve = NormalizedCVEFeed(
        records=[cve_record], errors=[], metadata={"record_count": 1}
    )
    return sbom, sarif, cve


def _ensure_overlay_for_mode(
    overlay: OverlayConfig, desired_mode: Optional[str], overlay_path: Optional[Path]
) -> OverlayConfig:
    if not desired_mode or desired_mode.lower() == overlay.mode:
        return overlay

    source_path = overlay.metadata.get("source_path")
    candidate = Path(overlay_path or (source_path or DEFAULT_OVERLAY_PATH))
    raw = _parse_overlay_config(_read_overlay_text(candidate))
    if not isinstance(raw, Mapping):
        raise ValueError("Overlay configuration must be a mapping to apply profiles")

    base: MutableMapping[str, Any] = {
        "mode": desired_mode,
        "jira": dict(raw.get("jira", {})),
        "confluence": dict(raw.get("confluence", {})),
        "git": dict(raw.get("git", {})),
        "ci": dict(raw.get("ci", {})),
        "auth": dict(raw.get("auth", {})),
        "data": dict(raw.get("data", {})),
        "toggles": dict(raw.get("toggles", {})),
        "metadata": {"source_path": str(candidate)},
        "guardrails": dict(raw.get("guardrails", {})),
        "context_engine": dict(raw.get("context_engine", {})),
        "evidence_hub": dict(raw.get("evidence_hub", {})),
        "onboarding": dict(raw.get("onboarding", {})),
        "compliance": dict(raw.get("compliance", {})),
        "policy_automation": dict(raw.get("policy_automation", {})),
        "pricing": dict(raw.get("pricing", {})),
        "limits": dict(raw.get("limits", {})),
        "ai_agents": dict(raw.get("ai_agents", {})),
        "ssdlc": dict(raw.get("ssdlc", {})),
        "exploit_signals": dict(raw.get("exploit_signals", {})),
    }

    profiles = raw.get("profiles") if isinstance(raw, Mapping) else {}
    selected_mode = str(desired_mode).lower()
    if isinstance(profiles, Mapping):
        overrides = profiles.get(selected_mode)
        if isinstance(overrides, Mapping):
            _merge_overlay(base, dict(overrides))

    toggles = base.setdefault("toggles", {})
    toggles.setdefault("require_design_input", True)
    toggles.setdefault("auto_attach_overlay_metadata", True)

    metadata = base.setdefault("metadata", {})
    metadata.setdefault("profile_applied", selected_mode)
    metadata.setdefault(
        "available_profiles",
        sorted(profiles.keys()) if isinstance(profiles, Mapping) else [],
    )

    return OverlayConfig(
        mode=selected_mode,
        jira=dict(base.get("jira", {})),
        confluence=dict(base.get("confluence", {})),
        git=dict(base.get("git", {})),
        ci=dict(base.get("ci", {})),
        auth=dict(base.get("auth", {})),
        data=dict(base.get("data", {})),
        toggles=dict(toggles),
        metadata=dict(metadata),
        guardrails=dict(base.get("guardrails", {})),
        context_engine=dict(base.get("context_engine", {})),
        evidence_hub=dict(base.get("evidence_hub", {})),
        onboarding=dict(base.get("onboarding", {})),
        compliance=dict(base.get("compliance", {})),
        policy_automation=dict(base.get("policy_automation", {})),
        pricing=dict(base.get("pricing", {})),
        limits=dict(base.get("limits", {})),
        ai_agents=dict(base.get("ai_agents", {})),
        ssdlc=dict(base.get("ssdlc", {})),
        exploit_signals=dict(base.get("exploit_signals", {})),
        allowed_data_roots=overlay.allowed_data_roots,
        auth_tokens=overlay.auth_tokens,
    )


def _write_design_context(
    design_rows: list[Mapping[str, Any]], overlay: OverlayConfig, mode: str
) -> Optional[Path]:
    directory = overlay.data_directories.get("design_context_dir")
    if not directory:
        return None
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{mode}-cve-2021-44228.csv"
    columns = sorted({key for row in design_rows for key in row.keys()})
    with path.open("w", encoding="utf-8") as handle:
        handle.write(",".join(columns) + "\n")
        for row in design_rows:
            handle.write(",".join(str(row.get(col, "")) for col in columns) + "\n")
    return path


def run_simulation(
    *, mode: Optional[str] = None, overlay_path: Optional[Path | str] = None
) -> RunResult:
    """Execute the CVE-2021-44228 simulation for the requested overlay mode."""

    overlay = load_overlay(Path(overlay_path) if overlay_path else None)
    overlay = _ensure_overlay_for_mode(
        overlay, mode, Path(overlay_path) if overlay_path else None
    )
    active_mode = overlay.mode

    contexts = _load_contexts()
    scenario = contexts.get(active_mode)
    if scenario is None:
        raise ValueError(f"No scenario context defined for mode '{active_mode}'")

    sbom, sarif, cve = _build_artifacts()

    design_rows = scenario["design_rows"]
    design_dataset = {
        "columns": sorted({key for row in design_rows for key in row.keys()}),
        "rows": design_rows,
    }

    orchestrator = PipelineOrchestrator()
    pipeline_result = orchestrator.run(
        design_dataset=design_dataset,
        sbom=sbom,
        sarif=sarif,
        cve=cve,
        overlay=overlay,
    )

    risk_scorer = _resolve_risk_scorer()
    scanner_severity = str(scenario.get("scanner_severity") or cve.records[0].severity)
    adjusted = risk_scorer.apply(
        [
            {
                "id": cve.records[0].cve_id,
                "severity": scanner_severity,
            }
        ],
        scenario["business_context"],
    )[0]
    adjusted["cve_id"] = cve.records[0].cve_id
    adjusted["nvd_cvss_v3"] = 10.0

    evidence_dir = overlay.data_directories.get("evidence_dir") or (
        Path("data") / "evidence" / active_mode
    )
    evidence_dir.mkdir(parents=True, exist_ok=True)

    score_path = evidence_dir / f"cve-2021-44228-{active_mode}-scores.json"
    evidence_path = evidence_dir / f"cve-2021-44228-{active_mode}-evidence.json"

    guardrail_evaluation = pipeline_result.get("guardrail_evaluation")
    context_summary = pipeline_result.get("context_summary")
    compliance_status = pipeline_result.get("compliance_status")
    policy_automation = pipeline_result.get("policy_automation")
    evidence_bundle = pipeline_result.get("evidence_bundle", {})

    score_payload = {
        "mode": active_mode,
        "scenario": scenario["label"],
        "cve_reference": {"id": cve.records[0].cve_id, "source": CVE_SOURCE_URL},
        "raw_feed_severity": cve.records[0].severity,
        "scanner_severity": scanner_severity,
        "contextualised": adjusted,
        "justification": scenario["justification"],
        "business_context": scenario["business_context"],
        "overlay_required_inputs": list(overlay.required_inputs),
        "context_summary": context_summary,
        "compliance_status": compliance_status,
        "policy_automation": policy_automation,
        "ssdlc_assessment": pipeline_result.get("ssdlc_assessment"),
        "exploitability_insights": pipeline_result.get("exploitability_insights"),
    }
    if guardrail_evaluation:
        score_payload["guardrail_evaluation"] = guardrail_evaluation

    crosswalk_entry = next(
        (entry for entry in pipeline_result["crosswalk"] if entry["cves"]),
        pipeline_result["crosswalk"][0],
    )
    evidence_payload = {
        "mode": active_mode,
        "overlay": overlay.to_sanitised_dict(),
        "design_row": crosswalk_entry["design_row"],
        "sbom_component": crosswalk_entry["sbom_component"],
        "sarif_findings": crosswalk_entry["findings"],
        "cve_record": crosswalk_entry["cves"],
        "pipeline_summary": {
            "design": pipeline_result["design_summary"],
            "sbom": pipeline_result["sbom_summary"],
            "sarif": pipeline_result["sarif_summary"],
            "cve": pipeline_result["cve_summary"],
            "severity": pipeline_result.get("severity_overview"),
        },
        "context_summary": context_summary,
        "compliance_status": compliance_status,
        "policy_automation": policy_automation,
        "ssdlc_assessment": pipeline_result.get("ssdlc_assessment"),
        "exploitability_insights": pipeline_result.get("exploitability_insights"),
        "justification": scenario["justification"],
    }
    if guardrail_evaluation:
        evidence_payload["guardrail_evaluation"] = guardrail_evaluation

    score_path.write_text(json.dumps(score_payload, indent=2), encoding="utf-8")
    evidence_path.write_text(json.dumps(evidence_payload, indent=2), encoding="utf-8")

    bundle_path = evidence_bundle.get("files", {}).get("bundle")
    manifest_path = evidence_bundle.get("files", {}).get("manifest")
    if bundle_path and manifest_path:
        # Ensure simulation evidence references the overlay-managed bundle.
        evidence_payload["evidence_bundle"] = evidence_bundle
        evidence_path.write_text(
            json.dumps(evidence_payload, indent=2), encoding="utf-8"
        )

    _write_design_context(design_rows, overlay, active_mode)

    return RunResult(
        mode=active_mode,
        score_path=score_path,
        evidence_path=Path(bundle_path) if bundle_path else evidence_path,
        adjusted_severity=adjusted["fixops_severity"],
        risk_adjustment=adjusted["risk_adjustment"],
        justification=scenario["justification"],
        guardrail_status=(guardrail_evaluation or {}).get("status", "unknown"),
    )


def _build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the FixOps CVE-2021-44228 contextual scoring simulation",
    )
    parser.add_argument(
        "--mode",
        choices=["enterprise", "local"],
        help="Overlay mode to execute. Defaults to the mode encoded in the overlay file.",
    )
    parser.add_argument(
        "--overlay",
        type=Path,
        default=None,
        help="Path to the overlay configuration file (defaults to config/fixops.overlay.yml).",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_cli()
    args = parser.parse_args(argv)
    overlay_path = args.overlay or DEFAULT_OVERLAY_PATH
    result = run_simulation(mode=args.mode, overlay_path=overlay_path)
    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - manual execution helper
    raise SystemExit(main())
