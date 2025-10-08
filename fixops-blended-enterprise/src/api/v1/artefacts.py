"""Unified artefact ingestion endpoint with canonical output materialisation."""

from __future__ import annotations

import csv
import io
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, Sequence
from zipfile import ZipFile

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.dependencies import authenticate
from src.services import run_registry
from src.services.id_allocator import ensure_ids

router = APIRouter(tags=["artefacts"])


class ArtefactSubmission(BaseModel):
    type: str = Field(min_length=1)
    payload: Any | None = None
    app_id: str | None = None
    run_id: str | None = None


class ArtefactResponse(BaseModel):
    app_id: str
    run_id: str
    stored_as: str


_INPUT_FILE_MAP: Dict[str, str] = {
    "requirements": "requirements-input.csv",
    "design": "design-input.json",
    "sbom": "sbom.json",
    "sarif": "scanner.sarif",
    "provenance": "provenance.slsa.json",
    "tfplan": "tfplan.json",
    "ops": "ops-telemetry.json",
    "tests": "tests-input.json",
    "decision": "decision-input.json",
}

Processor = Callable[[Any, run_registry.RunContext, Path, ArtefactSubmission], None]


@router.post("", response_model=ArtefactResponse, status_code=status.HTTP_201_CREATED)
async def submit_artefact(
    submission: ArtefactSubmission,
    _: None = Depends(authenticate),
) -> ArtefactResponse:
    artefact_type = submission.type.lower()
    if artefact_type not in _INPUT_FILE_MAP:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported artefact type")

    payload = submission.payload
    if artefact_type == "design":
        if not isinstance(payload, Mapping):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Design payload must be an object")
        payload = ensure_ids(payload)

    context = _resolve_context(submission, artefact_type, payload)
    filename = _INPUT_FILE_MAP[artefact_type]
    stored_payload = payload if payload is not None else ""
    stored_path = context.save_input(filename, stored_payload)
    processor = _PROCESSORS.get(artefact_type)
    if processor:
        processor(payload, context, stored_path, submission)
    relative = stored_path.relative_to(context.run_path)
    return ArtefactResponse(app_id=context.app_id, run_id=context.run_id, stored_as=str(relative))


def _resolve_context(
    submission: ArtefactSubmission,
    artefact_type: str,
    payload: Any,
) -> run_registry.RunContext:
    if submission.run_id:
        try:
            return run_registry.reopen_run(submission.app_id, submission.run_id)
        except FileNotFoundError as exc:  # pragma: no cover - API wiring
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found") from exc
    app_hint = submission.app_id
    if artefact_type == "design" and isinstance(payload, Mapping):
        app_hint = str(payload.get("app_id") or app_hint)
    return run_registry.resolve_run(app_hint)


def _process_requirements(_: Any, context: run_registry.RunContext, stored_path: Path, __: ArtefactSubmission) -> None:
    text = stored_path.read_text()
    records: list[dict[str, Any]] = []
    if text.strip():
        reader = csv.DictReader(io.StringIO(text))
        if reader.fieldnames:
            for row in reader:
                if not any(row.values()):
                    continue
                records.append(_normalize_requirement_row(row))
    if not records:
        # Fallback to JSON payload stored on disk
        try:
            payload = context.load_input_json(stored_path.name)
        except Exception:  # pragma: no cover - defensive
            payload = []
        records.extend(_normalize_requirement_payload(payload))

    anchor = _compute_ssvc_anchor(records)
    context.write_output("requirements.json", {"requirements": records, "ssvc_anchor": anchor})


def _normalize_requirement_row(row: Mapping[str, Any]) -> dict[str, Any]:
    refs = _split_refs(row.get("control_refs"))
    return {
        "requirement_id": str(row.get("requirement_id") or "REQ-UNKNOWN"),
        "feature": str(row.get("feature") or ""),
        "control_refs": refs,
        "data_class": str(row.get("data_class") or "unknown").lower(),
        "pii": _as_bool(row.get("pii")),
        "internet_facing": _as_bool(row.get("internet_facing")),
    }


def _normalize_requirement_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, Mapping):
        payload = payload.get("requirements")
    if not isinstance(payload, Iterable):
        return []
    rows = []
    for item in payload:
        if not isinstance(item, Mapping):
            continue
        rows.append(_normalize_requirement_row(item))
    return rows


def _split_refs(value: Any) -> list[str]:
    if isinstance(value, str):
        return [token.strip() for token in value.split(";") if token.strip()]
    if isinstance(value, Iterable):
        return [str(token) for token in value if str(token).strip()]
    return []


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1"}
    return bool(value)


def _compute_ssvc_anchor(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    internet = any(record.get("internet_facing") for record in records)
    pii = any(record.get("pii") for record in records)
    if internet and pii:
        return {"stakeholder": "mission", "impact_tier": "critical"}
    if pii:
        return {"stakeholder": "safety", "impact_tier": "high"}
    return {"stakeholder": "maintenance", "impact_tier": "moderate"}


def _process_design(payload: Any, context: run_registry.RunContext, _: Path, __: ArtefactSubmission) -> None:
    if not isinstance(payload, Mapping):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Design payload must be an object")
    manifest = dict(payload)
    components = manifest.get("components") if isinstance(manifest.get("components"), list) else []
    for component in components or []:
        if isinstance(component, dict):
            component.setdefault("component_id", _mint_component_token(component.get("name")))
    manifest["design_risk_score"] = _design_risk_score(manifest)
    context.write_output("design.manifest.json", manifest)


def _mint_component_token(name: Any) -> str:
    token = str(name or "component").lower().replace(" ", "-")
    token = "".join(ch if ch.isalnum() or ch == "-" else "-" for ch in token).strip("-") or "component"
    return f"C-{token.split('-')[0]}"


def _design_risk_score(payload: Mapping[str, Any]) -> float:
    components = payload.get("components") if isinstance(payload, Mapping) else []
    score = 0.5
    if isinstance(components, list):
        if any(str(item.get("exposure")).lower() == "internet" for item in components if isinstance(item, Mapping)):
            score += 0.2
        if any(bool(item.get("pii")) for item in components if isinstance(item, Mapping)):
            score += 0.08
    return round(min(score, 0.99), 2)


def _process_build(_: Any, context: run_registry.RunContext, __: Path, ___: ArtefactSubmission) -> None:
    try:
        sbom = context.load_input_json("sbom.json")
    except FileNotFoundError:
        return
    components = [component for component in sbom.get("components", []) if isinstance(component, Mapping)]
    components_indexed = len(components)
    risk_flags: list[dict[str, Any]] = []
    for component in components:
        identifier = component.get("purl") or component.get("name")
        if identifier and "log4j" in str(identifier):
            risk_flags.append({"purl": str(identifier), "reason": "historical RCE family"})
    links = {}
    for key in ("sbom.json", "scanner.sarif", "provenance.slsa.json"):
        path = context.inputs_dir / key
        if path.exists():
            links[key.split(".")[0] if key != "scanner.sarif" else "sarif"] = context.relative_to_outputs(path)
    design = _load_design_manifest(context)
    app_id = design.get("app_id") if isinstance(design, Mapping) else context.app_id
    score = 0.5 + (0.16 * min(1, len(risk_flags)))
    filtered_links = {key: value for key, value in links.items() if value}
    report = {
        "app_id": app_id,
        "components_indexed": components_indexed,
        "risk_flags": risk_flags,
        "links": filtered_links,
        "build_risk_score": round(min(score, 0.99), 2),
    }
    context.write_output("build.report.json", report)


def _load_design_manifest(context: run_registry.RunContext) -> Mapping[str, Any]:
    try:
        return context.load_output_json("design.manifest.json")
    except FileNotFoundError:
        return {}


def _process_tests(_: Any, context: run_registry.RunContext, __: Path, ___: ArtefactSubmission) -> None:
    findings = _sarif_findings(context)
    severities = Counter(finding["severity"] for finding in findings)
    summary = {"critical": severities.get("critical", 0), "high": severities.get("high", 0), "medium": severities.get("medium", 0), "low": severities.get("low", 0)}
    drift = {"new_findings": 0}
    try:
        tests_payload = context.load_input_json("tests-input.json")
        drift["new_findings"] = len(tests_payload.get("new_findings", []) if isinstance(tests_payload, Mapping) else [])
    except FileNotFoundError:
        pass
    score = 0.3
    score += 0.1 * summary["critical"]
    score += 0.08 * summary["high"]
    score += 0.04 * drift["new_findings"]
    report = {
        "summary": summary,
        "drift": drift,
        "test_risk_score": round(min(score, 0.99), 2),
    }
    context.write_output("test.report.json", report)


def _sarif_findings(context: run_registry.RunContext) -> list[dict[str, Any]]:
    try:
        sarif = context.load_input_json("scanner.sarif")
    except FileNotFoundError:
        return []
    findings: list[dict[str, Any]] = []
    for run in sarif.get("runs", []):
        if not isinstance(run, Mapping):
            continue
        for result in run.get("results", []) or []:
            if not isinstance(result, Mapping):
                continue
            level = str(result.get("level") or "medium").lower()
            severity = {
                "error": "critical",
                "warning": "high",
                "note": "medium",
            }.get(level, "low")
            findings.append({"severity": severity})
    return findings


def _process_deploy(_: Any, context: run_registry.RunContext, __: Path, ___: ArtefactSubmission) -> None:
    try:
        tfplan = context.load_input_json("tfplan.json")
    except FileNotFoundError:
        return
    public_buckets: list[str] = []
    tls_policy = None
    for resource in tfplan.get("resources", []) or []:
        if not isinstance(resource, Mapping):
            continue
        rtype = resource.get("type")
        changes = resource.get("changes") if isinstance(resource.get("changes"), Mapping) else {}
        after = changes.get("after") if isinstance(changes.get("after"), Mapping) else {}
        if rtype == "aws_s3_bucket" and after.get("acl") == "public-read":
            public_buckets.append(str(resource.get("name")))
        if rtype == "aws_lb_listener":
            tls_policy = after.get("ssl_policy")
    posture = {
        "public_buckets": public_buckets,
        "tls_policy": tls_policy,
    }
    digests: list[str] = []
    provenance_path = context.inputs_dir / "provenance.slsa.json"
    if provenance_path.exists():
        provenance = context.load_input_json("provenance.slsa.json")
        subjects = provenance.get("subject", []) if isinstance(provenance, Mapping) else []
        if subjects:
            digest = subjects[0].get("digest") if isinstance(subjects[0], Mapping) else {}
            sha = digest.get("sha256") if isinstance(digest, Mapping) else None
            if sha:
                digests.append(f"sha256:{sha}")
    requirements = _load_requirements(context)
    evidence, failing_controls = _deploy_evidence(requirements, posture, context)
    score = 0.5
    if public_buckets:
        score += 0.16
    if tls_policy and "2016" in str(tls_policy):
        score += 0.05
    from src.services.marketplace import get_recommendations

    recommendations = get_recommendations(failing_controls)
    manifest = {
        "digests": digests,
        "posture": posture,
        "control_evidence": evidence,
        "marketplace_recommendations": recommendations,
        "deploy_risk_score": round(min(score, 0.99), 2),
    }
    context.write_output("deploy.manifest.json", manifest)


def _load_requirements(context: run_registry.RunContext) -> Mapping[str, Any]:
    try:
        return context.load_output_json("requirements.json")
    except FileNotFoundError:
        return {}


def _deploy_evidence(requirements: Mapping[str, Any], posture: Mapping[str, Any], context: run_registry.RunContext) -> tuple[list[dict[str, Any]], list[str]]:
    evidence: list[dict[str, Any]] = []
    failing: list[str] = []
    controls = []
    for requirement in requirements.get("requirements", []) or []:
        if not isinstance(requirement, Mapping):
            continue
        controls.extend(requirement.get("control_refs", []))
    controls = [str(control) for control in controls]
    tfplan_path = context.inputs_dir / "tfplan.json"
    for control in controls:
        result = "pass"
        source = "tls_policy"
        if "AC-2" in control and posture.get("public_buckets"):
            result = "fail"
            source = "public_buckets"
        elif "AC-1" in control and not posture.get("tls_policy"):
            result = "partial"
        evidence_item = {
            "control": control,
            "result": result,
            "source": source,
            "evidence_file": context.relative_to_outputs(tfplan_path),
        }
        evidence.append(evidence_item)
        if result == "fail":
            failing.append(control)
    return evidence, failing


def _process_operate(_: Any, context: run_registry.RunContext, __: Path, ___: ArtefactSubmission) -> None:
    telemetry: Mapping[str, Any] = {}
    try:
        telemetry = context.load_input_json("ops-telemetry.json")
    except FileNotFoundError:
        telemetry = {}
    build_report = {}
    try:
        build_report = context.load_output_json("build.report.json")
    except FileNotFoundError:
        build_report = {}
    kev_hits: list[str] = []
    epss: list[dict[str, Any]] = []
    risk_components = build_report.get("risk_flags", []) if isinstance(build_report, Mapping) else []
    if any("log4j" in flag.get("purl", "") for flag in risk_components if isinstance(flag, Mapping)):
        kev_hits.append("CVE-2021-44228")
        epss.append({"cve": "CVE-2021-44228", "score": 0.97})
    pressure = 0.4
    if isinstance(telemetry, Mapping):
        latency = telemetry.get("latency_ms_p95")
        if isinstance(latency, (int, float)):
            pressure = min(0.95, max(pressure, latency / 660))
    design = _load_design_manifest(context)
    service_name = design.get("app_name") if isinstance(design, Mapping) else context.app_id
    pressure_snapshot = [{"service": service_name, "pressure": round(pressure, 2)}]
    score = 0.5
    if kev_hits:
        score += 0.12
    if pressure >= 0.55:
        score += 0.07
    manifest = {
        "kev_hits": kev_hits,
        "epss": epss,
        "pressure_by_service": pressure_snapshot,
        "operate_risk_score": round(min(score, 0.99), 2),
    }
    context.write_output("operate.snapshot.json", manifest)


def _process_decision(payload: Any, context: run_registry.RunContext, __: Path, ___: ArtefactSubmission) -> None:
    requirements = _load_requirements(context)
    design = _load_design_manifest(context)
    build_report = _safe_output(context, "build.report.json")
    test_report = _safe_output(context, "test.report.json")
    deploy_manifest = _safe_output(context, "deploy.manifest.json")
    operate_snapshot = _safe_output(context, "operate.snapshot.json")

    failing_controls = [
        item.get("control")
        for item in (deploy_manifest.get("control_evidence") or [])
        if isinstance(item, Mapping) and item.get("result") == "fail"
    ]
    top_factors = _decision_factors(deploy_manifest, operate_snapshot)
    compliance_rollup = _compliance_rollup(requirements, deploy_manifest)
    verdict = "DEFER" if failing_controls or operate_snapshot.get("kev_hits") else "ALLOW"
    confidence = 0.7 + 0.07 * len(top_factors)
    from src.services.marketplace import get_recommendations

    recommendations = get_recommendations(failing_controls)
    evidence_id = f"ev_{datetime.utcnow().strftime('%Y_%m_%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    decision = {
        "decision": verdict,
        "confidence_score": round(min(confidence, 0.99), 2),
        "top_factors": top_factors,
        "compliance_rollup": compliance_rollup,
        "marketplace_recommendations": recommendations,
        "evidence_id": evidence_id,
    }
    context.write_output("decision.json", decision)
    _write_evidence_bundle(context)


def _safe_output(context: run_registry.RunContext, name: str) -> Mapping[str, Any]:
    try:
        data = context.load_output_json(name)
    except FileNotFoundError:
        return {}
    return data if isinstance(data, Mapping) else {}


def _decision_factors(deploy_manifest: Mapping[str, Any], operate_snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    factors: list[dict[str, Any]] = []
    public_buckets = deploy_manifest.get("posture", {}).get("public_buckets", []) if isinstance(deploy_manifest, Mapping) else []
    if public_buckets:
        factors.append(
            {
                "reason": "Public S3 bucket violates guardrail",
                "weight": 0.40,
            }
        )
    if operate_snapshot.get("epss"):
        factors.append(
            {
                "reason": "High EPSS on tier-0 component",
                "weight": 0.35,
            }
        )
    if not factors:
        factors.append({"reason": "Stable controls", "weight": 0.2})
    return factors


def _compliance_rollup(requirements: Mapping[str, Any], deploy_manifest: Mapping[str, Any]) -> dict[str, Any]:
    controls = {}
    frameworks: dict[str, list[float]] = {}
    evidence_lookup = {}
    for item in deploy_manifest.get("control_evidence", []) or []:
        if isinstance(item, Mapping):
            evidence_lookup[str(item.get("control"))] = item
    for requirement in requirements.get("requirements", []) or []:
        if not isinstance(requirement, Mapping):
            continue
        for control_ref in requirement.get("control_refs", []) or []:
            control_id = str(control_ref)
            evidence = evidence_lookup.get(control_id, {})
            result = evidence.get("result")
            coverage = 1.0 if result == "pass" else 0.0 if result == "fail" else 0.5
            controls[control_id] = coverage
            framework = control_id.split(":")[0]
            frameworks.setdefault(framework, []).append(coverage)
    framework_rollup = []
    for framework, values in frameworks.items():
        coverage = round(sum(values) / len(values), 2)
        if coverage >= 1.0:
            continue
        framework_rollup.append({"name": framework, "coverage": coverage})
    controls_list = [
        {"id": control_id, "coverage": round(coverage, 2)} for control_id, coverage in controls.items()
    ]
    return {"controls": controls_list, "frameworks": framework_rollup}


def _write_evidence_bundle(context: run_registry.RunContext) -> None:
    output_files = [
        "requirements.json",
        "design.manifest.json",
        "build.report.json",
        "test.report.json",
        "deploy.manifest.json",
        "operate.snapshot.json",
        "decision.json",
    ]
    bundle_path = context.outputs_dir / "evidence_bundle.zip"
    with ZipFile(bundle_path, "w") as archive:
        for filename in output_files:
            path = context.outputs_dir / filename
            if path.exists():
                archive.write(path, arcname=filename)


_PROCESSORS: Dict[str, Processor] = {
    "requirements": _process_requirements,
    "design": _process_design,
    "sbom": _process_build,
    "sarif": _process_build,
    "provenance": _process_build,
    "tests": _process_tests,
    "tfplan": _process_deploy,
    "ops": _process_operate,
    "decision": _process_decision,
}

__all__ = ["router"]
