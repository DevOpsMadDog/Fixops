"""FastAPI router exposing risk scoring results."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Request

# Knowledge Brain + Event Bus integration (graceful degradation)
try:
    from core.event_bus import Event, EventType, get_event_bus
    from core.knowledge_brain import get_brain

    _HAS_BRAIN = True
except ImportError:
    _HAS_BRAIN = False

router = APIRouter(prefix="/risk", tags=["risk"])


def _resolve_directory(request: Request) -> Path:
    directory = getattr(request.app.state, "risk_dir", None)
    if directory is None:
        raise HTTPException(status_code=503, detail="Risk storage not configured")
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _load_latest_report(directory: Path) -> Dict[str, Any]:
    candidates = sorted(directory.glob("risk*.json"))
    default_path = directory / "risk.json"
    if default_path.is_file() and default_path not in candidates:
        candidates.append(default_path)
    if not candidates:
        raise HTTPException(status_code=404, detail="No risk reports available")
    latest = max(candidates, key=lambda candidate: candidate.stat().st_mtime)
    with latest.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _component_index(report: Mapping[str, Any]) -> Dict[str, Any]:
    index: Dict[str, Any] = {}
    for component in report.get("components", []):
        if not isinstance(component, dict):
            continue
        slug = component.get("slug")
        if isinstance(slug, str) and slug:
            index[slug.lower()] = component
    return index


@router.get("/")
async def risk_summary(request: Request) -> Dict[str, Any]:
    directory = _resolve_directory(request)
    report = _load_latest_report(directory)
    result = {
        "generated_at": report.get("generated_at"),
        "summary": report.get("summary", {}),
        "available_components": len(report.get("components", [])),
        "available_cves": len(report.get("cves", {})),
    }

    # Emit risk calculated event
    if _HAS_BRAIN:
        bus = get_event_bus()
        await bus.emit(
            Event(
                event_type=EventType.RISK_CALCULATED,
                source="risk_router",
                data={
                    "components_count": result["available_components"],
                    "cves_count": result["available_cves"],
                },
            )
        )

    return result


@router.get("/component/{component_slug}")
async def component_risk(component_slug: str, request: Request) -> Dict[str, Any]:
    directory = _resolve_directory(request)
    report = _load_latest_report(directory)
    index = _component_index(report)
    component = index.get(component_slug.lower())
    if component is None:
        raise HTTPException(
            status_code=404, detail="Component not found in risk report"
        )
    return component


@router.get("/cve/{cve_id}")
async def cve_risk(cve_id: str, request: Request) -> Dict[str, Any]:
    directory = _resolve_directory(request)
    report = _load_latest_report(directory)
    cves = report.get("cves", {})
    if not isinstance(cves, dict):
        raise HTTPException(status_code=404, detail="No CVE index available")
    entry = cves.get(cve_id.upper())
    if entry is None:
        raise HTTPException(status_code=404, detail="CVE not present in risk report")

    # Emit risk calculated event for CVE lookup
    if _HAS_BRAIN:
        bus = get_event_bus()
        brain = get_brain()
        brain.ingest_cve(
            cve_id.upper(),
            severity=entry.get("severity", "unknown"),
            source="risk_report",
        )
        await bus.emit(
            Event(
                event_type=EventType.RISK_CALCULATED,
                source="risk_router",
                data={"cve_id": cve_id.upper(), "risk_data": entry},
            )
        )

    return entry


@router.get("/overview")
async def risk_overview(request: Request) -> Dict[str, Any]:
    """Risk overview — aggregate risk posture across all apps/components."""
    try:
        directory = _resolve_directory(request)
        report = _load_latest_report(directory)
        components = report.get("components", {})
        cves = report.get("cves", {})
    except HTTPException:
        components = {}
        cves = {}

    # Severity breakdown from CVEs
    severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for entry in (cves.values() if isinstance(cves, dict) else []):
        sev = (entry.get("severity") or "low").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    total_findings = sum(severity_counts.values())
    risk_score = min(100, severity_counts["critical"] * 25 + severity_counts["high"] * 10 + severity_counts["medium"] * 3 + severity_counts["low"])

    return {
        "status": "ok",
        "risk_score": risk_score,
        "risk_level": "critical" if risk_score >= 75 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low",
        "total_findings": total_findings,
        "severity_breakdown": severity_counts,
        "total_components": len(components) if isinstance(components, dict) else 0,
        "total_cves": len(cves) if isinstance(cves, dict) else 0,
        "top_risks": [
            {"cve_id": cve_id, "severity": (entry.get("severity") or "unknown"), "score": entry.get("cvss_score", 0)}
            for cve_id, entry in (list(cves.items())[:10] if isinstance(cves, dict) else [])
        ],
        "trends": {"direction": "stable", "change_7d": 0, "change_30d": 0},
    }


@router.get("/score")
async def risk_score(request: Request) -> Dict[str, Any]:
    """Get aggregate enterprise risk score."""
    try:
        directory = _resolve_directory(request)
        report = _load_latest_report(directory)
        components = report.get("components", {})
    except HTTPException:
        components = {}
    scores = [
        (data.get("risk_score", 0) if isinstance(data, dict) else 0)
        for _, data in (components.items() if isinstance(components, dict) else [])
    ]
    avg = round(sum(scores) / max(len(scores), 1), 1)
    return {
        "status": "ok",
        "risk_score": avg,
        "level": "critical" if avg >= 80 else "high" if avg >= 60 else "medium" if avg >= 40 else "low",
        "components_assessed": len(scores),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/scores")
async def risk_scores(request: Request) -> Dict[str, Any]:
    """Risk scores per component/app."""
    try:
        directory = _resolve_directory(request)
        report = _load_latest_report(directory)
        components = report.get("components", {})
    except HTTPException:
        components = {}

    scores = []
    for name, data in (components.items() if isinstance(components, dict) else []):
        score = data.get("risk_score", 0) if isinstance(data, dict) else 0
        scores.append({"component": name, "risk_score": score, "severity": data.get("severity", "low") if isinstance(data, dict) else "low"})

    scores.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "status": "ok",
        "scores": scores[:50],
        "total": len(scores),
        "average_score": round(sum(s["risk_score"] for s in scores) / max(len(scores), 1), 1),
    }


@router.get("/health")
async def risk_health(org_id: str = Depends(get_org_id)):
    """Risk analysis service health check."""
    return {"status": "healthy", "engine": "risk", "version": "1.0.0"}


@router.get("/status")
async def risk_status(org_id: str = Depends(get_org_id)):
    """Risk analysis service status (alias for /health)."""
    return await risk_health()


__all__ = ["router"]
