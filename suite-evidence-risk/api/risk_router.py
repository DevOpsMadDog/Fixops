"""FastAPI router exposing risk scoring results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping

from fastapi import APIRouter, HTTPException, Request

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
        await bus.emit(Event(
            event_type=EventType.RISK_CALCULATED,
            source="risk_router",
            data={"components_count": result["available_components"],
                  "cves_count": result["available_cves"]},
        ))

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
        brain.ingest_cve(cve_id.upper(), severity=entry.get("severity", "unknown"), source="risk_report")
        await bus.emit(Event(
            event_type=EventType.RISK_CALCULATED,
            source="risk_router",
            data={"cve_id": cve_id.upper(), "risk_data": entry},
        ))

    return entry


__all__ = ["router"]
