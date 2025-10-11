from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from services.graph.graph import GraphSources, build_graph_from_sources

router = APIRouter(prefix="/graph", tags=["graph"])


def _latest_file(directory: Path, pattern: str, fallback: str) -> Path | None:
    if not directory or not directory.exists():
        return None
    candidates = sorted(directory.glob(pattern))
    default_path = directory / fallback
    if default_path.exists() and default_path not in candidates:
        candidates.append(default_path)
    if not candidates:
        return None
    return max(candidates, key=lambda candidate: candidate.stat().st_mtime)


def _graph_config(request: Request) -> dict[str, Any]:
    config = getattr(request.app.state, "graph_config", None)
    if config is None:
        raise HTTPException(status_code=503, detail="Graph sources not configured")
    return config


def _build_sources(config: dict[str, Any]) -> GraphSources:
    repo_path = Path(config.get("repo_path", ".")).resolve()
    attestation_dir = Path(config.get("attestation_dir", "artifacts/attestations")).resolve()
    sbom_dir = Path(config.get("sbom_dir", "artifacts/sbom")).resolve()
    risk_dir = Path(config.get("risk_dir", "artifacts")).resolve()
    releases_path_value = config.get("releases_path")
    releases_path = Path(releases_path_value).resolve() if releases_path_value else None
    normalized_sbom = _latest_file(sbom_dir, "normalized*.json", "normalized.json")
    risk_report = _latest_file(risk_dir, "risk*.json", "risk.json")
    return GraphSources(
        repo_path=repo_path,
        attestation_dir=attestation_dir,
        normalized_sbom=normalized_sbom,
        risk_report=risk_report,
        releases_path=releases_path,
    )


def _build_graph(request: Request):
    config = _graph_config(request)
    sources = _build_sources(config)
    graph = build_graph_from_sources(sources)
    return graph, sources


@router.get("/")
async def graph_summary(request: Request) -> dict[str, Any]:
    graph, sources = _build_graph(request)
    try:
        return {
            "nodes": graph.graph.number_of_nodes(),
            "edges": graph.graph.number_of_edges(),
            "configured_sources": {
                "sbom": bool(sources.normalized_sbom),
                "risk": bool(sources.risk_report),
            },
        }
    finally:
        graph.close()


@router.get("/lineage/{artifact_name}")
async def artifact_lineage(artifact_name: str, request: Request) -> dict[str, Any]:
    graph, _ = _build_graph(request)
    try:
        return graph.lineage(artifact_name)
    finally:
        graph.close()


@router.get("/kev-components")
async def kev_components(request: Request, last: int = Query(3, ge=1, le=50)) -> list[dict[str, Any]]:
    graph, _ = _build_graph(request)
    try:
        return graph.components_with_kev(last_releases=last)
    finally:
        graph.close()


@router.get("/anomalies")
async def version_anomalies(request: Request) -> list[dict[str, Any]]:
    graph, _ = _build_graph(request)
    try:
        return graph.detect_version_anomalies()
    finally:
        graph.close()
