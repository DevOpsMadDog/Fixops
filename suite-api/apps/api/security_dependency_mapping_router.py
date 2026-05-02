"""Security Dependency Mapping Router — ALDECI.

Service dependency map and blast radius analysis for incident impact assessment.

Prefix: /api/v1/dependency-mapping
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/dependency-mapping/services                          register_service
  GET    /api/v1/dependency-mapping/services                          list_services
  GET    /api/v1/dependency-mapping/services/{service_id}             get_service
  POST   /api/v1/dependency-mapping/dependencies                      add_dependency
  DELETE /api/v1/dependency-mapping/dependencies/{dependency_id}      remove_dependency
  POST   /api/v1/dependency-mapping/services/{service_id}/blast-radius compute_blast_radius
  GET    /api/v1/dependency-mapping/critical-paths                    get_critical_paths
  GET    /api/v1/dependency-mapping/summary                           get_summary
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/dependency-mapping",
    tags=["Security Dependency Mapping"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_dependency_mapping_engine import (
            SecurityDependencyMappingEngine,
        )
        _engine = SecurityDependencyMappingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------


class RegisterServiceBody(BaseModel):
    service_name: str = Field(..., description="Unique service name")
    service_type: str = Field(
        default="application",
        description="application | database | api | queue | cache | auth | monitoring | storage | network | external",
    )
    criticality: str = Field(default="medium", description="critical | high | medium | low")
    owner: str = Field(default="", description="Owning team or person")
    environment: str = Field(default="production", description="production | staging | development | dr")
    data_classification: str = Field(
        default="internal",
        description="public | internal | confidential | restricted",
    )


class AddDependencyBody(BaseModel):
    source_service_id: str = Field(..., description="Service ID that has the dependency")
    target_service_id: str = Field(..., description="Service ID being depended upon")
    dependency_type: str = Field(default="runtime", description="runtime | build | test | optional | fallback")
    criticality: str = Field(default="medium", description="critical | high | medium | low")
    protocol: str = Field(default="", description="Network protocol (e.g. HTTPS, gRPC)")
    port: int = Field(default=0, description="Port number (0 = not applicable)")
    description: str = Field(default="", description="Human-readable description")


class BlastRadiusBody(BaseModel):
    analysis_type: str = Field(
        default="downstream",
        description="downstream (who breaks if I go down) or upstream (what I depend on)",
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/services")
def register_service(
    body: RegisterServiceBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Register a new service in the dependency map."""
    try:
        return _get_engine().register_service(
            org_id=org_id,
            service_name=body.service_name,
            service_type=body.service_type,
            criticality=body.criticality,
            owner=body.owner,
            environment=body.environment,
            data_classification=body.data_classification,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/services")
def list_services(
    org_id: str = Query(default="default"),
    service_type: Optional[str] = Query(default=None),
    criticality: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List services, optionally filtered by type and criticality."""
    return _get_engine().list_services(org_id, service_type=service_type, criticality=criticality)


@router.get("/services/{service_id}")
def get_service(
    service_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Fetch a service with its dependency edges."""
    result = _get_engine().get_service(service_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Service not found")
    return result


@router.post("/dependencies")
def add_dependency(
    body: AddDependencyBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Add a directed dependency between two services."""
    try:
        return _get_engine().add_dependency(
            org_id=org_id,
            source_service_id=body.source_service_id,
            target_service_id=body.target_service_id,
            dependency_type=body.dependency_type,
            criticality=body.criticality,
            protocol=body.protocol,
            port=body.port,
            description=body.description,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.delete("/dependencies/{dependency_id}")
def remove_dependency(
    dependency_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Remove a dependency and update service counters."""
    try:
        return _get_engine().remove_dependency(dependency_id, org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/services/{service_id}/blast-radius")
def compute_blast_radius(
    service_id: str,
    body: BlastRadiusBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Compute blast radius (BFS) from a source service."""
    try:
        return _get_engine().compute_blast_radius(org_id, service_id, body.analysis_type)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/critical-paths")
def get_critical_paths(
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    """Return critical services ordered by dependent_count (most critical first)."""
    return _get_engine().get_critical_paths(org_id)


@router.get("/summary")
def get_summary(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return aggregate dependency map summary for the org."""
    return _get_engine().get_summary(org_id)


@router.get("/source-trace")
def source_trace(
    source_file: str = Query(..., description="Relative path to a source file, e.g. suite-core/core/siem_integration_engine.py"),
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Map a source file to deployed cloud assets via service name-matching.

    Returns matched services and their downstream blast radius — enabling
    code-to-cloud tracing: which cloud assets are affected when this file changes.
    """
    return _get_engine().get_source_trace(org_id, source_file)


# ---------------------------------------------------------------------------
# REPO INTROSPECTION  (real path — parses on-disk manifests, registers nodes)
# ---------------------------------------------------------------------------

# Path-traversal protection: only allow repos under approved roots.
# We compare against both the raw and the symlink-resolved form of each root
# so platform quirks (macOS /tmp -> /private/tmp) don't false-reject.
_RAW_ALLOWED_ROOTS = (
    "/tmp/fixops-fleet",
    "/tmp/aldeci-fleet",
    "/Users/devops.ai/fixops",
    "/workspace",
    "/repos",
)


def _normalised_roots() -> List[str]:
    out: List[str] = []
    for r in _RAW_ALLOWED_ROOTS:
        try:
            resolved = str(Path(r).resolve())
        except OSError:
            resolved = r
        for v in (r, resolved):
            v = v.rstrip("/")
            if v and v not in out:
                out.append(v)
    return out


def _safe_repo_path(repo_path: str) -> Path:
    """Resolve repo_path and reject if it escapes an allowed root."""
    if not repo_path or len(repo_path) > 1024:
        raise HTTPException(status_code=422, detail="repo_path missing or too long")
    candidate = Path(repo_path).expanduser().resolve()
    if not candidate.exists() or not candidate.is_dir():
        raise HTTPException(status_code=404, detail=f"repo_path '{candidate}' not found or not a directory")
    candidate_str = str(candidate)
    for root in _normalised_roots():
        if candidate_str == root or candidate_str.startswith(root + "/"):
            return candidate
    raise HTTPException(
        status_code=403,
        detail=f"repo_path '{candidate_str}' must live under an approved fleet root",
    )


def _parse_node_pkg(pkg_json: Path, max_deps: int = 200) -> Dict[str, str]:
    """Return dep_name -> version, capped to max_deps to prevent zip-bomb-style abuse."""
    try:
        size = pkg_json.stat().st_size
        if size > 8 * 1024 * 1024:  # reject manifests >8MB
            return {}
        with pkg_json.open("r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    deps: Dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        section = data.get(key) or {}
        if not isinstance(section, dict):
            continue
        for name, ver in section.items():
            if not isinstance(name, str) or not name or len(name) > 200:
                continue
            ver_str = str(ver)[:80] if ver is not None else ""
            deps.setdefault(name, ver_str)
            if len(deps) >= max_deps:
                return deps
    return deps


def _parse_python_requirements(req_file: Path, max_deps: int = 200) -> Dict[str, str]:
    """Parse requirements.txt-style file; only handles `name==ver`, `name>=ver`, plain names."""
    try:
        if req_file.stat().st_size > 4 * 1024 * 1024:
            return {}
        text = req_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    deps: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # split on first version specifier
        for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
            if sep in line:
                name, _, ver = line.partition(sep)
                name = name.strip()
                if name and len(name) <= 200:
                    deps[name] = (sep + ver.strip())[:80]
                break
        else:
            name = line.split(";", 1)[0].split("[", 1)[0].strip()
            if name and len(name) <= 200:
                deps.setdefault(name, "")
        if len(deps) >= max_deps:
            break
    return deps


def _parse_pyproject(toml_file: Path, max_deps: int = 200) -> Dict[str, str]:
    """Best-effort regex extraction of pyproject.toml dependencies (no toml lib needed)."""
    import re
    try:
        if toml_file.stat().st_size > 4 * 1024 * 1024:
            return {}
        text = toml_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    deps: Dict[str, str] = {}
    # match `name = "version"` and `"name>=ver"`
    for match in re.finditer(r'^\s*([A-Za-z][A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"', text, re.MULTILINE):
        name, ver = match.group(1), match.group(2)
        if name.lower() in {"name", "version", "description", "authors", "license", "readme", "requires-python"}:
            continue
        if len(name) <= 200:
            deps[name] = ver[:80]
        if len(deps) >= max_deps:
            return deps
    for match in re.finditer(r'"([A-Za-z][A-Za-z0-9_\-]+)\s*([=<>!~]+)\s*([0-9A-Za-z\.\-_]+)"', text):
        name, op, ver = match.group(1), match.group(2), match.group(3)
        if len(name) <= 200:
            deps.setdefault(name, f"{op}{ver}"[:80])
        if len(deps) >= max_deps:
            break
    return deps


def _detect_repo_deps(repo_root: Path) -> Dict[str, str]:
    """Walk top-level manifests and return merged dep map."""
    merged: Dict[str, str] = {}
    pkg = repo_root / "package.json"
    if pkg.exists():
        merged.update(_parse_node_pkg(pkg))
    for req_name in ("requirements.txt", "requirements-dev.txt"):
        req = repo_root / req_name
        if req.exists():
            merged.update(_parse_python_requirements(req))
    pyproj = repo_root / "pyproject.toml"
    if pyproj.exists():
        merged.update(_parse_pyproject(pyproj))
    setup_py = repo_root / "setup.py"
    if setup_py.exists() and not pyproj.exists():
        # very loose: extract install_requires=['x','y']
        import re
        try:
            txt = setup_py.read_text(encoding="utf-8", errors="replace")[:200_000]
            for m in re.finditer(r"['\"]([A-Za-z][A-Za-z0-9_\-]+)\s*([=<>!~]+\s*[0-9A-Za-z\.\-_]+)?['\"]", txt):
                name = m.group(1)
                if len(name) <= 200 and name not in merged:
                    merged[name] = (m.group(2) or "").strip()
                if len(merged) >= 200:
                    break
        except OSError:
            pass
    return merged


class MapRepoBody(BaseModel):
    repo_path: str = Field(..., description="Absolute path to repo on disk", min_length=1, max_length=1024)
    service_name: Optional[str] = Field(default=None, description="Override service name (defaults to repo dir name)", max_length=200)
    criticality: str = Field(default="medium", description="critical | high | medium | low")


@router.post("/map-repo")
def map_repo(
    body: MapRepoBody,
    org_id: str = Query(default="default", max_length=256),
) -> Dict[str, Any]:
    """Introspect a real repository on disk and register it as a service node
    with one outgoing dependency per declared third-party package.

    This is the *real path* — no mocks. Reads package.json, requirements.txt,
    pyproject.toml, and setup.py from the top of repo_path, then:
      1. Registers the root repo as an `application` service.
      2. Registers each unique dependency as an `external` service (idempotent per org).
      3. Wires a runtime dependency edge from the root → each dep.

    Caps at 200 deps per repo to bound work and prevent abuse.
    """
    repo_root = _safe_repo_path(body.repo_path)
    eng = _get_engine()
    svc_name = (body.service_name or repo_root.name)[:200] or "unknown-repo"

    deps = _detect_repo_deps(repo_root)

    # 1. Find or create root service
    existing = [s for s in eng.list_services(org_id) if s.get("service_name") == svc_name]
    if existing:
        root = existing[0]
    else:
        try:
            root = eng.register_service(
                org_id=org_id,
                service_name=svc_name,
                service_type="application",
                criticality=body.criticality,
                owner=org_id,
                environment="production",
                data_classification="internal",
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

    root_id = root["id"]
    registered_deps: List[Dict[str, Any]] = []
    skipped: List[str] = []

    # Pre-fetch existing services for this org to dedupe by name
    existing_by_name = {s["service_name"]: s["id"] for s in eng.list_services(org_id)}
    # Existing edges from root to avoid duplicates
    root_full = eng.get_service(root_id, org_id) or {}
    existing_edge_targets = {
        d.get("target_service_id")
        for d in (root_full.get("outgoing_dependencies") or [])
    }

    for dep_name, ver in deps.items():
        # Skip self-references
        if dep_name == svc_name:
            continue
        # Find or create dep service
        dep_id = existing_by_name.get(dep_name)
        if dep_id is None:
            try:
                dep_svc = eng.register_service(
                    org_id=org_id,
                    service_name=dep_name,
                    service_type="external",
                    criticality="medium",
                    owner="third-party",
                    environment="production",
                    data_classification="public",
                )
                dep_id = dep_svc["id"]
                existing_by_name[dep_name] = dep_id
            except ValueError:
                skipped.append(dep_name)
                continue
        # Create edge if not already present
        if dep_id in existing_edge_targets:
            continue
        try:
            edge = eng.add_dependency(
                org_id=org_id,
                source_service_id=root_id,
                target_service_id=dep_id,
                dependency_type="runtime",
                criticality="medium",
                description=f"declared dep: {dep_name} {ver}".strip(),
            )
            registered_deps.append({"dep_name": dep_name, "dep_id": dep_id, "edge_id": edge.get("id")})
        except ValueError:
            skipped.append(dep_name)

    return {
        "org_id": org_id,
        "repo_path": str(repo_root),
        "service_name": svc_name,
        "service_id": root_id,
        "deps_detected": len(deps),
        "deps_registered": len(registered_deps),
        "deps_skipped": len(skipped),
        "edges": registered_deps[:50],  # cap response size
    }


@router.get("/blast-radius")
def blast_radius_by_name(
    node: str = Query(..., description="Node identifier — service name OR file path", min_length=1, max_length=1024),
    org_id: str = Query(default="default", max_length=256),
    analysis_type: str = Query(default="downstream"),
) -> Dict[str, Any]:
    """GET-style blast-radius lookup keyed by service name (or file path fallback).

    Resolves `node` to a service in two passes:
      1. Exact service_name match for org_id.
      2. If no match, treat `node` as a relative path and look for a service whose
         name equals `Path(node).stem` (e.g. `src/index.ts` → `index`).
      3. If still no match, fall back to source-trace.
    """
    if analysis_type not in {"downstream", "upstream"}:
        raise HTTPException(status_code=422, detail="analysis_type must be downstream or upstream")
    eng = _get_engine()

    # Pass 1: exact name
    services = eng.list_services(org_id)
    by_name = {s["service_name"]: s["id"] for s in services}
    svc_id = by_name.get(node)

    # Pass 2: file path -> stem
    if svc_id is None:
        stem = Path(node).stem
        svc_id = by_name.get(stem)

    # Pass 3: source-trace (returns matched services already)
    if svc_id is None:
        trace = eng.get_source_trace(org_id, node)
        matched = trace.get("matched_services") or []
        if matched:
            svc_id = matched[0].get("id") or matched[0].get("service_id")
        if svc_id is None:
            return {
                "node": node,
                "org_id": org_id,
                "matched": False,
                "affected_services": [],
                "affected_count": 0,
                "critical_count": 0,
                "hint": "node did not resolve to a registered service; call /map-repo first",
            }

    try:
        result = eng.compute_blast_radius(org_id, svc_id, analysis_type)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    result["node"] = node
    result["org_id"] = org_id
    result["matched"] = True
    return result
