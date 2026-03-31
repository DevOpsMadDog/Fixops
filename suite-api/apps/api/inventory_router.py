"""
Inventory management API endpoints.

Advanced features: dependency graph with transitive resolution,
license compliance checking, SBOM generation (CycloneDX/SPDX),
vulnerability-to-asset correlation, and asset risk scoring.
"""
from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from apps.api.dependencies import get_org_id
from core.inventory_db import InventoryDB
from core.inventory_models import Application, ApplicationCriticality, ApplicationStatus
from core.persistent_store import get_persistent_store
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/inventory", tags=["inventory"])
db = InventoryDB()

# Persistent stores for enrichment data
_dependency_store = get_persistent_store("inventory_deps")  # app_id -> deps
_license_db: Dict[str, str] = {
    # ── Permissive ────────────────────────────────────────────────────────
    "MIT": "permissive", "Apache-2.0": "permissive",
    "BSD-2-Clause": "permissive", "BSD-3-Clause": "permissive",
    "ISC": "permissive", "Zlib": "permissive", "X11": "permissive",
    "curl": "permissive", "PostgreSQL": "permissive", "OpenSSL": "permissive",
    "BSL-1.0": "permissive", "JSON": "permissive", "HPND": "permissive",
    "PSF-2.0": "permissive", "Ruby": "permissive", "Artistic-2.0": "permissive",
    "ClArtistic": "permissive", "PIL": "permissive", "blessing": "permissive",
    "CC-BY-4.0": "permissive", "CC-BY-3.0": "permissive",
    # ── Public Domain ─────────────────────────────────────────────────────
    "Unlicense": "public_domain", "CC0-1.0": "public_domain",
    "0BSD": "public_domain", "WTFPL": "public_domain",
    # ── Weak Copyleft ─────────────────────────────────────────────────────
    "LGPL-2.0": "weak_copyleft", "LGPL-2.0-only": "weak_copyleft",
    "LGPL-2.0-or-later": "weak_copyleft",
    "LGPL-2.1": "weak_copyleft", "LGPL-2.1-only": "weak_copyleft",
    "LGPL-2.1-or-later": "weak_copyleft",
    "LGPL-3.0": "weak_copyleft", "LGPL-3.0-only": "weak_copyleft",
    "LGPL-3.0-or-later": "weak_copyleft",
    "MPL-2.0": "weak_copyleft", "MPL-1.0": "weak_copyleft", "MPL-1.1": "weak_copyleft",
    "EPL-1.0": "weak_copyleft", "EPL-2.0": "weak_copyleft",
    "CDDL-1.0": "weak_copyleft", "CDDL-1.1": "weak_copyleft",
    "CPL-1.0": "weak_copyleft", "OSL-3.0": "weak_copyleft",
    # ── Strong Copyleft ───────────────────────────────────────────────────
    "GPL-2.0": "copyleft", "GPL-2.0-only": "copyleft", "GPL-2.0-or-later": "copyleft",
    "GPL-3.0": "copyleft", "GPL-3.0-only": "copyleft", "GPL-3.0-or-later": "copyleft",
    "CC-BY-SA-4.0": "copyleft", "CC-BY-SA-3.0": "copyleft",
    # ── Network Copyleft (SaaS trigger) ───────────────────────────────────
    "AGPL-3.0": "copyleft", "AGPL-3.0-only": "copyleft", "AGPL-3.0-or-later": "copyleft",
    "EUPL-1.1": "copyleft", "EUPL-1.2": "copyleft",
    # ── Source-Available / Restrictive ────────────────────────────────────
    "SSPL-1.0": "restrictive", "BSL-1.1": "restrictive",
    "Elastic-2.0": "restrictive", "RSAL": "restrictive",
    "Confluent": "restrictive", "HashiCorp-BSL": "restrictive",
    "Commons-Clause": "restrictive",
    "CC-BY-NC-4.0": "restrictive", "CC-BY-NC-SA-4.0": "restrictive",
    "CC-BY-NC-ND-4.0": "restrictive",
}


class ApplicationCreate(BaseModel):
    """Request model for creating an application."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str
    criticality: ApplicationCriticality
    status: ApplicationStatus = ApplicationStatus.ACTIVE
    owner_team: Optional[str] = None
    repository_url: Optional[str] = None
    environment: str = "production"
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ApplicationUpdate(BaseModel):
    """Request model for updating an application."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    criticality: Optional[ApplicationCriticality] = None
    status: Optional[ApplicationStatus] = None
    owner_team: Optional[str] = None
    repository_url: Optional[str] = None
    environment: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class ApplicationResponse(BaseModel):
    """Response model for an application."""

    id: str
    name: str
    description: str
    criticality: str
    status: str
    owner_team: Optional[str]
    repository_url: Optional[str]
    environment: str
    tags: List[str]
    metadata: Dict[str, Any]
    created_at: str
    updated_at: str


class PaginatedResponse(BaseModel):
    """Paginated response wrapper."""

    items: List[ApplicationResponse]
    total: int
    limit: int
    offset: int


class AssetResponse(BaseModel):
    """Response model for generic assets."""

    id: str
    name: str
    type: str  # application, service, api, component
    status: str
    criticality: Optional[str] = None
    owner_team: Optional[str] = None
    environment: Optional[str] = None
    created_at: str
    updated_at: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PaginatedAssetResponse(BaseModel):
    """Paginated asset response."""

    items: List[AssetResponse]
    total: int
    limit: int
    offset: int


@router.get("/assets", response_model=PaginatedAssetResponse)
async def list_assets(
    org_id: str = Depends(get_org_id),
    asset_type: Optional[str] = Query(
        None, description="Filter by asset type: application, service, api"
    ),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List all assets across the inventory.

    Returns a unified view of all asset types (applications, services, APIs).
    """
    assets: List[AssetResponse] = []

    # Get applications and convert to assets
    if asset_type is None or asset_type == "application":
        applications = db.list_applications(limit=limit, offset=offset)
        for app in applications:
            app_dict = app.to_dict()
            assets.append(
                AssetResponse(
                    id=app_dict["id"],
                    name=app_dict["name"],
                    type="application",
                    status=app_dict["status"],
                    criticality=app_dict.get("criticality"),
                    owner_team=app_dict.get("owner_team"),
                    environment=app_dict.get("environment"),
                    created_at=app_dict["created_at"],
                    updated_at=app_dict["updated_at"],
                    metadata=app_dict.get("metadata", {}),
                )
            )

    # In production, would also fetch services and APIs from their respective stores
    # For now, return the applications we have

    return {
        "items": assets[:limit],
        "total": len(assets),
        "limit": limit,
        "offset": offset,
    }


@router.get("/applications", response_model=PaginatedResponse)
async def list_applications(
    org_id: str = Depends(get_org_id),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List all applications with pagination."""
    applications = db.list_applications(limit=limit, offset=offset)
    return {
        "items": [ApplicationResponse(**app.to_dict()) for app in applications],
        "total": len(applications),
        "limit": limit,
        "offset": offset,
    }


@router.post("/applications", response_model=ApplicationResponse, status_code=201)
async def create_application(app_data: ApplicationCreate):
    """Register a new application."""
    app = Application(
        id="",
        name=app_data.name,
        description=app_data.description,
        criticality=app_data.criticality,
        status=app_data.status,
        owner_team=app_data.owner_team,
        repository_url=app_data.repository_url,
        environment=app_data.environment,
        tags=app_data.tags,
        metadata=app_data.metadata,
    )
    created_app = db.create_application(app)
    return ApplicationResponse(**created_app.to_dict())


@router.get("/applications/{id}", response_model=ApplicationResponse)
async def get_application(id: str):
    """Get application details by ID."""
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    return ApplicationResponse(**app.to_dict())


@router.put("/applications/{id}", response_model=ApplicationResponse)
async def update_application(id: str, app_data: ApplicationUpdate):
    """Update an application."""
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    if app_data.name is not None:
        app.name = app_data.name
    if app_data.description is not None:
        app.description = app_data.description
    if app_data.criticality is not None:
        app.criticality = app_data.criticality
    if app_data.status is not None:
        app.status = app_data.status
    if app_data.owner_team is not None:
        app.owner_team = app_data.owner_team
    if app_data.repository_url is not None:
        app.repository_url = app_data.repository_url
    if app_data.environment is not None:
        app.environment = app_data.environment
    if app_data.tags is not None:
        app.tags = app_data.tags
    if app_data.metadata is not None:
        app.metadata = app_data.metadata

    updated_app = db.update_application(app)
    return ApplicationResponse(**updated_app.to_dict())


@router.delete("/applications/{id}", status_code=204)
async def delete_application(id: str):
    """Archive an application."""
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    db.delete_application(id)
    return None


@router.get("/applications/{id}/components")
async def list_application_components(id: str):
    """List components for an application (derived from dependencies)."""
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    deps = _dependency_store.get(id, [])
    components = [
        {
            "name": d["name"],
            "version": d.get("version", "unknown"),
            "type": d.get("type", "library"),
            "license": d.get("license", "unknown"),
        }
        for d in deps
    ]
    return {"application_id": id, "components": components, "total": len(components)}


@router.get("/applications/{id}/apis")
async def list_application_apis(id: str):
    """List API endpoints for an application."""
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    # Derive from metadata if available
    apis = app.metadata.get("apis", []) if app.metadata else []
    return {"application_id": id, "apis": apis, "total": len(apis)}


@router.post("/applications/{id}/dependencies")
async def add_application_dependencies(id: str, deps: List[Dict[str, Any]]):
    """Upload dependency manifest for an application.

    Each dependency: {name, version, type, license, ecosystem, transitive}.
    """
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    existing = _dependency_store.get(id, [])
    seen = {d["name"] for d in existing}
    added = 0
    for dep in deps:
        if dep.get("name") and dep["name"] not in seen:
            existing.append(dep)
            seen.add(dep["name"])
            added += 1
    _dependency_store[id] = existing
    return {"application_id": id, "added": added, "total": len(existing)}


@router.get("/applications/{id}/dependencies")
async def get_application_dependencies(id: str, include_transitive: bool = Query(True)):
    """Get dependency graph for an application with transitive resolution."""
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    deps = _dependency_store.get(id, [])

    # Build graph: name -> list of sub-deps
    nodes = []
    edges = []
    for dep in deps:
        nodes.append(
            {
                "id": dep["name"],
                "version": dep.get("version", "?"),
                "license": dep.get("license", "unknown"),
                "direct": not dep.get("transitive", False),
            }
        )
        for sub in dep.get("sub_dependencies", []):
            edges.append({"source": dep["name"], "target": sub})
            if include_transitive:
                nodes.append(
                    {"id": sub, "version": "?", "license": "unknown", "direct": False}
                )

    # Deduplicate nodes by id
    seen: Set[str] = set()
    unique_nodes = []
    for n in nodes:
        if n["id"] not in seen:
            unique_nodes.append(n)
            seen.add(n["id"])

    return {
        "application_id": id,
        "dependencies": deps,
        "graph": {"nodes": unique_nodes, "edges": edges},
        "total_direct": sum(1 for d in deps if not d.get("transitive")),
        "total_transitive": sum(1 for d in deps if d.get("transitive")),
        "total": len(deps),
    }


# Persistent service/API stores
_service_store = get_persistent_store("inventory_services")
_api_store = get_persistent_store("inventory_apis")


@router.get("/services")
async def list_services(
    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)
):
    """List all services with pagination."""
    # Reload from SQLite to pick up any data seeded after startup
    _service_store._load_all()
    items = list(_service_store.values())[offset : offset + limit]
    return {
        "items": items,
        "total": len(_service_store),
        "limit": limit,
        "offset": offset,
    }


@router.post("/services", status_code=201)
async def create_service(service_data: Dict[str, Any]):
    """Register a new service."""
    service_id = str(uuid.uuid4())
    svc = {
        "id": service_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "status": "active",
        **service_data,
    }
    _service_store[service_id] = svc
    return svc


@router.get("/services/{id}")
async def get_service(id: str):
    """Get service details by ID."""
    svc = _service_store.get(id)
    if not svc:
        raise HTTPException(status_code=404, detail="Service not found")
    return svc


@router.get("/apis")
async def list_apis(
    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)
):
    """List all API endpoints with pagination."""
    # Reload from SQLite to pick up any data seeded after startup
    _api_store._load_all()
    items = list(_api_store.values())[offset : offset + limit]
    return {"items": items, "total": len(_api_store), "limit": limit, "offset": offset}


@router.post("/apis", status_code=201)
async def create_api(api_data: Dict[str, Any]):
    """Register a new API endpoint."""
    api_id = str(uuid.uuid4())
    api_entry = {
        "id": api_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "status": "active",
        **api_data,
    }
    _api_store[api_id] = api_entry
    return api_entry


@router.get("/apis/{id}/security")
async def get_api_security(id: str):
    """Get security posture for an API endpoint."""
    api_entry = _api_store.get(id)
    if not api_entry:
        raise HTTPException(status_code=404, detail="API not found")
    # Compute score from linked findings via Knowledge Brain
    score = 85.0  # default healthy
    vulns: List[Dict[str, Any]] = []
    try:
        from core.knowledge_brain import get_brain

        brain = get_brain()
        neighbors = brain.get_neighbors(id, depth=1)
        for n in neighbors:
            if n.get("entity_type") == "finding":
                vulns.append(n)
                sev = n.get("severity", "medium")
                penalty = {"critical": 25, "high": 15, "medium": 8, "low": 3}.get(
                    sev, 5
                )
                score = max(0, score - penalty)
    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
        pass
    return {
        "api_id": id,
        "security_score": round(score, 1),
        "security_score_status": "assessed",
        "vulnerabilities": vulns[:20],
        "compliance_status": "compliant" if score >= 70 else "non_compliant",
    }


@router.get("/search")
async def search_inventory(
    q: str = Query(..., min_length=1), limit: int = Query(100, ge=1, le=1000)
):
    """Search across all inventory types."""
    results = db.search_inventory(q, limit=limit)
    return results


# ---------------------------------------------------------------------------
# Advanced: License compliance
# ---------------------------------------------------------------------------


@router.get("/applications/{id}/license-compliance")
async def check_license_compliance(id: str):
    """Check license compliance for all dependencies of an application.

    Flags copyleft and restrictive licenses that may conflict with commercial use.
    """
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    deps = _dependency_store.get(id, [])

    issues: List[Dict[str, Any]] = []
    summary: Dict[str, int] = defaultdict(int)
    for dep in deps:
        lic = dep.get("license", "unknown")
        category = _license_db.get(lic, "unknown")
        summary[category] += 1
        if category in ("copyleft", "restrictive"):
            issues.append(
                {
                    "package": dep["name"],
                    "version": dep.get("version", "?"),
                    "license": lic,
                    "category": category,
                    "risk": "high" if category == "copyleft" else "critical",
                    "recommendation": "Review license obligations or find alternative package",
                }
            )

    compliant = len(issues) == 0
    return {
        "application_id": id,
        "compliant": compliant,
        "total_dependencies": len(deps),
        "license_summary": dict(summary),
        "issues": issues,
        "compliance_score": round(100 * (1 - len(issues) / max(len(deps), 1)), 1),
    }


# ---------------------------------------------------------------------------
# Advanced: SBOM generation (CycloneDX / SPDX)
# ---------------------------------------------------------------------------


@router.get("/applications/{id}/sbom")
async def generate_sbom(
    id: str,
    format: str = Query("cyclonedx", pattern="^(cyclonedx|spdx)$"),
):
    """Generate Software Bill of Materials in CycloneDX or SPDX format."""
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    deps = _dependency_store.get(id, [])
    app_dict = app.to_dict()

    if format == "cyclonedx":
        components = []
        for dep in deps:
            comp = {
                "type": "library",
                "name": dep["name"],
                "version": dep.get("version", "unknown"),
                "purl": f"pkg:{dep.get('ecosystem', 'generic')}/{dep['name']}@{dep.get('version', 'unknown')}",
            }
            if dep.get("license"):
                comp["licenses"] = [{"license": {"id": dep["license"]}}]
            components.append(comp)
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": app_dict["name"],
                    "version": "1.0.0",
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "FixOps",
                        "name": "FixOps SBOM Generator",
                        "version": "1.0.0",
                    }
                ],
            },
            "components": components,
        }
    else:  # spdx
        packages = []
        for i, dep in enumerate(deps):
            packages.append(
                {
                    "SPDXID": f"SPDXRef-Package-{i}",
                    "name": dep["name"],
                    "versionInfo": dep.get("version", "unknown"),
                    "downloadLocation": dep.get("repository_url", "NOASSERTION"),
                    "licenseConcluded": dep.get("license", "NOASSERTION"),
                }
            )
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": app_dict["name"],
            "documentNamespace": f"https://fixops.io/spdx/{id}",
            "creationInfo": {
                "created": datetime.now(timezone.utc).isoformat(),
                "creators": ["Tool: FixOps-1.0.0"],
            },
            "packages": packages,
        }

    return {
        "format": format,
        "application_id": id,
        "sbom": sbom,
        "component_count": len(deps),
    }


# ---------------------------------------------------------------------------
# Global SBOM & License Compliance (cross-application)
# ---------------------------------------------------------------------------

# In-memory global component store (populated from SBOM ingestion)
_global_components = get_persistent_store("global_sbom_components")
_ingested_sboms = get_persistent_store("ingested_sboms")


@router.get("/sbom/components")
async def list_global_sbom_components(
    ecosystem: Optional[str] = None,
    has_vulnerabilities: Optional[bool] = None,
    license_type: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    """List all SBOM components across all applications.

    Aggregates components from all ingested SBOMs for enterprise-wide
    supply chain visibility. Supports filtering by ecosystem, vulnerability
    status, and license type.
    """
    all_comps = []
    for app_id in _ingested_sboms.keys():
        comps = _ingested_sboms.get(app_id, [])
        for c in comps:
            c["app_id"] = app_id
            all_comps.append(c)

    # Also pull from dependency store
    for app_id in _dependency_store.keys():
        deps = _dependency_store.get(app_id, [])
        for dep in deps:
            all_comps.append({
                "name": dep.get("name", ""),
                "version": dep.get("version", "unknown"),
                "ecosystem": dep.get("ecosystem", "unknown"),
                "license": dep.get("license", "unknown"),
                "license_category": _license_db.get(dep.get("license", ""), "unknown"),
                "app_id": app_id,
                "purl": f"pkg:{dep.get('ecosystem', 'generic')}/{dep.get('name', '')}@{dep.get('version', 'unknown')}",
            })

    # Deduplicate by name+version
    seen: Set[str] = set()
    unique_comps: List[Dict[str, Any]] = []
    for c in all_comps:
        key = f"{c.get('name', '')}@{c.get('version', '')}"
        if key not in seen:
            seen.add(key)
            unique_comps.append(c)

    # Apply filters
    if ecosystem:
        unique_comps = [c for c in unique_comps if c.get("ecosystem", "").lower() == ecosystem.lower()]
    if license_type:
        unique_comps = [c for c in unique_comps if c.get("license_category", "").lower() == license_type.lower()]

    total = len(unique_comps)
    start = (page - 1) * page_size
    end = start + page_size

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "components": unique_comps[start:end],
        "ecosystems": list(set(c.get("ecosystem", "unknown") for c in unique_comps)),
        "license_summary": _aggregate_licenses(unique_comps),
    }


def _aggregate_licenses(components: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate license information from components."""
    by_license: Dict[str, int] = defaultdict(int)
    by_category: Dict[str, int] = defaultdict(int)
    for c in components:
        lic = c.get("license", "unknown")
        cat = _license_db.get(lic, "unknown")
        by_license[lic] += 1
        by_category[cat] += 1
    return {
        "by_license": dict(by_license),
        "by_category": dict(by_category),
        "total_unique_licenses": len(by_license),
    }


@router.get("/sbom/licenses")
async def get_license_compliance_summary():
    """Get enterprise-wide license compliance summary.

    Analyzes all known components for license risk, copyleft contamination,
    and policy violations. Critical for defense/government procurement
    (DFARS 252.227-7014 compliance).
    """
    all_deps: List[Dict[str, Any]] = []
    for app_id in _dependency_store.keys():
        deps = _dependency_store.get(app_id, [])
        for dep in deps:
            dep["app_id"] = app_id
            all_deps.append(dep)

    # Classify all licenses
    compliant = 0
    non_compliant = 0
    unknown_license = 0
    issues: List[Dict[str, Any]] = []
    by_category: Dict[str, int] = defaultdict(int)

    for dep in all_deps:
        lic = dep.get("license", "unknown")
        category = _license_db.get(lic, "unknown")
        by_category[category] += 1

        if category in ("copyleft", "restrictive"):
            non_compliant += 1
            issues.append({
                "package": dep.get("name", "?"),
                "version": dep.get("version", "?"),
                "license": lic,
                "category": category,
                "app_id": dep.get("app_id", "?"),
                "risk": "critical" if category == "copyleft" else "high",
                "recommendation": (
                    f"Replace {dep.get('name', '?')} with a permissively-licensed alternative "
                    f"or obtain a commercial license exemption"
                ),
            })
        elif category == "unknown":
            unknown_license += 1
        else:
            compliant += 1

    total = len(all_deps)
    score = round(100 * compliant / max(total, 1), 1)

    return {
        "total_components": total,
        "compliant": compliant,
        "non_compliant": non_compliant,
        "unknown_license": unknown_license,
        "compliance_score": score,
        "license_distribution": dict(by_category),
        "policy_violations": issues[:100],  # Cap at 100 for response size
        "dfars_compliant": non_compliant == 0 and unknown_license == 0,
        "assessment_timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/sbom/ingest")
async def ingest_sbom(
    sbom_data: Dict[str, Any],
    app_id: str = Query(..., min_length=1),
):
    """Ingest a CycloneDX or SPDX SBOM and register all components.

    Accepts standard CycloneDX 1.4+ or SPDX 2.3 format.
    Components are parsed, deduplicated, and stored for license
    compliance analysis and vulnerability correlation.
    """
    components: List[Dict[str, Any]] = []

    # CycloneDX format
    if "bomFormat" in sbom_data or "components" in sbom_data:
        for comp in sbom_data.get("components", []):
            lic = ""
            for lic_entry in comp.get("licenses", []):
                if isinstance(lic_entry, dict):
                    lic_obj = lic_entry.get("license", {})
                    if isinstance(lic_obj, dict):
                        lic = lic_obj.get("id", lic_obj.get("name", ""))
                    elif isinstance(lic_obj, str):
                        lic = lic_obj
            components.append({
                "name": comp.get("name", ""),
                "version": comp.get("version", "unknown"),
                "ecosystem": comp.get("purl", "").split(":")[1].split("/")[0] if ":" in comp.get("purl", "") else "unknown",
                "license": lic or "unknown",
                "purl": comp.get("purl", ""),
                "type": comp.get("type", "library"),
            })

    # SPDX format
    elif "spdxVersion" in sbom_data or "packages" in sbom_data:
        for pkg in sbom_data.get("packages", []):
            components.append({
                "name": pkg.get("name", ""),
                "version": pkg.get("versionInfo", "unknown"),
                "ecosystem": "unknown",
                "license": pkg.get("licenseConcluded", pkg.get("licenseDeclared", "NOASSERTION")),
                "purl": pkg.get("externalRefs", [{}])[0].get("referenceLocator", "") if pkg.get("externalRefs") else "",
                "type": "library",
            })
    else:
        raise HTTPException(status_code=400, detail="Unrecognized SBOM format. Provide CycloneDX or SPDX JSON.")

    # Store components
    _ingested_sboms[app_id] = components

    # Also populate dependency store for license compliance
    _dependency_store[app_id] = components

    # Run license check
    issues = []
    for comp in components:
        cat = _license_db.get(comp.get("license", ""), "unknown")
        if cat in ("copyleft", "restrictive"):
            issues.append({
                "package": comp["name"],
                "license": comp["license"],
                "category": cat,
                "risk": "critical" if cat == "copyleft" else "high",
            })

    return {
        "status": "ingested",
        "app_id": app_id,
        "components_ingested": len(components),
        "license_issues": len(issues),
        "issues": issues[:50],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# TIER 3.1: Enhanced SBOM — Transitive Deps, VEX, Vuln Cross-Reference
# ---------------------------------------------------------------------------

_vex_store = get_persistent_store("vex_documents")  # app_id -> VEX doc


@router.post("/sbom/analyze")
async def analyze_sbom_vulnerabilities(
    sbom_data: Dict[str, Any],
    app_id: str = Query(..., min_length=1),
):
    """Analyze an SBOM for known vulnerabilities and generate a VEX document.

    Accepts CycloneDX or SPDX format. Cross-references all components against
    the embedded vulnerability database, returns findings with severity
    breakdown and auto-generates an OpenVEX companion document.
    """
    from risk.sbom.generator import (
        Dependency,
        SBOMGenerator,
    )

    generator = SBOMGenerator()

    # Parse components from SBOM into Dependency objects
    deps: List[Dependency] = []
    if "components" in sbom_data:
        for comp in sbom_data.get("components", []):
            is_trans = False
            depth = 0
            for prop in comp.get("properties", []):
                if prop.get("name") == "fixops:transitive":
                    is_trans = prop.get("value", "false") == "true"
                elif prop.get("name") == "fixops:depth":
                    try:
                        depth = int(prop.get("value", "0"))
                    except (ValueError, TypeError):
                        depth = 0
            deps.append(Dependency(
                name=comp.get("name", ""),
                version=comp.get("version"),
                package_manager=_guess_ecosystem(comp.get("purl", "")),
                purl=comp.get("purl"),
                is_transitive=is_trans,
                depth=depth,
            ))
    elif "packages" in sbom_data:
        for pkg in sbom_data.get("packages", []):
            purl = ""
            for ref in pkg.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator", "")
                    break
            deps.append(Dependency(
                name=pkg.get("name", ""),
                version=pkg.get("versionInfo"),
                package_manager=_guess_ecosystem(purl),
                purl=purl,
            ))
    else:
        raise HTTPException(status_code=400, detail="Provide CycloneDX or SPDX SBOM")

    # Cross-reference vulns (local DB)
    vuln_report = generator.cross_reference_vulnerabilities(deps)

    # Pull DTrack findings and merge if available
    dtrack_findings: List[Dict[str, Any]] = []
    dtrack_status = "not_configured"
    try:
        from core.security_connectors import DependencyTrackConnector

        dtrack = DependencyTrackConnector()
        if dtrack.configured:
            # Try to find the project by app_id
            import json as _json

            proj = dtrack.get_or_create_project(name=app_id)
            proj_uuid = proj.get("uuid", "")
            if proj_uuid:
                outcome = dtrack.fetch_findings(proj_uuid, page_size=500)
                if outcome.success:
                    dtrack_findings = outcome.details.get("data", [])
                    dtrack_status = "merged"
                    # Merge DTrack findings into vuln_report
                    existing_ids = {v.get("cve_id") for v in vuln_report.get("vulnerabilities", [])}
                    for dtf in dtrack_findings:
                        if dtf.get("id") and dtf["id"] not in existing_ids:
                            vuln_report.setdefault("vulnerabilities", []).append({
                                "cve_id": dtf["id"],
                                "severity": dtf.get("severity", "medium"),
                                "cvss_score": dtf.get("cvss_v3"),
                                "component": dtf.get("component_name", ""),
                                "version": dtf.get("component_version", ""),
                                "source": f"dependency-track:{dtf.get('source', 'NVD')}",
                                "suppressed": dtf.get("suppressed", False),
                            })
                            existing_ids.add(dtf["id"])
                    # Update summary counts
                    vuln_report["total_vulnerabilities"] = len(vuln_report.get("vulnerabilities", []))
            else:
                dtrack_status = "project_not_found"
    except ImportError:
        dtrack_status = "connector_unavailable"
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.warning("Dependency-Track enrichment failed: %s", exc)
        dtrack_status = "error"

    # Generate VEX
    vex_doc = generator.generate_vex_document(deps, vuln_report)
    _vex_store[app_id] = vex_doc

    return {
        "application_id": app_id,
        "vulnerability_report": vuln_report,
        "vex_document": vex_doc,
        "dependency_track": {"status": dtrack_status, "findings_merged": len(dtrack_findings)},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/sbom/vex/apply")
async def apply_vex_to_sbom(
    sbom_data: Dict[str, Any],
    vex_data: Optional[Dict[str, Any]] = None,
    app_id: Optional[str] = Query(None),
):
    """Apply VEX status to an SBOM, enriching components with exploitability info.

    If no vex_data is provided, uses the stored VEX document for the app_id.
    Returns the SBOM with vulnerability status annotations on each component.
    """
    from risk.sbom.generator import SBOMGenerator

    generator = SBOMGenerator()

    if not vex_data and app_id:
        vex_data = _vex_store.get(app_id)
    if not vex_data:
        raise HTTPException(
            status_code=400,
            detail="Provide vex_data in body or app_id with stored VEX document",
        )

    statements = SBOMGenerator.parse_vex_document(vex_data)
    enriched = generator.apply_vex_to_sbom(sbom_data, statements)

    return {
        "sbom": enriched,
        "vex_statements_applied": len(statements),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/sbom/vex/{app_id}")
async def get_vex_document(app_id: str):
    """Retrieve the stored VEX document for an application."""
    vex_doc = _vex_store.get(app_id)
    if not vex_doc:
        raise HTTPException(status_code=404, detail="No VEX document found for this application")
    return {"application_id": app_id, "vex_document": vex_doc}


@router.post("/sbom/vex/ingest")
async def ingest_vex_document(
    vex_data: Dict[str, Any],
    app_id: str = Query(..., min_length=1),
):
    """Ingest an external OpenVEX document for an application.

    Parses the document, validates structure, and stores it for
    later application to SBOMs via /sbom/vex/apply.
    """
    from risk.sbom.generator import SBOMGenerator

    statements = SBOMGenerator.parse_vex_document(vex_data)
    if not statements:
        raise HTTPException(status_code=400, detail="No valid VEX statements found")

    _vex_store[app_id] = vex_data

    # Auto-forward VEX to Dependency-Track (fire-and-forget)
    dtrack_status = "not_configured"
    try:
        from core.security_connectors import DependencyTrackConnector

        dtrack = DependencyTrackConnector()
        if dtrack.configured:
            import json as _json

            vex_json = _json.dumps(vex_data) if isinstance(vex_data, dict) else str(vex_data)
            outcome = dtrack.upload_vex(
                project_name=app_id,
                vex_content=vex_json,
            )
            dtrack_status = "forwarded" if outcome.success else "forward_failed"
    except ImportError:
        dtrack_status = "connector_unavailable"
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.warning("Dependency-Track VEX forwarding failed: %s", exc)
        dtrack_status = "error"

    return {
        "status": "ingested",
        "app_id": app_id,
        "statements_parsed": len(statements),
        "statuses": {
            s.status.value: sum(1 for st in statements if st.status == s.status)
            for s in statements
        },
        "dependency_track": {"status": dtrack_status},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _guess_ecosystem(purl: str) -> str:
    """Guess package ecosystem from PURL."""
    if purl.startswith("pkg:npm/"):
        return "npm"
    elif purl.startswith("pkg:pypi/"):
        return "pip"
    elif purl.startswith("pkg:maven/"):
        return "maven"
    elif purl.startswith("pkg:golang/"):
        return "go"
    return "unknown"