"""CSPM Engine — Cloud Security Posture Management API endpoints.

Provides cloud resource inventory, security scanning, and posture analysis:
- POST /sync          — bulk-import cloud resources
- GET  /resources     — list resources with optional filters
- GET  /resources/{id} — get resource by internal UUID
- POST /scan          — run security checks
- GET  /results       — retrieve check results
- GET  /summary       — compliance summary (pass/fail counts, by category)
- GET  /public        — internet-exposed resources
- GET  /unencrypted   — resources without encryption
- GET  /iam           — IAM findings (overly permissive policies)
- GET  /score         — 0-100 cloud security posture score
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

try:
    from core.cspm import (
        CloudProvider,
        CloudResource,
        ComplianceStatus,
        CSPMEngine,
        ResourceCategory,
    )

    _engine: Optional[CSPMEngine] = None

    def _get_engine() -> CSPMEngine:
        global _engine
        if _engine is None:
            _engine = CSPMEngine()
        return _engine

    _HAS_ENGINE = True
except ImportError as _exc:
    _logger.warning("cspm_engine_router: cspm module unavailable: %s", _exc)
    _HAS_ENGINE = False

router = APIRouter(prefix="/api/v1/cspm-engine", tags=["cspm-engine"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class SyncResourceRequest(BaseModel):
    provider: str
    org_id: str = "default"
    resources: List[Dict[str, Any]]


class ScanRequest(BaseModel):
    org_id: str = "default"
    provider: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/sync")
def sync_resources(request: SyncResourceRequest) -> Dict[str, Any]:
    """Bulk-import cloud resources for an org/provider. Returns count of upserted records."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="CSPMEngine not available")
    try:
        provider = CloudProvider(request.provider)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid provider '{request.provider}'. Valid: {[p.value for p in CloudProvider]}",
        )
    engine = _get_engine()
    try:
        resources = [CloudResource(**r) for r in request.resources]
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid resource data: {exc}")
    count = engine.sync_resources(resources, provider, request.org_id)
    return {"synced": count, "provider": provider.value, "org_id": request.org_id}


@router.get("/resources")
def list_resources(
    org_id: str = Query(default="default"),
    provider: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    public_only: bool = Query(default=False),
) -> Dict[str, Any]:
    """List cloud resources with optional filters."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="CSPMEngine not available")
    engine = _get_engine()
    provider_filter: Optional[CloudProvider] = None
    if provider:
        try:
            provider_filter = CloudProvider(provider)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid provider '{provider}'")
    category_filter: Optional[ResourceCategory] = None
    if category:
        try:
            category_filter = ResourceCategory(category)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid category '{category}'")
    resources = engine.list_resources(
        org_id=org_id,
        provider=provider_filter,
        category=category_filter,
        public_only=public_only,
    )
    return {"resources": [r.model_dump(mode="json") for r in resources], "count": len(resources)}


@router.get("/resources/{resource_id}")
def get_resource(resource_id: str) -> Dict[str, Any]:
    """Get a cloud resource by its internal UUID."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="CSPMEngine not available")
    engine = _get_engine()
    resource = engine.get_resource(resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="Resource not found")
    return resource.model_dump(mode="json")


@router.post("/scan")
def run_scan(request: ScanRequest) -> Dict[str, Any]:
    """Run all applicable security checks for an org. Returns check results."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="CSPMEngine not available")
    provider_filter: Optional[CloudProvider] = None
    if request.provider:
        try:
            provider_filter = CloudProvider(request.provider)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid provider '{request.provider}'. Valid: {[p.value for p in CloudProvider]}",
            )
    engine = _get_engine()
    results = engine.run_security_checks(org_id=request.org_id, provider=provider_filter)
    # TrustGraph explicit indexing (fire-and-forget)
    try:
        from core.trustgraph_event_bus import EVENT_FINDING_CREATED
        from core.trustgraph_event_bus import get_event_bus as _get_eb
        _bus = _get_eb()
        if _bus and _bus.enabled and results:
            import asyncio as _asyncio
            _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                "finding_id": f"cspm-scan-{request.org_id}-{len(results)}",
                "type": "cspm_finding", "severity": "medium",
                "source": "cspm_engine_router", "data": {"count": len(results), "org_id": request.org_id},
            }))
    except Exception:
        pass
    return {
        "results": [r.model_dump(mode="json") for r in results],
        "count": len(results),
        "org_id": request.org_id,
    }


@router.get("/results")
def get_results(
    org_id: str = Query(default="default"),
    provider: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Retrieve stored check results with optional filters."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="CSPMEngine not available")
    engine = _get_engine()
    provider_filter: Optional[CloudProvider] = None
    if provider:
        try:
            provider_filter = CloudProvider(provider)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid provider '{provider}'")
    status_filter: Optional[ComplianceStatus] = None
    if status:
        try:
            status_filter = ComplianceStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status '{status}'")
    results = engine.get_check_results(
        org_id=org_id, provider=provider_filter, status_filter=status_filter
    )
    return {"results": [r.model_dump(mode="json") for r in results], "count": len(results)}


@router.get("/summary")
def get_summary(
    org_id: str = Query(default="default"),
    provider: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Return compliance summary: pass/fail counts, compliance rate, and breakdown by category."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="CSPMEngine not available")
    engine = _get_engine()
    provider_filter: Optional[CloudProvider] = None
    if provider:
        try:
            provider_filter = CloudProvider(provider)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid provider '{provider}'")
    return engine.get_compliance_summary(org_id=org_id, provider=provider_filter)


@router.get("/public")
def get_public_resources(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return internet-exposed cloud resources."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="CSPMEngine not available")
    engine = _get_engine()
    resources = engine.get_public_resources(org_id)
    return {"resources": [r.model_dump(mode="json") for r in resources], "count": len(resources)}


@router.get("/unencrypted")
def get_unencrypted_resources(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return cloud resources with encryption disabled."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="CSPMEngine not available")
    engine = _get_engine()
    resources = engine.get_unencrypted_resources(org_id)
    return {"resources": [r.model_dump(mode="json") for r in resources], "count": len(resources)}


@router.get("/iam")
def get_iam_findings(
    org_id: str = Query(default="default"),
    provider: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Return IAM resources with overly permissive policies or misconfigurations."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="CSPMEngine not available")
    engine = _get_engine()
    provider_filter: Optional[CloudProvider] = None
    if provider:
        try:
            provider_filter = CloudProvider(provider)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid provider '{provider}'")
    findings = engine.get_iam_findings(org_id=org_id, provider=provider_filter)
    return {"findings": findings, "count": len(findings)}


@router.get("/score")
def get_cspm_score(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return a 0-100 cloud security posture score for the org."""
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="CSPMEngine not available")
    engine = _get_engine()
    score = engine.get_cspm_score(org_id)
    grade = (
        "A" if score >= 90
        else "B" if score >= 80
        else "C" if score >= 70
        else "D" if score >= 60
        else "F"
    )
    return {"score": score, "grade": grade, "org_id": org_id}
