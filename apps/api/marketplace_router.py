"""Marketplace API router exposing remediation packs and full marketplace functionality.

This router provides the marketplace API endpoints for the main FixOps API.
It imports the marketplace service from fixops-enterprise using importlib to avoid
path conflicts with other src directories.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

# Load the marketplace service module directly using importlib to avoid path conflicts
# This is optional - if enterprise modules aren't present, we use stub implementations
_service_path = (
    Path(__file__).parent.parent.parent
    / "fixops-enterprise"
    / "src"
    / "services"
    / "marketplace_service.py"
)


def _load_enterprise_marketplace():
    """Attempt to load enterprise marketplace module, return stub implementations if unavailable."""
    from enum import Enum

    # Stub implementations for when enterprise modules aren't available
    class _StubContentType(Enum):
        REMEDIATION_PACK = "remediation_pack"
        POLICY_TEMPLATE = "policy_template"
        INTEGRATION = "integration"
        REPORT_TEMPLATE = "report_template"

    class _StubPricingModel(Enum):
        FREE = "free"
        PAID = "paid"
        SUBSCRIPTION = "subscription"

    def _stub_get_marketplace_service():
        return None

    if not _service_path.exists():
        return _StubContentType, _StubPricingModel, _stub_get_marketplace_service, False

    try:
        _spec = importlib.util.spec_from_file_location(
            "marketplace_service_module", str(_service_path)
        )
        if _spec is not None and _spec.loader is not None:
            _marketplace_service_module = importlib.util.module_from_spec(_spec)
            sys.modules["marketplace_service_module"] = _marketplace_service_module
            _spec.loader.exec_module(_marketplace_service_module)

            return (
                _marketplace_service_module.ContentType,
                _marketplace_service_module.PricingModel,
                _marketplace_service_module.get_marketplace_service,
                True,
            )
    except (ImportError, FileNotFoundError) as e:
        print(f"Enterprise marketplace module not available: {e}")

    return _StubContentType, _StubPricingModel, _stub_get_marketplace_service, False


(
    ContentType,
    PricingModel,
    get_marketplace_service,
    _ENTERPRISE_AVAILABLE,
) = _load_enterprise_marketplace()


def _require_enterprise_service():
    """Helper to check if enterprise marketplace service is available."""
    service = get_marketplace_service()
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Marketplace service requires enterprise modules. The /packs endpoint is available for basic remediation packs.",
        )
    return service


router = APIRouter(tags=["marketplace"])

# Simple API key authentication (matches main app)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def authenticate(api_key: Optional[str] = Depends(api_key_header)) -> None:
    """Simple API key authentication."""
    expected_token = os.getenv("FIXOPS_API_TOKEN", "demo-token")
    if not api_key or api_key != expected_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API token",
        )


class ContributeRequest(BaseModel):
    name: str
    description: str = ""
    content_type: str
    compliance_frameworks: List[str] = Field(default_factory=list)
    ssdlc_stages: List[str] = Field(default_factory=list)
    pricing_model: str = "free"
    price: float = 0.0
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    version: str = "1.0.0"


class UpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    compliance_frameworks: Optional[List[str]] = None
    ssdlc_stages: Optional[List[str]] = None
    pricing_model: Optional[str] = None
    price: Optional[float] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    version: Optional[str] = None


class RateRequest(BaseModel):
    rating: float = Field(ge=1, le=5)


class PurchaseRequest(BaseModel):
    organization: str = "default"


# Legacy endpoint - keep for backward compatibility
@router.get("/packs/{framework}/{control}")
async def fetch_pack(framework: str, control: str) -> dict:
    """Fetch a remediation pack for a specific framework and control."""
    # Return hardcoded packs for backward compatibility
    packs = {
        ("ISO27001", "AC-1"): {
            "framework": "ISO27001",
            "control": "AC-1",
            "name": "Access Control Policy",
            "description": "Implements access control policy requirements",
            "remediation_steps": [
                "Define access control policy",
                "Implement role-based access control",
                "Review access rights periodically",
            ],
        },
        ("ISO27001", "AC-2"): {
            "framework": "ISO27001",
            "control": "AC-2",
            "name": "Account Management",
            "description": "Implements account management requirements",
            "remediation_steps": [
                "Establish account provisioning process",
                "Implement account review procedures",
                "Define account termination process",
            ],
        },
        ("PCI", "8.3"): {
            "framework": "PCI",
            "control": "8.3",
            "name": "Multi-Factor Authentication",
            "description": "Implements MFA requirements for PCI DSS",
            "remediation_steps": [
                "Implement MFA for all administrative access",
                "Configure MFA for remote access",
                "Document MFA implementation",
            ],
        },
        ("SOC2", "CC6.1"): {
            "framework": "SOC2",
            "control": "CC6.1",
            "name": "Logical Access Security",
            "description": "Implements logical access security controls",
            "remediation_steps": [
                "Implement logical access controls",
                "Configure authentication mechanisms",
                "Monitor access attempts",
            ],
        },
    }
    key = (framework, control)
    if key not in packs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Pack not found"
        )
    return packs[key]


# New marketplace endpoints (cherry-picked from legacy)
@router.get("/browse")
async def browse_marketplace(
    content_type: Optional[str] = Query(None, description="Filter by content type"),
    compliance_framework: Optional[str] = Query(
        None, description="Filter by compliance framework"
    ),
    ssdlc_stage: Optional[str] = Query(None, description="Filter by SSDLC stage"),
    pricing_model: Optional[str] = Query(None, description="Filter by pricing model"),
    query: Optional[str] = Query(None, description="Search query"),
) -> Dict[str, Any]:
    """Browse and search marketplace items with optional filters."""
    service = _require_enterprise_service()
    ct = ContentType(content_type) if content_type else None
    pm = PricingModel(pricing_model) if pricing_model else None
    frameworks = [compliance_framework] if compliance_framework else None
    stages = [ssdlc_stage] if ssdlc_stage else None

    items = await service.search_marketplace(
        content_type=ct,
        compliance_frameworks=frameworks,
        ssdlc_stages=stages,
        pricing_model=pm,
        query=query,
    )
    return {
        "items": [
            {
                "id": item.id,
                "name": item.name,
                "description": item.description,
                "content_type": item.content_type.value,
                "compliance_frameworks": item.compliance_frameworks,
                "ssdlc_stages": item.ssdlc_stages,
                "pricing_model": item.pricing_model.value,
                "price": item.price,
                "tags": item.tags,
                "rating": item.rating,
                "rating_count": item.rating_count,
                "downloads": item.downloads,
                "version": item.version,
                "qa_status": item.qa_status.value,
                "created_at": item.created_at,
                "updated_at": item.updated_at,
            }
            for item in items
        ],
        "total": len(items),
    }


@router.get("/recommendations")
async def get_recommendations(
    organization_type: str = Query("general", description="Organization type"),
    compliance_requirements: str = Query(
        "", description="Comma-separated compliance frameworks"
    ),
) -> Dict[str, Any]:
    """Get recommended marketplace content based on organization profile."""
    service = _require_enterprise_service()
    requirements = [r.strip() for r in compliance_requirements.split(",") if r.strip()]
    items = await service.get_recommended_content(
        organization_type=organization_type,
        compliance_requirements=requirements,
    )
    return {
        "recommendations": [
            {
                "id": item.id,
                "name": item.name,
                "description": item.description,
                "content_type": item.content_type.value,
                "compliance_frameworks": item.compliance_frameworks,
                "pricing_model": item.pricing_model.value,
                "price": item.price,
                "rating": item.rating,
                "downloads": item.downloads,
            }
            for item in items
        ]
    }


@router.get("/items/{item_id}")
async def get_item(item_id: str) -> Dict[str, Any]:
    """Get details of a specific marketplace item."""
    service = _require_enterprise_service()
    item = await service.get_item(item_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Item not found"
        )
    return {
        "id": item.id,
        "name": item.name,
        "description": item.description,
        "content_type": item.content_type.value,
        "compliance_frameworks": item.compliance_frameworks,
        "ssdlc_stages": item.ssdlc_stages,
        "pricing_model": item.pricing_model.value,
        "price": item.price,
        "tags": item.tags,
        "metadata": item.metadata,
        "rating": item.rating,
        "rating_count": item.rating_count,
        "downloads": item.downloads,
        "version": item.version,
        "qa_status": item.qa_status.value,
        "qa_summary": item.qa_summary,
        "qa_checks": item.qa_checks,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


@router.post("/contribute")
async def contribute_content(
    request: ContributeRequest,
    author: str = Query(..., description="Author name"),
    organization: str = Query(..., description="Organization name"),
) -> Dict[str, Any]:
    """Submit new content to the marketplace."""
    service = _require_enterprise_service()
    try:
        item_id = await service.contribute_content(
            content=request.model_dump(),
            author=author,
            organization=organization,
        )
        return {"item_id": item_id, "status": "submitted"}
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@router.put("/items/{item_id}")
async def update_item(
    item_id: str,
    request: UpdateRequest,
) -> Dict[str, Any]:
    """Update an existing marketplace item."""
    service = _require_enterprise_service()
    try:
        patch = {k: v for k, v in request.model_dump().items() if v is not None}
        updated = await service.update_content(item_id, patch)
        return updated
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@router.post("/items/{item_id}/rate")
async def rate_item(
    item_id: str,
    request: RateRequest,
    reviewer: str = Query(..., description="Reviewer name"),
) -> Dict[str, Any]:
    """Rate a marketplace item."""
    service = _require_enterprise_service()
    try:
        result = await service.rate_content(item_id, request.rating, reviewer)
        return result
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@router.post("/purchase/{item_id}")
async def purchase_item(
    item_id: str,
    request: PurchaseRequest,
    purchaser: str = Query(..., description="Purchaser name"),
) -> Dict[str, Any]:
    """Purchase a marketplace item and get download token."""
    service = _require_enterprise_service()
    try:
        result = await service.purchase_content(
            item_id, purchaser, request.organization
        )
        return result
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@router.get("/download/{token}")
async def download_content(token: str) -> Dict[str, Any]:
    """Download purchased content using a valid token."""
    service = _require_enterprise_service()
    try:
        result = await service.download_by_token(token)
        return result
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
        ) from exc


@router.get("/contributors")
async def get_contributors(
    author: Optional[str] = Query(None, description="Filter by author"),
    organization: Optional[str] = Query(None, description="Filter by organization"),
) -> Dict[str, Any]:
    """Get contributor leaderboard and metrics."""
    service = _require_enterprise_service()
    contributors = await service.get_contributor_metrics(author, organization)
    return {"contributors": contributors, "total": len(contributors)}


@router.get("/compliance-content/{stage}")
async def get_compliance_content(
    stage: str,
    frameworks: str = Query(..., description="Comma-separated compliance frameworks"),
) -> Dict[str, Any]:
    """Get marketplace content for a specific SSDLC stage and frameworks."""
    service = _require_enterprise_service()
    framework_list = [f.strip() for f in frameworks.split(",") if f.strip()]
    result = await service.get_compliance_content_for_stage(stage, framework_list)
    return result


@router.get("/stats")
async def get_marketplace_stats() -> Dict[str, Any]:
    """Get marketplace statistics and quality summary."""
    service = _require_enterprise_service()
    stats = await service.get_stats()
    return stats


__all__ = ["router"]
