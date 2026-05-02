"""
Data Retention and Purge API endpoints.

Provides configurable retention policies, automated purge operations,
pre-purge export, and GDPR right-to-erasure (Article 17) compliance.

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.data_retention import (
    DataCategory,
    DataRetentionManager,
    ErasureRequest,
    PurgeRecord,
    RetentionPolicy,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/retention", tags=["retention"])

# Module-level manager — in-memory for tests, real path in production
_manager = None  # lazy-initialised on first request


def _get_manager():
    global _manager
    if _manager is None:
        _manager = DataRetentionManager()
    return _manager


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class RetentionPolicyRequest(BaseModel):
    """Request body for creating or updating a retention policy."""

    category: DataCategory
    retention_days: int = Field(..., ge=1, le=36500)
    description: str = Field(default="", max_length=2000)
    compliance_framework: Optional[str] = Field(default=None, max_length=64)
    enabled: bool = True


class PurgeRequest(BaseModel):
    """Request body for a targeted purge operation."""

    export_first: bool = False


class ErasureRequestBody(BaseModel):
    """Request body for a GDPR erasure request."""

    subject_email: str = Field(..., max_length=320)


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@router.post("/policies", response_model=RetentionPolicy, status_code=201)
async def set_policy(
    body: RetentionPolicyRequest,
    org_id: str = Depends(get_org_id),
) -> RetentionPolicy:
    """Create or update a retention policy for a data category."""
    policy = RetentionPolicy(
        category=body.category,
        retention_days=body.retention_days,
        description=body.description,
        compliance_framework=body.compliance_framework,
        enabled=body.enabled,
        org_id=org_id,
    )
    return _get_manager().set_policy(policy)


@router.get("/policies", response_model=List[RetentionPolicy])
async def list_policies(
    org_id: str = Depends(get_org_id),
) -> List[RetentionPolicy]:
    """List all configured retention policies for the org."""
    return _get_manager().list_policies(org_id)


@router.delete("/policies/{policy_id}", status_code=204)
async def delete_policy(policy_id: str) -> None:
    """Delete a retention policy by ID."""
    _get_manager().delete_policy(policy_id)
    return None


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


@router.get("/defaults", response_model=List[RetentionPolicy])
async def get_defaults() -> List[RetentionPolicy]:
    """Return the built-in default retention policies for all categories."""
    return _get_manager().get_default_policies()


# ---------------------------------------------------------------------------
# Purgeable
# ---------------------------------------------------------------------------


@router.get("/purgeable")
async def get_purgeable(
    org_id: str = Depends(get_org_id),
    category: Optional[DataCategory] = Query(default=None),
) -> Dict[str, Any]:
    """Identify records that are past their retention period and can be purged."""
    return _get_manager().identify_purgeable(org_id, category)


# ---------------------------------------------------------------------------
# Purge operations
# ---------------------------------------------------------------------------


@router.post("/purge/{category}", response_model=PurgeRecord)
async def purge_category(
    category: DataCategory,
    body: PurgeRequest = PurgeRequest(),
    org_id: str = Depends(get_org_id),
) -> PurgeRecord:
    """Purge expired records for a specific data category.

    Set export_first=true to export data to JSON before deleting.
    """
    policy = _get_manager().get_policy(category, org_id)
    if policy is None:
        raise HTTPException(
            status_code=404,
            detail=f"No retention policy configured for category '{category.value}'. "
            "Set a policy first via POST /api/v1/retention/policies.",
        )
    return _get_manager().purge_expired(org_id, category, export_first=body.export_first)


@router.post("/purge-all", response_model=List[PurgeRecord])
async def purge_all(
    org_id: str = Depends(get_org_id),
) -> List[PurgeRecord]:
    """Purge expired records across all configured categories for the org."""
    return _get_manager().purge_all_expired(org_id)


# ---------------------------------------------------------------------------
# GDPR erasure
# ---------------------------------------------------------------------------


@router.post("/erasure", response_model=ErasureRequest, status_code=201)
async def create_erasure_request(
    body: ErasureRequestBody,
    org_id: str = Depends(get_org_id),
) -> ErasureRequest:
    """Submit a GDPR right-to-erasure request (Article 17) for a data subject."""
    return _get_manager().request_erasure(body.subject_email, org_id)


@router.post("/erasure/{request_id}/process", response_model=ErasureRequest)
async def process_erasure(request_id: str) -> ErasureRequest:
    """Execute a pending GDPR erasure request across all data stores."""
    try:
        return _get_manager().process_erasure(request_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/erasure", response_model=List[ErasureRequest])
async def list_erasure_requests(
    org_id: str = Depends(get_org_id),
) -> List[ErasureRequest]:
    """List all GDPR erasure requests for the org."""
    return _get_manager().get_erasure_requests(org_id)


# ---------------------------------------------------------------------------
# Dashboard + history
# ---------------------------------------------------------------------------


@router.get("/dashboard")
async def get_dashboard(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Retention dashboard: per-category sizes, purgeable counts, and policy status."""
    return _get_manager().get_retention_dashboard(org_id)


@router.get("/history", response_model=List[PurgeRecord])
async def get_purge_history(
    org_id: str = Depends(get_org_id),
    limit: int = Query(default=100, ge=1, le=1000),
) -> List[PurgeRecord]:
    """Return purge history for the org, newest first."""
    history = _get_manager().get_purge_history(org_id)
    return history[:limit]
