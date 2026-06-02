"""Policy Enforcement Router — ALDECI.

Security policy lifecycle and exception management endpoints.

Prefix: /api/v1/policy-enforcement
Auth:   api_key_auth dependency

Routes:
  POST   /policies                              create_policy
  GET    /policies                              list_policies
  GET    /policies/{policy_id}                  get_policy
  POST   /policies/{policy_id}/version          create_policy_version
  POST   /exceptions                            record_exception
  PUT    /exceptions/{exception_id}/approve     approve_exception
  GET    /exceptions                            list_exceptions
  GET    /stats                                 get_enforcement_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/policy-enforcement",
    tags=["policy-enforcement"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton
# ---------------------------------------------------------------------------
_engine_cache: Dict[str, Any] = {}


def _get_engine(org_id: str):
    if org_id not in _engine_cache:
        from core.policy_enforcement_engine import get_engine
        _engine_cache[org_id] = get_engine(org_id)
    return _engine_cache[org_id]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class PolicyCreate(BaseModel):
    name: str
    policy_domain: str = Field(..., description="network/identity/data/endpoint/cloud/application/physical")
    policy_type: str = Field("mandatory", description="mandatory/recommended/prohibited")
    enforcement_mechanism: str = Field("manual", description="automated/manual/hybrid")
    content: str = ""


class PolicyVersionCreate(BaseModel):
    content: str
    change_summary: str


class ExceptionCreate(BaseModel):
    policy_id: str
    exception_type: str = Field("temporary", description="permanent/temporary/conditional")
    justification: str
    requested_by: str
    approver: Optional[str] = None
    expiry_date: Optional[str] = None


class ApproveRequest(BaseModel):
    approved_by: str
    notes: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/policies", response_model=Dict[str, Any], status_code=201)
def create_policy(
    body: PolicyCreate,
    org_id: str = Query("default", description="Organisation ID"),
):
    """Create a new enforcement policy."""
    try:
        return _get_engine(org_id).create_policy(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/policies", response_model=List[Dict[str, Any]])
def list_policies(
    org_id: str = Query("default"),
    policy_domain: Optional[str] = Query(None, description="Filter by policy_domain"),
    policy_type: Optional[str] = Query(None, description="Filter by policy_type"),
):
    """List policies with optional filters."""
    return _get_engine(org_id).list_policies(
        org_id, policy_domain=policy_domain, policy_type=policy_type
    )


@router.get("/policies/{policy_id}", response_model=Dict[str, Any])
def get_policy(
    policy_id: str,
    org_id: str = Query("default"),
):
    """Return a single policy."""
    result = _get_engine(org_id).get_policy(org_id, policy_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Policy not found.")
    return result


@router.post("/policies/{policy_id}/version", response_model=Dict[str, Any], status_code=201)
def create_policy_version(
    policy_id: str,
    body: PolicyVersionCreate,
    org_id: str = Query("default"),
):
    """Create a new version of an existing policy."""
    result = _get_engine(org_id).create_policy_version(
        org_id, policy_id, body.content, body.change_summary
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Policy not found.")
    return result


@router.post("/exceptions", response_model=Dict[str, Any], status_code=201)
def record_exception(
    body: ExceptionCreate,
    org_id: str = Query("default"),
):
    """Submit a policy exception request."""
    try:
        return _get_engine(org_id).record_exception(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.put("/exceptions/{exception_id}/approve", response_model=Dict[str, Any])
def approve_exception(
    exception_id: str,
    body: ApproveRequest,
    org_id: str = Query("default"),
):
    """Approve a pending policy exception."""
    result = _get_engine(org_id).approve_exception(
        org_id, exception_id, body.approved_by, body.notes
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Exception not found.")
    return result


@router.get("/exceptions", response_model=List[Dict[str, Any]])
def list_exceptions(
    org_id: str = Query("default"),
    policy_id: Optional[str] = Query(None, description="Filter by policy_id"),
    status: Optional[str] = Query(None, description="Filter by status"),
):
    """List exceptions with optional filters."""
    return _get_engine(org_id).list_exceptions(
        org_id, policy_id=policy_id, status=status
    )


@router.get("/stats", response_model=Dict[str, Any])
def get_enforcement_stats(
    org_id: str = Query("default"),
):
    """Return aggregated policy enforcement statistics."""
    return _get_engine(org_id).get_enforcement_stats(org_id)


# ---------------------------------------------------------------------------
# Hook policy + runtime status (DevSecOps hooks lifecycle)
# UI: HooksPolicyPanel / HooksStatusPanel under /comply/policies/authoring.
# Backed by DevSecOpsEngine.get_active_hook_policy / apply_hook_policy — real,
# persisted in the hook_policies table (NO MOCKS). Status rows are DERIVED from
# the CONFIGURED hooks in the active policy with status "idle" (configured, no
# execution events tracked yet) — never fabricated health/metrics; honest empty
# list when no hook policy exists for the org.
# ---------------------------------------------------------------------------


def _devsecops():
    from core.devsecops_engine import get_devsecops_engine
    return get_devsecops_engine()


@router.get("/hooks/policy")
def get_hook_policy(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return the active hook policy (the hooks dict) for the org, or {} if none."""
    try:
        rec = _devsecops().get_active_hook_policy(org_id)
    except Exception as exc:  # pragma: no cover
        _logger.exception("get_hook_policy failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return (rec.get("policy", {}) or {}) if rec else {}


@router.put("/hooks/policy")
def put_hook_policy(body: Dict[str, Any], org_id: str = Query("default")) -> Dict[str, Any]:
    """Persist an edited hook policy (the hooks dict). Idempotent on content hash."""
    if not isinstance(body, dict) or not body:
        raise HTTPException(
            status_code=422, detail="Body must be a non-empty hook policy object."
        )
    try:
        return _devsecops().apply_hook_policy(org_id, body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        _logger.exception("put_hook_policy failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/hooks/status", response_model=List[Dict[str, Any]])
def get_hook_status(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    """Derive a runtime-status list from the active policy's CONFIGURED hooks.

    Each configured stage becomes one row with status ``idle`` (configured, no
    execution events are tracked yet) — honest, never fabricated health. Returns
    an empty list when no hook policy is configured for the org.
    """
    try:
        rec = _devsecops().get_active_hook_policy(org_id)
    except Exception as exc:  # pragma: no cover
        _logger.exception("get_hook_status failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    if not rec:
        return []
    policy = rec.get("policy", {}) or {}
    rows: List[Dict[str, Any]] = []
    for stage, cfg in policy.items():
        if not isinstance(stage, str):
            continue
        enabled = True
        if isinstance(cfg, dict) and "enabled" in cfg:
            enabled = bool(cfg["enabled"])
        rows.append(
            {
                "hook_id": f"{rec.get('id', '')}:{stage}",
                "name": stage,
                "hook_type": stage,
                "stage": stage,
                "status": "idle" if enabled else "disabled",
                "trigger_count": 0,
                "error_count": 0,
            }
        )
    return rows
