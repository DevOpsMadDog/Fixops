"""Unified Rule Taxonomy Router — ALDECI (GAP-062, Sprint 3).

Canonical cross-engine rule registry. 5+ scanner engines (sast, dast, secrets,
container, cspm, api_security) reference the same {rule_key, domain, category,
severity, rule_type, enabled} shape.

Prefix: /api/v1/rules/unified
Auth:   api_key_auth dependency

Routes:
  POST   /                       register_unified_rule     (UPSERT)
  GET    /                       list_unified_rules        (filter: domain/source/enabled)
  POST   /{rule_key}/enable      enable_rule
  POST   /{rule_key}/disable     disable_rule
  GET    /taxonomy               get_rule_taxonomy         (canonical schema)
  POST   /sync                   sync_from_unified_registry (shim → policy_enforcement)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/rules/unified",
    tags=["unified-rules"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy engine accessors
# ---------------------------------------------------------------------------

def _get_policy_engine():
    from core.policy_engine import get_policy_engine
    return get_policy_engine()


def _get_enforcement_engine(org_id: str):
    from core.policy_enforcement_engine import get_engine
    return get_engine(org_id)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class UnifiedRuleCreate(BaseModel):
    rule_key: str = Field(..., min_length=1, max_length=200,
                          description="Canonical cross-engine key, e.g. 'sast.sql.injection'")
    domain: str = Field(..., description="sast/dast/secrets/iac/container/cspm/api_security/...")
    category: str = Field(..., min_length=1, description="Subcategory within domain")
    severity: str = Field(..., description="critical/high/medium/low/info")
    rule_type: str = Field(..., description="detection/validation/compliance/posture/hardening")
    source_engine: str = Field(..., min_length=1,
                               description="Originating engine (e.g. sast_engine, secrets_scanner)")


class SyncRequest(BaseModel):
    source_engine: str = Field(..., min_length=1,
                               description="Which source_engine's rules to sync")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("", response_model=Dict[str, Any], status_code=201)
def register_unified_rule(
    body: UnifiedRuleCreate,
    org_id: str = Query("default", description="Organisation ID"),
):
    """UPSERT a rule into the canonical taxonomy registry."""
    try:
        return _get_policy_engine().register_unified_rule(
            org_id,
            body.rule_key,
            body.domain,
            body.category,
            body.severity,
            body.rule_type,
            body.source_engine,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("", response_model=List[Dict[str, Any]])
def list_unified_rules(
    org_id: str = Query("default"),
    domain: Optional[str] = Query(None, description="Filter by domain"),
    source_engine: Optional[str] = Query(None, description="Filter by source_engine"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled flag"),
):
    """List registered unified rules with optional filters."""
    return _get_policy_engine().list_unified_rules(
        org_id, domain=domain, source_engine=source_engine, enabled=enabled
    )


@router.post("/{rule_key}/enable", response_model=Dict[str, Any])
def enable_rule(
    rule_key: str,
    org_id: str = Query("default"),
):
    """Enable a rule in the registry."""
    result = _get_policy_engine().enable_rule(org_id, rule_key)
    if result is None:
        raise HTTPException(status_code=404, detail="Rule not found.")
    return result


@router.post("/{rule_key}/disable", response_model=Dict[str, Any])
def disable_rule(
    rule_key: str,
    org_id: str = Query("default"),
):
    """Disable a rule in the registry (soft-delete)."""
    result = _get_policy_engine().disable_rule(org_id, rule_key)
    if result is None:
        raise HTTPException(status_code=404, detail="Rule not found.")
    return result


@router.get("/taxonomy", response_model=Dict[str, Any])
def get_rule_taxonomy():
    """Return the canonical rule taxonomy shape/schema for UI/API consumers."""
    return _get_policy_engine().get_rule_taxonomy()


@router.post("/sync", response_model=Dict[str, Any])
def sync_from_unified_registry(
    body: SyncRequest,
    org_id: str = Query("default"),
):
    """Shim: sync registry rules for a source_engine into policy_enforcement_engine.

    Writes enabled rules into the existing policies table with field alignment.
    Does NOT ALTER TABLE — pure field mapping.
    """
    try:
        return _get_enforcement_engine(org_id).sync_from_unified_registry(
            org_id, body.source_engine
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
