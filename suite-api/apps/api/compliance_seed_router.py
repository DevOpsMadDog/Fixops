"""Compliance Seed Router — ALDECI GAP-022 + GAP-023.

Triggers bulk population of compliance_mapping_engine's framework catalog
(100+ frameworks) and policy_engine's policy catalog (3000+ rules).
Idempotent: re-runs skip already-present entries.

Prefix: /api/v1/compliance-seed
Auth:   api_key_auth dependency on ALL endpoints.

Routes:
  POST /api/v1/compliance-seed/frameworks   seed 100+ framework controls
  POST /api/v1/compliance-seed/policies     seed 3000+ policy rules
  GET  /api/v1/compliance-seed/stats        counts of seeded content
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from apps.api.org_middleware import get_org_id
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/compliance-seed",
    tags=["Compliance Seed (GAP-022/023)"],
    dependencies=[Depends(api_key_auth)],
)


class SeedRequest(BaseModel):
    org_id: Optional[str] = None


def _compliance_engine():
    from core.compliance_mapping_engine import ComplianceMappingEngine
    return ComplianceMappingEngine()


def _policy_engine():
    from core.policy_engine import PolicyEngine
    return PolicyEngine()


@router.post("/frameworks", response_model=Dict[str, Any])
def seed_frameworks(req: SeedRequest, org: str = Depends(get_org_id)) -> Dict[str, Any]:
    target_org = req.org_id or org or "default"
    try:
        return _compliance_engine().seed_framework_library(org_id=target_org)
    except Exception as exc:
        _logger.exception("seed_framework_library failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/policies", response_model=Dict[str, Any])
def seed_policies(req: SeedRequest, org: str = Depends(get_org_id)) -> Dict[str, Any]:
    target_org = req.org_id or org or "default"
    try:
        return _policy_engine().seed_policy_library(org_id=target_org)
    except Exception as exc:
        _logger.exception("seed_policy_library failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", response_model=Dict[str, Any])
def stats(org: str = Depends(get_org_id)) -> Dict[str, Any]:
    org_id = org or "default"
    try:
        ce = _compliance_engine()
        pe = _policy_engine()
        return {
            "org_id": org_id,
            "frameworks_controls_total": ce.count_controls(org_id=org_id) if hasattr(ce, "count_controls") else None,
            "policies_total": pe.count_policies(org_id=org_id) if hasattr(pe, "count_policies") else None,
        }
    except Exception as exc:
        _logger.exception("compliance_seed.stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
