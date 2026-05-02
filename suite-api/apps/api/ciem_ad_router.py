"""CIEM + Active Directory Attack Paths Router — ALDECI.

Unified API surface covering the MERGE from GAP-032 + GAP-033:
  - CIEM identity-scoped least-privilege recommendations
  - AD/Entra ID specific identity risks (Kerberoast, DCSync, adminCount, unconstrained delegation)
  - Privileged standing-access + JIT recommendations
  - ITDR AD attack detection (ESC1/ESC4, Golden/Skeleton ticket heuristics)
  - Cross-engine AD attack-path builder (kerberoastable -> cracked -> admin_count -> domain_admin)

Prefix: /api/v1/ciem-ad
Auth:   api_key_auth dependency
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ciem-ad",
    tags=["CIEM+AD Attack Paths"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singletons (avoid eager DB creation at import)
# ---------------------------------------------------------------------------

_ciem = None
_identity_risk = None
_pag = None
_itdr = None
_priv_esc = None


def _get_ciem():
    global _ciem
    if _ciem is None:
        from core.ciem_engine import get_ciem_engine
        _ciem = get_ciem_engine()
    return _ciem


def _get_identity_risk():
    global _identity_risk
    if _identity_risk is None:
        from core.identity_risk_engine import IdentityRiskEngine
        _identity_risk = IdentityRiskEngine()
    return _identity_risk


def _get_pag():
    global _pag
    if _pag is None:
        from core.privileged_access_governance_engine import (
            PrivilegedAccessGovernanceEngine,
        )
        _pag = PrivilegedAccessGovernanceEngine()
    return _pag


def _get_itdr():
    global _itdr
    if _itdr is None:
        from core.itdr_engine import ITDREngine
        _itdr = ITDREngine()
    return _itdr


def _get_priv_esc():
    global _priv_esc
    if _priv_esc is None:
        from core.privilege_escalation_detector_engine import (
            get_privilege_escalation_detector,
        )
        _priv_esc = get_privilege_escalation_detector()
    return _priv_esc


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class LeastPrivilegeRequest(BaseModel):
    org_id: str = Field("default", description="Organization identifier")
    current_permissions: Optional[List[str]] = Field(
        default=None, description="Permissions currently granted to the identity"
    )
    used_permissions: Optional[List[str]] = Field(
        default=None, description="Permissions actually used (explicit)"
    )
    usage_log: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Usage log rows [{action, timestamp}] — actions in the last window_days are used",
    )
    window_days: int = Field(90, ge=1, le=365, description="Look-back window in days")


class ADRisksRequest(BaseModel):
    ad_objects: List[Dict[str, Any]] = Field(
        ..., description="List of AD/Entra object dicts (sAMAccountName, SPN, memberOf, uac, adminCount, ...)"
    )


class ITDRDetectRequest(BaseModel):
    org_id: str = Field("default", description="Organization identifier")
    templates: Optional[List[Dict[str, Any]]] = Field(
        default=None, description="ADCS certificate templates (for ESC1/ESC4)"
    )
    auth_events: Optional[List[Dict[str, Any]]] = Field(
        default=None, description="Kerberos/LSASS auth events (for Golden/Skeleton ticket)"
    )


class AttackPathRequest(BaseModel):
    org_id: str = Field("default", description="Organization identifier")
    start_identity: str = Field(..., min_length=1, description="Starting principal")
    target: str = Field("domain_admin", description="Target principal/role")
    graph: Optional[Dict[str, List[Dict[str, Any]]]] = Field(
        default=None, description="Optional adjacency map — uses canonical chain if omitted"
    )
    max_hops: int = Field(8, ge=1, le=20)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/least-privilege/{identity_id}",
    summary="CIEM least-privilege recommendation for a specific identity",
)
def least_privilege_for_identity(
    identity_id: str,
    body: LeastPrivilegeRequest,
) -> Dict[str, Any]:
    """Return current perms, unused perms over the window, and right-sized policy."""
    try:
        return _get_ciem().recommend_least_privilege(
            org_id=body.org_id,
            identity_id=identity_id,
            current_permissions=body.current_permissions,
            used_permissions=body.used_permissions,
            usage_log=body.usage_log,
            window_days=body.window_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("least_privilege_for_identity failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/ad-risks",
    summary="Evaluate all AD/Entra risk predicates against a set of AD objects",
)
def evaluate_ad_risks(
    body: ADRisksRequest,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Runs kerberoastable, DCSync, adminCount mismatch, unconstrained delegation."""
    try:
        return _get_identity_risk().evaluate_ad_risks(org_id, body.ad_objects)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("evaluate_ad_risks failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/ad-risks",
    summary="Empty default evaluation (stats-only)",
)
def list_ad_risks_stats(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return empty-evaluation shape — useful as a smoke endpoint."""
    try:
        return _get_identity_risk().evaluate_ad_risks(org_id, [])
    except Exception as exc:
        _logger.exception("list_ad_risks_stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/standing-privilege",
    summary="Detect standing privilege + produce JIT recommendations",
)
def standing_privilege(
    org_id: str = Query("default"),
    stale_days: int = Query(30, ge=1, le=365),
    lookback_days: int = Query(30, ge=1, le=365),
) -> Dict[str, Any]:
    """Combined output of detect_standing_privilege + just_in_time_recommendations."""
    try:
        pag = _get_pag()
        findings = pag.detect_standing_privilege(org_id, stale_days=stale_days)
        jit = pag.just_in_time_recommendations(org_id, lookback_days=lookback_days)
        return {
            "org_id": org_id,
            "standing_privilege_findings": findings,
            "jit": jit,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("standing_privilege failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/itdr/detect",
    summary="Run ITDR AD-specific detection rules (ESC1, ESC4, Golden/Skeleton ticket)",
)
def itdr_detect(body: ITDRDetectRequest) -> Dict[str, Any]:
    """Evaluate ADCS template + Kerberos/LSASS auth events for AD-specific attacks."""
    try:
        return _get_itdr().detect_ad_attacks(
            org_id=body.org_id,
            templates=body.templates,
            auth_events=body.auth_events,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("itdr_detect failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/attack-path",
    summary="Build AD attack path from start_identity to target",
)
def attack_path(body: AttackPathRequest) -> Dict[str, Any]:
    """Chains kerberoastable -> cracked -> admin_count -> domain_admin by default."""
    try:
        return _get_priv_esc().build_ad_attack_path(
            org_id=body.org_id,
            start_identity=body.start_identity,
            target=body.target,
            graph=body.graph,
            max_hops=body.max_hops,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("attack_path failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/stats",
    summary="Aggregated CIEM+AD stats across the 5 merged engines",
)
def stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Cross-engine summary. Never raises — missing DBs yield zero counters."""
    result: Dict[str, Any] = {"org_id": org_id, "sources": {}}
    # identity_risk
    try:
        result["sources"]["identity_risk"] = _get_identity_risk().get_identity_risk_stats(
            org_id
        )
    except Exception as exc:
        result["sources"]["identity_risk"] = {"error": str(exc)}
    # pag
    try:
        result["sources"]["pag"] = _get_pag().get_pag_stats(org_id)
    except Exception as exc:
        result["sources"]["pag"] = {"error": str(exc)}
    # itdr
    try:
        result["sources"]["itdr"] = _get_itdr().get_itdr_stats(org_id)
    except Exception as exc:
        result["sources"]["itdr"] = {"error": str(exc)}
    # privilege escalation
    try:
        result["sources"]["privilege_escalation"] = _get_priv_esc().get_detection_stats(
            org_id
        )
    except Exception as exc:
        result["sources"]["privilege_escalation"] = {"error": str(exc)}
    # CIEM risks (principal-scoped list)
    try:
        result["sources"]["ciem_risks_sample"] = _get_ciem().list_risks(limit=10)
    except Exception as exc:
        result["sources"]["ciem_risks_sample"] = {"error": str(exc)}
    return result
