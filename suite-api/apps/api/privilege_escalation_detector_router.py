"""Privilege Escalation Detector Router — exposes PrivilegeEscalationDetectorEngine.

Endpoints
---------
POST /api/v1/privilege-escalation-detector/events             Record privilege event.
GET  /api/v1/privilege-escalation-detector/events             List events.
GET  /api/v1/privilege-escalation-detector/events/{id}/analyze Analyse a single event.
POST /api/v1/privilege-escalation-detector/rules              Create detection rule.
GET  /api/v1/privilege-escalation-detector/rules              List detection rules.
GET  /api/v1/privilege-escalation-detector/heatmap            Escalation heatmap.
POST /api/v1/privilege-escalation-detector/ad-attack-path     Build AD attack path.
GET  /api/v1/privilege-escalation-detector/stats              Detection stats.
GET  /api/v1/privilege-escalation-detector/health             Liveness probe.
GET  /api/v1/privilege-escalation-detector/status             Status alias.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

try:
    from apps.api.auth_deps import api_key_auth
except Exception:  # pragma: no cover
    def api_key_auth() -> None:  # type: ignore
        return None

logger = structlog.get_logger(__name__)
_stdlib_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/privilege-escalation-detector",
    tags=["Privilege Escalation Detector"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    from core.privilege_escalation_detector_engine import (
        get_privilege_escalation_detector,
    )

    return get_privilege_escalation_detector()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class PrivilegeEventRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    user_id: str = Field(..., min_length=1, max_length=256)
    from_role: str = Field(..., min_length=1, max_length=128)
    to_role: str = Field(..., min_length=1, max_length=128)
    method: str = Field(default="other", max_length=64)
    source_ip: str = Field(default="", max_length=64)

    @field_validator("method")
    @classmethod
    def _check_method(cls, v: str) -> str:
        allowed = {"sudo", "setuid", "token", "exploit", "impersonation", "suid", "other"}
        if v.lower() not in allowed:
            raise ValueError(f"method must be one of {sorted(allowed)}, got {v!r}")
        return v.lower()


class DetectionRuleRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    name: str = Field(..., min_length=1, max_length=256)
    pattern: str = Field(..., min_length=1, max_length=2048)
    severity: str = Field(default="medium", max_length=32)
    action: str = Field(default="alert", max_length=32)


class ADAttackPathRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    start_identity: str = Field(..., min_length=1, max_length=256)
    target: str = Field(default="domain_admin", max_length=128)
    graph: Optional[Dict[str, List[Dict[str, Any]]]] = None
    max_hops: int = Field(default=8, ge=1, le=32)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/events")
def record_event(body: PrivilegeEventRequest) -> Dict[str, Any]:
    try:
        return _engine().record_privilege_event(
            org_id=body.org_id,
            data={
                "user_id": body.user_id,
                "from_role": body.from_role,
                "to_role": body.to_role,
                "method": body.method,
                "source_ip": body.source_ip,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("privilege_event.record_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"record_failure: {exc}")


@router.get("/events")
def list_events(
    org_id: str = Query(..., min_length=1, max_length=128),
    user_id: Optional[str] = Query(default=None, max_length=256),
    limit: int = Query(default=100, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    try:
        return _engine().list_privilege_events(org_id=org_id, user_id=user_id, limit=limit)
    except Exception as exc:  # pragma: no cover
        logger.exception("privilege_event.list_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"list_failure: {exc}")


@router.get("/events/{event_id}/analyze")
def analyze_event(
    event_id: str,
    org_id: str = Query(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    try:
        return _engine().detect_anomalous_escalation(org_id=org_id, event_id=event_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("privilege_event.analyze_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"analyze_failure: {exc}")


@router.post("/rules")
def create_rule(body: DetectionRuleRequest) -> Dict[str, Any]:
    try:
        return _engine().create_detection_rule(
            org_id=body.org_id,
            data={
                "name": body.name,
                "pattern": body.pattern,
                "severity": body.severity,
                "action": body.action,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("privilege_rule.create_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"rule_create_failure: {exc}")


@router.get("/rules")
def list_rules(
    org_id: str = Query(..., min_length=1, max_length=128),
) -> List[Dict[str, Any]]:
    try:
        return _engine().list_detection_rules(org_id=org_id)
    except Exception as exc:  # pragma: no cover
        logger.exception("privilege_rule.list_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"rule_list_failure: {exc}")


@router.get("/heatmap")
def get_heatmap(
    org_id: str = Query(..., min_length=1, max_length=128),
    hours: int = Query(default=24, ge=1, le=720),
) -> Dict[str, Any]:
    try:
        return _engine().get_escalation_heatmap(org_id=org_id, hours=hours)
    except Exception as exc:  # pragma: no cover
        logger.exception("privilege_heatmap.failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"heatmap_failure: {exc}")


@router.post("/ad-attack-path")
def build_attack_path(body: ADAttackPathRequest) -> Dict[str, Any]:
    try:
        return _engine().build_ad_attack_path(
            org_id=body.org_id,
            start_identity=body.start_identity,
            target=body.target,
            graph=body.graph,
            max_hops=body.max_hops,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("ad_attack_path.failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"ad_attack_path_failure: {exc}")


@router.get("/stats")
def stats(
    org_id: str = Query(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    try:
        return _engine().get_detection_stats(org_id=org_id)
    except Exception as exc:  # pragma: no cover
        logger.exception("privilege_stats.failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"stats_failure: {exc}")


@router.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "engine": "privilege_escalation_detector"}


@router.get("/status")
def status() -> Dict[str, Any]:
    return {"status": "ok", "engine": "privilege_escalation_detector", "ready": True}


__all__ = ["router"]
