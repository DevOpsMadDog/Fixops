"""MITRE ATT&CK Coverage Router — exposes MITREAttackCoverageEngine.

Endpoints
---------
POST /api/v1/mitre-attack-coverage/seed                 Seed 14 tactics + canonical techniques.
POST /api/v1/mitre-attack-coverage/techniques           Register a custom technique.
GET  /api/v1/mitre-attack-coverage/techniques           List techniques.
POST /api/v1/mitre-attack-coverage/detections           Log a detection event.
GET  /api/v1/mitre-attack-coverage/detections           List detections.
GET  /api/v1/mitre-attack-coverage/coverage             Per-tactic coverage breakdown.
GET  /api/v1/mitre-attack-coverage/gaps                 Undetected critical techniques.
GET  /api/v1/mitre-attack-coverage/heatmap              ATT&CK Navigator heatmap.
GET  /api/v1/mitre-attack-coverage/health               Liveness probe.
GET  /api/v1/mitre-attack-coverage/status               Status alias.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth
except Exception:  # pragma: no cover
    def api_key_auth() -> None:  # type: ignore
        return None

logger = structlog.get_logger(__name__)
_stdlib_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/mitre-attack-coverage",
    tags=["MITRE ATT&CK Coverage"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    from core.mitre_attack_coverage_engine import get_mitre_coverage_engine

    return get_mitre_coverage_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class SeedRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)


class TechniqueRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    technique_id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=256)
    tactic_id: str = Field(..., min_length=1, max_length=64)
    description: str = Field(default="", max_length=2048)
    severity: str = Field(default="medium", max_length=32)


class DetectionRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    technique_id: str = Field(..., min_length=1, max_length=64)
    source: str = Field(..., min_length=1, max_length=128)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    metadata: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/seed")
def seed(body: SeedRequest) -> Dict[str, Any]:
    try:
        count = _engine().seed_att_ck_techniques(org_id=body.org_id)
        return {"org_id": body.org_id, "seeded_techniques": count}
    except Exception as exc:  # pragma: no cover
        logger.exception("mitre.seed_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"seed_failure: {exc}")


@router.post("/techniques")
def add_technique(body: TechniqueRequest) -> Dict[str, Any]:
    try:
        return _engine().add_technique(
            org_id=body.org_id,
            data={
                "technique_id": body.technique_id,
                "name": body.name,
                "tactic_id": body.tactic_id,
                "description": body.description,
                "severity": body.severity,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("mitre.add_technique_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"add_technique_failure: {exc}")


@router.get("/techniques")
def list_techniques(
    org_id: str = Query(..., min_length=1, max_length=128),
) -> List[Dict[str, Any]]:
    try:
        return _engine().get_techniques(org_id=org_id)
    except Exception as exc:  # pragma: no cover
        logger.exception("mitre.list_techniques_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"list_techniques_failure: {exc}")


@router.post("/detections")
def log_detection(body: DetectionRequest) -> Dict[str, Any]:
    try:
        return _engine().log_detection(
            org_id=body.org_id,
            technique_id=body.technique_id,
            source=body.source,
            confidence=body.confidence,
            metadata=body.metadata,
        )
    except Exception as exc:  # pragma: no cover
        logger.exception("mitre.log_detection_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"log_detection_failure: {exc}")


@router.get("/detections")
def list_detections(
    org_id: str = Query(..., min_length=1, max_length=128),
    technique_id: Optional[str] = Query(default=None, max_length=64),
    limit: int = Query(default=100, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    try:
        return _engine().get_detections(org_id=org_id, technique_id=technique_id, limit=limit)
    except Exception as exc:  # pragma: no cover
        logger.exception("mitre.list_detections_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"list_detections_failure: {exc}")


@router.get("/coverage")
def coverage(
    org_id: str = Query(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    try:
        return _engine().get_coverage(org_id=org_id)
    except Exception as exc:  # pragma: no cover
        logger.exception("mitre.coverage_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"coverage_failure: {exc}")


@router.get("/gaps")
def gaps(
    org_id: str = Query(..., min_length=1, max_length=128),
) -> List[Dict[str, Any]]:
    try:
        return _engine().get_gaps(org_id=org_id)
    except Exception as exc:  # pragma: no cover
        logger.exception("mitre.gaps_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"gaps_failure: {exc}")


@router.get("/heatmap")
def heatmap(
    org_id: str = Query(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    try:
        return _engine().get_heatmap(org_id=org_id)
    except Exception as exc:  # pragma: no cover
        logger.exception("mitre.heatmap_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"heatmap_failure: {exc}")


@router.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "engine": "mitre_attack_coverage"}


@router.get("/status")
def status() -> Dict[str, Any]:
    return {"status": "ok", "engine": "mitre_attack_coverage", "ready": True}


__all__ = ["router"]
