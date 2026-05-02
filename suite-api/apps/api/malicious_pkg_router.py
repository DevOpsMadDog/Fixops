"""Malicious Package Router — ALDECI GAP-009.

Unified router for:
  - Behavioral risk scoring of package purls
  - Quarantine queue (active/released lifecycle)
  - Malicious signal ingestion (into supply_chain_intel)

Prefix: /api/v1/malicious-pkg
Auth:   api_key_auth dependency on all endpoints.

Routes:
  POST /score        — score_package_behavior(purl, signals)
  POST /quarantine   — quarantine_package(purl, reason, quarantined_by)
  POST /release      — release_quarantine(purl, released_by, reason)
  GET  /quarantine   — list_quarantine(org_id, active_only)
  POST /signal       — ingest_malicious_signal(purl, signal_type, value, evidence_uri)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/malicious-pkg",
    tags=["Malicious Package Management"],
    dependencies=[Depends(api_key_auth)],
)

_scad_engine = None
_intel_engine = None


def _get_scad_engine():
    global _scad_engine
    if _scad_engine is None:
        from core.supply_chain_attack_detection_engine import (
            SupplyChainAttackDetectionEngine,
        )
        _scad_engine = SupplyChainAttackDetectionEngine()
    return _scad_engine


def _get_intel_engine():
    global _intel_engine
    if _intel_engine is None:
        from core.supply_chain_intel_engine import SupplyChainIntelEngine
        _intel_engine = SupplyChainIntelEngine()
    return _intel_engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ScoreReq(BaseModel):
    org_id: str = "default"
    package_purl: str = Field(..., min_length=1)
    signals: Dict[str, Any] = Field(default_factory=dict)


class QuarantineReq(BaseModel):
    org_id: str = "default"
    package_purl: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1)
    quarantined_by: str = Field(..., min_length=1)


class ReleaseReq(BaseModel):
    org_id: str = "default"
    package_purl: str = Field(..., min_length=1)
    released_by: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1)


class SignalReq(BaseModel):
    org_id: str = "default"
    package_purl: str = Field(..., min_length=1)
    signal_type: str = Field(..., min_length=1)
    value: Any = ""
    evidence_uri: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/score", status_code=200)
def score_package(body: ScoreReq) -> Dict[str, Any]:
    try:
        return _get_scad_engine().score_package_behavior(
            body.org_id, body.package_purl, body.signals
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # pragma: no cover - defensive
        _logger.error("malicious_pkg.score error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/quarantine", status_code=201)
def quarantine(body: QuarantineReq) -> Dict[str, Any]:
    try:
        return _get_scad_engine().quarantine_package(
            body.org_id, body.package_purl, body.reason, body.quarantined_by
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        _logger.error("malicious_pkg.quarantine error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/release", status_code=200)
def release(body: ReleaseReq) -> Dict[str, Any]:
    try:
        return _get_scad_engine().release_quarantine(
            body.org_id, body.package_purl, body.released_by, body.reason
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        _logger.error("malicious_pkg.release error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/quarantine")
def list_quarantine(
    org_id: str = Query(default="default"),
    active_only: bool = Query(default=True),
) -> List[Dict[str, Any]]:
    try:
        return _get_scad_engine().list_quarantine(org_id, active_only=active_only)
    except Exception as exc:  # pragma: no cover
        _logger.error("malicious_pkg.list_quarantine error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/signal", status_code=201)
def ingest_signal(body: SignalReq) -> Dict[str, Any]:
    try:
        return _get_intel_engine().ingest_malicious_signal(
            body.org_id,
            body.package_purl,
            body.signal_type,
            value=body.value,
            evidence_uri=body.evidence_uri,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        _logger.error("malicious_pkg.signal error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
