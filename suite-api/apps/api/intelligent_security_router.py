"""Intelligent Security Engine Router — exposes IntelligentSecurityEngine.

Endpoints
---------
POST /api/v1/intelligent-security/session/init        Initialise a new ISE session.
POST /api/v1/intelligent-security/intelligence        Gather threat intelligence.
POST /api/v1/intelligent-security/assessment         Run unified assessment.
POST /api/v1/intelligent-security/nl-graph           Natural-language graph question.
GET  /api/v1/intelligent-security/health             Liveness probe.
GET  /api/v1/intelligent-security/status             Engine status + intelligence level.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

try:
    from apps.api.auth_deps import api_key_auth
except Exception:  # pragma: no cover
    def api_key_auth() -> None:  # type: ignore
        return None

logger = structlog.get_logger(__name__)
_stdlib_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/intelligent-security",
    tags=["Intelligent Security Engine"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    from core.intelligent_security_engine import get_engine

    return get_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class SessionInitRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)


class IntelligenceRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    target: str = Field(..., min_length=1, max_length=512)
    cve_ids: List[str] = Field(..., min_length=1, max_length=64)
    include_osint: bool = True

    @field_validator("cve_ids")
    @classmethod
    def _check_cves(cls, v: List[str]) -> List[str]:
        for c in v:
            if not c or len(c) > 32:
                raise ValueError(f"invalid CVE id: {c!r}")
        return v


class AssessmentRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    target: str = Field(..., min_length=1, max_length=512)
    cve_ids: List[str] = Field(..., min_length=1, max_length=64)
    scan_type: str = Field(default="comprehensive", max_length=32)
    compliance_frameworks: Optional[List[str]] = Field(default=None, max_length=16)

    @field_validator("scan_type")
    @classmethod
    def _check_scan_type(cls, v: str) -> str:
        allowed = {"passive", "comprehensive", "aggressive"}
        if v not in allowed:
            raise ValueError(f"scan_type must be one of {sorted(allowed)}")
        return v


class NLGraphRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    question: str = Field(..., min_length=1, max_length=2048)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/session/init")
async def init_session(body: SessionInitRequest) -> Dict[str, Any]:
    try:
        session_id = await _engine().initialize_session()
        return {"org_id": body.org_id, "session_id": session_id}
    except Exception as exc:  # pragma: no cover
        logger.exception("ise.session_init_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"session_init_failure: {exc}")


@router.post("/intelligence")
async def gather_intelligence(body: IntelligenceRequest) -> Dict[str, Any]:
    try:
        intel = await _engine().gather_intelligence(
            target=body.target,
            cve_ids=body.cve_ids,
            include_osint=body.include_osint,
        )
        return {
            "org_id": body.org_id,
            "target": body.target,
            "cve_ids": intel.cve_ids,
            "epss_scores": intel.epss_scores,
            "kev_status": intel.kev_status,
            "mitre_techniques": intel.mitre_techniques,
            "threat_actors": intel.threat_actors,
            "exploit_availability": intel.exploit_availability,
            "iocs": intel.iocs,
            "risk_score": intel.risk_score,
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("ise.intelligence_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"intelligence_failure: {exc}")


@router.post("/assessment")
async def run_assessment(body: AssessmentRequest) -> Dict[str, Any]:
    try:
        return await _engine().run_unified_assessment(
            target=body.target,
            cve_ids=body.cve_ids,
            scan_type=body.scan_type,
            compliance_frameworks=body.compliance_frameworks,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("ise.assessment_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"assessment_failure: {exc}")


@router.post("/nl-graph")
def nl_graph(body: NLGraphRequest) -> Dict[str, Any]:
    try:
        return _engine().nl_graph_assistant(org_id=body.org_id, question=body.question)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("ise.nl_graph_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"nl_graph_failure: {exc}")


@router.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "engine": "intelligent_security"}


@router.get("/status")
def status() -> Dict[str, Any]:
    try:
        engine = _engine()
        return {
            "status": "ok",
            "engine": "intelligent_security",
            "ready": True,
            "intelligence_level": engine.config.intelligence_level.value,
            "state": engine.state.value,
            "mindsdb_enabled": engine.config.mindsdb_enabled,
            "consensus_threshold": engine.config.consensus_threshold,
        }
    except Exception as exc:  # pragma: no cover
        return {"status": "degraded", "engine": "intelligent_security", "error": str(exc)}


__all__ = ["router"]
