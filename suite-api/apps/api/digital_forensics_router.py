"""Digital Forensics API Router — ALDECI."""
from __future__ import annotations

from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/digital-forensics", tags=["digital-forensics"])

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.digital_forensics_engine import DigitalForensicsEngine
        _engine = DigitalForensicsEngine()
    return _engine


class CaseCreate(BaseModel):
    title: str
    case_type: str = "malware"
    priority: str = "medium"
    assigned_analyst: str = ""
    related_incident_id: str = ""


class EvidenceCreate(BaseModel):
    evidence_type: str = "log_file"
    filename: str = ""
    size_bytes: int = 0
    hash_md5: str = ""
    hash_sha256: str = ""
    storage_location: str = ""
    notes: str = ""


class AnalysisCreate(BaseModel):
    analysis_type: str = "static"
    analyst: str = ""
    findings: str = ""
    iocs_found: list = []
    malware_families: list = []
    risk_score: float = 0.0
    recommendations: str = ""


class CustodyCreate(BaseModel):
    action: str
    actor: str
    notes: str = ""


@router.get("/cases")
async def list_cases(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
    auth=Depends(api_key_auth),
):
    try:
        return _get_engine().list_cases(org_id=org_id, status=status)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/cases")
async def create_case(body: CaseCreate, org_id: str = Query(default="default"), auth=Depends(api_key_auth)):
    try:
        return _get_engine().create_case(org_id=org_id, data=body.model_dump())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/cases/{case_id}")
async def get_case(case_id: str, org_id: str = Query(default="default"), auth=Depends(api_key_auth)):
    result = _get_engine().get_case(org_id=org_id, case_id=case_id)
    if not result:
        raise HTTPException(status_code=404, detail="Case not found")
    return result


@router.post("/cases/{case_id}/close")
async def close_case(case_id: str, org_id: str = Query(default="default"), auth=Depends(api_key_auth)):
    ok = _get_engine().close_case(org_id=org_id, case_id=case_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"status": "closed", "case_id": case_id}


@router.get("/cases/{case_id}/evidence")
async def list_evidence(case_id: str, org_id: str = Query(default="default"), auth=Depends(api_key_auth)):
    return _get_engine().list_evidence(org_id=org_id, case_id=case_id)


@router.post("/cases/{case_id}/evidence")
async def add_evidence(
    case_id: str,
    body: EvidenceCreate,
    org_id: str = Query(default="default"),
    auth=Depends(api_key_auth),
):
    try:
        return _get_engine().add_evidence(org_id=org_id, case_id=case_id, data=body.model_dump())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/cases/{case_id}/analysis")
async def list_analysis(case_id: str, org_id: str = Query(default="default"), auth=Depends(api_key_auth)):
    return _get_engine().list_analysis_results(org_id=org_id, case_id=case_id)


@router.post("/cases/{case_id}/analysis")
async def add_analysis(
    case_id: str,
    body: AnalysisCreate,
    org_id: str = Query(default="default"),
    auth=Depends(api_key_auth),
):
    try:
        return _get_engine().add_analysis_result(org_id=org_id, case_id=case_id, data=body.model_dump())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/evidence/{evidence_id}/custody")
async def get_custody(evidence_id: str, org_id: str = Query(default="default"), auth=Depends(api_key_auth)):
    return _get_engine().get_chain_of_custody(org_id=org_id, evidence_id=evidence_id)


@router.post("/evidence/{evidence_id}/custody")
async def log_custody(
    evidence_id: str,
    body: CustodyCreate,
    org_id: str = Query(default="default"),
    auth=Depends(api_key_auth),
):
    try:
        return _get_engine().log_chain_of_custody(
            org_id=org_id,
            evidence_id=evidence_id,
            action=body.action,
            actor=body.actor,
            notes=body.notes,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/stats")
async def get_stats(org_id: str = Query(default="default"), auth=Depends(api_key_auth)):
    return _get_engine().get_forensics_stats(org_id=org_id)
