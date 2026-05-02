"""
Security Awareness Score Tracker Router — ALDECI.

Prefix: /api/v1/awareness-score
Auth:   X-API-Key header (injected via Depends(_verify_api_key) in app.py)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.awareness_score_engine import get_engine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/awareness-score", tags=["awareness-score"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterEmployeeRequest(BaseModel):
    employee_id: str
    name: str = ""
    department: str = ""
    role: str = ""
    risk_level: str = "standard"
    last_training_at: Optional[str] = None
    phishing_click_rate: float = 0.0
    training_completion_pct: float = 0.0


class RecordTrainingRequest(BaseModel):
    training_name: str
    training_type: str = "security_basics"
    completed_at: Optional[str] = None
    score: float = 0.0
    passed: Optional[int] = None
    expires_at: Optional[str] = None


class RecordPhishingRequest(BaseModel):
    campaign_name: str = ""
    sent_at: Optional[str] = None
    clicked: int = 0
    reported: int = 0
    clicked_at: Optional[str] = None
    reported_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Employees
# ---------------------------------------------------------------------------

@router.post("/orgs/{org_id}/employees", summary="Register or upsert an employee profile")
def register_employee(org_id: str, req: RegisterEmployeeRequest) -> Dict[str, Any]:
    try:
        return get_engine().register_employee(org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("register_employee failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/orgs/{org_id}/employees", summary="List employee profiles")
def list_employees(
    org_id: str,
    department: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return get_engine().list_employees(org_id, department=department, risk_level=risk_level)
    except Exception as exc:
        _logger.exception("list_employees failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

@router.post("/orgs/{org_id}/employees/{employee_id}/training", summary="Record a training completion")
def record_training(org_id: str, employee_id: str, req: RecordTrainingRequest) -> Dict[str, Any]:
    try:
        return get_engine().record_training(org_id, employee_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("record_training failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Phishing Tests
# ---------------------------------------------------------------------------

@router.post("/orgs/{org_id}/employees/{employee_id}/phishing", summary="Record a phishing test result")
def record_phishing_test(org_id: str, employee_id: str, req: RecordPhishingRequest) -> Dict[str, Any]:
    try:
        return get_engine().record_phishing_test(org_id, employee_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("record_phishing_test failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Scores
# ---------------------------------------------------------------------------

@router.post("/orgs/{org_id}/employees/{employee_id}/calculate-score", summary="Calculate awareness score")
def calculate_score(org_id: str, employee_id: str) -> Dict[str, Any]:
    try:
        return get_engine().calculate_score(org_id, employee_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("calculate_score failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/orgs/{org_id}/scores", summary="List latest awareness scores")
def list_scores(
    org_id: str,
    risk_tier: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return get_engine().list_scores(org_id, risk_tier=risk_tier)
    except Exception as exc:
        _logger.exception("list_scores failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------

@router.get("/orgs/{org_id}/department-summary", summary="Get awareness stats by department")
def get_department_summary(org_id: str) -> Dict[str, Any]:
    try:
        return get_engine().get_department_summary(org_id)
    except Exception as exc:
        _logger.exception("get_department_summary failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/orgs/{org_id}/stats", summary="Get org-level awareness statistics")
def get_awareness_stats(org_id: str) -> Dict[str, Any]:
    try:
        return get_engine().get_awareness_stats(org_id)
    except Exception as exc:
        _logger.exception("get_awareness_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
