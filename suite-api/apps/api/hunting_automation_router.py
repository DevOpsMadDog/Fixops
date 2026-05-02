"""Hunting Automation Router — ALDECI.

Automated threat hunting: hypotheses, queries, scheduled executions.

Prefix: /api/v1/hunting-automation
Auth: api_key_auth dependency on ALL endpoints

Routes:
  POST   /api/v1/hunting-automation/hypotheses                  create_hypothesis
  PUT    /api/v1/hunting-automation/hypotheses/{id}/validate     validate_hypothesis
  POST   /api/v1/hunting-automation/hypotheses/{id}/queries      add_query
  POST   /api/v1/hunting-automation/queries/{id}/execute         execute_query
  POST   /api/v1/hunting-automation/queries/{id}/fail            fail_execution
  GET    /api/v1/hunting-automation/summary                      get_hunt_summary
  GET    /api/v1/hunting-automation/hypotheses/{id}              get_hypothesis_detail
  GET    /api/v1/hunting-automation/executions                   get_recent_executions
  GET    /api/v1/hunting-automation/high-yield                   get_high_yield_queries
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/hunting-automation",
    tags=["Hunting Automation"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.hunting_automation_engine import HuntingAutomationEngine
        _engine = HuntingAutomationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------


class CreateHypothesisBody(BaseModel):
    hypothesis: str = Field(..., description="Hypothesis statement")
    threat_category: str = Field(
        default="lateral_movement",
        description="lateral_movement | privilege_escalation | exfiltration | persistence | "
                    "defense_evasion | discovery | collection | impact",
    )
    mitre_technique: str = Field(default="", description="MITRE ATT&CK technique ID e.g. T1078")
    confidence: str = Field(default="medium", description="low | medium | high")
    data_sources: List[str] = Field(default_factory=list, description="List of data sources")
    created_by: str = Field(default="", description="Creator user ID")


class ValidateHypothesisBody(BaseModel):
    validated: bool = Field(..., description="Whether hypothesis is validated")
    validation_result: str = Field(default="", description="Validation outcome notes")


class AddQueryBody(BaseModel):
    query_name: str = Field(..., description="Human-readable query name")
    query_language: str = Field(
        default="KQL",
        description="KQL | SPL | SQL | EQL | YARA | sigma | lucene",
    )
    query_content: str = Field(default="", description="Query body/content")
    data_source: str = Field(
        default="siem",
        description="siem | edr | network | cloud | identity | application",
    )


class ExecuteQueryBody(BaseModel):
    records_scanned: int = Field(default=0, description="Number of records scanned")
    findings: int = Field(default=0, description="Number of findings returned")
    execution_secs: float = Field(default=0.0, description="Execution time in seconds")
    notes: str = Field(default="", description="Optional execution notes")


class FailExecutionBody(BaseModel):
    notes: str = Field(..., description="Failure reason/notes")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/hypotheses", dependencies=[Depends(api_key_auth)])
def create_hypothesis(
    body: CreateHypothesisBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Create a new hunt hypothesis."""
    try:
        return _get_engine().create_hypothesis(
            org_id=org_id,
            hypothesis=body.hypothesis,
            threat_category=body.threat_category,
            mitre_technique=body.mitre_technique,
            confidence=body.confidence,
            data_sources=body.data_sources,
            created_by=body.created_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/hypotheses/{hypothesis_id}/validate", dependencies=[Depends(api_key_auth)])
def validate_hypothesis(
    hypothesis_id: str,
    body: ValidateHypothesisBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Update validation status of a hypothesis."""
    try:
        return _get_engine().validate_hypothesis(
            hypothesis_id=hypothesis_id,
            org_id=org_id,
            validated=body.validated,
            validation_result=body.validation_result,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/hypotheses/{hypothesis_id}/queries", dependencies=[Depends(api_key_auth)])
def add_query(
    hypothesis_id: str,
    body: AddQueryBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Add a hunt query to a hypothesis."""
    try:
        return _get_engine().add_query(
            hypothesis_id=hypothesis_id,
            org_id=org_id,
            query_name=body.query_name,
            query_language=body.query_language,
            query_content=body.query_content,
            data_source=body.data_source,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/queries/{query_id}/execute", dependencies=[Depends(api_key_auth)])
def execute_query(
    query_id: str,
    body: ExecuteQueryBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Record a successful query execution."""
    try:
        return _get_engine().execute_query(
            query_id=query_id,
            org_id=org_id,
            records_scanned=body.records_scanned,
            findings=body.findings,
            execution_secs=body.execution_secs,
            notes=body.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/queries/{query_id}/fail", dependencies=[Depends(api_key_auth)])
def fail_execution(
    query_id: str,
    body: FailExecutionBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Record a failed query execution (does not update query stats)."""
    return _get_engine().fail_execution(
        query_id=query_id,
        org_id=org_id,
        notes=body.notes,
    )


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_hunt_summary(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return aggregate hunting summary for the org."""
    return _get_engine().get_hunt_summary(org_id)


@router.get("/hypotheses/{hypothesis_id}", dependencies=[Depends(api_key_auth)])
def get_hypothesis_detail(
    hypothesis_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return a hypothesis with its queries and last 5 executions per query."""
    result = _get_engine().get_hypothesis_detail(hypothesis_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    return result


@router.get("/executions", dependencies=[Depends(api_key_auth)])
def get_recent_executions(
    org_id: str = Query(default="default"),
    limit: int = Query(default=20, ge=1, le=100),
) -> List[Dict[str, Any]]:
    """Return recent hunt executions with query metadata."""
    return _get_engine().get_recent_executions(org_id, limit=limit)


@router.get("/high-yield", dependencies=[Depends(api_key_auth)])
def get_high_yield_queries(
    org_id: str = Query(default="default"),
    min_findings: int = Query(default=1, ge=0),
) -> List[Dict[str, Any]]:
    """Return queries with findings_count >= min_findings, ordered by findings DESC."""
    return _get_engine().get_high_yield_queries(org_id, min_findings=min_findings)
