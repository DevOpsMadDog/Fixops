"""Threat Hunting Playbook Router — ALDECI.

Structured threat hunting playbook management.

Prefix: /api/v1/hunting-playbooks
Auth: api_key_auth dependency

Routes:
  POST /api/v1/hunting-playbooks/playbooks                           create_playbook
  GET  /api/v1/hunting-playbooks/playbooks                           list_playbooks
  GET  /api/v1/hunting-playbooks/playbooks/{playbook_id}             get_playbook
  POST /api/v1/hunting-playbooks/playbooks/{playbook_id}/hypotheses  add_hypothesis
  POST /api/v1/hunting-playbooks/hypotheses/{hypothesis_id}/validate validate_hypothesis
  POST /api/v1/hunting-playbooks/playbooks/{playbook_id}/executions  start_execution
  POST /api/v1/hunting-playbooks/executions/{execution_id}/complete  complete_execution
  GET  /api/v1/hunting-playbooks/stats                               get_hunt_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/hunting-playbooks",
    tags=["Threat Hunting Playbooks"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_hunting_playbook_engine import ThreatHuntingPlaybookEngine
        _engine = ThreatHuntingPlaybookEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------


class CreatePlaybookBody(BaseModel):
    playbook_name: str = Field(..., description="Name of the hunting playbook")
    hunt_type: str = Field(
        ...,
        description="hypothesis | ioc | anomaly | behavioral | threat-actor | ttp | situational",
    )
    threat_category: str = Field(..., description="Threat category being hunted")
    mitre_technique: str = Field(default="", description="MITRE ATT&CK technique ID")
    hypothesis: str = Field(default="", description="Primary hunt hypothesis")
    data_sources: Optional[List[str]] = Field(default=None, description="Data sources required")
    tools: Optional[List[str]] = Field(default=None, description="Tools used in this hunt")


class AddHypothesisBody(BaseModel):
    hypothesis_text: str = Field(..., description="Hypothesis statement")
    confidence: str = Field(default="medium", description="high | medium | low")


class ValidateHypothesisBody(BaseModel):
    evidence: str = Field(..., description="Evidence supporting or refuting the hypothesis")


class StartExecutionBody(BaseModel):
    analyst: str = Field(default="", description="Analyst performing the hunt")


class CompleteExecutionBody(BaseModel):
    outcome: str = Field(
        ...,
        description="finding | no_finding | partial_finding | inconclusive",
    )
    findings_count: int = Field(default=0, description="Number of findings discovered")
    iocs_discovered: Optional[List[str]] = Field(
        default=None, description="IOCs discovered during hunt"
    )
    notes: str = Field(default="", description="Hunt notes and observations")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/", dependencies=[Depends(api_key_auth)])
def list_hunting_playbooks(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get threat hunting playbook statistics for the org."""
    return _get_engine().get_hunt_stats(org_id)


@router.post("/playbooks", dependencies=[Depends(api_key_auth)])
def create_playbook(
    body: CreatePlaybookBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Create a new threat hunting playbook."""
    try:
        return _get_engine().create_playbook(
            org_id=org_id,
            playbook_name=body.playbook_name,
            hunt_type=body.hunt_type,
            threat_category=body.threat_category,
            mitre_technique=body.mitre_technique,
            hypothesis=body.hypothesis,
            data_sources=body.data_sources,
            tools=body.tools,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/playbooks", dependencies=[Depends(api_key_auth)])
def list_playbooks(
    org_id: str = Query(default="default"),
    hunt_type: Optional[str] = Query(default=None),
    threat_category: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """List org-authored hunting playbooks. When the org has not authored any,
    the response is a real-source library projected from the imported SigmaHQ
    detection-rule catalog (POST /import-sigma to populate). No mock data
    is ever returned."""
    return _get_engine().list_playbooks_with_sigma_fallback(
        org_id, hunt_type=hunt_type, threat_category=threat_category
    )


@router.post("/import-sigma", dependencies=[Depends(api_key_auth)])
def import_sigma_playbooks(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Import detection rules from SigmaHQ master branch into sigmahq_rules.db.

    Downloads https://github.com/SigmaHQ/sigma/archive/refs/heads/master.tar.gz,
    parses all YAML rules under rules/ (skipping deprecated/unsupported/tests),
    and upserts them by UUID.  Returns a summary with rule count by level and platform.
    """
    try:
        from feeds.sigmahq.importer import run_import
        result = run_import()
        return {"org_id": org_id, **result}
    except Exception as exc:
        _logger.exception("SigmaHQ import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/playbooks/{playbook_id}", dependencies=[Depends(api_key_auth)])
def get_playbook(
    playbook_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Fetch a single playbook with executions and hypotheses."""
    result = _get_engine().get_playbook(playbook_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return result


@router.post("/playbooks/{playbook_id}/hypotheses", dependencies=[Depends(api_key_auth)])
def add_hypothesis(
    playbook_id: str,
    body: AddHypothesisBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Add a hypothesis to a playbook."""
    try:
        return _get_engine().add_hypothesis(
            playbook_id=playbook_id,
            org_id=org_id,
            hypothesis_text=body.hypothesis_text,
            confidence=body.confidence,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/hypotheses/{hypothesis_id}/validate", dependencies=[Depends(api_key_auth)])
def validate_hypothesis(
    hypothesis_id: str,
    body: ValidateHypothesisBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Validate a hypothesis with evidence."""
    try:
        return _get_engine().validate_hypothesis(hypothesis_id, org_id, body.evidence)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/playbooks/{playbook_id}/executions", dependencies=[Depends(api_key_auth)])
def start_execution(
    playbook_id: str,
    body: StartExecutionBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Start a hunt execution for a playbook."""
    try:
        return _get_engine().start_execution(
            playbook_id=playbook_id,
            org_id=org_id,
            analyst=body.analyst,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/executions/{execution_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_execution(
    execution_id: str,
    body: CompleteExecutionBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Complete a hunt execution and update playbook stats."""
    try:
        return _get_engine().complete_execution(
            execution_id=execution_id,
            org_id=org_id,
            outcome=body.outcome,
            findings_count=body.findings_count,
            iocs_discovered=body.iocs_discovered,
            notes=body.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_hunt_stats(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return aggregate hunt statistics for the org."""
    return _get_engine().get_hunt_stats(org_id)
