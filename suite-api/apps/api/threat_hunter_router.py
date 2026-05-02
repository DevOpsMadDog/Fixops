"""
Threat Hunting Router — ALDECI.

8 endpoints for the threat hunting engine:
  GET  /api/v1/hunt/hypotheses        list_hypotheses
  POST /api/v1/hunt/start             start_hunt
  GET  /api/v1/hunt/active            active_hunts
  GET  /api/v1/hunt/iocs              list_iocs
  POST /api/v1/hunt/iocs/import       bulk_import_iocs (STIX 2.1)
  GET  /api/v1/hunt/sigma-rules       list_sigma_rules
  GET  /api/v1/hunt/actors            list_actors
  GET  /api/v1/hunt/kill-chain        kill_chain_coverage
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "threat_hunter_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.threat_hunter import (
    IOC,
    HuntFinding,
    HuntHypothesis,
    HuntSeverity,
    HuntStatus,
    HuntTriggerType,
    HuntWorkflow,
    IOCType,
    KillChainCoverage,
    KillChainPhase,
    MitreTactic,
    SigmaRule,
    ThreatActorMotivation,
    ThreatActorProfile,
    ThreatHunter,
    export_iocs_to_stix,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/hunt",
    tags=["Threat Hunting"],
    dependencies=_AUTH_DEP,
)

# Shared engine instance (file-backed, shared across requests)
_hunter: Optional[ThreatHunter] = None


def _get_hunter() -> ThreatHunter:
    global _hunter
    if _hunter is None:
        _hunter = ThreatHunter()
    return _hunter


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class StartHuntRequest(BaseModel):
    """Body for starting a new hunt workflow."""

    hypothesis_id: str = Field(..., description="ID of the hypothesis to hunt against")
    org_id: str = Field("default", description="Organisation ID")
    analyst: str = Field("system", description="Analyst name or user ID")
    trigger_type: HuntTriggerType = Field(
        HuntTriggerType.MANUAL, description="What initiated this hunt"
    )
    trigger_context: Dict[str, Any] = Field(
        default_factory=dict, description="Additional context about the trigger"
    )


class StartHuntResponse(BaseModel):
    hunt_id: str
    hypothesis_name: str
    status: HuntStatus
    message: str = "Hunt started"


class ImportIOCsRequest(BaseModel):
    """Body for bulk IOC import. Accepts either a STIX 2.1 bundle or a plain list."""

    stix_bundle: Optional[Dict[str, Any]] = Field(
        None, description="STIX 2.1 bundle with indicator objects"
    )
    iocs: Optional[List[IOC]] = Field(
        None, description="Plain list of IOC objects for direct import"
    )


class ImportIOCsResponse(BaseModel):
    imported: int
    message: str = "IOCs imported"


class ImportSigmaRequest(BaseModel):
    """Body for importing a Sigma rule from YAML."""

    yaml_content: str = Field(..., description="Raw Sigma rule YAML")


class AddFindingRequest(BaseModel):
    """Body for adding a finding to an active hunt."""

    hunt_id: str
    title: str
    description: str = ""
    severity: HuntSeverity = HuntSeverity.MEDIUM
    mitre_technique_id: str = ""
    evidence: List[str] = Field(default_factory=list)
    ioc_matches: List[str] = Field(default_factory=list)
    kill_chain_phase: Optional[KillChainPhase] = None


class FireTriggerRequest(BaseModel):
    """Body for firing an automated hunt trigger."""

    trigger_type: HuntTriggerType
    context: Dict[str, Any] = Field(default_factory=dict)
    org_id: str = "default"


class ExportIOCsResponse(BaseModel):
    bundle: Dict[str, Any]
    count: int


class HypothesesListResponse(BaseModel):
    hypotheses: List[HuntHypothesis]
    total: int


class IOCListResponse(BaseModel):
    iocs: List[IOC]
    total: int


class SigmaRulesResponse(BaseModel):
    rules: List[SigmaRule]
    total: int


class ActorsResponse(BaseModel):
    actors: List[ThreatActorProfile]
    total: int


class ActiveHuntsResponse(BaseModel):
    hunts: List[HuntWorkflow]
    total: int


class KillChainResponse(BaseModel):
    coverage: List[KillChainCoverage]
    covered_phases: int
    total_phases: int
    coverage_pct: float


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.get(
    "/hypotheses",
    response_model=HypothesesListResponse,
    summary="List hunt hypotheses",
)
def list_hypotheses(
    tactic: Optional[MitreTactic] = Query(None, description="Filter by MITRE tactic"),
    severity: Optional[HuntSeverity] = Query(None, description="Filter by severity"),
    kill_chain_phase: Optional[KillChainPhase] = Query(None, description="Filter by kill chain phase"),
) -> HypothesesListResponse:
    """
    List all hunt hypotheses from the library.

    Returns 30+ built-in MITRE ATT&CK-based hypotheses plus any custom ones.
    Supports filtering by tactic, severity, and kill chain phase.
    """
    hunter = _get_hunter()
    try:
        hypotheses = hunter.list_hypotheses(
            tactic=tactic,
            severity=severity,
            kill_chain_phase=kill_chain_phase,
        )
        return HypothesesListResponse(hypotheses=hypotheses, total=len(hypotheses))
    except Exception as exc:
        logger.exception("Failed to list hypotheses")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/start",
    response_model=StartHuntResponse,
    summary="Start a new hunt",
    status_code=201,
)
def start_hunt(body: StartHuntRequest) -> StartHuntResponse:
    """
    Start a structured threat hunt workflow for the specified hypothesis.

    Creates a new hunt in ACTIVE status, recording trigger type and context.
    Returns the hunt ID for subsequent status queries.
    """
    hunter = _get_hunter()
    try:
        workflow = hunter.start_hunt(
            hypothesis_id=body.hypothesis_id,
            org_id=body.org_id,
            analyst=body.analyst,
            trigger_type=body.trigger_type,
            trigger_context=body.trigger_context,
        )
        return StartHuntResponse(
            hunt_id=workflow.id,
            hypothesis_name=workflow.hypothesis_name,
            status=workflow.status,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to start hunt for hypothesis %s", body.hypothesis_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/active",
    response_model=ActiveHuntsResponse,
    summary="List active hunts with status",
)
def active_hunts(
    org_id: Optional[str] = Query(None, description="Filter by organisation ID"),
) -> ActiveHuntsResponse:
    """
    List all active, pending, and in-analysis hunt workflows.

    Returns current status, trigger type, findings count, and duration info.
    """
    hunter = _get_hunter()
    try:
        hunts = hunter.list_active_hunts(org_id=org_id)
        return ActiveHuntsResponse(hunts=hunts, total=len(hunts))
    except Exception as exc:
        logger.exception("Failed to list active hunts")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/iocs",
    response_model=IOCListResponse,
    summary="IOC database",
)
def list_iocs(
    ioc_type: Optional[IOCType] = Query(None, description="Filter by IOC type"),
    active_only: bool = Query(True, description="Return only active IOCs"),
    limit: int = Query(500, ge=1, le=5000, description="Maximum results"),
) -> IOCListResponse:
    """
    List Indicators of Compromise from the database.

    Supports filtering by type (ip, domain, md5, sha256, url, email, registry_key).
    Returns active IOCs by default.
    """
    hunter = _get_hunter()
    try:
        iocs = hunter.list_iocs(ioc_type=ioc_type, active_only=active_only, limit=limit)
        return IOCListResponse(iocs=iocs, total=len(iocs))
    except Exception as exc:
        logger.exception("Failed to list IOCs")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/iocs/import",
    response_model=ImportIOCsResponse,
    summary="Bulk import IOCs (STIX 2.1)",
    status_code=201,
)
def import_iocs(body: ImportIOCsRequest) -> ImportIOCsResponse:
    """
    Bulk import IOCs from a STIX 2.1 bundle or a plain IOC list.

    For STIX bundles: parses indicator objects with pattern fields.
    For plain lists: direct IOC model import.
    """
    hunter = _get_hunter()
    try:
        if body.stix_bundle is not None:
            count = hunter.import_stix_bundle(body.stix_bundle)
        elif body.iocs is not None:
            count = hunter.bulk_import_iocs(body.iocs)
        else:
            raise HTTPException(
                status_code=422,
                detail="Provide either stix_bundle or iocs in request body",
            )
        return ImportIOCsResponse(imported=count)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to import IOCs")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/iocs/export",
    response_model=ExportIOCsResponse,
    summary="Export IOCs as STIX 2.1 bundle",
)
def export_iocs(
    ioc_type: Optional[IOCType] = Query(None, description="Filter by IOC type for export"),
) -> ExportIOCsResponse:
    """Export active IOCs as a STIX 2.1 bundle for sharing with other platforms."""
    hunter = _get_hunter()
    try:
        iocs = hunter.list_iocs(ioc_type=ioc_type, active_only=True, limit=5000)
        bundle = export_iocs_to_stix(iocs)
        return ExportIOCsResponse(bundle=bundle, count=len(iocs))
    except Exception as exc:
        logger.exception("Failed to export IOCs")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/sigma-rules",
    response_model=SigmaRulesResponse,
    summary="List active Sigma rules",
)
def list_sigma_rules(
    enabled_only: bool = Query(True, description="Return only enabled rules"),
) -> SigmaRulesResponse:
    """
    List Sigma detection rules loaded into the engine.

    Each rule includes parsed detection keywords, converted search query,
    log source, and severity level.
    """
    hunter = _get_hunter()
    try:
        rules = hunter.list_sigma_rules(enabled_only=enabled_only)
        return SigmaRulesResponse(rules=rules, total=len(rules))
    except Exception as exc:
        logger.exception("Failed to list Sigma rules")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/sigma-rules/import",
    response_model=SigmaRule,
    summary="Import a Sigma rule from YAML",
    status_code=201,
)
def import_sigma_rule(body: ImportSigmaRequest) -> SigmaRule:
    """
    Parse and import a Sigma detection rule from YAML content.

    Converts Sigma detection logic to a search query and stores the rule.
    """
    hunter = _get_hunter()
    try:
        rule = hunter.import_sigma_yaml(body.yaml_content)
        return rule
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to import Sigma rule")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/actors",
    response_model=ActorsResponse,
    summary="List threat actor profiles",
)
def list_actors(
    motivation: Optional[ThreatActorMotivation] = Query(
        None, description="Filter by motivation (financial, espionage, hacktivism, sabotage)"
    ),
) -> ActorsResponse:
    """
    List known threat actor profiles with TTPs, targeted industries, and IOC associations.

    Includes 5 built-in profiles (APT28, APT29, Lazarus Group, FIN7, Volt Typhoon).
    """
    hunter = _get_hunter()
    try:
        actors = hunter.list_actors(motivation=motivation)
        return ActorsResponse(actors=actors, total=len(actors))
    except Exception as exc:
        logger.exception("Failed to list threat actors")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/kill-chain",
    response_model=KillChainResponse,
    summary="Kill chain coverage visualization",
)
def kill_chain_coverage() -> KillChainResponse:
    """
    Show coverage across all 7 Cyber Kill Chain phases.

    For each phase, returns: hypothesis count, sigma rule count,
    active hunt count, and whether coverage exists.
    Highlights gaps where no detection hypotheses are defined.
    """
    hunter = _get_hunter()
    try:
        coverage = hunter.get_kill_chain_coverage()
        covered = sum(1 for c in coverage if c.covered)
        total = len(coverage)
        pct = round((covered / total) * 100, 1) if total > 0 else 0.0
        return KillChainResponse(
            coverage=coverage,
            covered_phases=covered,
            total_phases=total,
            coverage_pct=pct,
        )
    except Exception as exc:
        logger.exception("Failed to compute kill chain coverage")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/findings",
    response_model=HuntFinding,
    summary="Add a finding to a hunt",
    status_code=201,
)
def add_finding(body: AddFindingRequest) -> HuntFinding:
    """Add a security finding discovered during an active hunt."""
    hunter = _get_hunter()
    try:
        finding = HuntFinding(
            hunt_id=body.hunt_id,
            title=body.title,
            description=body.description,
            severity=body.severity,
            mitre_technique_id=body.mitre_technique_id,
            evidence=body.evidence,
            ioc_matches=body.ioc_matches,
            kill_chain_phase=body.kill_chain_phase,
        )
        return hunter.add_finding(finding)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to add finding to hunt %s", body.hunt_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/findings/{hunt_id}",
    response_model=List[HuntFinding],
    summary="List findings for a hunt",
)
def list_findings(hunt_id: str) -> List[HuntFinding]:
    """List all findings for the specified hunt workflow."""
    hunter = _get_hunter()
    try:
        return hunter.list_findings(hunt_id=hunt_id)
    except Exception as exc:
        logger.exception("Failed to list findings for hunt %s", hunt_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/trigger",
    response_model=Optional[StartHuntResponse],
    summary="Fire an automated hunt trigger",
)
def fire_trigger(body: FireTriggerRequest) -> Optional[StartHuntResponse]:
    """
    Fire an automated trigger to initiate a hunt.

    Trigger types: new_cve, ioc_match, network_anomaly, compliance_failure.
    Automatically selects the best matching hypothesis and starts a hunt.
    Returns the started hunt details, or null if no matching hypothesis found.
    """
    hunter = _get_hunter()
    try:
        workflow = hunter.fire_trigger(
            trigger_type=body.trigger_type,
            context=body.context,
            org_id=body.org_id,
        )
        if workflow is None:
            return None
        return StartHuntResponse(
            hunt_id=workflow.id,
            hypothesis_name=workflow.hypothesis_name,
            status=workflow.status,
            message="Hunt auto-triggered",
        )
    except Exception as exc:
        logger.exception("Failed to fire trigger %s", body.trigger_type)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/hunts/{hunt_id}/complete",
    response_model=HuntWorkflow,
    summary="Mark a hunt as completed",
)
def complete_hunt(hunt_id: str, notes: str = Query("", description="Completion notes")) -> HuntWorkflow:
    """Mark an active hunt as completed with optional analyst notes."""
    hunter = _get_hunter()
    try:
        return hunter.complete_hunt(hunt_id=hunt_id, notes=notes)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to complete hunt %s", hunt_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
