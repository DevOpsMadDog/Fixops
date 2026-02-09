"""
FixOps Attack Simulation API Router.

REST API for Breach & Attack Simulation (BAS) capabilities:
- Create / list / get attack scenarios
- AI-generate scenarios with LLM
- Run attack campaigns across MITRE ATT&CK kill chain
- Get campaign results, attack paths, MITRE heatmap
- Breach impact assessment
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field

from core.attack_simulation_engine import (
    AttackSimulationEngine,
    CampaignStatus,
    get_attack_simulation_engine,
)

# Knowledge Brain + Event Bus integration (graceful degradation)
try:
    from core.event_bus import Event, EventType, get_event_bus
    from core.knowledge_brain import get_brain

    _HAS_BRAIN = True
except ImportError:
    _HAS_BRAIN = False

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/attack-sim", tags=["attack-simulation"])


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class CreateScenarioRequest(BaseModel):
    """Request to create an attack scenario."""
    name: str = Field(..., description="Scenario name")
    description: str = Field("", description="Scenario description")
    threat_actor: str = Field("cybercriminal", description="Threat actor profile")
    complexity: str = Field("medium", description="Attack complexity")
    target_assets: List[str] = Field(default_factory=list, description="Target assets")
    target_cves: List[str] = Field(default_factory=list, description="CVEs to exploit")
    objectives: List[str] = Field(default_factory=list, description="Attack objectives")
    initial_access_vector: str = Field("", description="MITRE technique ID for initial access")


class GenerateScenarioRequest(BaseModel):
    """Request to AI-generate a scenario."""
    target_description: str = Field(..., description="Description of the target")
    threat_actor: str = Field("cybercriminal", description="Threat actor profile")
    cve_ids: List[str] = Field(default_factory=list, description="Known CVEs")


class RunCampaignRequest(BaseModel):
    """Request to run an attack campaign."""
    scenario_id: str = Field(..., description="Scenario to execute")
    org_id: Optional[str] = Field(None, description="Organization ID")


class ScenarioResponse(BaseModel):
    """Scenario response."""
    scenario_id: str
    name: str
    description: str
    threat_actor: str
    complexity: str
    target_assets: List[str]
    target_cves: List[str]
    kill_chain_phases: List[str]
    objectives: List[str]
    created_at: str


class CampaignSummaryResponse(BaseModel):
    """Summary of a campaign."""
    campaign_id: str
    status: str
    scenario_name: str = ""
    risk_score: float = 0.0
    steps_executed: int = 0
    steps_succeeded: int = 0
    steps_failed: int = 0
    total_duration_seconds: float = 0.0
    started_at: str = ""
    completed_at: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/scenarios", response_model=ScenarioResponse)
async def create_scenario(req: CreateScenarioRequest):
    """Create a new attack scenario."""
    engine = get_attack_simulation_engine()
    scenario = engine.create_scenario(
        name=req.name,
        description=req.description,
        threat_actor=req.threat_actor,
        complexity=req.complexity,
        target_assets=req.target_assets,
        target_cves=req.target_cves,
        objectives=req.objectives,
        initial_access_vector=req.initial_access_vector,
    )
    return ScenarioResponse(
        scenario_id=scenario.scenario_id,
        name=scenario.name,
        description=scenario.description,
        threat_actor=scenario.threat_actor.value,
        complexity=scenario.complexity.value,
        target_assets=scenario.target_assets,
        target_cves=scenario.target_cves,
        kill_chain_phases=[p.value for p in scenario.kill_chain_phases],
        objectives=scenario.objectives,
        created_at=scenario.created_at,
    )


@router.post("/scenarios/generate", response_model=ScenarioResponse)
async def generate_scenario(req: GenerateScenarioRequest):
    """AI-generate an attack scenario using LLM."""
    engine = get_attack_simulation_engine()
    scenario = await engine.generate_scenario_with_llm(
        target_description=req.target_description,
        threat_actor=req.threat_actor,
        cve_ids=req.cve_ids,
    )
    return ScenarioResponse(
        scenario_id=scenario.scenario_id,
        name=scenario.name,
        description=scenario.description,
        threat_actor=scenario.threat_actor.value,
        complexity=scenario.complexity.value,
        target_assets=scenario.target_assets,
        target_cves=scenario.target_cves,
        kill_chain_phases=[p.value for p in scenario.kill_chain_phases],
        objectives=scenario.objectives,
        created_at=scenario.created_at,
    )


@router.get("/scenarios", response_model=List[ScenarioResponse])
async def list_scenarios():
    """List all attack scenarios."""
    engine = get_attack_simulation_engine()
    return [
        ScenarioResponse(
            scenario_id=s.scenario_id,
            name=s.name,
            description=s.description,
            threat_actor=s.threat_actor.value,
            complexity=s.complexity.value,
            target_assets=s.target_assets,
            target_cves=s.target_cves,
            kill_chain_phases=[p.value for p in s.kill_chain_phases],
            objectives=s.objectives,
            created_at=s.created_at,
        )
        for s in engine.list_scenarios()
    ]


@router.get("/scenarios/{scenario_id}", response_model=ScenarioResponse)
async def get_scenario(scenario_id: str):
    """Get a scenario by ID."""
    engine = get_attack_simulation_engine()
    s = engine.get_scenario(scenario_id)
    if not s:
        raise HTTPException(status_code=404, detail=f"Scenario {scenario_id} not found")
    return ScenarioResponse(
        scenario_id=s.scenario_id,
        name=s.name,
        description=s.description,
        threat_actor=s.threat_actor.value,
        complexity=s.complexity.value,
        target_assets=s.target_assets,
        target_cves=s.target_cves,
        kill_chain_phases=[p.value for p in s.kill_chain_phases],
        objectives=s.objectives,
        created_at=s.created_at,
    )


# ---- Campaign Endpoints ----


@router.post("/campaigns/run")
async def run_campaign(req: RunCampaignRequest, background_tasks: BackgroundTasks):
    """Run an attack simulation campaign (async)."""
    engine = get_attack_simulation_engine()
    scenario = engine.get_scenario(req.scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario {req.scenario_id} not found")

    # Run campaign (async, may take time for LLM calls)
    campaign = await engine.run_campaign(
        scenario_id=req.scenario_id,
        org_id=req.org_id,
    )

    return {
        "campaign_id": campaign.campaign_id,
        "status": campaign.status.value,
        "risk_score": campaign.risk_score,
        "steps_executed": campaign.steps_executed,
        "steps_succeeded": campaign.steps_succeeded,
        "steps_failed": campaign.steps_failed,
        "attack_paths": len(campaign.attack_paths),
        "executive_summary": campaign.executive_summary,
        "total_duration_seconds": campaign.total_duration_seconds,
    }


@router.get("/campaigns")
async def list_campaigns(
    status: Optional[str] = Query(None, description="Filter by status"),
):
    """List all campaigns."""
    engine = get_attack_simulation_engine()
    campaigns = engine.list_campaigns(status=status)
    return [
        CampaignSummaryResponse(
            campaign_id=c.campaign_id,
            status=c.status.value,
            scenario_name=c.scenario.name if c.scenario else "",
            risk_score=c.risk_score,
            steps_executed=c.steps_executed,
            steps_succeeded=c.steps_succeeded,
            steps_failed=c.steps_failed,
            total_duration_seconds=c.total_duration_seconds,
            started_at=c.started_at,
            completed_at=c.completed_at,
        )
        for c in campaigns
    ]


@router.get("/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str):
    """Get full campaign results including attack paths and breach impact."""
    engine = get_attack_simulation_engine()
    c = engine.get_campaign(campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    return {
        "campaign_id": c.campaign_id,
        "status": c.status.value,
        "scenario": asdict(c.scenario) if c.scenario else None,
        "risk_score": c.risk_score,
        "steps_executed": c.steps_executed,
        "steps_succeeded": c.steps_succeeded,
        "steps_failed": c.steps_failed,
        "attack_paths": [asdict(p) for p in c.attack_paths],
        "breach_impact": asdict(c.breach_impact) if c.breach_impact else None,
        "mitre_coverage": c.mitre_coverage,
        "executive_summary": c.executive_summary,
        "recommendations": c.recommendations,
        "total_duration_seconds": c.total_duration_seconds,
        "started_at": c.started_at,
        "completed_at": c.completed_at,
    }


@router.get("/campaigns/{campaign_id}/attack-paths")
async def get_attack_paths(campaign_id: str):
    """Get attack paths for a campaign."""
    engine = get_attack_simulation_engine()
    c = engine.get_campaign(campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")
    return {
        "campaign_id": campaign_id,
        "attack_paths": [asdict(p) for p in c.attack_paths],
        "total_paths": len(c.attack_paths),
    }


@router.get("/campaigns/{campaign_id}/breach-impact")
async def get_breach_impact(campaign_id: str):
    """Get breach impact assessment for a campaign."""
    engine = get_attack_simulation_engine()
    c = engine.get_campaign(campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")
    if not c.breach_impact:
        raise HTTPException(status_code=404, detail="No breach impact data available")
    return {
        "campaign_id": campaign_id,
        "breach_impact": asdict(c.breach_impact),
    }


@router.get("/campaigns/{campaign_id}/recommendations")
async def get_recommendations(campaign_id: str):
    """Get security recommendations from a campaign."""
    engine = get_attack_simulation_engine()
    c = engine.get_campaign(campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")
    return {
        "campaign_id": campaign_id,
        "recommendations": c.recommendations,
        "total": len(c.recommendations),
    }


# ---- MITRE ATT&CK Endpoints ----


@router.get("/mitre/heatmap")
async def get_mitre_heatmap():
    """Get MITRE ATT&CK technique heatmap across all campaigns."""
    engine = get_attack_simulation_engine()
    return {
        "heatmap": engine.get_mitre_heatmap(),
        "total_campaigns": len(engine.list_campaigns()),
    }


@router.get("/mitre/techniques")
async def get_mitre_techniques():
    """Get all supported MITRE ATT&CK techniques."""
    from core.attack_simulation_engine import MITRE_TECHNIQUES
    return {
        "techniques": {
            tid: {
                "name": info["name"],
                "phase": info["phase"],
                "severity": info["severity"],
            }
            for tid, info in MITRE_TECHNIQUES.items()
        },
        "total": len(MITRE_TECHNIQUES),
    }


# ---- Health ----


@router.get("/health")
async def attack_sim_health():
    """Health check for attack simulation engine."""
    engine = get_attack_simulation_engine()
    return {
        "status": "healthy",
        "engine": "AttackSimulationEngine",
        "scenarios_count": len(engine.list_scenarios()),
        "campaigns_count": len(engine.list_campaigns()),
        "mitre_techniques": 34,
        "kill_chain_phases": 8,
        "features": [
            "multi_stage_simulation",
            "llm_scenario_generation",
            "mitre_attack_mapping",
            "breach_impact_assessment",
            "knowledge_graph_integration",
            "event_bus_notifications",
        ],
    }

