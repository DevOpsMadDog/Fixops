"""ALdeci Copilot Agent APIs.

Specialized AI agents for security operations:
- Security Analyst Agent: Deep analysis, EPSS, KEV, threat intel
- Pentest Agent: Exploit validation, PoC generation, evidence collection
- Compliance Agent: Framework mapping, gap analysis, audit support
- Remediation Agent: Fix generation, PR creation, dependency updates

28 Endpoints for comprehensive agent control.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field

# Optional httpx import for MPTE integration
try:
    import httpx

    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

logger = logging.getLogger(__name__)

# Import FeedsService from suite-feeds (has proper __init__ with db_path param)
try:
    from feeds_service import FeedsService

    _FEEDS_SERVICE_AVAILABLE = True
except ImportError:
    _FEEDS_SERVICE_AVAILABLE = False
    logger.warning("FeedsService not available - using fallback behavior")

# Import ComplianceEngine for real compliance evaluation
try:
    from core.services.enterprise.compliance_engine import (  # noqa: F401
        ComplianceEngine,
        compliance_engine,
    )

    _COMPLIANCE_ENGINE_AVAILABLE = True
except ImportError:
    _COMPLIANCE_ENGINE_AVAILABLE = False
    compliance_engine = None
    logger.warning(
        "ComplianceEngine not available - compliance endpoints return pending"
    )

# Service configuration
MPTE_URL = os.environ.get("MPTE_BASE_URL", "https://localhost:8443")
MPTE_TOKEN = os.environ.get("MPTE_TOKEN", os.environ.get("MPTE_API_TOKEN", ""))

# Initialize feeds service singleton
_feeds_service = None


def _get_feeds_service():
    """Get or create FeedsService instance."""
    global _feeds_service
    if _feeds_service is None and _FEEDS_SERVICE_AVAILABLE:
        _DATA_DIR = Path("data/feeds")
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        _feeds_service = FeedsService(_DATA_DIR / "feeds.db")
    return _feeds_service


router = APIRouter(prefix="/api/v1/copilot/agents", tags=["copilot-agents"])


# =============================================================================
# Enums
# =============================================================================


class AgentType(str, Enum):
    """AI Agent types."""

    SECURITY_ANALYST = "security_analyst"
    PENTEST = "pentest"
    COMPLIANCE = "compliance"
    REMEDIATION = "remediation"
    ORCHESTRATOR = "orchestrator"


class AgentStatus(str, Enum):
    """Agent execution status."""

    IDLE = "idle"
    ANALYZING = "analyzing"
    EXECUTING = "executing"
    WAITING = "waiting"
    COMPLETED = "completed"
    ERROR = "error"


class TaskPriority(str, Enum):
    """Task priority levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ComplianceFramework(str, Enum):
    """Compliance frameworks."""

    PCI_DSS = "pci-dss"
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    HIPAA = "hipaa"
    NIST = "nist"
    GDPR = "gdpr"
    FedRAMP = "fedramp"


# =============================================================================
# Request/Response Models
# =============================================================================


# --- Security Analyst Agent ---


class AnalyzeVulnRequest(BaseModel):
    """Request for vulnerability analysis."""

    cve_id: Optional[str] = None
    finding_id: Optional[str] = None
    description: Optional[str] = None
    include_threat_intel: bool = True
    include_epss: bool = True
    include_kev: bool = True


class ThreatIntelRequest(BaseModel):
    """Request for threat intelligence."""

    cve_ids: List[str] = Field(default_factory=list)
    asset_ids: List[str] = Field(default_factory=list)
    include_dark_web: bool = True
    include_zero_day: bool = True


class PrioritizationRequest(BaseModel):
    """Request for vulnerability prioritization."""

    finding_ids: List[str] = Field(default_factory=list)
    algorithm: str = Field(default="ssvc", description="ssvc, epss, cvss, custom")
    business_context: Optional[Dict[str, Any]] = None


class AttackPathRequest(BaseModel):
    """Request for attack path analysis."""

    asset_id: str
    depth: int = Field(default=3, ge=1, le=10)
    include_lateral: bool = True


# --- Pentest Agent ---


class ValidateExploitRequest(BaseModel):
    """Request to validate exploitability."""

    cve_id: str
    target_id: str
    safe_mode: bool = Field(default=True, description="Non-destructive testing")
    collect_evidence: bool = True


class GeneratePocRequest(BaseModel):
    """Request to generate proof-of-concept."""

    cve_id: str
    language: str = Field(default="python", description="python, go, bash")
    safe_poc: bool = True


class ReachabilityRequest(BaseModel):
    """Request for reachability analysis."""

    cve_id: str
    asset_ids: List[str]
    depth: str = Field(default="deep", description="shallow, medium, deep")


class SimulateAttackRequest(BaseModel):
    """Request to simulate attack scenario."""

    scenario_type: str = Field(
        default="ransomware", description="ransomware, apt, insider"
    )
    target_assets: List[str]
    kill_chain_stages: List[str] = Field(
        default_factory=lambda: ["reconnaissance", "weaponization"]
    )


# --- Compliance Agent ---


class MapFindingsRequest(BaseModel):
    """Request to map findings to compliance frameworks."""

    finding_ids: List[str]
    frameworks: List[ComplianceFramework]


class GapAnalysisRequest(BaseModel):
    """Request for compliance gap analysis."""

    framework: ComplianceFramework
    scope: Optional[List[str]] = None  # Asset/control scope


class AuditEvidenceRequest(BaseModel):
    """Request for audit evidence collection."""

    framework: ComplianceFramework
    controls: List[str] = Field(default_factory=list)
    format: str = Field(default="pdf")


class RegulatoryAlertRequest(BaseModel):
    """Request to check regulatory alerts."""

    jurisdictions: List[str] = Field(default_factory=lambda: ["US", "EU"])
    industries: List[str] = Field(default_factory=lambda: ["financial", "healthcare"])


# --- Remediation Agent ---


class GenerateFixRequest(BaseModel):
    """Request to generate fix."""

    finding_id: str
    language: Optional[str] = None
    include_tests: bool = True


class CreatePRRequest(BaseModel):
    """Request to create pull request."""

    finding_ids: List[str]
    repository: str
    branch: str = Field(default="security-fixes")
    auto_merge: bool = False


class DependencyUpdateRequest(BaseModel):
    """Request to update dependencies."""

    sbom_id: Optional[str] = None
    package_ids: List[str] = Field(default_factory=list)
    update_strategy: str = Field(
        default="minor", description="patch, minor, major, latest"
    )


class PlaybookRequest(BaseModel):
    """Request to generate remediation playbook."""

    finding_ids: List[str]
    audience: str = Field(
        default="developer", description="developer, devops, security"
    )
    include_rollback: bool = True


# --- Orchestrator Agent ---


class OrchestrateRequest(BaseModel):
    """Request for multi-agent orchestration."""

    objective: str
    agents: List[AgentType] = Field(
        default_factory=lambda: [AgentType.SECURITY_ANALYST]
    )
    context: Dict[str, Any] = Field(default_factory=dict)
    max_iterations: int = Field(default=5, ge=1, le=20)


# =============================================================================
# Response Models
# =============================================================================


class AgentTaskResponse(BaseModel):
    """Generic agent task response."""

    task_id: str
    agent: AgentType
    status: AgentStatus
    created_at: datetime
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class VulnAnalysisResponse(BaseModel):
    """Vulnerability analysis result."""

    cve_id: Optional[str]
    severity: str
    epss_score: float
    epss_percentile: float
    kev_listed: bool
    first_seen: Optional[datetime] = None
    threat_intel: Dict[str, Any]
    attack_vector: str
    impact_analysis: Dict[str, Any]
    recommendation: str


class PentestResultResponse(BaseModel):
    """Pentest result."""

    task_id: str
    status: str
    exploitable: bool
    evidence_id: Optional[str] = None
    attack_chain: List[str] = Field(default_factory=list)
    proof: Optional[Dict[str, Any]] = None
    recommendations: List[str] = Field(default_factory=list)


class ComplianceMappingResponse(BaseModel):
    """Compliance mapping result."""

    framework: str
    controls_mapped: int = 0
    controls_affected: List[Dict[str, Any]] = Field(default_factory=list)
    gap_score: Optional[float] = None
    remediation_priority: List[str] = Field(default_factory=list)
    status: Optional[str] = None
    message: Optional[str] = None


# =============================================================================
# Helper Functions
# =============================================================================


def _generate_id() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


# In-memory task storage
_agent_tasks: Dict[str, Dict[str, Any]] = {}


# =============================================================================
# Security Analyst Agent Endpoints (7 APIs)
# =============================================================================


@router.post("/analyst/analyze", response_model=AgentTaskResponse)
async def analyze_vulnerability(
    request: AnalyzeVulnRequest,
    background_tasks: BackgroundTasks,
) -> AgentTaskResponse:
    """Deep vulnerability analysis.

    Combines EPSS, KEV, threat intel, and business context
    for comprehensive vulnerability assessment.
    """
    task_id = _generate_id()

    task = {
        "task_id": task_id,
        "agent": AgentType.SECURITY_ANALYST,
        "status": AgentStatus.ANALYZING,
        "created_at": _now(),
        "result": None,
        "error": None,
    }
    _agent_tasks[task_id] = task

    # Simulate async analysis
    background_tasks.add_task(_run_analysis, task_id, request)

    return AgentTaskResponse(**task)


async def _run_analysis(task_id: str, request: AnalyzeVulnRequest) -> None:
    """Run vulnerability analysis using real EPSS/KEV data."""
    task = _agent_tasks.get(task_id)
    if not task:
        return

    cve_id = request.cve_id or "UNKNOWN"

    # Get real EPSS and KEV data from FeedsService
    epss_score = 0.0
    epss_percentile = 0.0
    kev_listed = False
    kev_info = None

    feeds_service = _get_feeds_service()
    if feeds_service:
        try:
            epss_data = feeds_service.get_epss_score(cve_id)
            if epss_data:
                epss_score = epss_data.epss
                epss_percentile = epss_data.percentile

            kev_entry = feeds_service.get_kev_entry(cve_id)
            if kev_entry:
                kev_listed = True
                kev_info = {
                    "vendor": kev_entry.vendor_project,
                    "product": kev_entry.product,
                    "ransomware_use": kev_entry.known_ransomware_campaign_use
                    == "Known",
                    "due_date": kev_entry.due_date,
                    "required_action": kev_entry.required_action,
                }
        except Exception as e:
            logger.warning(f"FeedsService lookup failed: {e}")

    # Determine severity based on real scores
    if epss_score >= 0.5 or kev_listed:
        severity = "critical"
        recommendation = "Immediate patching required - high exploitation probability"
        if kev_listed:
            recommendation = f"URGENT: In CISA KEV catalog. {kev_info.get('required_action', 'Apply patches immediately.')}"
    elif epss_score >= 0.1:
        severity = "high"
        recommendation = "Prioritize patching - elevated exploitation risk"
    elif epss_score >= 0.01:
        severity = "medium"
        recommendation = "Schedule patching in next maintenance window"
    else:
        severity = "low"
        recommendation = "Monitor and patch as resources allow"

    task["result"] = {
        "cve_id": cve_id,
        "severity": severity,
        "epss_score": epss_score,
        "epss_percentile": epss_percentile,
        "kev_listed": kev_listed,
        "kev_info": kev_info,
        "threat_intel": {
            "active_exploitation": kev_listed,
            "ransomware_associated": kev_info.get("ransomware_use", False)
            if kev_info
            else False,
            "data_source": "CISA KEV + EPSS" if feeds_service else "pending_data_load",
        },
        "attack_vector": "network",  # Would need CVE details API for accurate data
        "recommendation": recommendation,
    }
    task["status"] = AgentStatus.COMPLETED


@router.post("/analyst/threat-intel")
async def get_threat_intelligence(request: ThreatIntelRequest) -> Dict[str, Any]:
    """Aggregate threat intelligence from all feeds.

    Includes: NVD, EPSS, KEV, Dark Web, Zero-Day indicators.
    """
    feeds_service = _get_feeds_service()

    cve_intel = []
    for cve in request.cve_ids or []:
        intel = {
            "cve_id": cve,
            "sources": [],
            "threat_level": "unknown",
            "exploitation_status": "unknown",
            "epss_score": None,
            "kev_listed": False,
        }

        if feeds_service:
            try:
                epss_data = feeds_service.get_epss_score(cve)
                if epss_data:
                    intel["sources"].append("epss")
                    intel["epss_score"] = epss_data.epss
                    intel["epss_percentile"] = epss_data.percentile
                    # Determine threat level from EPSS
                    if epss_data.epss >= 0.5:
                        intel["threat_level"] = "critical"
                        intel["exploitation_status"] = "high_probability"
                    elif epss_data.epss >= 0.1:
                        intel["threat_level"] = "high"
                        intel["exploitation_status"] = "elevated"
                    elif epss_data.epss >= 0.01:
                        intel["threat_level"] = "medium"
                    else:
                        intel["threat_level"] = "low"

                kev_entry = feeds_service.get_kev_entry(cve)
                if kev_entry:
                    intel["sources"].append("cisa-kev")
                    intel["kev_listed"] = True
                    intel["threat_level"] = "critical"
                    intel["exploitation_status"] = "active"
                    intel["ransomware_association"] = (
                        kev_entry.known_ransomware_campaign_use == "Known"
                    )
                    intel["due_date"] = kev_entry.due_date
            except Exception as e:
                logger.warning(f"Threat intel lookup failed for {cve}: {e}")
                intel["error"] = str(e)

        if not intel["sources"]:
            intel["sources"].append("pending_refresh")

        cve_intel.append(intel)

    return {
        "cve_intel": cve_intel,
        "data_sources": {
            "epss": "FIRST.org EPSS API",
            "kev": "CISA Known Exploited Vulnerabilities",
            "status": "connected" if feeds_service else "initializing",
        },
        "timestamp": _now().isoformat(),
    }


@router.post("/analyst/prioritize")
async def prioritize_vulnerabilities(request: PrioritizationRequest) -> Dict[str, Any]:
    """Prioritize vulnerabilities using SSVC/EPSS/custom algorithms with real EPSS data."""
    feeds_service = _get_feeds_service()

    # Build prioritized list based on real EPSS/KEV data
    prioritized = []
    finding_scores = []

    for fid in request.finding_ids or []:
        score_info = {
            "finding_id": fid,
            "epss_score": 0.0,
            "kev_listed": False,
            "priority_score": 0.0,
        }

        # Extract CVE from finding ID if it contains one (e.g., "F001-CVE-2021-44228")
        cve_match = None
        if "CVE-" in fid.upper():
            import re

            match = re.search(r"(CVE-\d{4}-\d+)", fid.upper())
            if match:
                cve_match = match.group(1)

        if feeds_service and cve_match:
            try:
                epss_data = feeds_service.get_epss_score(cve_match)
                if epss_data:
                    score_info["epss_score"] = epss_data.epss
                    score_info["priority_score"] = epss_data.epss

                kev_entry = feeds_service.get_kev_entry(cve_match)
                if kev_entry:
                    score_info["kev_listed"] = True
                    score_info["priority_score"] = max(
                        score_info["priority_score"], 1.0
                    )  # KEV = highest priority
            except Exception as e:
                logger.warning(f"EPSS/KEV lookup failed for {fid}: {e}")

        finding_scores.append(score_info)

    # Sort by priority score (highest first)
    finding_scores.sort(key=lambda x: x["priority_score"], reverse=True)

    # Assign priorities and actions
    immediate_count = 0
    scheduled_count = 0
    recommendations = []

    for i, score_info in enumerate(finding_scores):
        action = "scheduled"
        if score_info["kev_listed"]:
            action = "immediate"
            immediate_count += 1
            recommendations.append(
                f"URGENT: {score_info['finding_id']} is in CISA KEV - patch immediately"
            )
        elif score_info["epss_score"] >= 0.1:
            action = "immediate"
            immediate_count += 1
            recommendations.append(
                f"High risk: {score_info['finding_id']} has EPSS {score_info['epss_score']:.3f}"
            )
        else:
            scheduled_count += 1

        prioritized.append(
            {
                "finding_id": score_info["finding_id"],
                "priority": i + 1,
                "action": action,
                "epss_score": score_info["epss_score"],
                "kev_listed": score_info["kev_listed"],
            }
        )

    return {
        "algorithm": request.algorithm,
        "prioritized_findings": prioritized,
        "total_immediate": immediate_count,
        "total_scheduled": scheduled_count,
        "sla_at_risk": immediate_count,  # All immediate items are SLA risks
        "recommendations": recommendations
        or ["No high-priority items found based on EPSS/KEV data"],
        "data_source": "EPSS + CISA KEV" if feeds_service else "pending_data_load",
    }


@router.post("/analyst/attack-path")
async def analyze_attack_path(request: AttackPathRequest) -> Dict[str, Any]:
    """Analyze attack paths to/from an asset.

    Note: Attack path analysis requires asset inventory and network topology data.
    Returns pending status if data sources are not configured.
    """
    # TODO: Integrate with real asset inventory and network topology service
    # Currently returns pending status indicating the analysis is queued

    return {
        "asset_id": request.asset_id,
        "status": "integration_required",
        "integration_required": True,
        "message": "Attack path analysis requires asset inventory + network topology integration.",
        "attack_paths": [],
        "requirements": [
            "Asset inventory with network topology",
            "Vulnerability scan results mapped to assets",
            "Network segmentation data",
        ],
        "depth_requested": request.depth,
        "include_lateral": request.include_lateral,
    }


@router.get("/analyst/trending")
async def get_trending_threats(
    timeframe: str = Query(default="7d", description="1d, 7d, 30d"),
    limit: int = Query(default=10, le=50),
) -> Dict[str, Any]:
    """Get trending threats from KEV catalog with real EPSS data."""
    feeds_service = _get_feeds_service()

    trending = []
    kev_count = 0

    if feeds_service:
        try:
            # Get recent KEV entries as trending threats (they are actively exploited)
            stats = feeds_service.get_feed_stats()
            kev_count = stats.get("kev_count", 0)

            # Get high-EPSS CVEs from the database
            conn = __import__("sqlite3").connect(feeds_service.db_path)
            conn.row_factory = __import__("sqlite3").Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT cve_id, epss, percentile FROM epss_scores ORDER BY epss DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            conn.close()

            for row in rows:
                kev_entry = feeds_service.get_kev_entry(row["cve_id"])
                trending.append(
                    {
                        "cve_id": row["cve_id"],
                        "epss_score": row["epss"],
                        "epss_percentile": row["percentile"],
                        "in_kev": kev_entry is not None,
                        "threat_level": "critical"
                        if kev_entry or row["epss"] >= 0.5
                        else "high",
                    }
                )
        except Exception as e:
            logger.warning(f"Trending threats query failed: {e}")

    return {
        "trending": trending,
        "kev_catalog_size": kev_count,
        "data_source": "EPSS + CISA KEV" if feeds_service else "pending_data_load",
        "timeframe": timeframe,
        "note": "Trending based on EPSS scores and KEV catalog"
        if trending
        else "Data loading - please refresh feeds",
    }


@router.get("/analyst/risk-score/{asset_id}")
async def get_asset_risk_score(asset_id: str) -> Dict[str, Any]:
    """Calculate comprehensive risk score for an asset.

    Note: Risk scoring requires asset inventory with vulnerability mappings.
    Returns pending status if data sources are not configured.
    """
    # TODO: Integrate with asset inventory service to get real vulnerability counts

    return {
        "asset_id": asset_id,
        "status": "integration_required",
        "integration_required": True,
        "message": "Asset risk scoring requires asset inventory integration.",
        "risk_score": None,
        "requirements": [
            "Asset inventory with asset_id mapping",
            "Vulnerability scan results linked to assets",
            "Business criticality classification",
        ],
        "available_when_configured": {
            "risk_score": "0.0 - 10.0 scale",
            "risk_grade": "A (critical) to F (minimal)",
            "open_findings": "Count of unresolved vulnerabilities",
            "trend": "improving/stable/worsening",
        },
    }


@router.get("/analyst/cve/{cve_id}")
async def get_cve_deep_analysis(cve_id: str) -> VulnAnalysisResponse:
    """Get comprehensive CVE analysis using real EPSS/KEV data."""
    feeds_service = _get_feeds_service()

    epss_score = 0.0
    epss_percentile = 0.0
    kev_listed = False
    threat_intel = {}
    recommendation = "Unable to assess - data sources loading"
    severity = "unknown"

    if feeds_service:
        try:
            epss_data = feeds_service.get_epss_score(cve_id)
            if epss_data:
                epss_score = epss_data.epss
                epss_percentile = epss_data.percentile

            kev_entry = feeds_service.get_kev_entry(cve_id)
            if kev_entry:
                kev_listed = True
                threat_intel = {
                    "active_exploitation": True,
                    "vendor": kev_entry.vendor_project,
                    "product": kev_entry.product,
                    "ransomware_association": kev_entry.known_ransomware_campaign_use
                    == "Known",
                    "required_action": kev_entry.required_action,
                    "due_date": kev_entry.due_date,
                }
                recommendation = (
                    kev_entry.required_action or "Apply vendor patch immediately"
                )
                severity = "critical"
            elif epss_score >= 0.5:
                severity = "critical"
                recommendation = "High exploitation probability - prioritize patching"
                threat_intel = {
                    "exploitation_probability": "high",
                    "epss_data_available": True,
                }
            elif epss_score >= 0.1:
                severity = "high"
                recommendation = "Elevated risk - schedule patching soon"
                threat_intel = {
                    "exploitation_probability": "elevated",
                    "epss_data_available": True,
                }
            elif epss_score > 0:
                severity = "medium" if epss_score >= 0.01 else "low"
                recommendation = "Monitor and patch as resources allow"
                threat_intel = {
                    "exploitation_probability": "low",
                    "epss_data_available": True,
                }
            else:
                threat_intel = {
                    "epss_data_available": False,
                    "note": "CVE not found in EPSS database",
                }
                recommendation = "No EPSS data available - check CVE validity"
        except Exception as e:
            logger.warning(f"CVE analysis failed for {cve_id}: {e}")
            threat_intel = {"error": str(e)}

    return VulnAnalysisResponse(
        cve_id=cve_id,
        severity=severity,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        kev_listed=kev_listed,
        first_seen=None,  # Would need NVD API for this
        threat_intel=threat_intel,
        attack_vector="unknown",  # Would need NVD API for this
        impact_analysis={},  # Would need NVD API for this
        recommendation=recommendation,
    )


# =============================================================================
# Pentest Agent Endpoints (7 APIs) - Integrated with MPTE
# =============================================================================


async def _call_mpte_api(
    endpoint: str, method: str = "POST", data: dict = None
) -> dict:
    """Call MPTE API for real pentest operations."""
    if not _HTTPX_AVAILABLE:
        return {"success": False, "error": "httpx library not available"}

    url = f"{MPTE_URL}/api/v1/{endpoint}"
    headers = {"Authorization": f"Bearer {MPTE_TOKEN}"} if MPTE_TOKEN else {}

    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            if method == "POST":
                response = await client.post(url, json=data or {}, headers=headers)
            else:
                response = await client.get(url, headers=headers)

            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {
                    "success": False,
                    "error": f"MPTE returned {response.status_code}",
                }
    except Exception as e:
        logger.warning(f"MPTE API call failed: {e}")
        return {"success": False, "error": str(e)}


@router.post("/pentest/validate", response_model=AgentTaskResponse)
async def validate_exploit(
    request: ValidateExploitRequest,
    background_tasks: BackgroundTasks,
) -> AgentTaskResponse:
    """Validate if a vulnerability is exploitable.

    Uses MPTE for safe, controlled exploit validation.
    Collects evidence for compliance and audit trails.
    """
    task_id = _generate_id()

    task = {
        "task_id": task_id,
        "agent": AgentType.PENTEST,
        "status": AgentStatus.EXECUTING,
        "created_at": _now(),
        "result": None,
        "error": None,
    }
    _agent_tasks[task_id] = task

    background_tasks.add_task(_run_validation, task_id, request)

    return AgentTaskResponse(**task)


async def _run_validation(task_id: str, request: ValidateExploitRequest) -> None:
    """Run exploit validation via MPTE."""
    task = _agent_tasks.get(task_id)
    if not task:
        return

    # Call MPTE for real validation
    mpte_result = await _call_mpte_api(
        "pentest/validate",
        data={
            "cve_id": request.cve_id,
            "target_id": request.target_id,
            "safe_mode": request.safe_mode,
        },
    )

    if mpte_result["success"]:
        task["result"] = mpte_result["data"]
        task["status"] = AgentStatus.COMPLETED
    else:
        # Return queued status if MPTE unavailable
        task["result"] = {
            "cve_id": request.cve_id,
            "target_id": request.target_id,
            "status": "queued",
            "message": "Validation request queued - MPTE processing",
            "mpte_error": mpte_result.get("error"),
        }
        task["status"] = AgentStatus.WAITING


@router.post("/pentest/generate-poc")
async def generate_poc(request: GeneratePocRequest) -> Dict[str, Any]:
    """Generate proof-of-concept code for a CVE via MPTE."""

    # Try MPTE first
    mpte_result = await _call_mpte_api(
        "pentest/generate-poc",
        data={
            "cve_id": request.cve_id,
            "language": request.language,
            "safe_poc": request.safe_poc,
        },
    )

    if mpte_result["success"]:
        return mpte_result["data"]

    # Fallback: MPTE unavailable
    return {
        "cve_id": request.cve_id,
        "language": request.language,
        "safe_poc": request.safe_poc,
        "status": "integration_required",
        "integration_required": True,
        "message": "PoC generation requires Micro Pentest Engine (MPTE) connection.",
        "mpte_status": "unavailable",
        "error": mpte_result.get("error"),
    }


@router.post("/pentest/reachability")
async def check_reachability(request: ReachabilityRequest) -> Dict[str, Any]:
    """Check if vulnerability is reachable from attack surface.

    Note: Reachability analysis requires network topology data.
    """
    # Try MPTE for real reachability analysis
    mpte_result = await _call_mpte_api(
        "pentest/reachability",
        data={
            "cve_id": request.cve_id,
            "asset_ids": request.asset_ids,
            "depth": request.depth,
        },
    )

    if mpte_result["success"]:
        return mpte_result["data"]

    # MPTE unavailable
    return {
        "cve_id": request.cve_id,
        "assets_analyzed": len(request.asset_ids),
        "status": "integration_required",
        "integration_required": True,
        "message": "Reachability analysis requires MPTE + network topology data.",
        "reachability_results": [],
        "requirements": [
            "Micro Pentest Engine (MPTE) connection",
            "Network topology discovery",
            "Asset vulnerability mapping",
        ],
        "depth": request.depth,
    }


@router.post("/pentest/simulate")
async def simulate_attack(
    request: SimulateAttackRequest,
    background_tasks: BackgroundTasks,
) -> AgentTaskResponse:
    """Simulate attack scenario for tabletop exercise via MPTE."""
    task_id = _generate_id()

    # Try MPTE for real simulation
    mpte_result = await _call_mpte_api(
        "pentest/simulate",
        data={
            "scenario_type": request.scenario_type,
            "target_assets": request.target_assets,
            "kill_chain_stages": request.kill_chain_stages,
        },
    )

    if mpte_result["success"]:
        task = {
            "task_id": task_id,
            "agent": AgentType.PENTEST,
            "status": AgentStatus.COMPLETED,
            "created_at": _now(),
            "result": mpte_result["data"],
            "error": None,
        }
    else:
        # MPTE unavailable
        task = {
            "task_id": task_id,
            "agent": AgentType.PENTEST,
            "status": AgentStatus.WAITING,
            "created_at": _now(),
            "result": {
                "scenario": request.scenario_type,
                "status": "integration_required",
                "integration_required": True,
                "message": "Attack simulation requires MPTE connection.",
                "mpte_error": mpte_result.get("error"),
            },
            "error": None,
        }

    _agent_tasks[task_id] = task
    return AgentTaskResponse(**task)


@router.get("/pentest/results/{task_id}", response_model=PentestResultResponse)
async def get_pentest_results(task_id: str) -> PentestResultResponse:
    """Get pentest validation results."""
    if task_id not in _agent_tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    task = _agent_tasks[task_id]
    result = task.get("result", {})

    return PentestResultResponse(
        task_id=task_id,
        status=task["status"].value
        if isinstance(task["status"], Enum)
        else task["status"],
        exploitable=result.get("exploitable", False),
        evidence_id=result.get("evidence_id"),
        attack_chain=result.get("attack_chain", []),
        proof=result.get("proof"),
        recommendations=result.get("recommendations", []),
    )


@router.get("/pentest/evidence/{evidence_id}")
async def get_pentest_evidence(evidence_id: str) -> Dict[str, Any]:
    """Get evidence collected during pentest via MPTE."""

    # Try MPTE for real evidence
    mpte_result = await _call_mpte_api(f"pentest/evidence/{evidence_id}", method="GET")

    if mpte_result["success"]:
        return mpte_result["data"]

    # MPTE unavailable
    return {
        "evidence_id": evidence_id,
        "status": "integration_required",
        "integration_required": True,
        "message": "Evidence retrieval requires MPTE connection.",
        "artifacts": [],
        "mpte_error": mpte_result.get("error"),
    }


@router.post("/pentest/schedule")
async def schedule_pentest(
    target_ids: List[str],
    cve_ids: List[str],
    schedule: str = "immediate",
    notification_emails: List[str] = None,
) -> Dict[str, Any]:
    """Schedule a pentest campaign via MPTE."""

    # Try MPTE for real scheduling
    mpte_result = await _call_mpte_api(
        "pentest/schedule",
        data={
            "target_ids": target_ids,
            "cve_ids": cve_ids,
            "schedule": schedule,
            "notification_emails": notification_emails or [],
        },
    )

    if mpte_result["success"]:
        return mpte_result["data"]

    # MPTE unavailable
    return {
        "campaign_id": _generate_id(),
        "targets": len(target_ids),
        "cves_to_validate": len(cve_ids),
        "schedule": schedule,
        "status": "integration_required",
        "integration_required": True,
        "message": "Pentest campaign requires MPTE connection.",
        "mpte_error": mpte_result.get("error"),
    }


# =============================================================================
# Compliance Agent Endpoints (7 APIs)
# Note: Compliance data requires integration with policy engine and evidence store
# =============================================================================


@router.post("/compliance/map-findings", response_model=ComplianceMappingResponse)
async def map_findings_to_compliance(
    request: MapFindingsRequest,
) -> ComplianceMappingResponse:
    """Map vulnerability findings to compliance frameworks.

    Uses :class:`ComplianceEngine` when available, otherwise returns
    ``integration_required`` status.
    """
    framework = request.frameworks[0].value if request.frameworks else "pci-dss"

    if _COMPLIANCE_ENGINE_AVAILABLE and compliance_engine is not None:
        # Build lightweight finding dicts from IDs (real impl would look up details)
        finding_dicts = [
            {"id": fid, "severity": "MEDIUM"} for fid in request.finding_ids
        ]
        frameworks_list = [f.value for f in request.frameworks]
        result = compliance_engine.evaluate(frameworks_list, finding_dicts)
        fw_result = result.get(framework, result.get(frameworks_list[0], {}))
        return ComplianceMappingResponse(
            framework=framework,
            controls_mapped=len(fw_result.get("findings", [])),
            controls_affected=fw_result.get("findings", []),
            gap_score=None,
            remediation_priority=[],
            status=fw_result.get("status", "evaluated"),
            message=f"Evaluated via ComplianceEngine — threshold: {fw_result.get('threshold', 'N/A')}",
        )

    return ComplianceMappingResponse(
        framework=framework,
        controls_mapped=0,
        controls_affected=[],
        gap_score=None,
        remediation_priority=[],
        status="integration_required",
        message="Compliance mapping requires ComplianceEngine + control configuration.",
    )


@router.post("/compliance/gap-analysis")
async def run_gap_analysis(request: GapAnalysisRequest) -> Dict[str, Any]:
    """Run compliance gap analysis for a framework.

    Uses :class:`ComplianceEngine` with an empty findings list to show
    the baseline gap (no evidence → everything is a gap).
    """
    fw = request.framework.value

    if _COMPLIANCE_ENGINE_AVAILABLE and compliance_engine is not None:
        # Evaluate with no findings to surface baseline status
        result = compliance_engine.evaluate([fw], [])
        fw_result = result.get(fw, {})
        return {
            "framework": fw,
            "analysis_date": _now().isoformat(),
            "status": fw_result.get("status", "evaluated"),
            "threshold": fw_result.get("threshold"),
            "highest_fixops_severity": fw_result.get("highest_fixops_severity"),
            "message": "Gap analysis via ComplianceEngine — upload findings for detailed results.",
            "overall_score": None,
            "control_families": [],
            "critical_gaps": [],
        }

    return {
        "framework": fw,
        "analysis_date": _now().isoformat(),
        "status": "integration_required",
        "message": "Gap analysis requires ComplianceEngine + control baseline data.",
        "integration_required": True,
        "requirements": [
            "ComplianceEngine module",
            "Framework control definitions",
            "Current control implementation status",
        ],
        "overall_score": None,
        "control_families": [],
        "critical_gaps": [],
    }


@router.post("/compliance/audit-evidence")
async def collect_audit_evidence(request: AuditEvidenceRequest) -> Dict[str, Any]:
    """Collect and package evidence for auditors.

    Evidence Lake integration provides cryptographic audit trail when
    the database is configured.
    """
    evidence_package_id = _generate_id()

    return {
        "package_id": evidence_package_id,
        "framework": request.framework.value,
        "controls_covered": len(request.controls) if request.controls else 0,
        "status": "integration_required",
        "integration_required": True,
        "message": "Evidence collection requires Evidence Lake database + scan report sources.",
        "evidence_items": [],
        "supported_sources": [
            "Vulnerability scan reports (SARIF/CycloneDX)",
            "Remediation tracking (Jira/ServiceNow)",
            "Access review logs",
        ],
        "format": request.format,
    }


@router.post("/compliance/regulatory-alerts")
async def check_regulatory_alerts(request: RegulatoryAlertRequest) -> Dict[str, Any]:
    """Check for regulatory updates and alerts.

    Requires external regulatory feed subscription.
    """
    return {
        "status": "integration_required",
        "integration_required": True,
        "message": "Regulatory alert monitoring requires feed subscription.",
        "alerts": [],
        "industries": request.industries,
        "jurisdictions": request.jurisdictions,
        "supported_feeds": [
            "SEC EDGAR (US)",
            "FCA Handbook (UK)",
            "ESMA (EU)",
            "APRA (Australia)",
        ],
        "last_updated": None,
    }


@router.get("/compliance/controls/{framework}")
async def get_framework_controls(
    framework: ComplianceFramework,
    category: Optional[str] = None,
) -> Dict[str, Any]:
    """Get all controls for a compliance framework.

    Note: Returns framework metadata - full control library requires enterprise integration.
    """
    # TODO: Integrate with full compliance control library
    # These are metadata about available frameworks, not actual control data

    framework_info = {
        ComplianceFramework.PCI_DSS: {
            "name": "PCI-DSS v4.0",
            "total_controls": 64,
            "categories": [
                "Network",
                "Access Control",
                "Vulnerability",
                "Testing",
                "Encryption",
            ],
            "source": "https://www.pcisecuritystandards.org/",
        },
        ComplianceFramework.SOC2: {
            "name": "SOC 2 Type II",
            "total_controls": 117,
            "categories": [
                "Security",
                "Availability",
                "Processing Integrity",
                "Confidentiality",
                "Privacy",
            ],
            "source": "https://www.aicpa.org/",
        },
        ComplianceFramework.ISO27001: {
            "name": "ISO/IEC 27001:2022",
            "total_controls": 93,
            "categories": ["Organizational", "People", "Physical", "Technological"],
            "source": "https://www.iso.org/",
        },
        ComplianceFramework.HIPAA: {
            "name": "HIPAA Security Rule",
            "total_controls": 54,
            "categories": ["Administrative", "Physical", "Technical"],
            "source": "https://www.hhs.gov/hipaa/",
        },
        ComplianceFramework.NIST: {
            "name": "NIST CSF 2.0",
            "total_controls": 108,
            "categories": [
                "Govern",
                "Identify",
                "Protect",
                "Detect",
                "Respond",
                "Recover",
            ],
            "source": "https://www.nist.gov/cyberframework",
        },
    }

    info = framework_info.get(framework, {})

    return {
        "framework": framework.value,
        "framework_info": info,
        "controls": [],  # Full controls require enterprise integration
        "status": "metadata_only",
        "message": "Framework metadata available. Full control library requires enterprise compliance module integration.",
        "category_filter": category,
    }


@router.get("/compliance/dashboard")
async def get_compliance_dashboard() -> Dict[str, Any]:
    """Get compliance dashboard overview.

    When ComplianceEngine is available, shows baseline posture for all
    configured frameworks.
    """
    if _COMPLIANCE_ENGINE_AVAILABLE and compliance_engine is not None:
        supported = list(compliance_engine.framework_thresholds.keys())
        # Evaluate each supported framework with no findings → baseline
        framework_status = []
        for fw in supported:
            res = compliance_engine.evaluate([fw], [])
            fw_res = res.get(fw, {})
            framework_status.append(
                {
                    "framework": fw,
                    "status": fw_res.get("status", "unknown"),
                    "threshold": fw_res.get("threshold"),
                }
            )
        return {
            "status": "ready",
            "message": "Baseline posture — upload findings for detailed assessment.",
            "overall_posture": "no_findings_uploaded",
            "frameworks": framework_status,
            "open_gaps": 0,
            "critical_gaps": 0,
        }

    return {
        "status": "integration_required",
        "integration_required": True,
        "message": "Compliance dashboard requires ComplianceEngine + baseline assessments.",
        "overall_posture": None,
        "frameworks": [],
        "open_gaps": 0,
        "critical_gaps": 0,
    }


@router.post("/compliance/generate-report")
async def generate_compliance_report(
    framework: ComplianceFramework,
    report_type: str = "executive",
    include_evidence: bool = True,
) -> Dict[str, Any]:
    """Generate compliance report.

    When ComplianceEngine is available, generates a baseline report.
    """
    report_id = _generate_id()
    fw = framework.value

    if _COMPLIANCE_ENGINE_AVAILABLE and compliance_engine is not None:
        result = compliance_engine.evaluate([fw], [])
        fw_result = result.get(fw, {})
        return {
            "report_id": report_id,
            "framework": fw,
            "report_type": report_type,
            "status": "generated",
            "message": "Baseline report — upload findings for full compliance report.",
            "compliance_status": fw_result.get("status"),
            "threshold": fw_result.get("threshold"),
            "include_evidence": include_evidence,
        }

    return {
        "report_id": report_id,
        "framework": fw,
        "report_type": report_type,
        "status": "integration_required",
        "integration_required": True,
        "message": "Report generation requires ComplianceEngine + completed assessment.",
    }


# =============================================================================
# Remediation Agent Endpoints (7 APIs)
# Note: Remediation suggestions require LLM/code analysis integration
# =============================================================================


@router.post("/remediation/generate-fix")
async def generate_fix(request: GenerateFixRequest) -> Dict[str, Any]:
    """Generate fix code for a vulnerability via AI.

    Note: AI fix generation requires LLM integration.
    """
    # TODO: Integrate with LLM for code fix generation

    return {
        "finding_id": request.finding_id,
        "status": "integration_required",
        "integration_required": True,
        "message": "AI fix generation requires LLM API key (set OPENAI_API_KEY or ANTHROPIC_API_KEY).",
        "requirements": [
            "LLM API key (OpenAI / Anthropic / Azure OpenAI)",
            "Vulnerability context (affected code)",
            "Language/framework detection",
        ],
        "language": request.language or "unknown",
        "original_code": None,
        "fixed_code": None,
        "include_tests": request.include_tests,
    }


@router.post("/remediation/create-pr")
async def create_pull_request(request: CreatePRRequest) -> Dict[str, Any]:
    """Create a pull request with security fixes.

    Note: Requires GitHub/GitLab integration.
    """
    # TODO: Integrate with Git provider APIs

    return {
        "status": "integration_required",
        "integration_required": True,
        "message": "PR creation requires Git provider API token (set GITHUB_TOKEN or GITLAB_TOKEN).",
        "requirements": [
            "GitHub/GitLab API token",
            "Repository access permissions",
            "Branch protection configuration",
        ],
        "repository": request.repository,
        "branch": request.branch,
        "finding_ids": request.finding_ids,
    }


@router.post("/remediation/update-dependencies")
async def update_dependencies(request: DependencyUpdateRequest) -> Dict[str, Any]:
    """Update vulnerable dependencies.

    Note: Requires SBOM and package manager integration.
    """
    # TODO: Integrate with package managers

    return {
        "sbom_id": request.sbom_id,
        "status": "integration_required",
        "integration_required": True,
        "message": "Dependency updates require package manager integration.",
        "requirements": [
            "SBOM with vulnerability mappings",
            "Package manager access (npm, pip, maven)",
            "Repository write access",
        ],
        "packages_requested": request.package_ids,
        "strategy": request.update_strategy,
    }


@router.post("/remediation/playbook")
async def generate_playbook(request: PlaybookRequest) -> Dict[str, Any]:
    """Generate remediation playbook.

    Note: Playbook generation requires finding context and remediation knowledge base.
    """
    # TODO: Integrate with remediation knowledge base

    playbook_id = _generate_id()

    return {
        "playbook_id": playbook_id,
        "status": "integration_required",
        "integration_required": True,
        "message": "Playbook generation requires remediation knowledge base + LLM integration.",
        "findings_count": len(request.finding_ids),
        "audience": request.audience,
        "requirements": [
            "Finding details with vulnerability type",
            "Remediation pattern database",
            "LLM API key for procedure generation",
        ],
        "include_rollback": request.include_rollback,
    }


@router.get("/remediation/recommendations/{finding_id}")
async def get_recommendations(finding_id: str) -> Dict[str, Any]:
    """Get remediation recommendations for a finding.

    Note: Requires finding details to generate specific recommendations.
    """
    # TODO: Integrate with finding details and remediation database

    return {
        "finding_id": finding_id,
        "status": "integration_required",
        "integration_required": True,
        "message": "Recommendations require finding details lookup + vulnerability database.",
        "recommendations": [],
        "requirements": [
            "Finding vulnerability type",
            "Affected component details",
            "Remediation options database",
        ],
    }


@router.post("/remediation/verify")
async def verify_remediation(
    finding_ids: List[str],
    verification_type: str = "scan",
) -> Dict[str, Any]:
    """Verify remediation was successful.

    Note: Requires re-scan or validation check integration.
    """
    # TODO: Integrate with scanning tools for verification

    return {
        "verification_id": _generate_id(),
        "status": "integration_required",
        "integration_required": True,
        "message": "Verification requires scanner integration (set SCANNER_API_URL).",
        "findings_to_verify": finding_ids,
        "verification_type": verification_type,
        "requirements": [
            "Scanner API access (Snyk/Qualys/Nessus)",
            "Target system reachability",
            "Baseline scan results",
        ],
    }


@router.get("/remediation/queue")
async def get_remediation_queue(
    priority: Optional[TaskPriority] = None,
    assignee: Optional[str] = None,
    limit: int = Query(default=20, le=100),
) -> Dict[str, Any]:
    """Get remediation queue/backlog.

    Note: Requires remediation tracking database.
    """
    # TODO: Integrate with remediation tracking database

    return {
        "status": "integration_required",
        "integration_required": True,
        "message": "Remediation queue requires tracking database (set DATABASE_URL).",
        "queue": [],
        "requirements": [
            "Remediation tracking database (Postgres/SQLite)",
            "Finding assignment workflow",
            "SLA configuration",
        ],
        "filters_applied": {
            "priority": priority.value if priority else None,
            "assignee": assignee,
            "limit": limit,
        },
    }


# =============================================================================
# Orchestrator Agent Endpoints (1 API)
# =============================================================================


@router.post("/orchestrate")
async def orchestrate_agents(
    request: OrchestrateRequest,
    background_tasks: BackgroundTasks,
) -> AgentTaskResponse:
    """Orchestrate multiple agents for complex objectives.

    The orchestrator coordinates between specialist agents
    to achieve complex security objectives autonomously.

    Note: Full orchestration requires all agent integrations.
    """
    task_id = _generate_id()

    # Check which agents are available
    agents_available = []
    agents_pending = []

    for agent in request.agents:
        if agent == AgentType.SECURITY_ANALYST:
            if _get_feeds_service():
                agents_available.append(agent.value)
            else:
                agents_pending.append(agent.value)
        elif agent == AgentType.PENTEST:
            if MPTE_TOKEN:
                agents_available.append(agent.value)
            else:
                agents_pending.append(agent.value)
        else:
            agents_pending.append(agent.value)

    task = {
        "task_id": task_id,
        "agent": AgentType.ORCHESTRATOR,
        "status": AgentStatus.WAITING if agents_pending else AgentStatus.EXECUTING,
        "created_at": _now(),
        "result": {
            "objective": request.objective,
            "agents_available": agents_available,
            "agents_pending_configuration": agents_pending,
            "message": "Orchestration ready"
            if not agents_pending
            else f"Waiting for agent configurations: {agents_pending}",
        },
        "error": None,
    }
    _agent_tasks[task_id] = task

    return AgentTaskResponse(**task)


# =============================================================================
# Agent Status & Health Endpoints
# =============================================================================


@router.get("/status")
async def get_agents_status() -> Dict[str, Any]:
    """Get status of all agents with real integration status."""
    feeds_service = _get_feeds_service()
    mpte_available = bool(MPTE_TOKEN)

    return {
        "agents": {
            AgentType.SECURITY_ANALYST.value: {
                "status": "ready" if feeds_service else "pending_configuration",
                "feeds_service": "connected" if feeds_service else "not_configured",
                "data_sources": ["EPSS", "CISA KEV"] if feeds_service else [],
            },
            AgentType.PENTEST.value: {
                "status": "ready" if mpte_available else "pending_configuration",
                "mpte": "configured" if mpte_available else "not_configured",
                "mpte_url": MPTE_URL,
            },
            AgentType.COMPLIANCE.value: {
                "status": "ready"
                if _COMPLIANCE_ENGINE_AVAILABLE
                else "integration_required",
                "compliance_engine": "connected"
                if _COMPLIANCE_ENGINE_AVAILABLE
                else "not_available",
                "supported_frameworks": list(
                    compliance_engine.framework_thresholds.keys()
                )
                if _COMPLIANCE_ENGINE_AVAILABLE and compliance_engine
                else [],
            },
            AgentType.REMEDIATION.value: {
                "status": "integration_required",
                "message": "Requires LLM API key and Git provider token",
            },
            AgentType.ORCHESTRATOR.value: {
                "status": "ready",
                "message": "Coordinates available agents",
            },
        },
        "feeds_service": "connected" if feeds_service else "not_configured",
        "mpte_connection": "configured" if mpte_available else "not_configured",
    }


@router.get("/tasks/{task_id}")
async def get_task(task_id: str) -> AgentTaskResponse:
    """Get status of any agent task."""
    if task_id not in _agent_tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    return AgentTaskResponse(**_agent_tasks[task_id])


@router.get("/health")
async def agents_health() -> Dict[str, str]:
    """Agent system health check."""
    return {
        "status": "healthy",
        "service": "aldeci-copilot-agents",
        "version": "1.0.0",
    }
