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

from apps.api.dependencies import get_org_id
from core.persistent_store import get_persistent_store
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field

# Optional httpx import for MPTE integration
try:
    import httpx

    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

try:
    from core.tls_config import tls_verify
except ImportError:

    def tls_verify():
        return os.environ.get("FIXOPS_TLS_VERIFY", "true").lower() != "false"


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

# Import AnalyticsDB for findings queries
try:
    from core.analytics_db import AnalyticsDB

    _ANALYTICS_DB_AVAILABLE = True
except ImportError:
    _ANALYTICS_DB_AVAILABLE = False
    logger.warning("AnalyticsDB not available - some agent endpoints limited")

# Import KnowledgeBrain for graph traversal
try:
    from core.knowledge_brain import get_brain

    _BRAIN_AVAILABLE = True
except ImportError:
    _BRAIN_AVAILABLE = False
    logger.warning("KnowledgeBrain not available - attack path / risk scoring limited")

# Import AutoFixEngine for remediation
try:
    from core.autofix_engine import get_autofix_engine

    _AUTOFIX_AVAILABLE = True
except ImportError:
    _AUTOFIX_AVAILABLE = False
    logger.warning("AutoFixEngine not available - remediation endpoints limited")

# Import PlaybookRunner for playbook generation
try:
    from core.playbook_runner import PlaybookRunner

    _PLAYBOOK_AVAILABLE = True
except ImportError:
    _PLAYBOOK_AVAILABLE = False
    logger.warning("PlaybookRunner not available - playbook endpoints limited")

# Import micro_pentest for local pentest fallback when MPTE is unavailable
try:
    from core.micro_pentest import MicroPentestConfig, run_micro_pentest

    _MICRO_PENTEST_AVAILABLE = True
except ImportError:
    _MICRO_PENTEST_AVAILABLE = False
    logger.warning("micro_pentest not available - pentest local fallback disabled")

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


# Initialize analytics DB singleton
_analytics_db = None


def _get_analytics_db():
    """Get or create AnalyticsDB instance."""
    global _analytics_db
    if _analytics_db is None and _ANALYTICS_DB_AVAILABLE:
        _analytics_db = AnalyticsDB()
    return _analytics_db


def _get_brain():
    """Get KnowledgeBrain instance."""
    if _BRAIN_AVAILABLE:
        return get_brain()
    return None


def _get_autofix():
    """Get AutoFixEngine instance."""
    if _AUTOFIX_AVAILABLE:
        return get_autofix_engine()
    return None


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


# Persistent task storage — survives restarts
_agent_tasks = get_persistent_store("agent_tasks")


# =============================================================================
# Security Analyst Agent Endpoints (7 APIs)
# =============================================================================


@router.post("/analyst/analyze", response_model=AgentTaskResponse)
async def analyze_vulnerability(
    request: AnalyzeVulnRequest,
    background_tasks: BackgroundTasks,
    org_id: str = Depends(get_org_id),
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
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
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
    _agent_tasks.persist(task_id)


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
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.warning("Threat intel lookup failed for %s: %s", cve, type(e).__name__)
                intel["error"] = type(e).__name__

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
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
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
    """Analyze attack paths to/from an asset using KnowledgeBrain graph.

    Uses KnowledgeBrain.get_neighbors() and find_paths() for real graph
    traversal when nodes exist. Falls back to AnalyticsDB for finding context.
    """
    brain = _get_brain()

    if brain:
        try:
            # Get the node and its neighborhood
            node = brain.get_node(request.asset_id)
            neighbors = brain.get_neighbors(
                request.asset_id,
                depth=min(request.depth, 5),
                edge_types=None,
            )

            attack_paths: List[Dict[str, Any]] = []
            if neighbors and neighbors.nodes:
                # Build attack path entries from graph edges
                for n in neighbors.nodes:
                    if n and n.get("node_id") != request.asset_id:
                        ntype = n.get("node_type", "unknown")
                        risk = brain.risk_score_for_node(n["node_id"])
                        attack_paths.append(
                            {
                                "node_id": n["node_id"],
                                "node_type": ntype,
                                "risk_score": round(risk, 3),
                                "properties": n.get("properties", {}),
                            }
                        )

                # Sort by risk descending
                attack_paths.sort(key=lambda x: x["risk_score"], reverse=True)

            asset_risk = brain.risk_score_for_node(request.asset_id)
            return {
                "asset_id": request.asset_id,
                "status": "analyzed",
                "asset_found": node is not None,
                "asset_risk_score": round(asset_risk, 3),
                "message": f"Graph traversal found {len(attack_paths)} connected nodes at depth {request.depth}.",
                "attack_paths": attack_paths[:20],  # Cap
                "total_connected_nodes": len(attack_paths),
                "depth_requested": request.depth,
                "include_lateral": request.include_lateral,
            }
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.error(f"Attack path analysis failed: {e}")
            return {
                "asset_id": request.asset_id,
                "status": "error",
                "message": f"Graph traversal failed: {e}",
                "attack_paths": [],
            }

    return {
        "asset_id": request.asset_id,
        "status": "engine_unavailable",
        "message": "KnowledgeBrain not available — load graph data first.",
        "attack_paths": [],
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
            import sqlite3
            conn = sqlite3.connect(feeds_service.db_path)
            conn.row_factory = sqlite3.Row
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
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
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

    Uses KnowledgeBrain graph risk scoring (node type, severity, connectivity)
    and enriches with AnalyticsDB finding counts when available.
    """
    brain = _get_brain()
    analytics = _get_analytics_db()

    risk_score: Optional[float] = None
    risk_grade = "unknown"
    open_findings = 0
    node_info: Optional[Dict[str, Any]] = None

    if brain:
        try:
            node_info = brain.get_node(asset_id)
            raw_score = brain.risk_score_for_node(asset_id)
            # Convert 0-1 scale to 0-10 scale
            risk_score = round(raw_score * 10.0, 1)

            # Determine grade from score
            if risk_score >= 9.0:
                risk_grade = "A"  # Critical
            elif risk_score >= 7.0:
                risk_grade = "B"  # High
            elif risk_score >= 4.0:
                risk_grade = "C"  # Medium
            elif risk_score >= 2.0:
                risk_grade = "D"  # Low
            else:
                risk_grade = "F"  # Minimal

            # Count connected edges for context
            edges = brain.get_edges(asset_id)
            connected_count = len(edges) if edges else 0
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning(f"Brain risk scoring for {asset_id}: {e}")
            connected_count = 0
    else:
        connected_count = 0

    # Count real findings from AnalyticsDB
    if analytics:
        try:
            findings = analytics.list_findings(status="open", limit=1000, offset=0)
            # Count findings that reference this asset
            for f in findings:
                fd = f.to_dict()
                if (
                    fd.get("application_id") == asset_id
                    or fd.get("service_id") == asset_id
                    or asset_id in (fd.get("metadata") or "")
                ):
                    open_findings += 1
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug(f"Finding count for {asset_id}: {e}")

    return {
        "asset_id": asset_id,
        "status": "scored" if risk_score is not None else "no_graph_data",
        "message": f"Risk score {risk_score}/10 (grade {risk_grade})"
        if risk_score is not None
        else "Asset not found in KnowledgeBrain — ingest graph data first.",
        "risk_score": risk_score,
        "risk_grade": risk_grade,
        "open_findings": open_findings,
        "connected_nodes": connected_count,
        "node_type": node_info.get("node_type") if node_info else None,
        "trend": "stable",  # Would need historical data for real trend
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
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning("CVE analysis failed for %s: %s", cve_id, type(e).__name__)
            threat_intel = {"error": type(e).__name__}

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
        async with httpx.AsyncClient(verify=tls_verify(), timeout=30.0) as client:
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
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.warning("MPTE API call failed: %s", type(e).__name__)
        return {"success": False, "error": type(e).__name__}


@router.post("/pentest/validate", response_model=AgentTaskResponse)
async def validate_exploit(
    request: ValidateExploitRequest,
    background_tasks: BackgroundTasks,
    org_id: str = Depends(get_org_id),
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
    _agent_tasks.persist(task_id)


@router.post("/pentest/generate-poc")
async def generate_poc(request: GeneratePocRequest) -> Dict[str, Any]:
    """Generate proof-of-concept verification code for a CVE.

    Strategy: MPTE first → local FeedsService CVE-based PoC template → error.
    """

    # Try MPTE first (full MPTE engine can produce advanced PoCs)
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

    # Fallback: generate safe verification script from CVE metadata
    feeds_service = _get_feeds_service()
    cve_description = ""
    epss_score = 0.0
    kev_listed = False

    if feeds_service:
        try:
            epss_data = feeds_service.get_epss_score(request.cve_id)
            if epss_data:
                epss_score = epss_data.epss
            kev_entry = feeds_service.get_kev_entry(request.cve_id)
            if kev_entry:
                kev_listed = True
                cve_description = kev_entry.vulnerability_name or ""
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning(f"FeedsService lookup failed for PoC generation: {e}")

    # Build a safe verification template based on language
    poc_templates = {
        "python": (
            f"#!/usr/bin/env python3\n"
            f'"""Safe verification script for {request.cve_id}"""\n'
            f"import requests\n"
            f"import sys\n\n"
            f"TARGET = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080'\n\n"
            f"def verify_{request.cve_id.replace('-', '_').lower()}(target: str) -> dict:\n"
            f'    """Check if target is vulnerable to {request.cve_id}."""\n'
            f"    # SAFE: This only checks version/headers, does NOT exploit\n"
            f"    try:\n"
            f"        resp = requests.get(target, timeout=10, verify=True)\n"  # nosemgrep: dynamic-urllib-use-detected
            f"        headers = dict(resp.headers)\n"
            f"        return {{\n"
            f"            'cve_id': '{request.cve_id}',\n"
            f"            'target': target,\n"
            f"            'status_code': resp.status_code,\n"
            f"            'server': headers.get('Server', 'unknown'),\n"
            f"            'security_headers': {{\n"
            f"                'x_content_type_options': 'X-Content-Type-Options' in headers,\n"
            f"                'x_frame_options': 'X-Frame-Options' in headers,\n"
            f"                'strict_transport_security': 'Strict-Transport-Security' in headers,\n"
            f"            }},\n"
            f"            'verdict': 'NEEDS_MANUAL_REVIEW',\n"
            f"        }}\n"
            f"    except Exception as e:\n"
            f"        return {{'cve_id': '{request.cve_id}', 'error': str(e)}}\n\n"
            f"if __name__ == '__main__':\n"
            f"    import json\n"
            f"    print(json.dumps(verify_{request.cve_id.replace('-', '_').lower()}(TARGET), indent=2))\n"
        ),
        "bash": (
            f"#!/usr/bin/env bash\n"
            f"# Safe verification script for {request.cve_id}\n"
            f'TARGET="${{1:-http://localhost:8080}}"\n'
            f'echo "[*] Checking $TARGET for {request.cve_id}..."\n'
            f"HTTP_CODE=$(curl -sk -o /dev/null -w '%{{http_code}}' \"$TARGET\")\n"
            f"SERVER=$(curl -sk -I \"$TARGET\" | grep -i '^Server:' | cut -d' ' -f2-)\n"
            f'echo "[*] HTTP: $HTTP_CODE | Server: $SERVER"\n'
            f'echo "[*] Verdict: NEEDS_MANUAL_REVIEW"\n'
        ),
        "go": (
            f"package main\n\n"
            f'import (\n\t"crypto/tls"\n\t"fmt"\n\t"net/http"\n\t"os"\n)\n\n'
            f"// Safe verification for {request.cve_id}\n"
            f"func main() {{\n"
            f'\ttarget := "http://localhost:8080"\n'
            f"\tif len(os.Args) > 1 {{ target = os.Args[1] }}\n"
            f"\tclient := &http.Client{{Transport: &http.Transport{{TLSClientConfig: &tls.Config{{InsecureSkipVerify: true}}}}}}\n"
            f"\tresp, err := client.Get(target)\n"
            f'\tif err != nil {{ fmt.Println("Error:", err); return }}\n'
            f"\tdefer resp.Body.Close()\n"
            f'\tfmt.Printf("[*] %s — HTTP %d — Server: %s\\n", "{request.cve_id}", resp.StatusCode, resp.Header.Get("Server"))\n'
            f"}}\n"
        ),
    }

    lang = request.language.lower()
    poc_code = poc_templates.get(lang, poc_templates["python"])

    return {
        "cve_id": request.cve_id,
        "language": lang,
        "safe_poc": request.safe_poc,
        "status": "generated",
        "source": "local_template",
        "poc_code": poc_code,
        "epss_score": epss_score,
        "kev_listed": kev_listed,
        "description": cve_description
        or f"Safe verification template for {request.cve_id}",
        "warning": "This is a safe verification script — it checks for indicators only, does NOT exploit.",
    }


@router.post("/pentest/reachability")
async def check_reachability(request: ReachabilityRequest) -> Dict[str, Any]:
    """Check if vulnerability is reachable from attack surface.

    Strategy: MPTE first → KnowledgeBrain graph traversal → error.
    """
    # Try MPTE for full network-level reachability analysis
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

    # Fallback: use KnowledgeBrain graph to check reachability
    brain = _get_brain()
    reachability_results = []

    if brain:
        try:
            for asset_id in request.asset_ids:
                node = brain.get_node(asset_id)
                if node is None:
                    reachability_results.append(
                        {
                            "asset_id": asset_id,
                            "reachable": False,
                            "reason": "asset_not_in_graph",
                            "confidence": 0.0,
                        }
                    )
                    continue

                # Check if CVE node exists and if there's a path to the asset
                cve_node = brain.get_node(request.cve_id)
                neighbors = brain.get_neighbors(asset_id)
                neighbor_ids = [n.get("id", "") for n in neighbors] if neighbors else []

                # Check for direct or 1-hop connection to CVE
                is_reachable = cve_node is not None and request.cve_id in neighbor_ids

                # For deep analysis, also check risk score as proxy for exposure
                risk_score = brain.risk_score_for_node(asset_id)

                reachability_results.append(
                    {
                        "asset_id": asset_id,
                        "reachable": is_reachable,
                        "risk_score": round(risk_score * 10.0, 1),
                        "neighbor_count": len(neighbor_ids),
                        "cve_in_graph": cve_node is not None,
                        "confidence": 0.7 if is_reachable else 0.5,
                        "method": "knowledge_graph_traversal",
                    }
                )
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning(f"KnowledgeBrain reachability check failed: {e}")
            reachability_results = [
                {
                    "asset_id": aid,
                    "reachable": False,
                    "reason": f"graph_error: {e}",
                    "confidence": 0.0,
                }
                for aid in request.asset_ids
            ]

        return {
            "cve_id": request.cve_id,
            "assets_analyzed": len(request.asset_ids),
            "status": "analyzed",
            "source": "knowledge_graph",
            "reachability_results": reachability_results,
            "depth": request.depth,
            "note": "Graph-based analysis. For network-level reachability, connect MPTE.",
        }

    # Neither MPTE nor KnowledgeBrain available
    # Tier 3: Sandboxed reachability probes (Docker-isolated network checks)
    try:
        from core.sandbox_verifier import SandboxedReachabilityProbe

        probe = SandboxedReachabilityProbe()
        if probe.docker_available:
            # Use asset_ids as probe targets (may be URLs or host:port)
            probe_results = probe.probe_multiple(request.asset_ids)
            return {
                "cve_id": request.cve_id,
                "assets_analyzed": len(request.asset_ids),
                "status": "analyzed",
                "source": "sandboxed_probe",
                "reachability_results": [
                    {
                        "asset_id": request.asset_ids[i] if i < len(request.asset_ids) else "",
                        "reachable": r.reachable,
                        "http_status": r.http_status,
                        "open_ports": r.open_ports,
                        "tls_valid": r.tls_valid,
                        "server_header": r.server_header,
                        "latency_ms": r.latency_ms,
                        "confidence": r.confidence,
                        "method": "sandboxed_docker_probe",
                        "evidence_hash": r.evidence_hash,
                    }
                    for i, r in enumerate(probe_results)
                ],
                "depth": request.depth,
                "note": "Network-level reachability via Docker sandbox. MPTE and KnowledgeBrain unavailable.",
            }
    except ImportError:
        pass
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.warning(f"Sandboxed reachability probe failed: {e}")

    # Tier 4: Nothing available
    return {
        "cve_id": request.cve_id,
        "assets_analyzed": len(request.asset_ids),
        "status": "engine_unavailable",
        "reachability_results": [],
        "depth": request.depth,
        "message": "Neither MPTE, KnowledgeBrain, nor Docker sandbox available for reachability analysis.",
    }


@router.post("/pentest/simulate")
async def simulate_attack(
    request: SimulateAttackRequest,
    background_tasks: BackgroundTasks,
    org_id: str = Depends(get_org_id),
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
    """Get evidence collected during pentest.

    Strategy: MPTE first → AnalyticsDB local lookup → not_found.
    """

    # Try MPTE for real evidence
    mpte_result = await _call_mpte_api(f"pentest/evidence/{evidence_id}", method="GET")

    if mpte_result["success"]:
        return mpte_result["data"]

    # Fallback: look up evidence in AnalyticsDB
    analytics = _get_analytics_db()
    if analytics:
        try:
            # Try to find the evidence as a finding in AnalyticsDB
            finding = analytics.get_finding(evidence_id)
            if finding:
                finding_dict = finding.to_dict()
                return {
                    "evidence_id": evidence_id,
                    "status": "found",
                    "source": "analytics_db",
                    "finding": finding_dict,
                    "artifacts": [
                        {
                            "type": "finding_record",
                            "id": evidence_id,
                            "severity": finding_dict.get("severity", "unknown"),
                            "title": finding_dict.get("title", ""),
                            "description": finding_dict.get("description", ""),
                        }
                    ],
                    "collected_at": _now().isoformat(),
                }
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning(f"AnalyticsDB evidence lookup failed: {e}")

    # Neither source has the evidence
    return {
        "evidence_id": evidence_id,
        "status": "not_found",
        "artifacts": [],
        "message": f"No evidence found for ID '{evidence_id}'. Evidence may not have been collected yet.",
    }


@router.post("/pentest/schedule")
async def schedule_pentest(
    target_ids: List[str],
    cve_ids: List[str],
    background_tasks: BackgroundTasks,
    schedule: str = "immediate",
    notification_emails: List[str] = None,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Schedule a pentest campaign.

    Strategy: MPTE first → local micro_pentest for immediate → queued for deferred.
    """

    # Try MPTE for full campaign management
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

    campaign_id = _generate_id()

    # Fallback: for immediate schedule, run local micro_pentest
    if schedule == "immediate" and _MICRO_PENTEST_AVAILABLE:
        try:
            # Use target_ids as target URLs (assets may be URLs or hostnames)
            urls = [
                tid if tid.startswith(("http://", "https://")) else f"https://{tid}"
                for tid in target_ids
            ]
            config = MicroPentestConfig()

            async def _run_campaign() -> None:
                """Background task to run the pentest campaign."""
                try:
                    result = await run_micro_pentest(
                        cve_ids=cve_ids,
                        target_urls=urls,
                        config=config,
                    )
                    logger.info(
                        f"Pentest campaign {campaign_id} completed: {result.status}"
                    )
                except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                    logger.error(f"Pentest campaign {campaign_id} failed: {exc}")

            background_tasks.add_task(_run_campaign)

            return {
                "campaign_id": campaign_id,
                "targets": len(target_ids),
                "cves_to_validate": len(cve_ids),
                "schedule": schedule,
                "status": "running",
                "source": "local_micro_pentest",
                "message": "Campaign started via local micro-pentest engine.",
                "notification_emails": notification_emails or [],
            }
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning(f"Local micro_pentest scheduling failed: {e}")

    # Deferred schedule or no local engine available — record the request
    return {
        "campaign_id": campaign_id,
        "targets": len(target_ids),
        "cves_to_validate": len(cve_ids),
        "schedule": schedule,
        "status": "queued",
        "message": f"Campaign queued for '{schedule}' execution. MPTE required for full scheduling.",
        "notification_emails": notification_emails or [],
    }


# =============================================================================
# Compliance Agent Endpoints (7 APIs)
# Note: Compliance data requires integration with policy engine and evidence store
# =============================================================================


@router.post("/compliance/map-findings", response_model=ComplianceMappingResponse)
async def map_findings_to_compliance(
    request: MapFindingsRequest,
    org_id: str = Depends(get_org_id),
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

    Uses ComplianceEngine with real findings from AnalyticsDB to produce
    an accurate gap analysis rather than a baseline-only view.
    """
    fw = request.framework.value

    if _COMPLIANCE_ENGINE_AVAILABLE and compliance_engine is not None:
        # Pull real findings from AnalyticsDB for accurate gap analysis
        analytics = _get_analytics_db()
        finding_dicts = []
        if analytics:
            findings = analytics.list_findings(limit=1000, offset=0)
            finding_dicts = [f.to_dict() for f in findings]

        result = compliance_engine.evaluate([fw], finding_dicts)
        fw_result = result.get(fw, {})

        # Calculate gap metrics from evaluation
        normalized = fw_result.get("findings", [])
        critical_gaps = [
            f for f in normalized if f.get("fixops_severity") in ("HIGH", "CRITICAL")
        ]
        total = len(finding_dicts)
        resolved = sum(
            1 for f in finding_dicts if f.get("status") in ("resolved", "RESOLVED")
        )
        score = round((resolved / total * 100) if total > 0 else 0.0, 1)

        return {
            "framework": fw,
            "analysis_date": _now().isoformat(),
            "status": fw_result.get("status", "evaluated"),
            "threshold": fw_result.get("threshold"),
            "highest_fixops_severity": fw_result.get("highest_fixops_severity"),
            "message": f"Gap analysis complete — {total} findings evaluated, {len(critical_gaps)} critical gaps.",
            "overall_score": score,
            "total_findings": total,
            "resolved_findings": resolved,
            "control_families": [],
            "critical_gaps": [
                {"id": g.get("id"), "severity": g.get("fixops_severity")}
                for g in critical_gaps[:20]
            ],
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

    Pulls real findings from AnalyticsDB, evaluates them against the
    requested compliance framework, and packages results as audit evidence.
    """
    evidence_package_id = _generate_id()
    fw = request.framework.value
    analytics = _get_analytics_db()

    evidence_items: List[Dict[str, Any]] = []
    compliance_result = None

    if analytics:
        # Pull real findings as evidence artifacts
        findings = analytics.list_findings(limit=500, offset=0)
        for f in findings:
            fd = f.to_dict()
            evidence_items.append(
                {
                    "evidence_id": fd.get("id", _generate_id()),
                    "type": "vulnerability_finding",
                    "title": fd.get("title", "Unknown"),
                    "severity": fd.get("severity", "unknown"),
                    "status": fd.get("status", "open"),
                    "source": fd.get("source", "scanner"),
                    "cve_id": fd.get("cve_id"),
                    "created_at": fd.get("created_at"),
                    "resolved_at": fd.get("resolved_at"),
                }
            )

        # Run compliance evaluation on findings
        if _COMPLIANCE_ENGINE_AVAILABLE and compliance_engine is not None:
            finding_dicts = [f.to_dict() for f in findings]
            result = compliance_engine.evaluate([fw], finding_dicts)
            compliance_result = result.get(fw, {})

    return {
        "package_id": evidence_package_id,
        "framework": fw,
        "controls_covered": len(request.controls) if request.controls else 0,
        "status": "collected" if evidence_items else "no_findings",
        "message": f"Collected {len(evidence_items)} evidence items for {fw} audit."
        if evidence_items
        else "No findings in database — upload scan results first.",
        "total_evidence_items": len(evidence_items),
        "evidence_items": evidence_items[:50],  # Cap response size
        "compliance_evaluation": compliance_result,
        "format": request.format,
        "generated_at": _now().isoformat(),
    }


@router.post("/compliance/regulatory-alerts")
async def check_regulatory_alerts(request: RegulatoryAlertRequest) -> Dict[str, Any]:
    """Check for regulatory updates and alerts.

    Uses CISA KEV catalog as a regulatory alert source — actively exploited
    vulnerabilities have direct compliance implications for most frameworks.
    """
    feeds_service = _get_feeds_service()
    alerts: List[Dict[str, Any]] = []
    last_updated = None

    if feeds_service:
        try:
            stats = feeds_service.get_feed_stats()
            last_updated = stats.get("kev_last_updated") or stats.get("last_sync")

            # Pull recent KEV entries as regulatory alerts
            import sqlite3 as _sql

            conn = _sql.connect(feeds_service.db_path)
            conn.row_factory = _sql.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT cve_id, vendor_project, product, vulnerability_name, "
                "date_added, due_date, required_action, known_ransomware_campaign_use "
                "FROM kev_entries ORDER BY date_added DESC LIMIT 20"
            )
            for row in cursor.fetchall():
                alerts.append(
                    {
                        "alert_type": "CISA_KEV",
                        "cve_id": row["cve_id"],
                        "vendor": row["vendor_project"],
                        "product": row["product"],
                        "vulnerability": row["vulnerability_name"],
                        "date_added": row["date_added"],
                        "due_date": row["due_date"],
                        "required_action": row["required_action"],
                        "ransomware_use": row["known_ransomware_campaign_use"]
                        == "Known",
                        "regulatory_impact": "Mandatory remediation per BOD 22-01"
                        if "US" in request.jurisdictions
                        else "Advisory — actively exploited",
                    }
                )
            conn.close()
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning(f"Regulatory alerts query failed: {e}")

    return {
        "status": "active" if alerts else "no_alerts",
        "message": f"{len(alerts)} active regulatory alerts from CISA KEV catalog."
        if alerts
        else "No KEV data loaded — run feed sync first.",
        "alerts": alerts,
        "total_alerts": len(alerts),
        "industries": request.industries,
        "jurisdictions": request.jurisdictions,
        "data_sources": ["CISA KEV (BOD 22-01)"],
        "last_updated": last_updated,
    }


@router.get("/compliance/controls/{framework}")
async def get_framework_controls(
    framework: ComplianceFramework,
    category: Optional[str] = None,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Get all controls for a compliance framework.

    Returns framework metadata and representative controls from official standards.
    When ComplianceEngine is available, also includes posture evaluation.
    """
    # Built-in control libraries based on official framework standards
    _FRAMEWORK_CONTROLS: Dict[str, Dict[str, Any]] = {
        "pci-dss": {
            "name": "PCI-DSS v4.0",
            "source": "https://www.pcisecuritystandards.org/",
            "controls": [
                {
                    "id": "PCI-1",
                    "category": "Network",
                    "title": "Install and maintain network security controls",
                    "description": "Network security controls (NSCs) — firewalls, cloud security groups.",
                },
                {
                    "id": "PCI-2",
                    "category": "Network",
                    "title": "Apply secure configurations to all system components",
                    "description": "Change vendor defaults, harden configurations.",
                },
                {
                    "id": "PCI-3",
                    "category": "Encryption",
                    "title": "Protect stored account data",
                    "description": "Encryption, truncation, masking, hashing of stored data.",
                },
                {
                    "id": "PCI-4",
                    "category": "Encryption",
                    "title": "Protect cardholder data with strong cryptography during transmission",
                    "description": "TLS 1.2+, certificate management.",
                },
                {
                    "id": "PCI-5",
                    "category": "Vulnerability",
                    "title": "Protect all systems and networks from malicious software",
                    "description": "Anti-malware, vulnerability scanning.",
                },
                {
                    "id": "PCI-6",
                    "category": "Vulnerability",
                    "title": "Develop and maintain secure systems and software",
                    "description": "Secure SDLC, patch management, code review.",
                },
                {
                    "id": "PCI-7",
                    "category": "Access Control",
                    "title": "Restrict access to system components and cardholder data by business need to know",
                    "description": "Least privilege, role-based access.",
                },
                {
                    "id": "PCI-8",
                    "category": "Access Control",
                    "title": "Identify users and authenticate access to system components",
                    "description": "MFA, strong passwords, identity management.",
                },
                {
                    "id": "PCI-9",
                    "category": "Access Control",
                    "title": "Restrict physical access to cardholder data",
                    "description": "Physical access controls, visitor management.",
                },
                {
                    "id": "PCI-10",
                    "category": "Testing",
                    "title": "Log and monitor all access to system components and cardholder data",
                    "description": "Audit logs, SIEM, log review.",
                },
                {
                    "id": "PCI-11",
                    "category": "Testing",
                    "title": "Test security of systems and networks regularly",
                    "description": "Vulnerability scans, penetration tests, IDS/IPS.",
                },
                {
                    "id": "PCI-12",
                    "category": "Network",
                    "title": "Support information security with organizational policies and programs",
                    "description": "Security policies, awareness training, incident response.",
                },
            ],
        },
        "soc2": {
            "name": "SOC 2 Type II",
            "source": "https://www.aicpa.org/",
            "controls": [
                {
                    "id": "CC1",
                    "category": "Security",
                    "title": "Control Environment",
                    "description": "Commitment to integrity, board oversight, organizational structure.",
                },
                {
                    "id": "CC2",
                    "category": "Security",
                    "title": "Communication and Information",
                    "description": "Internal/external communication of security policies.",
                },
                {
                    "id": "CC3",
                    "category": "Security",
                    "title": "Risk Assessment",
                    "description": "Risk identification, fraud risk, change management.",
                },
                {
                    "id": "CC4",
                    "category": "Security",
                    "title": "Monitoring Activities",
                    "description": "Ongoing monitoring, deficiency evaluation.",
                },
                {
                    "id": "CC5",
                    "category": "Security",
                    "title": "Control Activities",
                    "description": "Policy enforcement, technology controls.",
                },
                {
                    "id": "CC6",
                    "category": "Security",
                    "title": "Logical and Physical Access Controls",
                    "description": "Authentication, authorization, physical security.",
                },
                {
                    "id": "CC7",
                    "category": "Security",
                    "title": "System Operations",
                    "description": "Detection of anomalies, incident response, recovery.",
                },
                {
                    "id": "CC8",
                    "category": "Security",
                    "title": "Change Management",
                    "description": "Change authorization, testing, approval.",
                },
                {
                    "id": "CC9",
                    "category": "Security",
                    "title": "Risk Mitigation",
                    "description": "Vendor management, business continuity.",
                },
                {
                    "id": "A1",
                    "category": "Availability",
                    "title": "Availability Controls",
                    "description": "Capacity management, backup, disaster recovery.",
                },
                {
                    "id": "PI1",
                    "category": "Processing Integrity",
                    "title": "Processing Integrity Controls",
                    "description": "Input validation, processing accuracy, output review.",
                },
                {
                    "id": "C1",
                    "category": "Confidentiality",
                    "title": "Confidentiality Controls",
                    "description": "Data classification, encryption, disposal.",
                },
                {
                    "id": "P1-P8",
                    "category": "Privacy",
                    "title": "Privacy Criteria",
                    "description": "Notice, choice, collection, use/retention, access, disclosure, quality, monitoring.",
                },
            ],
        },
        "iso27001": {
            "name": "ISO/IEC 27001:2022",
            "source": "https://www.iso.org/",
            "controls": [
                {
                    "id": "A.5.1",
                    "category": "Organizational",
                    "title": "Policies for information security",
                    "description": "Management direction for information security.",
                },
                {
                    "id": "A.5.2",
                    "category": "Organizational",
                    "title": "Information security roles and responsibilities",
                    "description": "Defined and allocated responsibilities.",
                },
                {
                    "id": "A.5.23",
                    "category": "Organizational",
                    "title": "Information security for use of cloud services",
                    "description": "Cloud service acquisition, use, management, exit.",
                },
                {
                    "id": "A.6.1",
                    "category": "People",
                    "title": "Screening",
                    "description": "Background verification checks.",
                },
                {
                    "id": "A.6.3",
                    "category": "People",
                    "title": "Information security awareness, education and training",
                    "description": "Security awareness programs.",
                },
                {
                    "id": "A.7.1",
                    "category": "Physical",
                    "title": "Physical security perimeters",
                    "description": "Areas containing sensitive information.",
                },
                {
                    "id": "A.8.1",
                    "category": "Technological",
                    "title": "User endpoint devices",
                    "description": "Endpoint protection and management.",
                },
                {
                    "id": "A.8.5",
                    "category": "Technological",
                    "title": "Secure authentication",
                    "description": "Authentication technologies and procedures.",
                },
                {
                    "id": "A.8.8",
                    "category": "Technological",
                    "title": "Management of technical vulnerabilities",
                    "description": "Vulnerability identification, risk evaluation, patching.",
                },
                {
                    "id": "A.8.9",
                    "category": "Technological",
                    "title": "Configuration management",
                    "description": "Hardware/software/service/network configurations.",
                },
                {
                    "id": "A.8.15",
                    "category": "Technological",
                    "title": "Logging",
                    "description": "Activity logs, event correlation.",
                },
                {
                    "id": "A.8.16",
                    "category": "Technological",
                    "title": "Monitoring activities",
                    "description": "Anomaly detection, security event monitoring.",
                },
            ],
        },
        "hipaa": {
            "name": "HIPAA Security Rule",
            "source": "https://www.hhs.gov/hipaa/",
            "controls": [
                {
                    "id": "164.308(a)(1)",
                    "category": "Administrative",
                    "title": "Security Management Process",
                    "description": "Risk analysis, risk management, sanction policy, information system activity review.",
                },
                {
                    "id": "164.308(a)(3)",
                    "category": "Administrative",
                    "title": "Workforce Security",
                    "description": "Authorization/supervision, workforce clearance, termination procedures.",
                },
                {
                    "id": "164.308(a)(4)",
                    "category": "Administrative",
                    "title": "Information Access Management",
                    "description": "Access authorization, access establishment and modification.",
                },
                {
                    "id": "164.308(a)(5)",
                    "category": "Administrative",
                    "title": "Security Awareness and Training",
                    "description": "Security reminders, malicious software protection, login monitoring.",
                },
                {
                    "id": "164.308(a)(6)",
                    "category": "Administrative",
                    "title": "Security Incident Procedures",
                    "description": "Incident response and reporting.",
                },
                {
                    "id": "164.310(a)(1)",
                    "category": "Physical",
                    "title": "Facility Access Controls",
                    "description": "Contingency operations, facility security plan, access control.",
                },
                {
                    "id": "164.310(d)(1)",
                    "category": "Physical",
                    "title": "Device and Media Controls",
                    "description": "Disposal, media re-use, data backup, accountability.",
                },
                {
                    "id": "164.312(a)(1)",
                    "category": "Technical",
                    "title": "Access Control",
                    "description": "Unique user identification, emergency access, automatic logoff, encryption.",
                },
                {
                    "id": "164.312(b)",
                    "category": "Technical",
                    "title": "Audit Controls",
                    "description": "Hardware/software/procedural mechanisms for recording and examining access.",
                },
                {
                    "id": "164.312(c)(1)",
                    "category": "Technical",
                    "title": "Integrity",
                    "description": "Mechanism to authenticate electronic PHI.",
                },
                {
                    "id": "164.312(d)",
                    "category": "Technical",
                    "title": "Person or Entity Authentication",
                    "description": "Verify identity of persons seeking access to ePHI.",
                },
                {
                    "id": "164.312(e)(1)",
                    "category": "Technical",
                    "title": "Transmission Security",
                    "description": "Integrity controls, encryption for ePHI in transit.",
                },
            ],
        },
        "nist": {
            "name": "NIST CSF 2.0",
            "source": "https://www.nist.gov/cyberframework",
            "controls": [
                {
                    "id": "GV.OC-01",
                    "category": "Govern",
                    "title": "Organizational Context",
                    "description": "Mission, stakeholder expectations, legal/regulatory requirements.",
                },
                {
                    "id": "GV.RM-01",
                    "category": "Govern",
                    "title": "Risk Management Strategy",
                    "description": "Risk management objectives, risk appetite, risk tolerance.",
                },
                {
                    "id": "ID.AM-01",
                    "category": "Identify",
                    "title": "Asset Management — Inventories",
                    "description": "Hardware, software, data, systems inventories maintained.",
                },
                {
                    "id": "ID.RA-01",
                    "category": "Identify",
                    "title": "Risk Assessment — Vulnerabilities",
                    "description": "Vulnerabilities in assets identified, validated, recorded.",
                },
                {
                    "id": "PR.AA-01",
                    "category": "Protect",
                    "title": "Identity Management & Access Control",
                    "description": "Identities and credentials managed for authorized users/services.",
                },
                {
                    "id": "PR.DS-01",
                    "category": "Protect",
                    "title": "Data Security",
                    "description": "Data-at-rest protection, data-in-transit protection.",
                },
                {
                    "id": "PR.PS-01",
                    "category": "Protect",
                    "title": "Platform Security",
                    "description": "Configuration management, software maintained/replaced/removed.",
                },
                {
                    "id": "DE.CM-01",
                    "category": "Detect",
                    "title": "Continuous Monitoring",
                    "description": "Networks and network services monitored for anomalous events.",
                },
                {
                    "id": "DE.AE-02",
                    "category": "Detect",
                    "title": "Adverse Event Analysis",
                    "description": "Anomalies correlated, incidents declared.",
                },
                {
                    "id": "RS.MA-01",
                    "category": "Respond",
                    "title": "Incident Management",
                    "description": "Incident response plan executed, incidents triaged.",
                },
                {
                    "id": "RS.MI-01",
                    "category": "Respond",
                    "title": "Incident Mitigation",
                    "description": "Incidents contained, eradicated.",
                },
                {
                    "id": "RC.RP-01",
                    "category": "Recover",
                    "title": "Recovery Execution",
                    "description": "Recovery portion of incident response plan executed.",
                },
            ],
        },
    }

    fw_key = framework.value
    fw_data = _FRAMEWORK_CONTROLS.get(fw_key, {})
    controls = fw_data.get("controls", [])

    # Filter by category if specified
    if category and controls:
        controls = [c for c in controls if c["category"].lower() == category.lower()]

    # If ComplianceEngine is available, add posture evaluation
    posture = None
    if _COMPLIANCE_ENGINE_AVAILABLE and compliance_engine is not None:
        try:
            analytics = _get_analytics_db()
            finding_dicts = []
            if analytics:
                findings = analytics.list_findings(limit=1000, offset=0)
                finding_dicts = [f.to_dict() for f in findings]
            result = compliance_engine.evaluate([fw_key], finding_dicts)
            posture = result.get(fw_key)
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning(f"ComplianceEngine posture evaluation failed: {e}")

    return {
        "framework": fw_key,
        "framework_info": {
            "name": fw_data.get("name", fw_key),
            "total_controls": len(fw_data.get("controls", [])),
            "categories": sorted({c["category"] for c in fw_data.get("controls", [])}),
            "source": fw_data.get("source", ""),
        },
        "controls": controls,
        "total_returned": len(controls),
        "status": "complete",
        "posture": posture,
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
        # Pull real findings for accurate posture
        analytics = _get_analytics_db()
        finding_dicts = []
        if analytics:
            findings = analytics.list_findings(limit=1000, offset=0)
            finding_dicts = [f.to_dict() for f in findings]

        framework_status = []
        open_gaps = 0
        critical_gaps = 0
        for fw in supported:
            res = compliance_engine.evaluate([fw], finding_dicts)
            fw_res = res.get(fw, {})
            status = fw_res.get("status", "unknown")
            framework_status.append(
                {
                    "framework": fw,
                    "status": status,
                    "threshold": fw_res.get("threshold"),
                    "highest_fixops_severity": fw_res.get("highest_fixops_severity"),
                }
            )
            if status == "non_compliant":
                open_gaps += 1
                if fw_res.get("highest_fixops_severity") in ("HIGH", "CRITICAL"):
                    critical_gaps += 1

        total = len(finding_dicts)
        resolved = sum(
            1 for f in finding_dicts if f.get("status") in ("resolved", "RESOLVED")
        )
        posture = (
            "compliant"
            if open_gaps == 0 and total > 0
            else ("non_compliant" if open_gaps > 0 else "no_findings_uploaded")
        )

        return {
            "status": "ready",
            "message": f"Evaluated {total} findings across {len(supported)} frameworks.",
            "overall_posture": posture,
            "total_findings": total,
            "resolved_findings": resolved,
            "frameworks": framework_status,
            "open_gaps": open_gaps,
            "critical_gaps": critical_gaps,
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
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Generate compliance report.

    When ComplianceEngine is available, generates a baseline report.
    """
    report_id = _generate_id()
    fw = framework.value

    if _COMPLIANCE_ENGINE_AVAILABLE and compliance_engine is not None:
        # Use real findings for accurate compliance report
        analytics = _get_analytics_db()
        finding_dicts = []
        if analytics:
            findings = analytics.list_findings(limit=1000, offset=0)
            finding_dicts = [f.to_dict() for f in findings]

        result = compliance_engine.evaluate([fw], finding_dicts)
        fw_result = result.get(fw, {})
        return {
            "report_id": report_id,
            "framework": fw,
            "report_type": report_type,
            "status": "generated",
            "message": f"Compliance report generated with {len(finding_dicts)} findings.",
            "compliance_status": fw_result.get("status"),
            "threshold": fw_result.get("threshold"),
            "highest_fixops_severity": fw_result.get("highest_fixops_severity"),
            "total_findings_evaluated": len(finding_dicts),
            "include_evidence": include_evidence,
            "generated_at": _now().isoformat(),
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
    """Generate fix code for a vulnerability via AutoFixEngine.

    Uses the AutoFixEngine with LLM providers (OpenAI/Anthropic) to
    generate precise code patches, dependency updates, and config fixes.
    """
    engine = _get_autofix()
    analytics = _get_analytics_db()

    # Build finding dict from AnalyticsDB or request
    finding_dict: Dict[str, Any] = {"id": request.finding_id}
    if analytics:
        finding = analytics.get_finding(request.finding_id)
        if finding:
            finding_dict = finding.to_dict()

    if request.language:
        finding_dict["language"] = request.language

    if engine:
        try:
            suggestion = await engine.generate_fix(
                finding=finding_dict,
                source_code=None,
                repo_context={"language": request.language or "python"},
            )
            from dataclasses import asdict

            fix_data = asdict(suggestion)
            return {
                "finding_id": request.finding_id,
                "status": "generated",
                "fix_id": fix_data.get("fix_id"),
                "title": fix_data.get("title"),
                "description": fix_data.get("description"),
                "fix_type": fix_data.get("fix_type"),
                "confidence": fix_data.get("confidence"),
                "confidence_score": fix_data.get("confidence_score"),
                "code_patches": fix_data.get("code_patches", []),
                "dependency_fixes": fix_data.get("dependency_fixes", []),
                "pr_branch": fix_data.get("pr_branch"),
                "pr_title": fix_data.get("pr_title"),
                "language": request.language or "unknown",
                "include_tests": request.include_tests,
            }
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.error(f"AutoFix generate failed: {e}")
            return {
                "finding_id": request.finding_id,
                "status": "error",
                "message": f"Fix generation failed: {e}",
                "language": request.language or "unknown",
            }

    return {
        "finding_id": request.finding_id,
        "status": "engine_unavailable",
        "message": "AutoFixEngine not available — check OPENAI_API_KEY is set.",
        "language": request.language or "unknown",
    }


@router.post("/remediation/create-pr")
async def create_pull_request(request: CreatePRRequest) -> Dict[str, Any]:
    """Create a pull request with security fixes via AutoFixEngine.

    Generates fixes for specified findings and applies them to a repository
    via the AutoFixEngine PR generation pipeline.
    """
    engine = _get_autofix()
    analytics = _get_analytics_db()

    if engine:
        try:
            # Generate fixes for each finding, then apply
            fix_ids = []
            for fid in request.finding_ids[:10]:  # Cap at 10
                finding_dict: Dict[str, Any] = {"id": fid}
                if analytics:
                    finding = analytics.get_finding(fid)
                    if finding:
                        finding_dict = finding.to_dict()
                suggestion = await engine.generate_fix(finding=finding_dict)
                fix_ids.append(suggestion.fix_id)

            # Apply the first fix with PR creation
            if fix_ids:
                result = await engine.apply_fix(
                    fix_id=fix_ids[0],
                    repository=request.repository,
                    create_pr=True,
                    auto_merge=request.auto_merge,
                )
                return {
                    "status": "created" if result.success else "pr_creation_pending",
                    "message": f"Generated {len(fix_ids)} fixes for {request.repository}.",
                    "repository": request.repository,
                    "branch": request.branch,
                    "finding_ids": request.finding_ids,
                    "fix_ids": fix_ids,
                    "pr_url": result.pr_url,
                    "auto_merge": request.auto_merge,
                }
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.error(f"PR creation failed: {e}")
            return {
                "status": "error",
                "message": f"PR creation failed: {e}",
                "repository": request.repository,
                "finding_ids": request.finding_ids,
            }

    return {
        "status": "engine_unavailable",
        "message": "AutoFixEngine not available — set OPENAI_API_KEY and GITHUB_TOKEN.",
        "repository": request.repository,
        "branch": request.branch,
        "finding_ids": request.finding_ids,
    }


@router.post("/remediation/update-dependencies")
async def update_dependencies(request: DependencyUpdateRequest) -> Dict[str, Any]:
    """Update vulnerable dependencies via AutoFixEngine.

    Uses the AutoFixEngine dependency fix generation to produce
    manifest updates for vulnerable packages.
    """
    engine = _get_autofix()

    if engine:
        try:
            results = []
            for pkg_id in request.package_ids[:20]:  # Cap at 20
                finding_dict = {
                    "id": pkg_id,
                    "title": f"Vulnerable dependency: {pkg_id}",
                    "severity": "high",
                    "cwe_id": "CWE-1104",
                    "description": f"Outdated/vulnerable package {pkg_id}",
                }
                suggestion = await engine.generate_fix(
                    finding=finding_dict,
                    repo_context={"update_strategy": request.update_strategy},
                )
                results.append(
                    {
                        "package": pkg_id,
                        "fix_id": suggestion.fix_id,
                        "fix_type": suggestion.fix_type.value
                        if suggestion.fix_type
                        else "dependency_update",
                        "status": suggestion.status.value
                        if suggestion.status
                        else "generated",
                        "dependency_fixes": [
                            {
                                "package": df.package_name,
                                "current": df.current_version,
                                "target": df.fixed_version,
                            }
                            for df in suggestion.dependency_fixes
                        ]
                        if suggestion.dependency_fixes
                        else [],
                    }
                )
            return {
                "sbom_id": request.sbom_id,
                "status": "generated",
                "message": f"Generated dependency updates for {len(results)} packages.",
                "packages": results,
                "strategy": request.update_strategy,
            }
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.error(f"Dependency update failed: {e}")
            return {
                "sbom_id": request.sbom_id,
                "status": "error",
                "message": f"Dependency update failed: {e}",
            }

    return {
        "sbom_id": request.sbom_id,
        "status": "engine_unavailable",
        "message": "AutoFixEngine not available — set OPENAI_API_KEY.",
        "packages_requested": request.package_ids,
        "strategy": request.update_strategy,
    }


@router.post("/remediation/playbook")
async def generate_playbook(request: PlaybookRequest) -> Dict[str, Any]:
    """Generate a remediation playbook for the given findings.

    Constructs a real YAML playbook from finding data and executes it
    in dry-run mode via PlaybookRunner to validate the steps.
    """
    playbook_id = _generate_id()
    analytics = _get_analytics_db()

    # Gather real finding data
    finding_details: List[Dict[str, Any]] = []
    for fid in request.finding_ids[:20]:  # Cap
        if analytics:
            f = analytics.get_finding(fid)
            if f:
                finding_details.append(f.to_dict())
            else:
                finding_details.append(
                    {"id": fid, "title": f"Finding {fid}", "severity": "unknown"}
                )
        else:
            finding_details.append(
                {"id": fid, "title": f"Finding {fid}", "severity": "unknown"}
            )

    # Build playbook steps from findings
    steps: List[Dict[str, Any]] = []
    for i, fd in enumerate(finding_details):
        steps.append(
            {
                "name": f"remediate_{i+1}_{fd.get('id', 'unknown')[:8]}",
                "description": f"Fix: {fd.get('title', 'Unknown vulnerability')}",
                "severity": fd.get("severity", "medium"),
                "cve_id": fd.get("cve_id"),
                "action": "Patch or update affected component",
            }
        )
        if request.include_rollback:
            steps.append(
                {
                    "name": f"rollback_{i+1}_{fd.get('id', 'unknown')[:8]}",
                    "description": f"Rollback plan for: {fd.get('title', 'Unknown')}",
                    "action": "Revert to previous version if fix causes regression",
                }
            )

    # Try to run through PlaybookRunner in dry-run if available
    validated = False
    if _PLAYBOOK_AVAILABLE:
        try:
            runner = PlaybookRunner()
            import yaml as _yaml

            playbook_yaml = {
                "apiVersion": "fixops.io/v1",
                "kind": "Playbook",
                "metadata": {
                    "name": f"remediation-{playbook_id[:8]}",
                    "version": "1.0.0",
                    "description": f"Auto-generated remediation playbook for {len(finding_details)} findings",
                },
                "spec": {
                    "steps": [
                        {
                            "name": s["name"],
                            "action": "data.filter",
                            "params": {
                                "finding": s.get("description", ""),
                                "severity": s.get("severity", "medium"),
                            },
                        }
                        for s in steps[:10]  # Cap steps for validation
                    ],
                },
            }
            pb = runner.load_playbook_from_string(_yaml.dump(playbook_yaml))
            await runner.execute(pb, inputs={}, dry_run=True)
            validated = True
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning(f"Playbook dry-run validation failed: {e}")

    return {
        "playbook_id": playbook_id,
        "status": "generated",
        "message": f"Playbook generated with {len(steps)} steps for {len(finding_details)} findings.",
        "validated": validated,
        "findings_count": len(finding_details),
        "audience": request.audience,
        "steps": steps,
        "include_rollback": request.include_rollback,
        "generated_at": _now().isoformat(),
    }


@router.get("/remediation/recommendations/{finding_id}")
async def get_recommendations(finding_id: str) -> Dict[str, Any]:
    """Get remediation recommendations for a finding.

    Pulls the real finding from AnalyticsDB and enriches with KnowledgeBrain
    graph data to produce contextual remediation advice.
    """
    analytics = _get_analytics_db()
    brain = _get_brain()

    finding_dict: Optional[Dict[str, Any]] = None
    if analytics:
        f = analytics.get_finding(finding_id)
        if f:
            finding_dict = f.to_dict()

    if finding_dict is None:
        return {
            "finding_id": finding_id,
            "status": "not_found",
            "message": f"Finding {finding_id} not found in database.",
            "recommendations": [],
        }

    recommendations: List[Dict[str, Any]] = []
    severity = (finding_dict.get("severity") or "medium").upper()
    cve_id = finding_dict.get("cve_id")
    title = finding_dict.get("title", "Unknown vulnerability")

    # Priority-based recommendation
    if severity in ("CRITICAL", "HIGH"):
        recommendations.append(
            {
                "priority": "immediate",
                "action": f"Patch or mitigate: {title}",
                "reason": f"Severity {severity} — requires immediate attention per SLA.",
            }
        )
    else:
        recommendations.append(
            {
                "priority": "scheduled",
                "action": f"Plan remediation for: {title}",
                "reason": f"Severity {severity} — schedule within maintenance window.",
            }
        )

    # CVE-specific recommendation
    if cve_id:
        recommendations.append(
            {
                "priority": "high",
                "action": f"Check vendor advisory for {cve_id}",
                "reason": "Vendor patches are the most reliable fix source.",
            }
        )
        # Enrich from KEV if available
        feeds = _get_feeds_service()
        if feeds:
            try:
                kev = feeds.get_kev_entry(cve_id)
                if kev:
                    recommendations.append(
                        {
                            "priority": "critical",
                            "action": f"CISA KEV: {kev.get('required_action', 'Apply vendor fix')}",
                            "reason": f"Actively exploited — BOD 22-01 due date: {kev.get('due_date', 'N/A')}",
                            "kev_entry": True,
                        }
                    )
            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                pass

    # KnowledgeBrain enrichment
    if brain:
        try:
            risk = brain.risk_score_for_node(finding_id)
            if risk > 0:
                recommendations.append(
                    {
                        "priority": "high" if risk > 0.7 else "medium",
                        "action": "Review connected assets in knowledge graph",
                        "reason": f"Graph risk score: {risk:.2f} — blast radius may be wider.",
                        "risk_score": round(risk, 3),
                    }
                )
            neighbors = brain.get_neighbors(finding_id, depth=1)
            if neighbors and neighbors.nodes:
                connected = [
                    n["node_id"]
                    for n in neighbors.nodes
                    if n and n.get("node_id") != finding_id
                ]
                if connected:
                    recommendations.append(
                        {
                            "priority": "info",
                            "action": f"Assess impact on {len(connected)} connected node(s)",
                            "reason": "Related assets may also be affected.",
                            "connected_nodes": connected[:10],
                        }
                    )
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug(f"Brain enrichment for {finding_id}: {e}")

    return {
        "finding_id": finding_id,
        "status": "recommendations_ready",
        "title": title,
        "severity": severity,
        "cve_id": cve_id,
        "total_recommendations": len(recommendations),
        "recommendations": recommendations,
    }


@router.post("/remediation/verify")
async def verify_remediation(
    finding_ids: List[str],
    verification_type: str = "scan",
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Verify remediation by checking finding status in AnalyticsDB.

    Looks up each finding and reports whether it has been resolved,
    is still open, or cannot be found.
    """
    analytics = _get_analytics_db()
    verification_id = _generate_id()

    results: List[Dict[str, Any]] = []
    verified = 0
    still_open = 0
    not_found = 0

    for fid in finding_ids[:50]:  # Cap
        if analytics:
            f = analytics.get_finding(fid)
            if f:
                fd = f.to_dict()
                status = fd.get("status", "open")
                is_resolved = status in ("resolved", "RESOLVED", "closed", "CLOSED")
                results.append(
                    {
                        "finding_id": fid,
                        "title": fd.get("title", "Unknown"),
                        "current_status": status,
                        "verified": is_resolved,
                        "resolved_at": fd.get("resolved_at"),
                    }
                )
                if is_resolved:
                    verified += 1
                else:
                    still_open += 1
            else:
                results.append(
                    {
                        "finding_id": fid,
                        "current_status": "not_found",
                        "verified": False,
                    }
                )
                not_found += 1
        else:
            results.append(
                {
                    "finding_id": fid,
                    "current_status": "db_unavailable",
                    "verified": False,
                }
            )

    return {
        "verification_id": verification_id,
        "status": "verified" if still_open == 0 and verified > 0 else "incomplete",
        "message": f"{verified} verified, {still_open} still open, {not_found} not found.",
        "verification_type": verification_type,
        "total_checked": len(results),
        "verified_count": verified,
        "still_open_count": still_open,
        "not_found_count": not_found,
        "results": results,
        "verified_at": _now().isoformat(),
    }


@router.get("/remediation/queue")
async def get_remediation_queue(
    priority: Optional[TaskPriority] = None,
    assignee: Optional[str] = None,
    limit: int = Query(default=20, le=100),
) -> Dict[str, Any]:
    """Get remediation queue from AnalyticsDB.

    Returns open findings ordered by severity as the remediation backlog.
    Supports filtering by priority (mapped to severity) and limit.
    """
    analytics = _get_analytics_db()

    if analytics:
        # Map priority to severity filter
        severity_filter = None
        if priority:
            severity_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
            }
            severity_filter = severity_map.get(priority.value.lower())

        findings = analytics.list_findings(
            severity=severity_filter,
            status="open",
            limit=limit,
            offset=0,
        )
        queue_items = []
        for f in findings:
            fd = f.to_dict()
            queue_items.append(
                {
                    "finding_id": fd.get("id"),
                    "title": fd.get("title", "Unknown"),
                    "severity": fd.get("severity", "medium"),
                    "status": fd.get("status", "open"),
                    "source": fd.get("source"),
                    "cve_id": fd.get("cve_id"),
                    "created_at": fd.get("created_at"),
                    "assignee": assignee,  # Pass-through filter
                }
            )

        return {
            "status": "ready",
            "message": f"{len(queue_items)} items in remediation queue.",
            "total_items": len(queue_items),
            "queue": queue_items,
            "filters_applied": {
                "priority": priority.value if priority else None,
                "assignee": assignee,
                "limit": limit,
            },
        }

    return {
        "status": "db_unavailable",
        "message": "AnalyticsDB not available — cannot load remediation queue.",
        "queue": [],
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
    org_id: str = Depends(get_org_id),
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
                "status": "ready" if _AUTOFIX_AVAILABLE else "pending_configuration",
                "autofix_engine": "connected"
                if _AUTOFIX_AVAILABLE
                else "not_available",
                "playbook_runner": "connected"
                if _PLAYBOOK_AVAILABLE
                else "not_available",
                "analytics_db": "connected"
                if _ANALYTICS_DB_AVAILABLE
                else "not_available",
                "knowledge_brain": "connected" if _BRAIN_AVAILABLE else "not_available",
                "message": "AutoFix + PlaybookRunner + AnalyticsDB available"
                if _AUTOFIX_AVAILABLE
                else "Set OPENAI_API_KEY or ANTHROPIC_API_KEY for full remediation",
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
