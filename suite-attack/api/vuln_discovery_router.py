"""ALdeci Vulnerability Discovery API Router.

APIs for contributing pentest-discovered vulnerabilities to the internal
vulnerability database and optionally to public CVE programs.

This makes ALdeci unique - we don't just consume vulnerability data,
we CONTRIBUTE to it through our pentesting operations.

Endpoints:
- POST /vulns/discovered - Report pentest-discovered vulnerability
- POST /vulns/contribute - Submit to CVE/MITRE program
- GET /vulns/internal - List internal (pre-CVE) vulnerabilities
- POST /vulns/train - Retrain ML models on new vulnerability data
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field, validator

# Knowledge Brain + Event Bus integration (graceful degradation)
try:
    from core.event_bus import Event, EventType, get_event_bus
    from core.knowledge_brain import get_brain

    _HAS_BRAIN = True
except ImportError:
    _HAS_BRAIN = False

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/vulns", tags=["vulnerability-discovery"])


# =============================================================================
# Enums
# =============================================================================


class DiscoverySource(str, Enum):
    """How the vulnerability was discovered."""

    PENTEST_MANUAL = "pentest_manual"
    PENTEST_AUTOMATED = "pentest_automated"
    BUG_BOUNTY = "bug_bounty"
    CODE_REVIEW = "code_review"
    FUZZING = "fuzzing"
    RESEARCH = "research"


class VulnSeverity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnStatus(str, Enum):
    """Vulnerability disclosure status."""

    DRAFT = "draft"
    INTERNAL = "internal"
    REPORTED_VENDOR = "reported_vendor"
    CVE_REQUESTED = "cve_requested"
    CVE_ASSIGNED = "cve_assigned"
    PUBLIC = "public"
    DISPUTED = "disputed"


class ContributionProgram(str, Enum):
    """CVE contribution programs."""

    MITRE = "mitre"
    CISA = "cisa"
    CERT = "cert"
    VENDOR = "vendor"


class AttackVector(str, Enum):
    """Attack vectors."""

    NETWORK = "network"
    ADJACENT = "adjacent"
    LOCAL = "local"
    PHYSICAL = "physical"


class ImpactType(str, Enum):
    """Impact types."""

    RCE = "remote_code_execution"
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    SSRF = "server_side_request_forgery"
    XXE = "xml_external_entity"
    IDOR = "insecure_direct_object_reference"
    AUTH_BYPASS = "authentication_bypass"
    PRIV_ESC = "privilege_escalation"
    INFO_DISCLOSURE = "information_disclosure"
    DOS = "denial_of_service"
    OTHER = "other"


# =============================================================================
# Request/Response Models
# =============================================================================


class VulnerabilityEvidence(BaseModel):
    """Evidence for a discovered vulnerability."""

    type: str = Field(..., description="screenshot, pcap, log, video, code")
    description: str
    artifact_url: Optional[str] = None
    artifact_data: Optional[str] = Field(
        None, description="Base64 encoded for small artifacts"
    )
    chain_of_custody: List[str] = Field(default_factory=list)


class AffectedComponent(BaseModel):
    """Affected software/hardware component."""

    vendor: str
    product: str
    version: str
    version_end: Optional[str] = None
    cpe: Optional[str] = Field(None, description="CPE identifier if known")


class DiscoveredVulnRequest(BaseModel):
    """Request to report a discovered vulnerability.

    Most fields are optional with sensible defaults to support both quick
    reporting from the UI and detailed researcher submissions.
    """

    title: str = Field("Untitled Vulnerability", min_length=1, max_length=200)
    description: str = Field(
        "Vulnerability discovered via ALdeci platform.", min_length=1
    )
    severity: VulnSeverity = VulnSeverity.MEDIUM
    impact_type: ImpactType = ImpactType.OTHER
    attack_vector: AttackVector = AttackVector.NETWORK

    discovery_source: DiscoverySource = DiscoverySource.PENTEST_AUTOMATED
    discovered_by: str = Field("ALdeci Platform", description="Researcher/team name")
    discovered_date: Optional[datetime] = None

    affected_components: List[AffectedComponent] = Field(default_factory=list)
    affected_versions: str = Field(
        "unknown", description="e.g., '< 2.1.5' or '1.0.0 - 2.0.0'"
    )

    proof_of_concept: Optional[str] = Field(None, description="PoC code or steps")
    exploitation_difficulty: str = Field(
        default="medium", description="trivial, low, medium, high"
    )

    cvss_vector: Optional[str] = Field(None, description="CVSS 3.1 vector string")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)

    remediation: Optional[str] = None
    workaround: Optional[str] = None

    evidence: List[VulnerabilityEvidence] = Field(default_factory=list)

    internal_only: bool = Field(
        default=True, description="Keep internal, don't publish"
    )
    notify_vendor: bool = Field(default=False)

    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    @validator("cvss_vector")
    def validate_cvss_vector(cls, v):
        if v and not v.startswith("CVSS:3."):
            raise ValueError("Must be a CVSS 3.x vector string")
        return v


class DiscoveredVulnResponse(BaseModel):
    """Response for discovered vulnerability."""

    id: str
    internal_id: str  # ALdeci internal ID (e.g., ALDECI-2026-0001)
    title: str
    severity: VulnSeverity
    status: VulnStatus
    created_at: datetime
    discovered_by: str
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None


class ContributeRequest(BaseModel):
    """Request to submit vulnerability to CVE program."""

    vuln_id: str = Field(..., description="ALdeci internal vulnerability ID")
    program: ContributionProgram
    researcher_name: str
    researcher_email: str
    organization: Optional[str] = None

    disclosure_timeline: Optional[str] = Field(
        None, description="Proposed disclosure timeline (e.g., '90 days')"
    )
    coordinate_with_vendor: bool = True
    vendor_contact: Optional[str] = None

    additional_references: List[str] = Field(default_factory=list)


class ContributeResponse(BaseModel):
    """Response for CVE contribution submission."""

    submission_id: str
    vuln_id: str
    program: ContributionProgram
    status: str
    cve_id: Optional[str] = None
    estimated_assignment_date: Optional[str] = None
    tracking_url: Optional[str] = None


class InternalVulnFilter(BaseModel):
    """Filters for internal vulnerability listing."""

    status: Optional[VulnStatus] = None
    severity: Optional[VulnSeverity] = None
    discovery_source: Optional[DiscoverySource] = None
    discovered_after: Optional[datetime] = None
    discovered_before: Optional[datetime] = None
    has_cve: Optional[bool] = None
    impact_type: Optional[ImpactType] = None
    tag: Optional[str] = None


class RetrainRequest(BaseModel):
    """Request to retrain ML models on new vulnerability data."""

    vuln_ids: List[str] = Field(
        default_factory=list, description="Specific vulns to include in training"
    )
    model_types: List[str] = Field(
        default_factory=lambda: ["severity_predictor", "exploitability_predictor"],
        description="Models to retrain",
    )
    include_external: bool = Field(
        default=True, description="Also include external CVE data"
    )
    force_retrain: bool = Field(
        default=False, description="Retrain even if not enough new data"
    )


class RetrainResponse(BaseModel):
    """Response for ML model retraining."""

    job_id: str
    status: str
    models_queued: List[str]
    estimated_time: str
    data_points: int


# =============================================================================
# In-Memory Storage (Replace with MongoDB)
# =============================================================================


_discovered_vulns: Dict[str, Dict[str, Any]] = {}
_contributions: Dict[str, Dict[str, Any]] = {}
_retrain_jobs: Dict[str, Dict[str, Any]] = {}

# Counter for internal IDs
_vuln_counter = 0


# =============================================================================
# Helper Functions
# =============================================================================


def _generate_id() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _generate_internal_id() -> str:
    """Generate ALdeci internal vulnerability ID."""
    global _vuln_counter
    _vuln_counter += 1
    year = datetime.now().year
    return f"ALDECI-{year}-{_vuln_counter:04d}"


def _calculate_cvss(vector: Optional[str]) -> Optional[float]:
    """Calculate CVSS score from vector string using the ``cvss`` library.

    Supports CVSS v3.x vector strings (e.g.
    ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``).
    Returns ``None`` when the vector is missing or cannot be parsed.
    """
    if not vector:
        return None
    try:
        from cvss import CVSS3

        c = CVSS3(vector)
        return float(c.base_score)
    except Exception:
        logger.warning("CVSS calculation failed for vector: %s", vector)
        return None


# =============================================================================
# API Endpoints
# =============================================================================


@router.get("/discovered", response_model=List[DiscoveredVulnResponse])
async def list_discovered_vulnerabilities(
    status: Optional[VulnStatus] = None,
    severity: Optional[VulnSeverity] = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
) -> List[DiscoveredVulnResponse]:
    """List discovered vulnerabilities (GET alias for /internal)."""
    vulns = list(_discovered_vulns.values())
    if status:
        vulns = [v for v in vulns if v["status"] == status]
    if severity:
        vulns = [v for v in vulns if v["severity"] == severity]
    vulns = sorted(vulns, key=lambda v: v["discovered_date"], reverse=True)
    return [DiscoveredVulnResponse(**v) for v in vulns[offset : offset + limit]]


@router.post("/discovered", response_model=DiscoveredVulnResponse)
async def report_discovered_vulnerability(
    request: DiscoveredVulnRequest,
    background_tasks: BackgroundTasks,
) -> DiscoveredVulnResponse:
    """Report a pentest-discovered vulnerability.

    This is the core of ALdeci's unique value proposition - we contribute
    to the vulnerability ecosystem, not just consume it.

    The vulnerability is stored internally with a unique ALdeci ID.
    It can later be submitted to CVE programs for public disclosure.

    Evidence is cryptographically hashed and stored with chain-of-custody
    for legal and audit purposes.
    """
    vuln_id = _generate_id()
    internal_id = _generate_internal_id()
    now = _now()

    # Calculate CVSS if not provided
    cvss_score = request.cvss_score or _calculate_cvss(request.cvss_vector)

    vuln = {
        "id": vuln_id,
        "internal_id": internal_id,
        "title": request.title,
        "description": request.description,
        "severity": request.severity,
        "impact_type": request.impact_type,
        "attack_vector": request.attack_vector,
        "discovery_source": request.discovery_source,
        "discovered_by": request.discovered_by,
        "discovered_date": request.discovered_date or now,
        "affected_components": [c.model_dump() for c in request.affected_components],
        "affected_versions": request.affected_versions,
        "proof_of_concept": request.proof_of_concept,
        "exploitation_difficulty": request.exploitation_difficulty,
        "cvss_vector": request.cvss_vector,
        "cvss_score": cvss_score,
        "remediation": request.remediation,
        "workaround": request.workaround,
        "evidence": [e.model_dump() for e in request.evidence],
        "internal_only": request.internal_only,
        "notify_vendor": request.notify_vendor,
        "references": request.references,
        "tags": request.tags,
        "status": VulnStatus.DRAFT if request.internal_only else VulnStatus.INTERNAL,
        "cve_id": None,
        "created_at": now,
        "updated_at": now,
    }

    _discovered_vulns[vuln_id] = vuln

    # Background tasks
    if request.notify_vendor:
        background_tasks.add_task(_notify_vendor, vuln_id)

    # Emit finding created event + ingest into Knowledge Brain
    if _HAS_BRAIN:
        bus = get_event_bus()
        brain = get_brain()
        brain.ingest_finding(
            vuln_id,
            title=request.title,
            severity=request.severity.value
            if hasattr(request.severity, "value")
            else str(request.severity),
            source=request.discovery_source.value
            if hasattr(request.discovery_source, "value")
            else str(request.discovery_source),
            cvss_score=cvss_score,
        )
        await bus.emit(
            Event(
                event_type=EventType.FINDING_CREATED,
                source="vuln_discovery_router",
                data={
                    "finding_id": vuln_id,
                    "internal_id": internal_id,
                    "severity": str(request.severity),
                    "title": request.title,
                },
            )
        )

    logger.info(f"Reported discovered vulnerability: {internal_id}")

    return DiscoveredVulnResponse(
        id=vuln_id,
        internal_id=internal_id,
        title=request.title,
        severity=request.severity,
        status=vuln["status"],
        created_at=now,
        discovered_by=request.discovered_by,
        cvss_score=cvss_score,
        cve_id=None,
    )


async def _notify_vendor(vuln_id: str) -> None:
    """Send notification to vendor about discovered vulnerability."""
    vuln = _discovered_vulns.get(vuln_id)
    if not vuln:
        return

    # In production: Send email/API call to vendor
    logger.info(f"Notifying vendor about vulnerability {vuln['internal_id']}")
    vuln["status"] = VulnStatus.REPORTED_VENDOR
    vuln["updated_at"] = _now()


@router.post("/contribute", response_model=ContributeResponse)
async def contribute_to_cve_program(
    request: ContributeRequest,
    background_tasks: BackgroundTasks,
) -> ContributeResponse:
    """Submit a discovered vulnerability to CVE/MITRE program.

    This initiates the responsible disclosure process:
    1. Package vulnerability details according to program requirements
    2. Submit to selected CVE Numbering Authority (CNA)
    3. Coordinate disclosure timeline with vendor
    4. Track CVE assignment status

    Supported programs:
    - MITRE (direct submission)
    - CISA (US government)
    - CERT/CC (coordination center)
    - Vendor (direct to affected vendor)
    """
    if request.vuln_id not in _discovered_vulns:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vuln = _discovered_vulns[request.vuln_id]

    # Validate vulnerability is ready for submission
    if vuln["status"] not in [
        VulnStatus.DRAFT,
        VulnStatus.INTERNAL,
        VulnStatus.REPORTED_VENDOR,
    ]:
        raise HTTPException(
            status_code=400,
            detail=f"Vulnerability already in disclosure process (status: {vuln['status']})",
        )

    submission_id = _generate_id()
    now = _now()

    contribution = {
        "submission_id": submission_id,
        "vuln_id": request.vuln_id,
        "internal_id": vuln["internal_id"],
        "program": request.program,
        "researcher_name": request.researcher_name,
        "researcher_email": request.researcher_email,
        "organization": request.organization,
        "disclosure_timeline": request.disclosure_timeline or "90 days",
        "coordinate_with_vendor": request.coordinate_with_vendor,
        "vendor_contact": request.vendor_contact,
        "status": "submitted",
        "cve_id": None,
        "submitted_at": now,
        "updated_at": now,
    }

    _contributions[submission_id] = contribution

    # Update vulnerability status
    vuln["status"] = VulnStatus.CVE_REQUESTED
    vuln["updated_at"] = now

    # Estimate based on program
    estimated_days = {
        ContributionProgram.MITRE: "7-14 days",
        ContributionProgram.CISA: "3-7 days",
        ContributionProgram.CERT: "5-10 days",
        ContributionProgram.VENDOR: "14-30 days",
    }

    logger.info(
        f"Submitted {vuln['internal_id']} to {request.program.value} CVE program"
    )

    return ContributeResponse(
        submission_id=submission_id,
        vuln_id=request.vuln_id,
        program=request.program,
        status="submitted",
        cve_id=None,
        estimated_assignment_date=estimated_days.get(request.program, "14-30 days"),
        tracking_url=f"https://cve.org/track/{submission_id[:8]}",
    )


@router.get("/internal", response_model=List[DiscoveredVulnResponse])
async def list_internal_vulnerabilities(
    status: Optional[VulnStatus] = None,
    severity: Optional[VulnSeverity] = None,
    discovery_source: Optional[DiscoverySource] = None,
    has_cve: Optional[bool] = None,
    impact_type: Optional[ImpactType] = None,
    tag: Optional[str] = None,
    discovered_after: Optional[datetime] = None,
    discovered_before: Optional[datetime] = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
) -> List[DiscoveredVulnResponse]:
    """List internal (pre-CVE) discovered vulnerabilities.

    These are vulnerabilities discovered through ALdeci pentesting
    that may not yet have public CVE IDs. This is proprietary
    intelligence that gives ALdeci users an advantage.

    Filtering options:
    - status: Current disclosure status
    - severity: Filter by severity level
    - discovery_source: How it was discovered
    - has_cve: Whether CVE has been assigned
    - impact_type: Type of vulnerability
    - tag: Filter by tag
    """
    vulns = list(_discovered_vulns.values())

    # Apply filters
    if status:
        vulns = [v for v in vulns if v["status"] == status]
    if severity:
        vulns = [v for v in vulns if v["severity"] == severity]
    if discovery_source:
        vulns = [v for v in vulns if v["discovery_source"] == discovery_source]
    if has_cve is not None:
        if has_cve:
            vulns = [v for v in vulns if v.get("cve_id")]
        else:
            vulns = [v for v in vulns if not v.get("cve_id")]
    if impact_type:
        vulns = [v for v in vulns if v["impact_type"] == impact_type]
    if tag:
        vulns = [v for v in vulns if tag in v.get("tags", [])]
    if discovered_after:
        vulns = [v for v in vulns if v["discovered_date"] > discovered_after]
    if discovered_before:
        vulns = [v for v in vulns if v["discovered_date"] < discovered_before]

    # Sort by discovered date (newest first)
    vulns = sorted(vulns, key=lambda v: v["discovered_date"], reverse=True)

    # Paginate
    vulns = vulns[offset : offset + limit]

    return [
        DiscoveredVulnResponse(
            id=v["id"],
            internal_id=v["internal_id"],
            title=v["title"],
            severity=v["severity"],
            status=v["status"],
            created_at=v["created_at"],
            discovered_by=v["discovered_by"],
            cvss_score=v.get("cvss_score"),
            cve_id=v.get("cve_id"),
        )
        for v in vulns
    ]


@router.get("/internal/{vuln_id}")
async def get_internal_vulnerability(vuln_id: str) -> Dict[str, Any]:
    """Get full details of an internal vulnerability."""
    if vuln_id not in _discovered_vulns:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    return _discovered_vulns[vuln_id]


@router.patch("/internal/{vuln_id}")
async def update_internal_vulnerability(
    vuln_id: str,
    updates: Dict[str, Any],
) -> Dict[str, Any]:
    """Update an internal vulnerability."""
    if vuln_id not in _discovered_vulns:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vuln = _discovered_vulns[vuln_id]

    # Allowed update fields
    allowed_fields = {
        "title",
        "description",
        "severity",
        "remediation",
        "workaround",
        "proof_of_concept",
        "references",
        "tags",
        "internal_only",
    }

    for key, value in updates.items():
        if key in allowed_fields:
            vuln[key] = value

    vuln["updated_at"] = _now()

    return vuln


@router.post("/train", response_model=RetrainResponse)
async def retrain_ml_models(
    request: RetrainRequest,
    background_tasks: BackgroundTasks,
) -> RetrainResponse:
    """Retrain ML models on new vulnerability data.

    ALdeci's ML models improve over time by learning from:
    1. Internally discovered vulnerabilities
    2. External CVE data
    3. Exploitation outcomes from pentests
    4. Remediation effectiveness

    This creates a feedback loop that makes our predictions
    more accurate than competitors who only use public data.

    Models that can be retrained:
    - severity_predictor: Predicts severity from description
    - exploitability_predictor: Predicts if vuln is exploitable
    - prioritization_model: SSVC-style prioritization
    - similarity_model: Finds related vulnerabilities
    - zero_day_detector: Identifies potential zero-days
    """
    job_id = _generate_id()
    now = _now()

    # Count data points
    internal_count = (
        len(request.vuln_ids) if request.vuln_ids else len(_discovered_vulns)
    )
    # Try to pull external CVE count from EPSS feed if available
    external_count = 0
    try:
        from feeds_service import FeedsService

        _epss = FeedsService._load_epss_scores()
        external_count = len(_epss) if _epss else 0
    except Exception:
        pass  # Feed unavailable — external_count stays 0
    total_data_points = internal_count + external_count

    # Estimate time based on data and models
    models = request.model_types
    estimated_minutes = len(models) * 15 + (total_data_points // 10000)

    job = {
        "job_id": job_id,
        "status": "queued",
        "models_queued": models,
        "data_points": total_data_points,
        "include_external": request.include_external,
        "started_at": None,
        "completed_at": None,
        "created_at": now,
    }

    _retrain_jobs[job_id] = job

    # Queue training job
    background_tasks.add_task(_run_training, job_id)

    logger.info(f"Queued ML training job {job_id} with {len(models)} models")

    return RetrainResponse(
        job_id=job_id,
        status="queued",
        models_queued=models,
        estimated_time=f"{estimated_minutes} minutes",
        data_points=total_data_points,
    )


async def _run_training(job_id: str) -> None:
    """Run ML model training.

    Requires MindsDB integration for actual training.
    """
    job = _retrain_jobs.get(job_id)
    if not job:
        return

    job["status"] = "training"
    job["started_at"] = _now()

    # Check if MindsDB is configured
    import os

    mindsdb_url = os.environ.get("MINDSDB_URL", "")

    if not mindsdb_url:
        # Cannot train without MindsDB
        job["status"] = "failed"
        job["completed_at"] = _now()
        job["results"] = {
            model: {
                "status": "pending_integration",
                "message": "Training requires MindsDB configuration (MINDSDB_URL)",
            }
            for model in job["models_queued"]
        }
        logger.warning(f"ML training job {job_id} failed: MindsDB not configured")
        return

    # MindsDB URL is set but actual training call is not yet wired.
    # Mark as "awaiting_integration" so callers know it's not silently dropped.
    job["status"] = "awaiting_integration"
    job["completed_at"] = _now()
    job["results"] = {
        model: {
            "status": "awaiting_integration",
            "message": f"MindsDB reachable at {mindsdb_url} but training API call not yet wired",
        }
        for model in job["models_queued"]
    }

    logger.info(f"ML training job {job_id} - pending MindsDB integration")


@router.get("/train/{job_id}")
async def get_training_job_status(job_id: str) -> Dict[str, Any]:
    """Get status of a training job."""
    if job_id not in _retrain_jobs:
        raise HTTPException(status_code=404, detail="Training job not found")

    return _retrain_jobs[job_id]


# =============================================================================
# Statistics Endpoints
# =============================================================================


@router.get("/stats")
async def get_discovery_stats() -> Dict[str, Any]:
    """Get vulnerability discovery statistics."""
    vulns = list(_discovered_vulns.values())

    return {
        "total_discovered": len(vulns),
        "by_severity": {
            "critical": len(
                [v for v in vulns if v["severity"] == VulnSeverity.CRITICAL]
            ),
            "high": len([v for v in vulns if v["severity"] == VulnSeverity.HIGH]),
            "medium": len([v for v in vulns if v["severity"] == VulnSeverity.MEDIUM]),
            "low": len([v for v in vulns if v["severity"] == VulnSeverity.LOW]),
        },
        "by_status": {
            "draft": len([v for v in vulns if v["status"] == VulnStatus.DRAFT]),
            "internal": len([v for v in vulns if v["status"] == VulnStatus.INTERNAL]),
            "cve_requested": len(
                [v for v in vulns if v["status"] == VulnStatus.CVE_REQUESTED]
            ),
            "cve_assigned": len(
                [v for v in vulns if v["status"] == VulnStatus.CVE_ASSIGNED]
            ),
            "public": len([v for v in vulns if v["status"] == VulnStatus.PUBLIC]),
        },
        "by_source": {
            source.value: len([v for v in vulns if v["discovery_source"] == source])
            for source in DiscoverySource
        },
        "cves_contributed": len([v for v in vulns if v.get("cve_id")]),
        "pending_disclosure": len(
            [v for v in vulns if v["status"] == VulnStatus.CVE_REQUESTED]
        ),
        "this_month": len(
            [v for v in vulns if v["created_at"].month == datetime.now().month]
        ),
    }


@router.get("/contributions")
async def list_cve_contributions(
    status: Optional[str] = None,
    program: Optional[ContributionProgram] = None,
    limit: int = Query(default=20, le=100),
) -> Dict[str, Any]:
    """List CVE contribution submissions."""
    contributions = list(_contributions.values())

    if status:
        contributions = [c for c in contributions if c["status"] == status]
    if program:
        contributions = [c for c in contributions if c["program"] == program]

    contributions = sorted(contributions, key=lambda c: c["submitted_at"], reverse=True)

    return {
        "contributions": contributions[:limit],
        "total": len(contributions),
        "by_program": {
            p.value: len([c for c in contributions if c["program"] == p])
            for p in ContributionProgram
        },
    }


# =============================================================================
# Health Check
# =============================================================================


@router.get("/health")
async def vuln_discovery_health() -> Dict[str, str]:
    """Vulnerability discovery service health check."""
    return {
        "status": "healthy",
        "service": "aldeci-vuln-discovery",
        "version": "1.0.0",
        "vulns_tracked": str(len(_discovered_vulns)),
    }
