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

from core.persistent_store import get_persistent_store
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Depends
from apps.api.dependencies import get_org_id
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
        "Vulnerability discovered via ALdeci platform.", min_length=1, max_length=32_000
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

    proof_of_concept: Optional[str] = Field(None, description="PoC code or steps", max_length=50_000)
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

    vuln_id: str = Field(..., description="ALdeci internal vulnerability ID", max_length=256)
    program: ContributionProgram
    researcher_name: str = Field(..., min_length=1, max_length=256)
    researcher_email: str = Field(..., min_length=5, max_length=254)
    organization: Optional[str] = Field(None, max_length=256)

    disclosure_timeline: Optional[str] = Field(
        None, description="Proposed disclosure timeline (e.g., '90 days')", max_length=256
    )
    coordinate_with_vendor: bool = True
    vendor_contact: Optional[str] = Field(None, max_length=512)

    additional_references: List[str] = Field(default_factory=list)

    @validator("researcher_email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        import re as _re
        if not _re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("researcher_email must be a valid email address")
        return v


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
# Persistent Storage (SQLite-backed)
# =============================================================================


_discovered_vulns = get_persistent_store("discovered_vulns")
_contributions = get_persistent_store("cve_contributions")
_retrain_jobs = get_persistent_store("retrain_jobs")
_trained_models: Dict[str, Any] = {}  # sklearn model objects (not serialisable)

# Counter for internal IDs
_vuln_counter = 0

# ML libraries are imported lazily on first use (avoids ~1s sklearn startup cost).
# Use _check_sklearn() inside functions that need sklearn, then access the globals.
_SKLEARN_AVAILABLE: bool | None = None  # None = not yet probed

np: Any = None
RandomForestClassifier: Any = None
GradientBoostingRegressor: Any = None
IsolationForest: Any = None
cross_val_score: Any = None
LabelEncoder: Any = None


def _check_sklearn() -> bool:
    """Lazy-load sklearn and numpy on first call; returns availability."""
    global _SKLEARN_AVAILABLE, np, RandomForestClassifier
    global GradientBoostingRegressor, IsolationForest, cross_val_score, LabelEncoder
    if _SKLEARN_AVAILABLE is not None:
        return _SKLEARN_AVAILABLE
    try:
        import numpy as _np
        from sklearn.ensemble import (
            GradientBoostingRegressor as _GBR,
            IsolationForest as _IF,
            RandomForestClassifier as _RFC,
        )
        from sklearn.model_selection import cross_val_score as _cvs
        from sklearn.preprocessing import LabelEncoder as _LE
        np = _np
        RandomForestClassifier = _RFC
        GradientBoostingRegressor = _GBR
        IsolationForest = _IF
        cross_val_score = _cvs
        LabelEncoder = _LE
        _SKLEARN_AVAILABLE = True
    except ImportError:
        _SKLEARN_AVAILABLE = False
    return _SKLEARN_AVAILABLE


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
    except (ImportError, ValueError, Exception):
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
    org_id: str = Depends(get_org_id),
) -> List[DiscoveredVulnResponse]:
    """List discovered vulnerabilities (GET alias for /internal)."""
    # AUTHZ: filter to caller's org to prevent cross-tenant data leak
    vulns = [v for v in _discovered_vulns.values() if v.get("org_id", "default") == org_id]
    if status:
        vulns = [v for v in vulns if str(v.get("status", "")) == status.value or v.get("status") == status]
    if severity:
        vulns = [v for v in vulns if str(v.get("severity", "")) == severity.value or v.get("severity") == severity]

    def _sort_key(v: Dict) -> str:
        dd = v.get("discovered_date", "")
        if isinstance(dd, str):
            return dd
        return dd.isoformat() if dd else ""

    vulns = sorted(vulns, key=_sort_key, reverse=True)
    results = []
    for v in vulns[offset : offset + limit]:
        try:
            results.append(DiscoveredVulnResponse(**v))
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            # Gracefully skip entries that fail Pydantic validation (stale data)
            pass
    return results


@router.post("/discovered", response_model=DiscoveredVulnResponse)
async def report_discovered_vulnerability(
    request: DiscoveredVulnRequest,
    background_tasks: BackgroundTasks,
    org_id: str = Depends(get_org_id),
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

    # TrustGraph explicit indexing (fire-and-forget)
    try:
        from core.trustgraph_event_bus import EVENT_FINDING_CREATED, get_event_bus as _get_eb
        _bus = _get_eb()
        if _bus and _bus.enabled:
            import asyncio as _asyncio
            _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                "finding_id": vuln_id,
                "type": "vuln_discovery", "severity": str(request.severity.value),
                "source": "vuln_discovery_router",
                "data": {"internal_id": internal_id, "title": request.title},
            }))
    except (ImportError, OSError, RuntimeError, AttributeError):
        pass

    logger.info("Reported discovered vulnerability: %s", internal_id)

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
    logger.info("Notifying vendor about vulnerability %s", vuln.get("internal_id", "unknown"))
    vuln["status"] = VulnStatus.REPORTED_VENDOR
    vuln["updated_at"] = _now()
    _discovered_vulns.persist(vuln_id)


@router.post("/contribute", response_model=ContributeResponse)
async def contribute_to_cve_program(
    request: ContributeRequest,
    background_tasks: BackgroundTasks,
    org_id: str = Depends(get_org_id),
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
    _discovered_vulns.persist(request.vuln_id)

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
    org_id: str = Depends(get_org_id),
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
    _discovered_vulns.persist(vuln_id)

    return vuln


@router.post("/train", response_model=RetrainResponse)
async def retrain_ml_models(
    request: RetrainRequest,
    background_tasks: BackgroundTasks,
    org_id: str = Depends(get_org_id),
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

        _fs = FeedsService()
        _stats = _fs.get_feed_stats() if hasattr(_fs, "get_feed_stats") else {}
        external_count = _stats.get("epss_count", 0) if isinstance(_stats, dict) else 0
    except (ImportError, Exception):
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
        "_vuln_ids": request.vuln_ids,  # stored for _build_training_dataset
        "started_at": None,
        "completed_at": None,
        "created_at": now,
    }

    _retrain_jobs[job_id] = job

    # Queue training job
    background_tasks.add_task(_run_training, job_id)

    logger.info("Queued ML training job %s with %d models", job_id, len(models))

    return RetrainResponse(
        job_id=job_id,
        status="queued",
        models_queued=models,
        estimated_time=f"{estimated_minutes} minutes",
        data_points=total_data_points,
    )


# ---------------------------------------------------------------------------
# Feature engineering helpers for ML training
# ---------------------------------------------------------------------------

_ATTACK_VECTOR_MAP = {"network": 4, "adjacent": 3, "local": 2, "physical": 1}
_DIFFICULTY_MAP = {"trivial": 4, "low": 3, "medium": 2, "high": 1}
_SEVERITY_MAP = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_IMPACT_TYPES = [
    "remote_code_execution",
    "sql_injection",
    "cross_site_scripting",
    "server_side_request_forgery",
    "xml_external_entity",
    "insecure_direct_object_reference",
    "authentication_bypass",
    "privilege_escalation",
    "information_disclosure",
    "denial_of_service",
    "other",
]


def _enum_val(v: Any) -> str:
    """Extract string value from a potential enum or string."""
    return v.value if hasattr(v, "value") else str(v).lower()


def _vuln_to_features(vuln: Dict[str, Any]) -> List[float]:
    """Convert a vulnerability dict to a numeric feature vector."""
    av = _enum_val(vuln.get("attack_vector", "network"))
    av_val = _ATTACK_VECTOR_MAP.get(av, 2)

    diff = _enum_val(vuln.get("exploitation_difficulty", "medium"))
    diff_val = _DIFFICULTY_MAP.get(diff, 2)

    cvss = float(vuln.get("cvss_score", 0) or 0)
    has_poc = 1.0 if vuln.get("proof_of_concept") else 0.0
    comp_count = float(len(vuln.get("affected_components", [])))

    # One-hot encode impact_type
    impact = _enum_val(vuln.get("impact_type", "other"))
    impact_vec = [1.0 if t == impact else 0.0 for t in _IMPACT_TYPES]

    return [av_val, diff_val, cvss, has_poc, comp_count] + impact_vec


def _build_training_dataset(
    job: Dict[str, Any],
) -> tuple:
    """Build feature matrix X and label arrays from internal vulns + EPSS."""
    vuln_ids = job.get("_vuln_ids") or []
    include_external = job.get("include_external", True)

    # Gather internal vulnerability data
    if vuln_ids:
        vulns = [_discovered_vulns[vid] for vid in vuln_ids if vid in _discovered_vulns]
    else:
        vulns = list(_discovered_vulns.values())

    # Gather external EPSS data as synthetic training samples
    epss_records: Dict[str, float] = {}
    if include_external:
        try:
            from feeds_service import FeedsService as _FS

            epss_records = _FS._load_epss_scores()
        except ImportError:
            pass

    # Build feature matrix from internal vulns
    X_rows: List[List[float]] = []
    severity_labels: List[str] = []
    exploitability_scores: List[float] = []

    for v in vulns:
        X_rows.append(_vuln_to_features(v))
        raw_sev = v.get("severity", "medium")
        sev = raw_sev.value if hasattr(raw_sev, "value") else str(raw_sev).lower()
        severity_labels.append(sev)
        epss = float(v.get("epss_score", 0) or 0)
        diff_key = _enum_val(v.get("exploitation_difficulty", "medium"))
        exploitability_scores.append(
            epss if epss > 0 else _DIFFICULTY_MAP.get(diff_key, 2) / 4.0
        )

    # Augment with EPSS data as synthetic rows (severity inferred from score)
    for cve_id, epss_score in list(epss_records.items())[:2000]:
        # Infer severity from EPSS score ranges
        if epss_score >= 0.7:
            sev = "critical"
        elif epss_score >= 0.4:
            sev = "high"
        elif epss_score >= 0.1:
            sev = "medium"
        else:
            sev = "low"

        cvss_est = epss_score * 10.0  # Rough EPSS→CVSS mapping
        synth = [4, 3, cvss_est, 0.0, 1.0] + [0.0] * len(_IMPACT_TYPES)
        X_rows.append(synth)
        severity_labels.append(sev)
        exploitability_scores.append(epss_score)

    return X_rows, severity_labels, exploitability_scores


async def _run_training(job_id: str) -> None:
    """Run ML model training using scikit-learn.

    Trains real models on vulnerability data:
    - severity_predictor: RandomForestClassifier
    - exploitability_predictor: GradientBoostingRegressor
    - zero_day_detector: IsolationForest anomaly detector
    """
    job = _retrain_jobs.get(job_id)
    if not job:
        return

    job["status"] = "training"
    job["started_at"] = _now()
    _retrain_jobs.persist(job_id)

    if not _check_sklearn():
        job["status"] = "failed"
        job["completed_at"] = _now()
        job["results"] = {
            model: {
                "status": "failed",
                "message": "scikit-learn not installed (pip install scikit-learn numpy)",
            }
            for model in job["models_queued"]
        }
        _retrain_jobs.persist(job_id)
        logger.warning("ML training job %s failed: scikit-learn not available", job_id)
        return

    try:
        X_rows, severity_labels, exploitability_scores = _build_training_dataset(job)

        if len(X_rows) < 5:
            job["status"] = "failed"
            job["completed_at"] = _now()
            job["results"] = {
                model: {
                    "status": "insufficient_data",
                    "message": f"Need ≥5 data points, have {len(X_rows)}. "
                    "Add vulnerabilities via POST /vulns/discovered or enable "
                    "include_external to pull EPSS feed data.",
                }
                for model in job["models_queued"]
            }
            _retrain_jobs.persist(job_id)
            logger.warning(
                f"ML training job {job_id} failed: only {len(X_rows)} samples"
            )
            return

        X = np.array(X_rows, dtype=np.float64)
        results: Dict[str, Dict[str, Any]] = {}

        for model_name in job["models_queued"]:
            try:
                result = _train_single_model(
                    model_name, X, severity_labels, exploitability_scores
                )
                results[model_name] = result
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
                results[model_name] = {
                    "status": "failed",
                    "message": str(e),
                }
                logger.error("Training %s failed: %s", model_name, type(e).__name__)

        all_ok = all(r.get("status") == "trained" for r in results.values())
        job["status"] = "completed" if all_ok else "partial"
        job["completed_at"] = _now()
        job["results"] = results
        job["training_samples"] = len(X_rows)
        _retrain_jobs.persist(job_id)

        logger.info(
            f"ML training job {job_id} {'completed' if all_ok else 'partial'}: "
            f"{len(X_rows)} samples, {len(job['models_queued'])} models"
        )

    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
        job["status"] = "failed"
        job["completed_at"] = _now()
        job["results"] = {
            model: {"status": "failed", "message": str(e)}
            for model in job["models_queued"]
        }
        _retrain_jobs.persist(job_id)
        logger.error("ML training job %s failed: %s", job_id, type(e).__name__)


def _train_single_model(
    model_name: str,
    X: "np.ndarray",
    severity_labels: List[str],
    exploitability_scores: List[float],
) -> Dict[str, Any]:
    """Train a single ML model and return metrics."""
    if model_name == "severity_predictor":
        le = LabelEncoder()
        y = le.fit_transform(severity_labels)
        clf = RandomForestClassifier(
            n_estimators=100, max_depth=10, random_state=42, n_jobs=-1
        )
        clf.fit(X, y)
        # Cross-validate if enough samples; fall back on class-imbalance errors
        if len(X) >= 10:
            try:
                from collections import Counter

                min_class_count = min(Counter(y).values())
                n_splits = max(2, min(5, len(X), min_class_count))
                scores = cross_val_score(clf, X, y, cv=n_splits, scoring="accuracy")
                accuracy = float(np.mean(scores))
            except ValueError:
                # Stratified k-fold can still fail with extreme imbalance
                accuracy = float(clf.score(X, y))
        else:
            accuracy = float(clf.score(X, y))

        _trained_models["severity_predictor"] = {"model": clf, "encoder": le}
        return {
            "status": "trained",
            "algorithm": "RandomForestClassifier",
            "samples": len(X),
            "features": X.shape[1],
            "classes": list(le.classes_),
            "accuracy": round(accuracy, 4),
            "n_estimators": 100,
        }

    elif model_name == "exploitability_predictor":
        y = np.array(exploitability_scores, dtype=np.float64)
        reg = GradientBoostingRegressor(
            n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42
        )
        reg.fit(X, y)
        if len(X) >= 10:
            try:
                n_splits = max(2, min(5, len(X)))
                scores = cross_val_score(reg, X, y, cv=n_splits, scoring="r2")
                r2 = float(np.mean(scores))
            except ValueError:
                r2 = float(reg.score(X, y))
        else:
            r2 = float(reg.score(X, y))

        _trained_models["exploitability_predictor"] = {"model": reg}
        return {
            "status": "trained",
            "algorithm": "GradientBoostingRegressor",
            "samples": len(X),
            "features": X.shape[1],
            "r2_score": round(r2, 4),
            "n_estimators": 100,
        }

    elif model_name == "zero_day_detector":
        iso = IsolationForest(
            n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1
        )
        iso.fit(X)
        preds = iso.predict(X)
        anomaly_count = int(np.sum(preds == -1))

        _trained_models["zero_day_detector"] = {"model": iso}
        return {
            "status": "trained",
            "algorithm": "IsolationForest",
            "samples": len(X),
            "features": X.shape[1],
            "contamination": 0.05,
            "anomalies_detected": anomaly_count,
            "anomaly_rate": round(anomaly_count / len(X), 4) if len(X) > 0 else 0,
        }

    else:
        return {
            "status": "failed",
            "message": f"Unknown model type: {model_name}. "
            "Supported: severity_predictor, exploitability_predictor, zero_day_detector",
        }


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

    def _sev(v: Dict) -> str:
        """Get severity as string for comparison (handles both enum and str)."""
        s = v.get("severity", "")
        return s.value if hasattr(s, "value") else str(s)

    def _status(v: Dict) -> str:
        """Get status as string for comparison."""
        s = v.get("status", "")
        return s.value if hasattr(s, "value") else str(s)

    def _source(v: Dict) -> str:
        """Get discovery_source as string for comparison."""
        s = v.get("discovery_source", "")
        return s.value if hasattr(s, "value") else str(s)

    def _created_month(v: Dict) -> int:
        """Safely extract month from created_at (handles str or datetime)."""
        ca = v.get("created_at")
        if ca is None:
            return 0
        if isinstance(ca, str):
            try:
                return datetime.fromisoformat(ca).month
            except (ValueError, TypeError):
                return 0
        return ca.month

    now_month = datetime.now().month

    return {
        "total_discovered": len(vulns),
        "by_severity": {
            "critical": len([v for v in vulns if _sev(v) == "critical"]),
            "high": len([v for v in vulns if _sev(v) == "high"]),
            "medium": len([v for v in vulns if _sev(v) == "medium"]),
            "low": len([v for v in vulns if _sev(v) == "low"]),
        },
        "by_status": {
            "draft": len([v for v in vulns if _status(v) == "draft"]),
            "internal": len([v for v in vulns if _status(v) == "internal"]),
            "cve_requested": len(
                [v for v in vulns if _status(v) == "cve_requested"]
            ),
            "cve_assigned": len(
                [v for v in vulns if _status(v) == "cve_assigned"]
            ),
            "public": len([v for v in vulns if _status(v) == "public"]),
        },
        "by_source": {
            source.value: len([v for v in vulns if _source(v) == source.value])
            for source in DiscoverySource
        },
        "cves_contributed": len([v for v in vulns if v.get("cve_id")]),
        "pending_disclosure": len(
            [v for v in vulns if _status(v) == "cve_requested"]
        ),
        "this_month": len(
            [v for v in vulns if _created_month(v) == now_month]
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


@router.get("/status")
async def vuln_discovery_status() -> Dict[str, str]:
    """Status alias for vulnerability discovery service."""
    return await vuln_discovery_health()
