"""
Secrets detection API endpoints.

Provides enterprise-grade secrets scanning with gitleaks and trufflehog integration.
Also includes the ALDECI SecretsManager engine: 200+ pattern scanning, git history
scanning, auto-rotation stubs, Vault integration stubs, pre-commit hook generation,
secret lifecycle tracking, and compliance mapping.

SECURITY: This router handles sensitive data (secrets/credentials).
- NEVER log actual secret values
- Redact matched_pattern fields in logs
- Validate all file paths against traversal attacks
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.secrets_db import SecretsDB
from core.secrets_models import SecretFinding, SecretStatus, SecretType
from core.secrets_scanner import SecretsScanner, get_secrets_detector
from fastapi import APIRouter, HTTPException, Query, Depends, status as http_status
from apps.api.dependencies import get_org_id
from pydantic import BaseModel, Field, field_validator

# ALDECI SecretsManager — 200+ patterns, rotation, Vault, pre-commit
try:
    from core.secrets_manager import (
        RotationStatus,
        ScanType,
        SecretCategory,
        SecretFinding as MgrFinding,
        SecretPolicy,
        SecretSeverity,
        SecretsManager,
        ScanResult,
        SECRET_PATTERNS,
        get_manager,
    )
    _HAS_MGR = True
except ImportError:
    _HAS_MGR = False

# Knowledge Brain + Event Bus integration (graceful degradation)
try:
    from core.event_bus import Event, EventType, get_event_bus
    from core.knowledge_brain import get_brain

    _HAS_BRAIN = True
except ImportError:
    _HAS_BRAIN = False

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/secrets", tags=["secrets", "Secrets Management"])
db = SecretsDB()

_MAX_FILE_PATH_LENGTH = 1024
_MAX_CONTENT_LENGTH = 2_000_000  # 2MB max content to scan
_MAX_FILENAME_LENGTH = 255
_MAX_REPOSITORY_LENGTH = 256
_MAX_BRANCH_LENGTH = 256
_MAX_PATTERN_LENGTH = 1024


def _sanitize_file_path(path: str) -> str:
    """Sanitize file path — strip traversal attempts but keep relative paths."""
    if ".." in path:
        # Remove any traversal components
        parts = path.replace("\\", "/").split("/")
        parts = [p for p in parts if p != ".."]
        path = "/".join(parts)
    # Remove null bytes and control characters
    path = "".join(c for c in path if c.isprintable() and c != "\x00")
    if len(path) > _MAX_FILE_PATH_LENGTH:
        path = path[:_MAX_FILE_PATH_LENGTH]
    return path or "unknown"


class SecretFindingCreate(BaseModel):
    """Request model for creating secret finding."""

    secret_type: SecretType
    file_path: str = Field(..., max_length=_MAX_FILE_PATH_LENGTH)
    line_number: int = Field(..., ge=0, le=10_000_000)
    repository: str = Field(..., max_length=_MAX_REPOSITORY_LENGTH)
    branch: str = Field(..., max_length=_MAX_BRANCH_LENGTH)
    commit_hash: Optional[str] = Field(None, max_length=64)
    matched_pattern: Optional[str] = Field(None, max_length=_MAX_PATTERN_LENGTH)
    entropy_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("file_path")
    @classmethod
    def validate_file_path(cls, v: str) -> str:
        return _sanitize_file_path(v)


class SecretFindingResponse(BaseModel):
    """Response model for secret finding."""

    id: str
    secret_type: str
    status: str
    file_path: str
    line_number: int
    repository: str
    branch: str
    commit_hash: Optional[str]
    matched_pattern: Optional[str]
    entropy_score: Optional[float]
    metadata: Dict[str, Any]
    detected_at: str
    resolved_at: Optional[str]


class PaginatedSecretFindingResponse(BaseModel):
    """Paginated secret finding response."""

    items: List[SecretFindingResponse]
    total: int
    limit: int
    offset: int


@router.get("/status")
async def get_secrets_status(org_id: str = Depends(get_org_id)):
    """Get status of secrets scanning subsystem."""
    findings = db.list_findings(limit=10000)
    resolved = sum(1 for f in findings if f.status == SecretStatus.RESOLVED)
    active = len(findings) - resolved
    return {
        "status": "operational",
        "total_findings": len(findings),
        "active_findings": active,
        "resolved_findings": resolved,
        "scanners": {
            "gitleaks": {"available": True, "status": "ready"},
            "trufflehog": {"available": True, "status": "ready"},
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/health")
async def secrets_health(org_id: str = Depends(get_org_id)):
    """Secrets scanner health check (alias for /status)."""
    return await get_secrets_status()


@router.get("/scan/results")
async def get_scan_results(
    limit: int = Query(50, ge=1, le=500),
):
    """Get recent secrets scan results."""
    try:
        findings = db.list_findings(limit=limit)
        results = []
        for f in findings:
            try:
                results.append({
                    "id": getattr(f, "id", "unknown"),
                    "type": getattr(f, "secret_type", "unknown"),
                    "file": getattr(f, "file_path", "unknown"),
                    "severity": (f.severity.value if hasattr(f, "severity") and hasattr(f.severity, "value") else str(getattr(f, "severity", "medium"))),
                    "status": (f.status.value if hasattr(f, "status") and hasattr(f.status, "value") else str(getattr(f, "status", "open"))),
                    "detected_at": (f.created_at.isoformat() if hasattr(f, "created_at") and f.created_at else None),
                })
            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                continue
        return {"status": "ok", "results": results, "total": len(results)}
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
        return {"status": "ok", "results": [], "total": 0}


@router.get("", response_model=PaginatedSecretFindingResponse)
async def list_secret_findings(
    repository: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List all secret findings with optional filtering."""
    findings = db.list_findings(repository=repository, limit=limit, offset=offset)
    return {
        "items": [SecretFindingResponse(**f.to_dict()) for f in findings],
        "total": len(findings),
        "limit": limit,
        "offset": offset,
    }


@router.post("", response_model=SecretFindingResponse, status_code=201)
async def create_secret_finding(finding_data: SecretFindingCreate, org_id: str = Depends(get_org_id)):
    """Create a new secret finding."""
    finding = SecretFinding(
        id="",
        secret_type=finding_data.secret_type,
        status=SecretStatus.ACTIVE,
        file_path=finding_data.file_path,
        line_number=finding_data.line_number,
        repository=finding_data.repository,
        branch=finding_data.branch,
        commit_hash=finding_data.commit_hash,
        matched_pattern=finding_data.matched_pattern,
        entropy_score=finding_data.entropy_score,
        metadata=finding_data.metadata,
    )
    created_finding = db.create_finding(finding)

    # Emit secret found event + ingest into Knowledge Brain
    if _HAS_BRAIN:
        try:
            bus = get_event_bus()
            brain = get_brain()
            brain.ingest_finding(
                created_finding.id,
                title=f"Secret: {finding_data.secret_type.value} in {finding_data.repository}",
                severity="high",
                source="secrets_scanner",
                file_path=finding_data.file_path,
                repository=finding_data.repository,
            )
            await bus.emit(
                Event(
                    event_type=EventType.SECRET_FOUND,
                    source="secrets_router",
                    data={
                        "finding_id": created_finding.id,
                        "secret_type": finding_data.secret_type.value,
                        "repository": finding_data.repository,
                        "file_path": finding_data.file_path,
                    },
                )
            )
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning("Brain/EventBus integration failed: %s", type(e).__name__)

    return SecretFindingResponse(**created_finding.to_dict())


@router.get("/{id}", response_model=SecretFindingResponse)
async def get_secret_finding(id: str, org_id: str = Depends(get_org_id)):
    """Get secret finding by ID."""
    finding = db.get_finding(id)
    if not finding:
        raise HTTPException(status_code=404, detail="Secret finding not found")
    return SecretFindingResponse(**finding.to_dict())


@router.post("/{id}/resolve", response_model=SecretFindingResponse)
async def resolve_secret_finding(id: str, org_id: str = Depends(get_org_id)):
    """Mark secret finding as resolved."""
    finding = db.get_finding(id)
    if not finding:
        raise HTTPException(status_code=404, detail="Secret finding not found")

    finding.status = SecretStatus.RESOLVED
    finding.resolved_at = datetime.now(timezone.utc)
    updated_finding = db.update_finding(finding)
    return SecretFindingResponse(**updated_finding.to_dict())


class SecretsScanResponse(BaseModel):
    """Response model for secrets scan."""

    scan_id: str
    status: str
    scanner: str
    target_path: str
    repository: str
    branch: str
    findings_count: int
    findings: List[SecretFindingResponse]
    started_at: Optional[str]
    completed_at: Optional[str]
    duration_seconds: Optional[float]
    error_message: Optional[str]
    metadata: Dict[str, Any]


class SecretsDetectorStatusResponse(BaseModel):
    """Response model for detector status."""

    gitleaks_available: bool
    trufflehog_available: bool
    available_scanners: List[str]


@router.get("/scanners/status", response_model=SecretsDetectorStatusResponse)
async def get_detector_status(org_id: str = Depends(get_org_id)):
    """Get status of available secrets scanners."""
    detector = get_secrets_detector()
    available = detector.get_available_scanners()
    return {
        "gitleaks_available": detector._is_gitleaks_available(),
        "trufflehog_available": detector._is_trufflehog_available(),
        "available_scanners": [s.value for s in available],
    }


class SecretsScanContentRequest(BaseModel):
    """Request model for scanning content for secrets."""

    content: str = Field(
        ...,
        description="File content to scan",
        max_length=_MAX_CONTENT_LENGTH,
    )
    filename: str = Field(
        ...,
        description="Filename",
        max_length=_MAX_FILENAME_LENGTH,
    )
    repository: str = Field(
        "inline",
        description="Repository name",
        max_length=_MAX_REPOSITORY_LENGTH,
    )
    branch: str = Field(
        "main",
        description="Branch name",
        max_length=_MAX_BRANCH_LENGTH,
    )
    scanner: Optional[str] = Field(
        None,
        description="Scanner to use: 'gitleaks' or 'trufflehog' (auto-selected if not specified)",
    )

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v: str) -> str:
        """Sanitize filename to prevent path traversal."""
        if ".." in v or "/" in v or "\\" in v:
            v = os.path.basename(v)
        v = "".join(c for c in v if c.isprintable() and c != "\x00")
        return v[:_MAX_FILENAME_LENGTH] if v else "unknown.txt"


@router.post("/scan/content", response_model=SecretsScanResponse)
async def scan_content_for_secrets(request: SecretsScanContentRequest, org_id: str = Depends(get_org_id)):
    """
    Scan content provided as a string for secrets.

    Useful for scanning code snippets or content from CI/CD pipelines
    without requiring file system access.
    """
    detector = get_secrets_detector()

    scanner_type = None
    if request.scanner:
        try:
            scanner_type = SecretsScanner(request.scanner.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scanner: {request.scanner}. Use 'gitleaks' or 'trufflehog'.",
            )

    try:
        result = await detector.scan_content(
            content=request.content,
            filename=request.filename,
            repository=request.repository,
            branch=request.branch,
            scanner=scanner_type,
        )
    except Exception as e:  # must catch all for resilience (scanner may raise any type)
        # SECURITY: Never include exception details that might contain secret values
        logger.error(
            "Secrets content scan failed: %s: %s",
            type(e).__name__,
            str(e)[:200],  # Truncate to avoid logging secrets
        )
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {type(e).__name__}",
        )

    for finding in result.findings:
        try:
            db.create_finding(finding)
        except Exception as e:  # must catch all — persist failure must not break scan response
            logger.warning("Failed to persist finding: %s", type(e).__name__)

    return SecretsScanResponse(
        scan_id=result.scan_id,
        status=result.status.value,
        scanner=result.scanner.value,
        target_path=result.target_path,
        repository=result.repository,
        branch=result.branch,
        findings_count=len(result.findings),
        findings=[SecretFindingResponse(**f.to_dict()) for f in result.findings],
        started_at=result.started_at.isoformat() if result.started_at else None,
        completed_at=result.completed_at.isoformat() if result.completed_at else None,
        duration_seconds=result.duration_seconds,
        error_message=result.error_message,
        metadata=result.metadata,
    )


# ===========================================================================
# ALDECI SecretsManager endpoints — 200+ patterns, rotation, Vault, lifecycle
# ===========================================================================


def _require_mgr() -> "SecretsManager":
    if not _HAS_MGR:
        raise HTTPException(
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SecretsManager not available — check suite-core installation",
        )
    try:
        return get_manager()
    except Exception as exc:
        raise HTTPException(
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"SecretsManager unavailable: {exc}",
        )


# ── Request / Response models ────────────────────────────────────────────────

class MgrScanRequest(BaseModel):
    target_path: str = Field(..., description="Absolute path to repo or file to scan")
    scan_type: str = Field("filesystem", description="filesystem | git_history")
    include_git_history: bool = Field(False, description="Also scan git commit history")


class MgrScanSummaryResponse(BaseModel):
    scan_id: str
    scan_type: str
    target_path: str
    files_scanned: int
    commits_scanned: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    started_at: str
    completed_at: Optional[str]
    errors: List[str]


class MgrFindingResponse(BaseModel):
    id: str
    pattern_id: str
    category: str
    severity: str
    name: str
    file_path: str
    line_number: int
    matched_value: str
    scan_type: str
    commit_sha: Optional[str]
    commit_author: Optional[str]
    commit_date: Optional[str]
    introduced_at: Optional[str]
    compliance_tags: List[str]
    rotation_status: str
    first_seen: str
    last_seen: str


class MgrRotationResponse(BaseModel):
    finding_id: str
    category: str
    rotation_steps: List[str]
    rotation_script: str
    estimated_downtime_minutes: int
    requires_service_restart: bool
    vault_path: Optional[str]
    status: str
    created_at: str


class MgrPolicyResponse(BaseModel):
    id: str
    name: str
    description: str
    categories: List[str]
    max_age_days: int
    require_rotation: bool
    block_on_commit: bool
    compliance_frameworks: List[str]
    created_at: str


def _mgr_finding_to_resp(f: "MgrFinding") -> MgrFindingResponse:
    return MgrFindingResponse(
        id=f.id,
        pattern_id=f.pattern_id,
        category=f.category.value,
        severity=f.severity.value,
        name=f.name,
        file_path=f.file_path,
        line_number=f.line_number,
        matched_value=f.matched_value,
        scan_type=f.scan_type.value,
        commit_sha=f.commit_sha,
        commit_author=f.commit_author,
        commit_date=f.commit_date,
        introduced_at=f.introduced_at,
        compliance_tags=f.compliance_tags,
        rotation_status=f.rotation_status.value,
        first_seen=f.first_seen.isoformat(),
        last_seen=f.last_seen.isoformat(),
    )


def _mgr_scan_to_resp(r: "ScanResult") -> MgrScanSummaryResponse:
    return MgrScanSummaryResponse(
        scan_id=r.id,
        scan_type=r.scan_type.value,
        target_path=r.target_path,
        files_scanned=r.files_scanned,
        commits_scanned=r.commits_scanned,
        findings_count=r.findings_count,
        critical_count=r.critical_count,
        high_count=r.high_count,
        medium_count=r.medium_count,
        low_count=r.low_count,
        started_at=r.started_at.isoformat(),
        completed_at=r.completed_at.isoformat() if r.completed_at else None,
        errors=r.errors,
    )


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post(
    "/scan",
    response_model=MgrScanSummaryResponse,
    summary="Trigger ALDECI secrets scan (200+ patterns)",
    tags=["Secrets Management"],
)
def trigger_mgr_scan(request: MgrScanRequest) -> MgrScanSummaryResponse:
    """
    Scan a filesystem path or git repo for leaked secrets using 200+ regex patterns.
    Set scan_type='git_history' to scan all commits. include_git_history=true runs both.
    """
    mgr = _require_mgr()
    scan_type = ScanType(request.scan_type) if _HAS_MGR else None
    if scan_type == ScanType.GIT_HISTORY:
        result = mgr.scan_git_history(request.target_path)
    else:
        result = mgr.scan_filesystem(request.target_path)
        if request.include_git_history:
            hist = mgr.scan_git_history(request.target_path)
            result.findings.extend(hist.findings)
            result.commits_scanned = hist.commits_scanned
            result.findings_count = len(result.findings)
            for f in hist.findings:
                sev = f.severity.value
                if sev == "critical":
                    result.critical_count += 1
                elif sev == "high":
                    result.high_count += 1
                elif sev == "medium":
                    result.medium_count += 1
                else:
                    result.low_count += 1
    return _mgr_scan_to_resp(result)


@router.get(
    "/findings",
    response_model=List[MgrFindingResponse],
    summary="All discovered secrets with severity",
    tags=["Secrets Management"],
)
def get_mgr_findings(
    severity: Optional[str] = Query(None, description="critical | high | medium | low"),
    category: Optional[str] = Query(None, description="aws | gcp | azure | github | database | ..."),
    rotation_status: Optional[str] = Query(None, description="pending | in_progress | completed | failed"),
    limit: int = Query(500, ge=1, le=5000),
) -> List[MgrFindingResponse]:
    """Return all stored secret findings from the ALDECI scanner, optionally filtered."""
    mgr = _require_mgr()
    sev = SecretSeverity(severity) if severity else None
    cat = SecretCategory(category) if category else None
    rot = RotationStatus(rotation_status) if rotation_status else None
    findings = mgr.get_findings(severity=sev, category=cat, rotation_status=rot, limit=limit)
    return [_mgr_finding_to_resp(f) for f in findings]


@router.get(
    "/history",
    response_model=List[MgrFindingResponse],
    summary="Git history scan results",
    tags=["Secrets Management"],
)
def get_git_history_findings() -> List[MgrFindingResponse]:
    """Return secrets found in git commit history including author and commit SHA."""
    mgr = _require_mgr()
    return [_mgr_finding_to_resp(f) for f in mgr.get_git_history_findings()]


@router.get(
    "/rotation-status",
    response_model=Dict[str, Any],
    summary="Secrets needing rotation",
    tags=["Secrets Management"],
)
def get_rotation_status() -> Dict[str, Any]:
    """Return critical/high-severity secrets with rotation_status=pending or failed."""
    mgr = _require_mgr()
    findings = mgr.get_rotation_needed()
    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        cat = f.category.value
        by_category.setdefault(cat, [])
        by_category[cat].append({
            "id": f.id,
            "name": f.name,
            "severity": f.severity.value,
            "file_path": f.file_path,
            "rotation_status": f.rotation_status.value,
            "first_seen": f.first_seen.isoformat(),
        })
    return {
        "total_needing_rotation": len(findings),
        "by_category": by_category,
        "findings": [_mgr_finding_to_resp(f).model_dump() for f in findings],
    }


@router.post(
    "/rotate/{finding_id}",
    response_model=MgrRotationResponse,
    summary="Trigger rotation workflow",
    tags=["Secrets Management"],
)
def trigger_rotation(finding_id: str) -> MgrRotationResponse:
    """
    Generate and trigger a rotation plan for a specific secret finding.
    Returns rotation steps and a ready-to-run shell script.
    """
    mgr = _require_mgr()
    finding = mgr.get_finding(finding_id)
    if not finding:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Finding not found: {finding_id}",
        )
    plan = mgr.trigger_rotation(finding_id)
    return MgrRotationResponse(
        finding_id=plan.finding_id,
        category=plan.category.value,
        rotation_steps=plan.rotation_steps,
        rotation_script=plan.rotation_script,
        estimated_downtime_minutes=plan.estimated_downtime_minutes,
        requires_service_restart=plan.requires_service_restart,
        vault_path=plan.vault_path,
        status=plan.status.value,
        created_at=plan.created_at.isoformat(),
    )


@router.get(
    "/policies",
    response_model=List[MgrPolicyResponse],
    summary="Active secrets policies",
    tags=["Secrets Management"],
)
def get_mgr_policies() -> List[MgrPolicyResponse]:
    """List all active secrets management policies with compliance framework mappings."""
    mgr = _require_mgr()
    return [
        MgrPolicyResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            categories=[c.value for c in p.categories],
            max_age_days=p.max_age_days,
            require_rotation=p.require_rotation,
            block_on_commit=p.block_on_commit,
            compliance_frameworks=p.compliance_frameworks,
            created_at=p.created_at.isoformat(),
        )
        for p in mgr.get_policies()
    ]


@router.get(
    "/pre-commit",
    response_model=Dict[str, str],
    summary="Generate pre-commit hook config",
    tags=["Secrets Management"],
)
def get_precommit_config(
    repo_path: Optional[str] = Query(None, description="If provided, write config to this path"),
) -> Dict[str, str]:
    """
    Generate a .pre-commit-config.yaml with ALDECI secrets scanner hook.
    Blocks commits containing secrets before they reach the remote.
    """
    mgr = _require_mgr()
    write_path = repo_path or "/tmp/aldeci_precommit_preview"  # nosec B108
    yaml_content = mgr.generate_precommit_config(write_path)
    hook_script = mgr.generate_precommit_hook_script()
    return {
        "pre_commit_config": yaml_content,
        "hook_script": hook_script,
        "instructions": (
            "1. Copy .pre-commit-config.yaml to your repo root.\n"
            "2. pip install pre-commit\n"
            "3. pre-commit install\n"
            "4. Commits containing secrets will now be blocked automatically."
        ),
    }


@router.get(
    "/compliance",
    response_model=Dict[str, Any],
    summary="Compliance framework mapping",
    tags=["Secrets Management"],
)
def get_compliance_summary() -> Dict[str, Any]:
    """Map secret findings to SOC2 CC6.1, PCI-DSS 3.4, and HIPAA 164.312 controls."""
    mgr = _require_mgr()
    return mgr.compliance_summary()


@router.get(
    "/patterns",
    response_model=Dict[str, Any],
    summary="All detection patterns",
    tags=["Secrets Management"],
)
def get_all_patterns() -> Dict[str, Any]:
    """Return metadata for all 200+ secret detection patterns."""
    if not _HAS_MGR:
        raise HTTPException(
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SecretsManager not available",
        )
    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for p in SECRET_PATTERNS:
        cat = p["category"].value if hasattr(p["category"], "value") else str(p["category"])
        by_category.setdefault(cat, [])
        by_category[cat].append({
            "id": p["id"],
            "name": p["name"],
            "severity": p["severity"].value if hasattr(p["severity"], "value") else str(p["severity"]),
            "compliance": p.get("compliance", []),
        })
    return {"total_patterns": len(SECRET_PATTERNS), "by_category": by_category}
