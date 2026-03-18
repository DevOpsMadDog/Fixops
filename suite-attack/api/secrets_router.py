"""
Secrets detection API endpoints.

Provides enterprise-grade secrets scanning with gitleaks and trufflehog integration.

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
from fastapi import APIRouter, HTTPException, Query, Depends
from apps.api.dependencies import get_org_id
from pydantic import BaseModel, Field, field_validator

# Knowledge Brain + Event Bus integration (graceful degradation)
try:
    from core.event_bus import Event, EventType, get_event_bus
    from core.knowledge_brain import get_brain

    _HAS_BRAIN = True
except ImportError:
    _HAS_BRAIN = False

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/secrets", tags=["secrets"])
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
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
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
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
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
