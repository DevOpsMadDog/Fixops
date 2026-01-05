"""
Secrets detection API endpoints.

Provides enterprise-grade secrets scanning with gitleaks and trufflehog integration.
"""

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.secrets_db import SecretsDB
from core.secrets_models import SecretFinding, SecretStatus, SecretType
from core.secrets_scanner import SecretsScanner, get_secrets_detector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/secrets", tags=["secrets"])
db = SecretsDB()

# Server-side configured base path for scanning - NOT user-controllable
SCAN_BASE_PATH = os.getenv("FIXOPS_SCAN_BASE_PATH", "/var/fixops/scans")


class SecretFindingCreate(BaseModel):
    """Request model for creating secret finding."""

    secret_type: SecretType
    file_path: str
    line_number: int
    repository: str
    branch: str
    commit_hash: Optional[str] = None
    matched_pattern: Optional[str] = None
    entropy_score: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


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
async def create_secret_finding(finding_data: SecretFindingCreate):
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
    return SecretFindingResponse(**created_finding.to_dict())


@router.get("/{id}", response_model=SecretFindingResponse)
async def get_secret_finding(id: str):
    """Get secret finding by ID."""
    finding = db.get_finding(id)
    if not finding:
        raise HTTPException(status_code=404, detail="Secret finding not found")
    return SecretFindingResponse(**finding.to_dict())


@router.post("/{id}/resolve", response_model=SecretFindingResponse)
async def resolve_secret_finding(id: str):
    """Mark secret finding as resolved."""
    finding = db.get_finding(id)
    if not finding:
        raise HTTPException(status_code=404, detail="Secret finding not found")

    finding.status = SecretStatus.RESOLVED
    finding.resolved_at = datetime.utcnow()
    updated_finding = db.update_finding(finding)
    return SecretFindingResponse(**updated_finding.to_dict())


class SecretsScanRequest(BaseModel):
    """Request model for secrets scan."""

    target_path: str = Field(
        ...,
        description="Relative path to file or directory to scan (under configured base path)",
    )
    repository: Optional[str] = Field(
        None, description="Repository name (auto-detected if not specified)"
    )
    branch: Optional[str] = Field(
        None, description="Branch name (auto-detected if not specified)"
    )
    scanner: Optional[str] = Field(
        None,
        description="Scanner to use: 'gitleaks' or 'trufflehog' (auto-selected if not specified)",
    )


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
async def get_detector_status():
    """Get status of available secrets scanners."""
    detector = get_secrets_detector()
    available = detector.get_available_scanners()
    return {
        "gitleaks_available": detector._is_gitleaks_available(),
        "trufflehog_available": detector._is_trufflehog_available(),
        "available_scanners": [s.value for s in available],
    }


def _validate_scan_path(target_path: str) -> str:
    """
    Validate and resolve the scan path securely.

    Security measures:
    1. Reject null bytes in path
    2. Normalize path to prevent traversal via os.path.normpath
    3. Reject absolute paths from user input
    4. Reject path traversal attempts
    5. Resolve path under server-controlled base directory using os.path.realpath
    6. Verify resolved path stays within base directory using os.path.commonpath
    """
    # Reject null bytes in path
    if "\x00" in target_path:
        raise HTTPException(
            status_code=400,
            detail="Invalid path: contains null bytes.",
        )

    # Normalize the path to collapse .. and . components
    normalized = os.path.normpath(target_path)

    # Reject absolute paths - user must provide relative paths only
    if os.path.isabs(normalized):
        raise HTTPException(
            status_code=400,
            detail="Absolute paths are not allowed. Provide a relative path.",
        )

    # Reject obvious path traversal attempts
    if normalized.startswith("..") or "/../" in normalized or normalized == "..":
        raise HTTPException(
            status_code=400,
            detail="Path traversal is not allowed.",
        )

    # Get server-controlled base path using realpath (CodeQL-recognized sanitizer)
    base = os.path.realpath(SCAN_BASE_PATH)

    # Join with base path and resolve using realpath
    candidate = os.path.realpath(os.path.join(base, normalized))

    # Verify the resolved path stays within the base directory using commonpath
    # This is the containment check that CodeQL recognizes
    if os.path.commonpath([base, candidate]) != base:
        raise HTTPException(
            status_code=400,
            detail="Path traversal detected: path escapes base directory.",
        )

    return candidate


@router.post("/scan", response_model=SecretsScanResponse)
async def scan_for_secrets(request: SecretsScanRequest):
    """
    Trigger secrets scan for a file or directory.

    Uses gitleaks or trufflehog to scan for hardcoded secrets, API keys,
    passwords, and other sensitive data in code.

    The scanner is auto-selected based on availability:
    - gitleaks is preferred when available
    - trufflehog is used as fallback

    Findings are automatically persisted to the database.

    Security: Only relative paths under the configured FIXOPS_SCAN_BASE_PATH
    are allowed. Absolute paths and path traversal attempts are rejected.
    """
    # Validate and resolve the path securely using server-side base path
    validated_path = _validate_scan_path(request.target_path)

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
        # Pass the validated path directly - no user-controlled base_path
        result = await detector.scan(
            target_path=validated_path,
            repository=request.repository,
            branch=request.branch,
            scanner=scanner_type,
        )
    except Exception as e:
        logger.exception(f"Secrets scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    for finding in result.findings:
        try:
            db.create_finding(finding)
        except Exception as e:
            logger.warning(f"Failed to persist finding: {e}")

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


class SecretsScanContentRequest(BaseModel):
    """Request model for scanning content for secrets."""

    content: str = Field(..., description="File content to scan")
    filename: str = Field(..., description="Filename")
    repository: str = Field("inline", description="Repository name")
    branch: str = Field("main", description="Branch name")
    scanner: Optional[str] = Field(
        None,
        description="Scanner to use: 'gitleaks' or 'trufflehog' (auto-selected if not specified)",
    )


@router.post("/scan/content", response_model=SecretsScanResponse)
async def scan_content_for_secrets(request: SecretsScanContentRequest):
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
    except Exception as e:
        logger.exception(f"Secrets content scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    for finding in result.findings:
        try:
            db.create_finding(finding)
        except Exception as e:
            logger.warning(f"Failed to persist finding: {e}")

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


@router.post("/scan/repository")
async def scan_repository(repository: str, branch: str = "main"):
    """
    Trigger secret scan for a repository path.

    This is a convenience endpoint that wraps the main /scan endpoint
    for backward compatibility.

    Security: Only relative paths under the configured FIXOPS_SCAN_BASE_PATH
    are allowed. Absolute paths and path traversal attempts are rejected.
    """
    # Validate and resolve the path securely using server-side base path
    validated_path = _validate_scan_path(repository)

    detector = get_secrets_detector()

    try:
        result = await detector.scan(
            target_path=validated_path,
            repository=repository,
            branch=branch,
        )
    except Exception as e:
        logger.exception(f"Repository secrets scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    for finding in result.findings:
        try:
            db.create_finding(finding)
        except Exception as e:
            logger.warning(f"Failed to persist finding: {e}")

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
