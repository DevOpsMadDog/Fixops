"""
Secret Scanner API Router — regex-based secret detection with rotation tracking.

Endpoints:
    POST   /api/v1/secrets/scan              — scan text or diff content
    GET    /api/v1/secrets/active            — list active (unrotated) secrets
    POST   /api/v1/secrets/{id}/rotate       — mark secret as rotated
    POST   /api/v1/secrets/{id}/false-positive — mark secret as false positive
    GET    /api/v1/secrets/rotation-status   — rotation dashboard counts
    GET    /api/v1/secrets/patterns          — list all detection patterns
    POST   /api/v1/secrets/patterns          — add a custom pattern
    GET    /api/v1/secrets/precommit-config  — generate .pre-commit-config.yaml

All endpoints require API key authentication.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from apps.api.dependencies import get_org_id
from core.secret_scanner import (
    DetectedSecret,
    RotationRecord,
    SecretPattern,
    SecretScanner,
    SecretType,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/secrets", tags=["Secret Scanner"])

# Module-level scanner instance (SQLite-backed, thread-safe via WAL)
_scanner = SecretScanner()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Request body for /scan endpoint."""

    text: Optional[str] = Field(None, description="Raw text content to scan")
    diff: Optional[str] = Field(None, description="Git diff text (only added lines scanned)")
    file_path: str = Field(default="<stdin>", description="Logical file path for attribution")
    commit_sha: Optional[str] = Field(None, description="Commit SHA for attribution")
    author: Optional[str] = Field(None, description="Author for attribution")
    is_diff: bool = Field(default=False, description="Treat input as git diff (scan only + lines)")


class ScanResponse(BaseModel):
    """Response for /scan endpoint."""

    secrets_found: int
    secrets: List[DetectedSecret]


class RotateRequest(BaseModel):
    """Request body for /{id}/rotate endpoint."""

    rotated_by: str = Field(..., description="Email/username of person who rotated the secret")
    new_key_prefix: Optional[str] = Field(None, description="First chars of the replacement key (optional)")


class PatternCreate(BaseModel):
    """Request body for POST /patterns endpoint."""

    type: SecretType
    pattern: str = Field(..., description="Python regex pattern string")
    description: str
    severity: str = Field(default="high", description="critical | high | medium | low")
    false_positive_patterns: List[str] = Field(
        default_factory=list,
        description="Regex patterns that indicate a false positive",
    )


class RotationStatusResponse(BaseModel):
    """Response for /rotation-status endpoint."""

    org_id: str
    total: int
    active: int
    rotated: int
    false_positive: int
    rotation_rate: float


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/scan", response_model=ScanResponse, summary="Scan text or diff for secrets")
async def scan_secrets(
    body: ScanRequest,
    org_id: str = Depends(get_org_id),
) -> ScanResponse:
    """Scan raw text or a git diff for hardcoded secrets.

    - Use `text` + `file_path` for scanning file content.
    - Use `diff` (or `text` + `is_diff=true`) for scanning git diffs (only added lines).
    """
    if body.diff or body.is_diff:
        content = body.diff or body.text or ""
        secrets = _scanner.scan_diff(
            content,
            commit_sha=body.commit_sha,
            author=body.author,
            org_id=org_id,
        )
    else:
        content = body.text or ""
        if not content:
            raise HTTPException(status_code=422, detail="Provide 'text' or 'diff' content to scan")
        secrets = _scanner.scan_text(
            content,
            file_path=body.file_path,
            commit_sha=body.commit_sha,
            author=body.author,
            org_id=org_id,
        )

    return ScanResponse(secrets_found=len(secrets), secrets=secrets)


@router.get("/active", response_model=List[DetectedSecret], summary="List active unrotated secrets")
async def list_active_secrets(
    org_id: str = Depends(get_org_id),
) -> List[DetectedSecret]:
    """Return all active (not rotated, not false positive) detected secrets for the org."""
    return _scanner.get_active_secrets(org_id=org_id)


@router.get(
    "/rotation-status",
    response_model=RotationStatusResponse,
    summary="Rotation dashboard",
)
async def get_rotation_status(
    org_id: str = Depends(get_org_id),
) -> RotationStatusResponse:
    """Return counts of active vs rotated secrets for the org."""
    status = _scanner.get_rotation_status(org_id=org_id)
    return RotationStatusResponse(**status)


@router.get("/patterns", response_model=List[SecretPattern], summary="List detection patterns")
async def list_patterns() -> List[SecretPattern]:
    """Return all active secret detection patterns (built-in + custom)."""
    return _scanner.get_patterns()


@router.post("/patterns", response_model=Dict[str, str], summary="Add a custom detection pattern")
async def add_pattern(
    body: PatternCreate,
    org_id: str = Depends(get_org_id),
) -> Dict[str, str]:
    """Add an org-specific custom secret detection pattern."""
    import re

    try:
        re.compile(body.pattern)
    except re.error as exc:
        raise HTTPException(status_code=422, detail=f"Invalid regex pattern: {exc}") from exc

    pattern = SecretPattern(
        type=body.type,
        pattern=body.pattern,
        description=body.description,
        severity=body.severity,
        false_positive_patterns=body.false_positive_patterns,
    )
    _scanner.add_custom_pattern(pattern, org_id=org_id)
    return {"status": "added", "org_id": org_id}


@router.get(
    "/precommit-config",
    response_model=Dict[str, str],
    summary="Generate .pre-commit-config.yaml",
)
async def get_precommit_config() -> Dict[str, str]:
    """Generate a .pre-commit-config.yaml that includes the FixOps secret scanner hook."""
    config_yaml = _scanner.generate_precommit_config()
    return {"filename": ".pre-commit-config.yaml", "content": config_yaml}


@router.post("/{secret_id}/rotate", response_model=Dict[str, str], summary="Mark secret as rotated")
async def rotate_secret(
    secret_id: str,
    body: RotateRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, str]:
    """Mark a detected secret as rotated and record who rotated it."""
    success = _scanner.mark_rotated(
        secret_id, rotated_by=body.rotated_by, new_key_prefix=body.new_key_prefix
    )
    if not success:
        raise HTTPException(status_code=404, detail=f"Secret {secret_id!r} not found")
    return {"status": "rotated", "secret_id": secret_id, "rotated_by": body.rotated_by}


@router.post(
    "/{secret_id}/false-positive",
    response_model=Dict[str, str],
    summary="Mark secret as false positive",
)
async def mark_false_positive(
    secret_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, str]:
    """Mark a detected secret as a false positive (suppresses it from active list)."""
    success = _scanner.mark_false_positive(secret_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Secret {secret_id!r} not found")
    return {"status": "false_positive", "secret_id": secret_id}
