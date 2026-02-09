"""
FixOps AutoFix Router — AI-powered vulnerability remediation API.

Endpoints for generating code fixes, applying patches, creating PRs,
and tracking fix lifecycle.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/autofix", tags=["AutoFix"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class GenerateFixRequest(BaseModel):
    """Request to generate a fix for a finding."""
    finding: Dict[str, Any] = Field(..., description="Finding dict with id, title, severity, cve_ids, cwe_id, etc.")
    source_code: Optional[str] = Field(None, description="Source code surrounding the vulnerability")
    repo_context: Optional[Dict[str, Any]] = Field(None, description="Repo metadata (language, framework, etc.)")


class ApplyFixRequest(BaseModel):
    """Request to apply a generated fix."""
    fix_id: str = Field(..., description="ID of the previously generated fix")
    repository: str = Field(..., description="Repository slug (owner/repo)")
    create_pr: bool = Field(True, description="Whether to create a pull request")
    auto_merge: bool = Field(False, description="Auto-merge if high confidence")


class ValidateFixRequest(BaseModel):
    """Request to validate a fix."""
    fix_id: str = Field(..., description="ID of the fix to validate")


class RollbackFixRequest(BaseModel):
    """Request to rollback a fix."""
    fix_id: str = Field(..., description="ID of the fix to rollback")


class BulkGenerateRequest(BaseModel):
    """Request to generate fixes for multiple findings."""
    findings: List[Dict[str, Any]] = Field(..., description="List of finding dicts")
    repo_context: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_engine():
    from core.autofix_engine import get_autofix_engine
    return get_autofix_engine()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/generate", summary="Generate fix for a finding")
async def generate_fix(req: GenerateFixRequest):
    """Generate an AI-powered fix suggestion for a security vulnerability."""
    engine = _get_engine()
    suggestion = await engine.generate_fix(
        finding=req.finding,
        source_code=req.source_code,
        repo_context=req.repo_context,
    )
    return {"status": "ok", "fix": engine.to_dict(suggestion)}


@router.post("/generate/bulk", summary="Generate fixes for multiple findings")
async def generate_bulk_fixes(req: BulkGenerateRequest):
    """Generate fixes for a batch of findings."""
    engine = _get_engine()
    results = []
    for finding in req.findings[:20]:  # Cap at 20 per request
        suggestion = await engine.generate_fix(
            finding=finding, repo_context=req.repo_context,
        )
        results.append(engine.to_dict(suggestion))
    return {"status": "ok", "fixes": results, "count": len(results)}


@router.post("/apply", summary="Apply fix and create PR")
async def apply_fix(req: ApplyFixRequest):
    """Apply a generated fix to a repository and create a pull request."""
    engine = _get_engine()
    result = await engine.apply_fix(
        fix_id=req.fix_id,
        repository=req.repository,
        create_pr=req.create_pr,
        auto_merge=req.auto_merge,
    )
    return {
        "status": "ok" if result.success else "error",
        "success": result.success,
        "pr_url": result.pr_url,
        "pr_number": result.pr_number,
        "error": result.error,
        "validation_passed": result.validation_passed,
    }


@router.post("/validate", summary="Validate a generated fix")
async def validate_fix(req: ValidateFixRequest):
    """Re-validate an existing fix suggestion."""
    engine = _get_engine()
    fix = engine.get_fix(req.fix_id)
    if not fix:
        raise HTTPException(status_code=404, detail=f"Fix {req.fix_id} not found")
    validation = engine._validate_fix(fix)
    return {"status": "ok", "fix_id": req.fix_id, "validation": validation}


@router.post("/rollback", summary="Rollback an applied fix")
async def rollback_fix(req: RollbackFixRequest):
    """Rollback a previously applied fix."""
    engine = _get_engine()
    result = await engine.rollback_fix(req.fix_id)
    return result


@router.get("/fixes/{fix_id}", summary="Get fix details")
async def get_fix(fix_id: str):
    """Get details of a specific fix."""
    engine = _get_engine()
    fix = engine.get_fix(fix_id)
    if not fix:
        raise HTTPException(status_code=404, detail=f"Fix {fix_id} not found")
    return {"status": "ok", "fix": engine.to_dict(fix)}




@router.get("/suggestions/{finding_id}", summary="Get fix suggestions for a finding")
async def get_suggestions(
    finding_id: str,
    status: Optional[str] = Query(None, description="Filter by status"),
    fix_type: Optional[str] = Query(None, description="Filter by fix type"),
    limit: int = Query(50, ge=1, le=200),
):
    """Get all fix suggestions for a specific finding."""
    engine = _get_engine()
    from core.autofix_engine import FixStatus, FixType

    filters: Dict[str, Any] = {"finding_id": finding_id, "limit": limit}
    if status:
        try:
            filters["status"] = FixStatus(status)
        except ValueError:
            pass
    if fix_type:
        try:
            filters["fix_type"] = FixType(fix_type)
        except ValueError:
            pass

    fixes = engine.list_fixes(**filters)
    return {
        "status": "ok",
        "finding_id": finding_id,
        "suggestions": [engine.to_dict(f) for f in fixes],
        "count": len(fixes),
    }


@router.get("/history", summary="Fix action history")
async def get_history(limit: int = Query(100, ge=1, le=1000)):
    """Get the autofix action history."""
    engine = _get_engine()
    return {"status": "ok", "history": engine.get_history(limit)}


@router.get("/stats", summary="AutoFix statistics")
async def get_stats():
    """Get AutoFix engine statistics — generation rates, PR counts, etc."""
    engine = _get_engine()
    return {"status": "ok", "stats": engine.get_stats()}


@router.get("/health", summary="AutoFix health check")
async def health():
    """Health check for the AutoFix engine."""
    engine = _get_engine()
    stats = engine.get_stats()
    return {
        "status": "healthy",
        "engine": "autofix",
        "total_fixes": stats.get("total_fixes_stored", 0),
        "total_generated": stats.get("total_generated", 0),
        "total_prs_created": stats.get("total_prs_created", 0),
    }


@router.get("/fix-types", summary="List supported fix types")
async def list_fix_types():
    """List all supported fix types."""
    from core.autofix_engine import FixType
    return {
        "status": "ok",
        "fix_types": [{"value": ft.value, "name": ft.name} for ft in FixType],
    }


@router.get("/confidence-levels", summary="Confidence level definitions")
async def confidence_levels():
    """Get confidence level definitions and thresholds."""
    return {
        "status": "ok",
        "levels": {
            "high": {"min_score": 0.85, "description": "Safe to auto-apply"},
            "medium": {"min_score": 0.60, "description": "Needs human review"},
            "low": {"min_score": 0.0, "description": "Manual review required"},
        },
    }