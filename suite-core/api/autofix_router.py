"""
FixOps AutoFix Router — AI-powered vulnerability remediation API.

Endpoints for generating code fixes, applying patches, creating PRs,
and tracking fix lifecycle.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.audit_logger import create_audit_logger
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, model_validator

logger = logging.getLogger(__name__)
_audit = create_audit_logger()

router = APIRouter(prefix="/api/v1/autofix", tags=["AutoFix"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class GenerateFixRequest(BaseModel):
    """Request to generate a fix for a finding.

    Accepts either a full 'finding' dict or individual fields (finding_id, title, severity, cve_id).
    """

    finding: Optional[Dict[str, Any]] = Field(
        None, description="Finding dict with id, title, severity, cve_ids, cwe_id, etc."
    )
    finding_id: Optional[str] = Field(None, description="Finding ID (shorthand)")
    title: Optional[str] = Field(None, description="Finding title (shorthand)")
    severity: Optional[str] = Field(None, description="Finding severity (shorthand)")
    cve_id: Optional[str] = Field(None, description="CVE ID (shorthand)")
    language: Optional[str] = Field(
        None, description="Language hint (python, java, etc.)"
    )
    fix_type: Optional[str] = Field(
        None, description="Fix type (patch, config, upgrade)"
    )
    source_code: Optional[str] = Field(
        None, description="Source code surrounding the vulnerability"
    )
    repo_context: Optional[Dict[str, Any]] = Field(
        None, description="Repo metadata (language, framework, etc.)"
    )

    @model_validator(mode="before")
    @classmethod
    def build_finding(cls, values):
        """Build finding dict from individual fields or look up from analytics DB."""
        if not isinstance(values, dict):
            return values
        if values.get("finding"):
            return values

        # Try to look up finding from analytics.db using finding_id
        fid = values.get("finding_id")
        if fid:
            try:
                import sqlite3
                from pathlib import Path
                # Try known locations for analytics.db
                db_path = None
                for candidate in [
                    Path("/home/user/workspace/Fixops/data/analytics.db"),
                    Path(__file__).parents[3] / "data" / "analytics.db",
                    Path(__file__).resolve().parents[2] / "data" / "analytics.db",
                ]:
                    if candidate.exists():
                        db_path = candidate
                        break
                if db_path:
                    conn = sqlite3.connect(str(db_path))
                    conn.row_factory = sqlite3.Row
                    try:
                        row = conn.execute(
                            "SELECT * FROM findings WHERE id = ? LIMIT 1", (fid,)
                        ).fetchone()
                        if row:
                            row_dict = dict(row)
                            values["finding"] = {
                                "id": fid,
                                "title": row_dict.get("title", f"Vulnerability {fid}"),
                                "description": row_dict.get("description", ""),
                                "severity": row_dict.get("severity", "high"),
                                "cve_ids": [row_dict["cve_id"]] if row_dict.get("cve_id") else [],
                                "cwe_id": row_dict.get("cwe_id", ""),
                                "file_path": row_dict.get("file_path", ""),
                                "line_number": row_dict.get("line_number"),
                                "source": row_dict.get("source", ""),
                                "category": row_dict.get("category", ""),
                                "language": values.get("language"),
                                "fix_type": values.get("fix_type"),
                            }
                            logger.info("Looked up finding %s: %s", fid, row_dict.get("title"))
                            return values
                    finally:
                        conn.close()
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.warning("Failed to look up finding %s: %s", fid, type(e).__name__)

        # Fallback: build from individual fields
        fid = fid or f"FIND-{id(values) % 10000:04d}"
        values["finding"] = {
            "id": fid,
            "title": values.get("title") or f"Vulnerability {fid}",
            "severity": values.get("severity") or "high",
            "cve_ids": [values.get("cve_id")] if values.get("cve_id") else [],
            "language": values.get("language"),
            "fix_type": values.get("fix_type"),
        }
        return values


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
async def generate_fix(
    req: GenerateFixRequest,
    request: Request,
    org_id: str = Depends(get_org_id),
):
    """Generate an AI-powered fix suggestion for a security vulnerability."""
    engine = _get_engine()
    # Stamp the finding with org_id so generated fixes are tenant-scoped
    finding = req.finding or {}
    if isinstance(finding, dict) and not finding.get("org_id"):
        finding = {**finding, "org_id": org_id}
    suggestion = await engine.generate_fix(
        finding=finding,
        source_code=req.source_code,
        repo_context=req.repo_context,
    )
    _audit.log_autofix_application(
        action="generate",
        outcome="success",
        finding_id=finding.get("id") if isinstance(finding, dict) else None,
        user_id=getattr(request.state, "user_id", None),
        client_ip=request.client.host if request.client else None,
        correlation_id=getattr(request.state, "correlation_id", None),
    )
    return {"status": "ok", "fix": engine.to_dict(suggestion)}


@router.post("/generate/bulk", summary="Generate fixes for multiple findings")
async def generate_bulk_fixes(
    req: BulkGenerateRequest,
    org_id: str = Depends(get_org_id),
):
    """Generate fixes for a batch of findings."""
    engine = _get_engine()
    results = []
    for finding in req.findings[:20]:  # Cap at 20 per request
        # Stamp each finding with org_id if not already set
        if isinstance(finding, dict) and not finding.get("org_id"):
            finding = {**finding, "org_id": org_id}
        suggestion = await engine.generate_fix(
            finding=finding,
            repo_context=req.repo_context,
        )
        results.append(engine.to_dict(suggestion))
    return {"status": "ok", "fixes": results, "count": len(results)}


@router.post("/apply", summary="Apply fix and create PR")
async def apply_fix(req: ApplyFixRequest, request: Request):
    """Apply a generated fix to a repository and create a pull request."""
    engine = _get_engine()
    result = await engine.apply_fix(
        fix_id=req.fix_id,
        repository=req.repository,
        create_pr=req.create_pr,
        auto_merge=req.auto_merge,
    )
    _audit.log_autofix_application(
        action="apply_patch",
        outcome="success" if result.success else "failure",
        finding_id=req.fix_id,
        user_id=getattr(request.state, "user_id", None),
        client_ip=request.client.host if request.client else None,
        correlation_id=getattr(request.state, "correlation_id", None),
        details={"repository": req.repository, "pr_url": result.pr_url},
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
async def rollback_fix(req: RollbackFixRequest, request: Request):
    """Rollback a previously applied fix."""
    engine = _get_engine()
    result = await engine.rollback_fix(req.fix_id)
    _audit.log_autofix_application(
        action="rollback",
        outcome="success",
        finding_id=req.fix_id,
        user_id=getattr(request.state, "user_id", None),
        client_ip=request.client.host if request.client else None,
        correlation_id=getattr(request.state, "correlation_id", None),
    )
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
    org_id: str = Depends(get_org_id),
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
    # Filter to only return fixes belonging to this org
    fixes = [f for f in fixes if not getattr(f, "org_id", org_id) or getattr(f, "org_id", org_id) == org_id]
    return {
        "status": "ok",
        "finding_id": finding_id,
        "org_id": org_id,
        "suggestions": [engine.to_dict(f) for f in fixes],
        "count": len(fixes),
    }


@router.get("/history", summary="Fix action history")
async def get_history(
    limit: int = Query(100, ge=1, le=1000),
    org_id: str = Depends(get_org_id),
):
    """Get the autofix action history, scoped to the caller's org."""
    engine = _get_engine()
    history = engine.get_history(limit)
    # Filter history entries to this org (entries stamped with org_id by generate_fix)
    if isinstance(history, list):
        history = [
            h for h in history
            if not h.get("org_id") or h.get("org_id") == org_id
        ]
    return {"status": "ok", "org_id": org_id, "history": history}


class AutoMergeCheckRequest(BaseModel):
    """Request to check if a fix qualifies for auto-merge."""

    fix_id: str = Field(..., description="ID of the fix to check")
    finding: Optional[Dict[str, Any]] = Field(
        None, description="Original finding (for context enrichment)"
    )


@router.post("/auto-merge/check", summary="Check if fix qualifies for auto-merge")
async def check_auto_merge(req: AutoMergeCheckRequest):
    """Check whether a generated fix meets all gates for automated merge.

    [GODMODE] Evaluates 7 gates: confidence, validation, severity, EPSS/KEV,
    fix type safety, dangerous patterns, and multi-LLM consensus. Returns
    a full audit-trail-ready decision with reasons and blockers.
    """
    engine = _get_engine()
    fix = engine.get_fix(req.fix_id)
    if not fix:
        raise HTTPException(status_code=404, detail=f"Fix {req.fix_id} not found")

    # Use stored decision if available, otherwise compute fresh
    stored_decision = fix.metadata.get("auto_merge_decision")
    if stored_decision and not req.finding:
        return {"status": "ok", "fix_id": req.fix_id, "decision": stored_decision}

    finding = req.finding or {"severity": "high"}
    graph_ctx = fix.metadata.get("graph_context", {})
    decision = engine.should_auto_merge(fix, finding, graph_ctx)
    return {"status": "ok", "fix_id": req.fix_id, "decision": decision}


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


@router.get("/status", summary="AutoFix status")
async def autofix_status():
    """AutoFix engine status (alias for /health)."""
    return await health()


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


@router.get("/queue", summary="AutoFix queue")
async def autofix_queue():
    """Get pending AutoFix tasks in the queue."""
    engine = _get_engine()
    stats = engine.get_stats()
    # Expose pending/queued fixes
    pending = stats.get("pending_fixes", [])
    return {
        "status": "ok",
        "queue": pending if isinstance(pending, list) else [],
        "total_queued": len(pending) if isinstance(pending, list) else stats.get("total_pending", 0),
        "total_generated": stats.get("total_generated", 0),
    }


@router.get("/tasks", summary="AutoFix tasks")
async def autofix_tasks():
    """List recent AutoFix tasks."""
    engine = _get_engine()
    stats = engine.get_stats()
    fixes = stats.get("recent_fixes", []) or stats.get("fixes", [])
    return {
        "status": "ok",
        "tasks": fixes if isinstance(fixes, list) else [],
        "total": stats.get("total_fixes_stored", 0),
    }


@router.get("/summary", summary="AutoFix summary")
async def autofix_summary():
    """AutoFix engine summary — totals, success rates."""
    engine = _get_engine()
    stats = engine.get_stats()
    total_generated = stats.get("total_generated", 0)
    total_applied = stats.get("total_applied", 0) or stats.get("total_prs_created", 0)
    return {
        "status": "ok",
        "total_generated": total_generated,
        "total_applied": total_applied,
        "total_stored": stats.get("total_fixes_stored", 0),
        "success_rate": round(total_applied / max(total_generated, 1) * 100, 1),
        "by_type": stats.get("by_fix_type", {}),
        "by_confidence": stats.get("by_confidence", {}),
    }
