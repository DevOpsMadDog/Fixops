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


def _audit_autofix(
    *,
    action: str,
    outcome: str,
    org_id: str,
    finding_id=None,
    request=None,
    details=None,
) -> None:
    """Record an AutoFix action in the audit trail.

    Both call sites previously invoked ``_audit.log_autofix_application(...)``, which
    AuditLogger does not define — its API is ``log(AuditEvent)``. The result was an
    AttributeError raised *after* the fix had already been generated, so POST
    /api/v1/autofix/generate answered HTTP 500 while the work had in fact succeeded and
    nothing was recorded. The AutoFix button therefore always failed for the user.

    Audit failure must never lose the caller's result: a broken trail is reported in the
    log, not by discarding a completed action.
    """
    try:
        from core.audit_logger import AuditEvent

        _audit.log(
            AuditEvent(
                actor_id=getattr(getattr(request, "state", None), "user_id", None) or "system",
                action=f"autofix.{action}",
                resource_type="finding",
                resource_id=str(finding_id) if finding_id else None,
                org_id=org_id,
                result=outcome,
                details=details or {},
                ip_address=(request.client.host if request and request.client else None),
            )
        )
    except Exception as exc:  # noqa: BLE001 — auditing must not fail the request
        logger.warning("autofix audit write failed (%s): %s", type(exc).__name__, exc)


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

        # Look the finding up in the store the product actually keeps findings in.
        #
        # This previously opened data/analytics.db directly and queried a "findings"
        # table. That store does not hold the findings the UI lists — those live in
        # SecurityFindingsEngine — so the query raised
        # "sqlite3.OperationalError: no such table: findings", which the except clause
        # below did not catch, and AutoFix answered HTTP 500 for every finding on screen.
        fid = values.get("finding_id")
        if fid:
            try:
                from core.security_findings_engine import SecurityFindingsEngine

                org_id = values.get("org_id") or "default"
                row = SecurityFindingsEngine().get_finding(str(fid), org_id)
                if row:
                    values["finding"] = {
                        "id": fid,
                        "title": row.get("title") or f"Vulnerability {fid}",
                        "description": row.get("description", ""),
                        "severity": row.get("severity", "high"),
                        "cve_ids": [row["cve_id"]] if row.get("cve_id") else [],
                        "cwe_id": row.get("cwe_id", ""),
                        "file_path": row.get("file_path", ""),
                        "line_number": row.get("line") or row.get("line_number"),
                        "source": row.get("source_tool") or row.get("source", ""),
                        "category": row.get("finding_type") or row.get("category", ""),
                        "language": values.get("language"),
                        "fix_type": values.get("fix_type"),
                    }
                    logger.info("Looked up finding %s: %s", fid, row.get("title"))
                    return values
            except Exception as exc:  # noqa: BLE001 — lookup failure must not 500
                logger.warning(
                    "Failed to look up finding %s (%s): %s", fid, type(exc).__name__, exc
                )

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
    _audit_autofix(
        action="generate",
        outcome="success",
        org_id=org_id,
        finding_id=finding.get("id") if isinstance(finding, dict) else None,
        request=request,
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
    _audit_autofix(
        action="apply_patch",
        outcome="success" if result.success else "error",
        org_id=org_id,
        finding_id=req.fix_id,
        request=request,
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
async def rollback_fix(
    req: RollbackFixRequest, request: Request, org_id: str = Depends(get_org_id)
):
    """Rollback a previously applied fix."""
    engine = _get_engine()
    result = await engine.rollback_fix(req.fix_id)
    _audit_autofix(
        action="rollback",
        outcome="success",
        org_id=org_id,
        finding_id=req.fix_id,
        request=request,
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


@router.get("/", summary="AutoFix index — capabilities and live stats")
async def autofix_index():
    """Index for the AutoFix API: live engine stats + available operations."""
    engine = _get_engine()
    return {
        "service": "autofix",
        "status": "ok",
        "stats": engine.get_stats(),
        "endpoints": [
            "GET /stats",
            "GET /health",
            "GET /status",
            "GET /fix-types",
            "GET /history",
            "GET /fixes/{fix_id}",
            "GET /suggestions/{finding_id}",
        ],
    }


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
    """Confidence level thresholds + live per-level fix counts from the engine."""
    engine = _get_engine()
    stats = engine.get_stats()
    by_conf = stats.get("by_confidence", {}) or {}
    return {
        "status": "ok",
        "levels": {
            "high": {"min_score": 0.85, "description": "Safe to auto-apply", "count": int(by_conf.get("high", 0))},
            "medium": {"min_score": 0.60, "description": "Needs human review", "count": int(by_conf.get("medium", 0))},
            "low": {"min_score": 0.0, "description": "Manual review required", "count": int(by_conf.get("low", 0))},
        },
        "total_fixes": int(stats.get("total_fixes_stored", 0)),
        "avg_confidence_score": float(stats.get("avg_confidence_score", 0.0)),
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


@router.get("/fixes", summary="List generated fixes")
def list_fixes(
    finding_id: Optional[str] = Query(None, description="Filter by finding id"),
    limit: int = Query(200, ge=1, le=500),
    _org_id: str = Depends(get_org_id),
):
    """List generated auto-fixes (real engine data; honest-empty when none).

    Normalised to the shape the Developer "Fix Helpers" tab consumes
    ({fixes:[{id,title,file,repo,fix_snippet,rule_id,...}]}) — the panel was
    pointing at /api/v1/sast/auto-fix which never existed. No mocks: rows come
    from AutoFixEngine.list_fixes() (in-memory store; empty until fixes are
    generated for the org).
    """
    engine = _get_engine()
    try:
        raw = engine.list_fixes(finding_id=finding_id, limit=limit)
    except Exception as exc:  # pragma: no cover
        logger.exception("list_fixes failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    fixes: List[Dict[str, Any]] = []
    for s in raw:
        d = engine.to_dict(s)
        patches = d.get("code_patches") or []
        first = patches[0] if patches and isinstance(patches[0], dict) else {}
        fixes.append(
            {
                "id": d.get("fix_id", ""),
                "title": d.get("title") or d.get("finding_title") or "",
                "file": first.get("file_path", ""),
                "repo": d.get("repo", ""),
                "fix_snippet": first.get("patched_content") or first.get("diff") or "",
                "rule_id": d.get("rule_id") or d.get("cwe_id") or "",
                "finding_id": d.get("finding_id", ""),
                "fix_type": d.get("fix_type", ""),
                "status": d.get("status", ""),
            }
        )
    return {"fixes": fixes, "items": fixes, "total": len(fixes)}
