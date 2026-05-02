"""
Code Ownership API — assign code owners to files and security findings.

Provides 8 endpoints:
  POST   /api/v1/ownership/owners           register owner
  GET    /api/v1/ownership/owners           list owners
  DELETE /api/v1/ownership/owners/{email}   remove owner
  POST   /api/v1/ownership/rules            add glob rule
  GET    /api/v1/ownership/rules            list rules
  POST   /api/v1/ownership/resolve          resolve owner for a file
  POST   /api/v1/ownership/import           import CODEOWNERS file
  GET    /api/v1/ownership/coverage         ownership coverage stats
  POST   /api/v1/ownership/unowned          list unowned files
  GET    /api/v1/ownership/workload         findings-per-owner workload
  POST   /api/v1/ownership/auto-assign      bulk assign findings to owners
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.code_ownership import (
    CodeOwnership,
    Owner,
    OwnershipRule,
    get_code_ownership,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/ownership", tags=["code-ownership"])


def _svc() -> CodeOwnership:
    return get_code_ownership()


# ============================================================================
# Request / Response models
# ============================================================================


class AddRuleRequest(BaseModel):
    pattern: str = Field(..., description="Glob pattern (e.g. 'src/core/**')")
    owner_email: str
    priority: int = Field(default=0)


class ResolveRequest(BaseModel):
    file_path: str = Field(..., description="Repo-relative file path to resolve")


class ResolveResponse(BaseModel):
    file_path: str
    owner: Optional[Dict[str, Any]] = None
    resolved: bool


class ImportRequest(BaseModel):
    content: str = Field(..., description="Raw CODEOWNERS file text")


class CoverageRequest(BaseModel):
    org_id: str = "default"
    file_paths: List[str] = Field(..., description="List of file paths to evaluate")


class UnownedRequest(BaseModel):
    org_id: str = "default"
    file_paths: List[str] = Field(..., description="List of file paths to check")


class AutoAssignRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(..., description="List of finding dicts")
    org_id: str = "default"


# ============================================================================
# Endpoints
# ============================================================================


# ── Owners ──────────────────────────────────────────────────────────────────

@router.post("/owners", response_model=Owner, status_code=201)
async def register_owner(body: Owner):
    """Register (or update) a code owner."""
    return _svc().add_owner(body)


@router.get("/owners", response_model=List[Owner])
async def list_owners():
    """Return all registered code owners."""
    return _svc().list_owners()


@router.delete("/owners/{email}", response_model=Dict[str, Any])
async def delete_owner(email: str):
    """Remove a code owner by email."""
    deleted = _svc().delete_owner(email)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Owner '{email}' not found")
    return {"deleted": True, "email": email}


# ── Rules ───────────────────────────────────────────────────────────────────

@router.post("/rules", response_model=OwnershipRule, status_code=201)
async def add_rule(body: AddRuleRequest):
    """Add a CODEOWNERS-style glob ownership rule."""
    return _svc().add_rule(
        pattern=body.pattern,
        owner_email=body.owner_email,
        priority=body.priority,
    )


@router.get("/rules", response_model=List[OwnershipRule])
async def list_rules():
    """Return all ownership rules ordered by priority (highest first)."""
    return _svc().list_rules()


@router.delete("/rules/{rule_id}", response_model=Dict[str, Any])
async def delete_rule(rule_id: str):
    """Remove an ownership rule by ID."""
    deleted = _svc().delete_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
    return {"deleted": True, "rule_id": rule_id}


# ── Resolution ───────────────────────────────────────────────────────────────

@router.post("/resolve", response_model=ResolveResponse)
async def resolve_owner(body: ResolveRequest):
    """Find the owner for a given file path."""
    owner = _svc().resolve_owner(body.file_path)
    return ResolveResponse(
        file_path=body.file_path,
        owner=owner.model_dump() if owner else None,
        resolved=owner is not None,
    )


# ── CODEOWNERS import ────────────────────────────────────────────────────────

@router.post("/import", response_model=Dict[str, Any], status_code=201)
async def import_codeowners(body: ImportRequest):
    """Parse and import a CODEOWNERS file."""
    count = _svc().import_codeowners(body.content)
    return {"imported_rules": count}


# ── Coverage ─────────────────────────────────────────────────────────────────

@router.post("/coverage", response_model=Dict[str, Any])
async def ownership_coverage(body: CoverageRequest):
    """Return ownership coverage stats for a list of file paths."""
    return _svc().get_ownership_coverage(org_id=body.org_id, file_paths=body.file_paths)


# ── Unowned files ─────────────────────────────────────────────────────────────

@router.post("/unowned", response_model=Dict[str, Any])
async def unowned_files(body: UnownedRequest):
    """Return files in the list that have no owner."""
    unowned = _svc().get_unowned_files(org_id=body.org_id, file_paths=body.file_paths)
    return {
        "org_id": body.org_id,
        "total_checked": len(body.file_paths),
        "unowned_count": len(unowned),
        "unowned_files": unowned,
    }


# ── Workload ─────────────────────────────────────────────────────────────────

@router.get("/workload", response_model=List[Dict[str, Any]])
async def owner_workload(org_id: str = Query("default")):
    """Return findings-per-owner workload for an org."""
    return _svc().get_owner_workload(org_id=org_id)


# ── Auto-assign ──────────────────────────────────────────────────────────────

@router.post("/auto-assign", response_model=Dict[str, Any])
async def auto_assign_findings(body: AutoAssignRequest):
    """Bulk-assign security findings to their code owners."""
    assignments = _svc().auto_assign_findings(
        findings=body.findings,
        org_id=body.org_id,
    )
    assigned = [a for a in assignments if a.owner_email]
    unassigned = [a for a in assignments if not a.owner_email]
    return {
        "org_id": body.org_id,
        "total_findings": len(assignments),
        "assigned_count": len(assigned),
        "unassigned_count": len(unassigned),
        "assignments": [a.model_dump() for a in assignments],
    }
