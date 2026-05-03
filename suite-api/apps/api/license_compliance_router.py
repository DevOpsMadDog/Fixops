"""
License Compliance API endpoints.

Provides 7 endpoints under /api/v1/licenses for open-source license
risk management: license lookup, compatibility checking, policy CRUD,
SBOM audit, obligation tracking, risk scoring, and dual-license detection.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from core.license_compliance import (
    CompatibilityResult,
    LicenseCategory,
    LicensePolicy,
    SBOMComponent,
    get_engine,
    normalize_license_id,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/licenses", tags=["license-compliance"])

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = get_engine()
    return _engine


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class CompatibilityRequest(BaseModel):
    """Request body for license compatibility check."""

    project_license: str = Field(..., description="SPDX ID of the project license")
    dependency_license: str = Field(..., description="SPDX ID of the dependency license")


class CompatibilityResponse(BaseModel):
    result: CompatibilityResult
    project_license: str
    dependency_license: str
    notes: str


class SBOMAuditRequest(BaseModel):
    """Request body for SBOM compliance audit."""

    components: List[SBOMComponent]
    policy_id: str = Field(default="default-commercial", description="Policy to apply")
    report_id: Optional[str] = Field(default=None, description="Optional report ID")


class RiskScoreRequest(BaseModel):
    """Request body for per-dependency risk scoring."""

    components: List[SBOMComponent]


class NoticeFileRequest(BaseModel):
    """Request body for NOTICE/ATTRIBUTION file generation."""

    components: List[SBOMComponent]


class DualLicenseRequest(BaseModel):
    """Request body for dual-license detection."""

    components: List[SBOMComponent]


class PolicyCreateRequest(BaseModel):
    """Request body for creating a new policy."""

    policy: LicensePolicy


# ---------------------------------------------------------------------------
# Endpoint 0 — Router health / capability summary (GET /)
# ---------------------------------------------------------------------------


@router.get("/", response_model=Dict[str, Any])
async def get_root() -> Dict[str, Any]:
    """
    License compliance router health check and capability summary.

    Returns available endpoints, supported license categories, and a quick
    count of licenses in the database so callers can confirm the engine loaded.
    """
    engine = _get_engine()
    all_licenses = engine.list_licenses()
    category_counts: Dict[str, int] = {}
    for lic in all_licenses:
        category_counts[lic.category.value] = category_counts.get(lic.category.value, 0) + 1

    return {
        "status": "ok",
        "service": "license-compliance",
        "version": "1.0.0",
        "license_count": len(all_licenses),
        "categories": category_counts,
        "endpoints": [
            "GET  /api/v1/licenses/",
            "GET  /api/v1/licenses/lookup?spdx_id=<id>",
            "GET  /api/v1/licenses/list?category=<cat>",
            "POST /api/v1/licenses/compatibility",
            "GET  /api/v1/licenses/policies",
            "POST /api/v1/licenses/policies",
            "DELETE /api/v1/licenses/policies/{policy_id}",
            "POST /api/v1/licenses/audit",
            "POST /api/v1/licenses/obligations",
            "POST /api/v1/licenses/risk-scores",
            "POST /api/v1/licenses/dual-license",
            "GET  /api/v1/licenses/copyleft",
        ],
    }


# ---------------------------------------------------------------------------
# Endpoint 0b — Copyleft license listing (GET /copyleft)
# ---------------------------------------------------------------------------


@router.get("/copyleft", response_model=Dict[str, Any])
async def list_copyleft_licenses(
    strength: Optional[str] = Query(
        None,
        description="Filter by copyleft strength: 'weak', 'strong', or omit for both",
    ),
) -> Dict[str, Any]:
    """
    List all copyleft licenses, optionally filtered by strength (weak/strong).

    Returns licenses categorised as weak_copyleft or strong_copyleft, sorted
    by risk score descending so the most dangerous appear first.
    """
    engine = _get_engine()

    if strength == "weak":
        cats = [LicenseCategory.WEAK_COPYLEFT]
    elif strength == "strong":
        cats = [LicenseCategory.STRONG_COPYLEFT]
    elif strength is None:
        cats = [LicenseCategory.WEAK_COPYLEFT, LicenseCategory.STRONG_COPYLEFT]
    else:
        raise HTTPException(
            status_code=400,
            detail="strength must be 'weak', 'strong', or omitted",
        )

    licenses = []
    for cat in cats:
        licenses.extend(engine.list_licenses(cat))

    licenses.sort(key=lambda l: l.risk_score, reverse=True)

    return {
        "status": "ok",
        "strength_filter": strength or "all",
        "total": len(licenses),
        "licenses": [lic.model_dump() for lic in licenses],
    }


# ---------------------------------------------------------------------------
# Endpoint 1 — License Database Lookup
# ---------------------------------------------------------------------------


@router.get("/lookup", response_model=Dict[str, Any])
async def lookup_license(
    spdx_id: str = Query(..., description="SPDX license identifier, e.g. 'MIT'"),
) -> Dict[str, Any]:
    """
    Look up a license by SPDX ID or common alias.

    Returns full license metadata including category, OSI approval status,
    obligations, and base risk score.
    """
    info = _get_engine().lookup_license(spdx_id)
    if info is None:
        # Try normalization only when the result is not the generic UNKNOWN fallback
        norm = normalize_license_id(spdx_id)
        if norm != "UNKNOWN":
            info = _get_engine().lookup_license(norm)
    if info is None:
        raise HTTPException(
            status_code=404,
            detail=f"License '{spdx_id}' not found in database. Use SPDX identifiers.",
        )
    return {
        "status": "ok",
        "license": info.model_dump(),
    }


@router.get("/list", response_model=Dict[str, Any])
async def list_licenses(
    category: Optional[str] = Query(None, description="Filter by category: permissive, weak_copyleft, strong_copyleft, non_commercial, proprietary, unknown"),
) -> Dict[str, Any]:
    """
    List all licenses in the database, optionally filtered by category.

    Returns sorted list of LicenseInfo records.
    """
    cat: Optional[LicenseCategory] = None
    if category:
        try:
            cat = LicenseCategory(category)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown category '{category}'. Valid values: {[c.value for c in LicenseCategory]}",
            )
    licenses = _get_engine().list_licenses(cat)
    return {
        "status": "ok",
        "total": len(licenses),
        "licenses": [lic.model_dump() for lic in licenses],
    }


# ---------------------------------------------------------------------------
# Endpoint 2 — Compatibility Matrix
# ---------------------------------------------------------------------------


@router.post("/compatibility", response_model=CompatibilityResponse)
async def check_compatibility(body: CompatibilityRequest) -> CompatibilityResponse:
    """
    Check whether a dependency license is compatible with the project license.

    Uses a 60+ entry compatibility matrix with category-level fallback rules.
    Returns: compatible, incompatible, conditional, or unknown.
    """
    result, notes = _get_engine().check_compatibility(
        body.project_license, body.dependency_license
    )
    return CompatibilityResponse(
        result=result,
        project_license=body.project_license,
        dependency_license=body.dependency_license,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Endpoint 3 — Policy Management
# ---------------------------------------------------------------------------


@router.get("/policies", response_model=Dict[str, Any])
async def list_policies() -> Dict[str, Any]:
    """List all configured license compliance policies."""
    policies = _get_engine().list_policies()
    return {
        "status": "ok",
        "total": len(policies),
        "policies": [p.model_dump() for p in policies],
    }


@router.post("/policies", response_model=Dict[str, Any], status_code=201)
async def create_policy(body: PolicyCreateRequest) -> Dict[str, Any]:
    """
    Create or replace a license compliance policy.

    Policies define which license categories/IDs are blocked, warned,
    or require approval. Supports max copyleft percentage and OSI-only rules.
    """
    _get_engine().add_policy(body.policy)
    return {
        "status": "ok",
        "policy_id": body.policy.policy_id,
        "message": f"Policy '{body.policy.name}' saved successfully",
    }


@router.delete("/policies/{policy_id}", response_model=Dict[str, Any])
async def delete_policy(policy_id: str) -> Dict[str, Any]:
    """Delete a policy by ID. The built-in default policy cannot be deleted."""
    if policy_id == "default-commercial":
        raise HTTPException(
            status_code=400, detail="Cannot delete the built-in default-commercial policy"
        )
    deleted = _get_engine().delete_policy(policy_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found")
    return {"status": "ok", "deleted": policy_id}


# ---------------------------------------------------------------------------
# Endpoint 4 — SBOM License Audit
# ---------------------------------------------------------------------------


@router.post("/audit", response_model=Dict[str, Any])
async def audit_sbom(body: SBOMAuditRequest) -> Dict[str, Any]:
    """
    Run a full license compliance audit against an SBOM component list.

    - Evaluates each component license against the selected policy
    - Checks compatibility with the project license (if set in policy)
    - Detects dual-licensed components and uses the recommended option
    - Applies max copyleft percentage check
    - Returns violations, obligations, risk scores, and NOTICE file content
    """
    if not body.components:
        raise HTTPException(status_code=400, detail="components list must not be empty")

    policy = _get_engine().get_policy(body.policy_id)
    if policy is None:
        raise HTTPException(
            status_code=404, detail=f"Policy '{body.policy_id}' not found"
        )

    report_id = body.report_id or str(uuid.uuid4())
    report = _get_engine().audit(body.components, body.policy_id, report_id)

    return {
        "status": "ok",
        "report": report.model_dump(),
    }


# ---------------------------------------------------------------------------
# Endpoint 5 — Obligation Tracking
# ---------------------------------------------------------------------------


@router.post("/obligations", response_model=Dict[str, Any])
async def get_obligations(body: NoticeFileRequest) -> Dict[str, Any]:
    """
    Extract all license obligations for SBOM components.

    Returns per-component obligation items (attribution, source disclosure,
    patent grant, network disclosure, etc.) and a generated NOTICE file.
    """
    if not body.components:
        raise HTTPException(status_code=400, detail="components list must not be empty")

    from core.license_compliance import extract_obligations, generate_notice_file

    obligations = extract_obligations(body.components)
    notice_content = generate_notice_file(obligations, body.components)

    return {
        "status": "ok",
        "total_obligations": len(obligations),
        "obligations": [ob.model_dump() for ob in obligations],
        "notice_file": notice_content,
    }


# ---------------------------------------------------------------------------
# Endpoint 6 — Risk Scoring
# ---------------------------------------------------------------------------


@router.post("/risk-scores", response_model=Dict[str, Any])
async def compute_risk_scores(body: RiskScoreRequest) -> Dict[str, Any]:
    """
    Compute license risk scores for a list of SBOM components.

    Returns per-dependency breakdown (copyleft risk, commercial restriction,
    patent risk, attribution burden) and aggregate project-level score.
    """
    if not body.components:
        raise HTTPException(status_code=400, detail="components list must not be empty")

    from core.license_compliance import compute_project_risk_score

    scores = [_get_engine().score_component(comp) for comp in body.components]
    project_score, project_label = compute_project_risk_score(scores)

    return {
        "status": "ok",
        "project_risk_score": project_score,
        "project_risk_label": project_label,
        "component_count": len(scores),
        "scores": [s.model_dump() for s in scores],
    }


# ---------------------------------------------------------------------------
# Endpoint 7 — Dual License Detection
# ---------------------------------------------------------------------------


@router.post("/dual-license", response_model=Dict[str, Any])
async def detect_dual_licenses(body: DualLicenseRequest) -> Dict[str, Any]:
    """
    Detect components that offer multiple license options (dual licensing).

    For each dual-licensed package, recommends the most permissive (lowest
    risk score) license option available and explains the recommendation.
    """
    if not body.components:
        raise HTTPException(status_code=400, detail="components list must not be empty")

    detections = _get_engine().detect_dual_licenses(body.components)

    return {
        "status": "ok",
        "total_components": len(body.components),
        "dual_license_count": len(detections),
        "detections": [d.model_dump() for d in detections],
    }
