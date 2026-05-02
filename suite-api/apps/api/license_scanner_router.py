"""ALDECI License Compliance Scanner Router.

Exposes license compliance scanning as REST endpoints.

Endpoints:
  POST /api/v1/license-scanner/scan-requirements  — Scan a requirements.txt
  POST /api/v1/license-scanner/scan-package-json  — Scan a package.json
  POST /api/v1/license-scanner/evaluate-policy    — Re-evaluate results vs policy
  GET  /api/v1/license-scanner/summary            — Risk distribution for an org
  POST /api/v1/license-scanner/policy             — Set org policy rules
  GET  /api/v1/license-scanner/violations         — List policy violations for org
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/license-scanner",
    tags=["license-scanner"],
)


# ---------------------------------------------------------------------------
# Lazy import helper
# ---------------------------------------------------------------------------


def _get_scanner():
    """Return a LicenseScanner instance, or raise 503 on import failure."""
    try:
        from core.license_scanner import LicenseScanner
        return LicenseScanner()
    except ImportError as exc:
        logger.error("license_scanner import failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"license_scanner unavailable: {exc}")


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ScanRequirementsRequest(BaseModel):
    """Scan a requirements.txt file content."""

    content: str
    org_id: str = "default"


class ScanPackageJsonRequest(BaseModel):
    """Scan a package.json file content."""

    content: str
    org_id: str = "default"


class EvaluatePolicyRequest(BaseModel):
    """Re-evaluate a list of package scan results against a given policy."""

    packages: List[Dict[str, str]]
    policy: Dict[str, Any]
    org_id: str = "default"


class SetPolicyRequest(BaseModel):
    """Configure license policy rules for an org."""

    org_id: str = "default"
    rules: Dict[str, Any]


class LicenseResultItem(BaseModel):
    id: str
    package: str
    version: str
    license_name: str
    risk_level: str
    policy_action: str
    spdx_id: str
    org_id: str
    scanned_at: str


class ScanResponse(BaseModel):
    org_id: str
    total: int
    results: List[LicenseResultItem]


class SummaryResponse(BaseModel):
    org_id: str
    total: int
    by_risk: Dict[str, int]
    by_policy: Dict[str, int]
    generated_at: str


class PolicyResponse(BaseModel):
    org_id: str
    rules_saved: int
    status: str


class ViolationsResponse(BaseModel):
    org_id: str
    total_violations: int
    violations: List[LicenseResultItem]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result_to_item(r: Any) -> LicenseResultItem:
    return LicenseResultItem(
        id=r.id,
        package=r.package,
        version=r.version,
        license_name=r.license_name,
        risk_level=r.risk_level.value,
        policy_action=r.policy_action.value,
        spdx_id=r.spdx_id,
        org_id=r.org_id,
        scanned_at=r.scanned_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/scan-requirements",
    response_model=ScanResponse,
    summary="Scan a requirements.txt for license risks",
)
def scan_requirements(body: ScanRequirementsRequest) -> ScanResponse:
    """Parse the requirements.txt content and return license classification for each dep."""
    if not body.content.strip():
        raise HTTPException(status_code=400, detail="content must not be empty")

    scanner = _get_scanner()
    results = scanner.scan_requirements(body.content, org_id=body.org_id)
    return ScanResponse(
        org_id=body.org_id,
        total=len(results),
        results=[_result_to_item(r) for r in results],
    )


@router.post(
    "/scan-package-json",
    response_model=ScanResponse,
    summary="Scan a package.json for license risks",
)
def scan_package_json(body: ScanPackageJsonRequest) -> ScanResponse:
    """Parse a package.json and return license classification for each dependency."""
    if not body.content.strip():
        raise HTTPException(status_code=400, detail="content must not be empty")

    scanner = _get_scanner()
    results = scanner.scan_package_json(body.content, org_id=body.org_id)
    return ScanResponse(
        org_id=body.org_id,
        total=len(results),
        results=[_result_to_item(r) for r in results],
    )


@router.post(
    "/evaluate-policy",
    response_model=ScanResponse,
    summary="Re-evaluate packages against a given policy without persisting",
)
def evaluate_policy(body: EvaluatePolicyRequest) -> ScanResponse:
    """Scan packages inline (from name/version pairs) and apply the provided policy."""
    from core.license_scanner import (  # noqa: F401
        LicensePolicy,
        LicenseResult,
        LicenseRisk,
    )

    scanner = _get_scanner()

    # First scan the packages to get LicenseResult objects
    fake_requirements = "\n".join(
        f"{p.get('package', p.get('name', 'unknown'))}=={p.get('version', '0.0.0')}"
        for p in body.packages
    )
    base_results = scanner.scan_requirements(fake_requirements, org_id=body.org_id)
    evaluated = scanner.evaluate_policy(base_results, body.policy)

    return ScanResponse(
        org_id=body.org_id,
        total=len(evaluated),
        results=[_result_to_item(r) for r in evaluated],
    )


@router.get(
    "/summary",
    response_model=SummaryResponse,
    summary="Get license risk distribution for an org",
)
def get_summary(org_id: str = Query(default="default")) -> SummaryResponse:
    """Return counts of scanned packages grouped by risk level and policy action."""
    scanner = _get_scanner()
    summary = scanner.get_license_summary(org_id=org_id)
    return SummaryResponse(**summary)


@router.post(
    "/policy",
    response_model=PolicyResponse,
    summary="Configure org license policy",
)
def set_policy(body: SetPolicyRequest) -> PolicyResponse:
    """Set or update license policy rules for an organisation."""
    if not body.rules:
        raise HTTPException(status_code=400, detail="rules must not be empty")

    scanner = _get_scanner()
    scanner.set_policy(body.org_id, body.rules)
    return PolicyResponse(
        org_id=body.org_id,
        rules_saved=len(body.rules),
        status="ok",
    )


@router.get(
    "/violations",
    response_model=ViolationsResponse,
    summary="List packages that violate the org license policy",
)
def get_violations(org_id: str = Query(default="default")) -> ViolationsResponse:
    """Return all scan results where policy_action is BLOCK for the given org."""
    scanner = _get_scanner()
    violations = scanner.get_violations(org_id=org_id)
    return ViolationsResponse(
        org_id=org_id,
        total_violations=len(violations),
        violations=[_result_to_item(v) for v in violations],
    )
