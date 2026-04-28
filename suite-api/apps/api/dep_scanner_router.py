"""ALDECI Dependency Vulnerability Scanner Router.

Exposes ALDECI's own dependency vulnerability scanning as REST endpoints.

Endpoints:
  POST /api/v1/dep-scanner/scan-requirements   — Scan a requirements.txt file
  POST /api/v1/dep-scanner/scan-package-json   — Scan a package.json file
  GET  /api/v1/dep-scanner/scan-installed      — Scan pip-installed packages
  GET  /api/v1/dep-scanner/outdated            — List outdated packages
  GET  /api/v1/dep-scanner/vulnerable          — List vulnerable installed packages
  GET  /api/v1/dep-scanner/upgrade-plan        — Prioritized upgrade plan
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/dep-scanner",
    tags=["dep-scanner"],
)

# ---------------------------------------------------------------------------
# Repo root (used for default paths)
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_REQUIREMENTS = str(_REPO_ROOT / "requirements.txt")
_DEFAULT_PACKAGE_JSON = str(_REPO_ROOT / "suite-ui" / "aldeci-ui-new" / "package.json")


# ---------------------------------------------------------------------------
# Lazy scanner import
# ---------------------------------------------------------------------------


def _get_scanner():
    """Return a DependencyScanner instance, or raise 503 on import failure."""
    try:
        from core.dep_scanner import DependencyScanner
        return DependencyScanner()
    except ImportError as exc:
        logger.error("dep_scanner import failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"dep_scanner unavailable: {exc}")


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ScanFileRequest(BaseModel):
    """Path to the file to scan. Defaults to the ALDECI repo file when omitted."""

    file_path: Optional[str] = None


class VulnerabilityItem(BaseModel):
    package: str
    installed_version: str
    fixed_version: str
    cve_id: str
    severity: str
    description: str
    advisory_url: str


class ScanResult(BaseModel):
    file_path: str
    total: int
    vulnerabilities: List[VulnerabilityItem]


class OutdatedItem(BaseModel):
    package: str
    installed_version: str
    latest_version: str
    latest_filetype: str = "wheel"


class UpgradePlanResult(BaseModel):
    generated_at: str
    total_vulnerabilities: int
    critical: List[Dict[str, str]]
    high: List[Dict[str, str]]
    medium: List[Dict[str, str]]
    low: List[Dict[str, str]]
    upgrade_commands: List[str]
    summary: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_path(requested: Optional[str], default: str) -> str:
    """Resolve the file path.  Reject path traversal attempts."""
    path = requested or default
    # Reject obvious traversal
    if ".." in path:
        raise HTTPException(status_code=400, detail="Path traversal not allowed")
    return path


def _vuln_to_item(v: Any) -> VulnerabilityItem:
    return VulnerabilityItem(
        package=v.package,
        installed_version=v.installed_version,
        fixed_version=v.fixed_version,
        cve_id=v.cve_id,
        severity=v.severity,
        description=v.description,
        advisory_url=v.advisory_url,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/scan-requirements",
    response_model=ScanResult,
    summary="Scan a requirements.txt for known CVEs",
)
def scan_requirements(body: ScanFileRequest) -> ScanResult:
    """Scan the given requirements.txt (defaults to the ALDECI repo root file)."""
    file_path = _safe_path(body.file_path, _DEFAULT_REQUIREMENTS)
    if not Path(file_path).exists():
        raise HTTPException(status_code=404, detail=f"File not found: {file_path}")

    scanner = _get_scanner()
    vulns = scanner.scan_requirements(file_path)
    return ScanResult(
        file_path=file_path,
        total=len(vulns),
        vulnerabilities=[_vuln_to_item(v) for v in vulns],
    )


@router.post(
    "/scan-package-json",
    response_model=ScanResult,
    summary="Scan a package.json for known CVEs",
)
def scan_package_json(body: ScanFileRequest) -> ScanResult:
    """Scan the given package.json (defaults to suite-ui/aldeci-ui-new/package.json)."""
    file_path = _safe_path(body.file_path, _DEFAULT_PACKAGE_JSON)
    if not Path(file_path).exists():
        raise HTTPException(status_code=404, detail=f"File not found: {file_path}")

    scanner = _get_scanner()
    vulns = scanner.scan_package_json(file_path)
    return ScanResult(
        file_path=file_path,
        total=len(vulns),
        vulnerabilities=[_vuln_to_item(v) for v in vulns],
    )


@router.get(
    "/scan-installed",
    response_model=ScanResult,
    summary="Scan pip-installed packages for known CVEs",
)
def scan_installed() -> ScanResult:
    """Run pip freeze and check installed packages against the vulnerability DB."""
    scanner = _get_scanner()
    vulns = scanner.scan_installed()
    return ScanResult(
        file_path="pip freeze",
        total=len(vulns),
        vulnerabilities=[_vuln_to_item(v) for v in vulns],
    )


@router.get(
    "/outdated",
    response_model=List[OutdatedItem],
    summary="List pip packages with newer versions available",
)
def get_outdated() -> List[OutdatedItem]:
    """Run pip list --outdated and return packages with available upgrades."""
    scanner = _get_scanner()
    items = scanner.get_outdated()
    return [
        OutdatedItem(
            package=i.get("package", ""),
            installed_version=i.get("installed_version", ""),
            latest_version=i.get("latest_version", ""),
            latest_filetype=i.get("latest_filetype", "wheel"),
        )
        for i in items
    ]


@router.get(
    "/vulnerable",
    response_model=ScanResult,
    summary="List vulnerable installed packages",
)
def get_vulnerable() -> ScanResult:
    """Return all vulnerabilities found in currently-installed packages."""
    scanner = _get_scanner()
    vulns = scanner.get_vulnerable()
    return ScanResult(
        file_path="pip freeze (vulnerable only)",
        total=len(vulns),
        vulnerabilities=[_vuln_to_item(v) for v in vulns],
    )


@router.get(
    "/upgrade-plan",
    response_model=UpgradePlanResult,
    summary="Generate a prioritized upgrade plan for vulnerable packages",
)
def generate_upgrade_plan() -> UpgradePlanResult:
    """Scan installed packages and return a severity-ordered upgrade plan."""
    scanner = _get_scanner()
    plan = scanner.generate_upgrade_plan()
    return UpgradePlanResult(**plan)
