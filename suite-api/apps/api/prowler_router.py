"""Prowler CSPM Router — ALDECI.

Agentless cloud security scanning via Prowler (AWS/Azure/GCP).

Prefix: /api/v1/prowler
Auth: api_key_auth on ALL endpoints

Routes:
  POST   /api/v1/prowler/scan                  trigger_scan
  POST   /api/v1/prowler/ingest                ingest_from_json
  GET    /api/v1/prowler/scans                 list_scans
  GET    /api/v1/prowler/scans/{id}            get_scan
  GET    /api/v1/prowler/findings              list_findings
  GET    /api/v1/prowler/findings/{id}         get_finding
  PUT    /api/v1/prowler/findings/{id}/resolve resolve_finding
  PUT    /api/v1/prowler/findings/{id}/suppress suppress_finding
  GET    /api/v1/prowler/compliance            get_compliance
  GET    /api/v1/prowler/compliance/summary    get_compliance_summary
  GET    /api/v1/prowler/summary               get_summary
  GET    /api/v1/prowler/status                get_prowler_status
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/prowler",
    tags=["Prowler CSPM"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None
_connector = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.prowler_engine import ProwlerEngine
        _engine = ProwlerEngine()
    return _engine


def _get_connector(org_id: str = "default"):
    from suite_integrations_prowler import ProwlerConnector
    return ProwlerConnector(org_id=org_id, engine=_get_engine())


# Try direct import, fall back to inline import
try:
    from suite_integrations_prowler import ProwlerConnector as _PC
except ImportError:
    _PC = None


def _get_connector(org_id: str = "default"):
    """Get a ProwlerConnector for the given org."""
    if _PC is not None:
        return _PC(org_id=org_id, engine=_get_engine())
    # Fallback: import from the integrations path
    try:
        from integrations.prowler.prowler_connector import ProwlerConnector
        return ProwlerConnector(org_id=org_id, engine=_get_engine())
    except ImportError:
        pass
    # Final fallback: sys.path includes suite-integrations
    import sys
    import os
    _prowler_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
        "suite-integrations", "prowler",
    )
    if _prowler_dir not in sys.path:
        sys.path.insert(0, _prowler_dir)
    from prowler_connector import ProwlerConnector
    return ProwlerConnector(org_id=org_id, engine=_get_engine())


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class TriggerScanRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    provider: str = Field(default="aws", description="Cloud provider: aws/azure/gcp")
    account_id: str = Field(default="", description="Cloud account/subscription ID")
    regions: str = Field(default="", description="Comma-separated regions to scan")
    checks: Optional[List[str]] = Field(default=None, description="Specific checks to run")
    timeout: int = Field(default=3600, ge=60, le=7200, description="Scan timeout in seconds")


class IngestJsonRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    provider: str = Field(default="aws", description="Cloud provider: aws/azure/gcp")
    account_id: str = Field(default="", description="Cloud account ID")
    raw_json: str = Field(..., description="Raw Prowler JSON output")


class ResolveRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")


class SuppressRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan", summary="Trigger a Prowler scan against a cloud provider")
def trigger_scan(req: TriggerScanRequest) -> Dict[str, Any]:
    """Trigger a Prowler CLI scan. Requires Prowler to be installed on the host."""
    try:
        connector = _get_connector(org_id=req.org_id)
        return connector.run_scan(
            provider=req.provider,
            account_id=req.account_id,
            regions=req.regions,
            checks=req.checks,
            timeout=req.timeout,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("Prowler scan trigger failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/ingest", summary="Ingest raw Prowler JSON output")
def ingest_from_json(req: IngestJsonRequest) -> Dict[str, Any]:
    """Ingest findings from raw Prowler JSON output without running the CLI."""
    try:
        connector = _get_connector(org_id=req.org_id)
        return connector.ingest_from_json(
            raw_json=req.raw_json,
            provider=req.provider,
            account_id=req.account_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("Prowler ingest failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/scans", summary="List Prowler scan history")
def list_scans(
    org_id: str = Query(default="default"),
    provider: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> List[Dict[str, Any]]:
    return _get_engine().list_scans(
        org_id=org_id, provider=provider, status=status, limit=limit
    )


@router.get("/scans/{scan_id}", summary="Get a specific Prowler scan")
def get_scan(scan_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().get_scan(scan_id=scan_id, org_id=org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/findings", summary="List Prowler findings with filters")
def list_findings(
    org_id: str = Query(default="default"),
    scan_id: Optional[str] = Query(default=None),
    provider: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    service: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> List[Dict[str, Any]]:
    return _get_engine().get_findings(
        org_id=org_id, scan_id=scan_id, provider=provider,
        severity=severity, status=status, service=service, limit=limit,
    )


@router.get("/findings/{finding_id}", summary="Get a specific Prowler finding")
def get_finding(
    finding_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    try:
        return _get_engine().get_finding(finding_id=finding_id, org_id=org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.put("/findings/{finding_id}/resolve", summary="Resolve a Prowler finding")
def resolve_finding(finding_id: str, req: ResolveRequest) -> Dict[str, Any]:
    try:
        return _get_engine().resolve_finding(finding_id=finding_id, org_id=req.org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.put("/findings/{finding_id}/suppress", summary="Suppress a Prowler finding")
def suppress_finding(finding_id: str, req: SuppressRequest) -> Dict[str, Any]:
    try:
        return _get_engine().suppress_finding(finding_id=finding_id, org_id=req.org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/compliance", summary="Get CIS compliance results")
def get_compliance(
    org_id: str = Query(default="default"),
    scan_id: Optional[str] = Query(default=None),
    framework: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    return _get_engine().get_compliance(
        org_id=org_id, scan_id=scan_id, framework=framework
    )


@router.get("/compliance/summary", summary="Get aggregated compliance summary per framework")
def get_compliance_summary(
    org_id: str = Query(default="default"),
    scan_id: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    return _get_engine().get_compliance_summary(org_id=org_id, scan_id=scan_id)


@router.get("/summary", summary="Get overall Prowler scan summary")
def get_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().get_summary(org_id=org_id)


@router.get("/status", summary="Check Prowler CLI installation status")
def get_prowler_status() -> Dict[str, Any]:
    """Check if Prowler CLI is installed and available."""
    import shutil
    prowler_path = shutil.which("prowler")
    installed = prowler_path is not None

    version = ""
    if installed:
        import subprocess
        try:
            result = subprocess.run(
                [prowler_path, "--version"],
                capture_output=True, text=True, timeout=10,
            )
            version = result.stdout.strip() or result.stderr.strip()
        except Exception:
            version = "unknown"

    return {
        "installed": installed,
        "path": prowler_path or "",
        "version": version,
        "supported_providers": ["aws", "azure", "gcp"],
        "cis_benchmarks": {
            "aws": "CIS Amazon Web Services Foundations Benchmark v1.5.0",
            "azure": "CIS Microsoft Azure Foundations Benchmark v2.0.0",
            "gcp": "CIS Google Cloud Platform Foundation Benchmark v1.3.0",
        },
    }
