"""CSPM Connector Router — POST /api/v1/connectors/cspm/scan.

Wires the OSS CSPM family (Prowler + Checkov + CloudSploit + Agentless Snapshot)
into a single API endpoint. Per-tenant findings are mirrored to
``SecurityFindingsEngine`` keyed by ``org_id``.

Endpoints
---------
POST /api/v1/connectors/cspm/scan        Run scan for a single tenant.
POST /api/v1/connectors/cspm/scan-bulk   Run scan for many tenants in one call.
GET  /api/v1/connectors/cspm/status      Tool availability + connector health.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

try:
    from apps.api.auth_deps import api_key_auth
except Exception:  # pragma: no cover - fallback for tests
    def api_key_auth() -> None:  # type: ignore
        return None

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/connectors/cspm",
    tags=["CSPM Connectors"],
    dependencies=[Depends(api_key_auth)],
)

_connector = None


def _get_connector():
    global _connector
    if _connector is None:
        from connectors.cspm_connector import CSPMConnector

        _connector = CSPMConnector()
    return _connector


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CSPMScanRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    provider: str = Field(default="aws")
    account_id: str = Field(default="000000000000", max_length=128)
    localstack_endpoint: str = Field(default="http://localhost:4566", max_length=512)
    iac_dir: Optional[str] = Field(default=None, max_length=1024)
    run_prowler: bool = True
    run_checkov: bool = True
    run_cloudsploit: bool = True
    run_agentless: bool = True
    run_trivy: bool = True

    @field_validator("provider")
    @classmethod
    def _check_provider(cls, v: str) -> str:
        if v not in {"aws", "azure", "gcp"}:
            raise ValueError(f"provider must be one of aws|azure|gcp, got {v!r}")
        return v


class CSPMBulkScanRequest(BaseModel):
    tenants: List[str] = Field(..., min_length=1, max_length=64)
    provider: str = Field(default="aws")
    account_id: str = Field(default="000000000000")
    localstack_endpoint: str = Field(default="http://localhost:4566")
    iac_dir: Optional[str] = None
    run_prowler: bool = True
    run_checkov: bool = True
    run_cloudsploit: bool = True
    run_agentless: bool = True
    run_trivy: bool = True


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/scan")
def scan(body: CSPMScanRequest) -> Dict[str, Any]:
    """Run the CSPM family for a single tenant."""

    try:
        return _get_connector().scan_tenant(
            org_id=body.org_id,
            provider=body.provider,
            account_id=body.account_id,
            localstack_endpoint=body.localstack_endpoint,
            iac_dir=body.iac_dir,
            run_prowler=body.run_prowler,
            run_checkov=body.run_checkov,
            run_cloudsploit=body.run_cloudsploit,
            run_agentless=body.run_agentless,
            run_trivy=body.run_trivy,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("CSPM scan failed for %s: %s", body.org_id, exc)
        raise HTTPException(status_code=500, detail=f"cspm_scan_failure: {exc}")


@router.post("/scan-bulk")
def scan_bulk(body: CSPMBulkScanRequest) -> Dict[str, Any]:
    """Run the CSPM family for many tenants — used by per-tenant attribution flows."""

    connector = _get_connector()
    results: Dict[str, Any] = {}
    aggregate = {"tenants_scanned": 0, "ingested_total": 0, "errors": 0}
    for tenant in body.tenants:
        try:
            r = connector.scan_tenant(
                org_id=tenant,
                provider=body.provider,
                account_id=body.account_id,
                localstack_endpoint=body.localstack_endpoint,
                iac_dir=body.iac_dir,
                run_prowler=body.run_prowler,
                run_checkov=body.run_checkov,
                run_cloudsploit=body.run_cloudsploit,
                run_agentless=body.run_agentless,
                run_trivy=body.run_trivy,
            )
            results[tenant] = r
            aggregate["tenants_scanned"] += 1
            aggregate["ingested_total"] += int(r.get("_summary", {}).get("ingested_total") or 0)
            for tool, info in r.items():
                if isinstance(info, dict) and info.get("errors"):
                    aggregate["errors"] += len(info["errors"])
        except Exception as exc:
            results[tenant] = {"error": str(exc)}
            aggregate["errors"] += 1
    results["_aggregate"] = aggregate
    return results


@router.get("/status")
def status() -> Dict[str, Any]:
    connector = _get_connector()
    return {
        "connector": "cspm_oss",
        "tools": {
            "prowler_cli": connector._prowler_path,
            "checkov_cli": connector._checkov_path,
            "cloudsploit_cli": connector._cloudsploit_path,
            "trivy_cli": connector._trivy_path,
        },
        "fallback_available": True,
        "supported_providers": ["aws", "azure", "gcp"],
    }


# Health/status aliases per DEMO-001.
@router.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "connector": "cspm_oss"}


__all__ = ["router"]
