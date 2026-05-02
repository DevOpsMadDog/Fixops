"""
Multi-CSP Router (GAP-025) — ALDECI.

Adds unified multi-cloud provider coverage for OCI + Alibaba + IBM on top of
existing AWS/Azure/GCP scanners. Delegates to adapters in:
  - core.cspm_engine.PROVIDERS
  - core.cnapp_engine.PROVIDERS
  - core.cloud_account_monitoring_engine

Prefix: /api/v1/multi-csp
Auth:   X-API-Key header (injected via Depends(_verify_api_key) in app.py)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from core.cloud_account_monitoring_engine import (
    _VALID_PROVIDERS as _MON_VALID_PROVIDERS,
)
from core.cnapp_engine import (
    PROVIDERS as CNAPP_PROVIDERS,
)
from core.cnapp_engine import (
    get_workload_adapter as get_cnapp_adapter,
)
from core.cnapp_engine import (
    list_supported_cnapp_providers,
)
from core.cspm_engine import (
    PROVIDERS as CSPM_PROVIDERS,
)
from core.cspm_engine import (
    get_provider_adapter as get_cspm_adapter,
)
from core.cspm_engine import (
    list_supported_providers as list_cspm_providers,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/multi-csp", tags=["multi-csp"])

# The canonical set of supported providers exposed by GAP-025
SUPPORTED_PROVIDERS: List[str] = ["aws", "azure", "gcp", "oci", "alibaba", "ibm"]


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    provider: str = Field(..., description="Provider name: aws|azure|gcp|oci|alibaba|ibm")
    account_id: str = Field(..., min_length=1, description="Cloud account identifier")
    org_id: str = "default"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/providers")
def get_providers() -> Dict[str, Any]:
    """Return list of supported cloud providers."""
    return {
        "providers": SUPPORTED_PROVIDERS,
        "count": len(SUPPORTED_PROVIDERS),
        "cspm_providers": list_cspm_providers(),
        "cnapp_providers": list_supported_cnapp_providers(),
    }


@router.post("/scan")
def scan(req: ScanRequest) -> Dict[str, Any]:
    """Run a multi-CSP scan for a given provider + account.

    Routes to the appropriate adapter in CSPM/CNAPP. For AWS/Azure/GCP
    (native scanners), returns an empty resources list since they rely on
    IaC text input. For OCI/Alibaba/IBM, returns seeded resources + findings.
    """
    provider = (req.provider or "").lower().strip()
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported provider: {req.provider!r}. Must be one of {SUPPORTED_PROVIDERS}",
        )

    account_id = req.account_id.strip()
    if not account_id:
        raise HTTPException(status_code=400, detail="account_id is required")

    cspm_resources: List[Dict[str, Any]] = []
    cnapp_workloads: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    # --- CSPM adapter ---
    cspm_adapter = get_cspm_adapter(provider)
    if cspm_adapter is not None:
        try:
            cspm_resources = cspm_adapter.list_resources(account_id)
            for res in cspm_resources:
                findings.extend(cspm_adapter.scan_resource(res))
        except Exception as exc:  # noqa: BLE001
            _logger.warning("CSPM adapter scan failed for %s: %s", provider, exc)

    # --- CNAPP adapter ---
    cnapp_adapter = get_cnapp_adapter(provider)
    if cnapp_adapter is not None:
        try:
            cnapp_workloads = cnapp_adapter.list_resources(account_id)
            for wl in cnapp_workloads:
                findings.extend(cnapp_adapter.scan_resource(wl))
        except Exception as exc:  # noqa: BLE001
            _logger.warning("CNAPP adapter scan failed for %s: %s", provider, exc)

    by_severity: Dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "unknown"))
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "provider": provider,
        "account_id": account_id,
        "org_id": req.org_id,
        "resource_count": len(cspm_resources) + len(cnapp_workloads),
        "cspm_resources": cspm_resources,
        "cnapp_workloads": cnapp_workloads,
        "finding_count": len(findings),
        "findings": findings,
        "by_severity": by_severity,
    }


@router.get("/coverage")
def coverage(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return per-provider asset counts and coverage summary."""
    per_provider: Dict[str, Dict[str, Any]] = {}
    for provider in SUPPORTED_PROVIDERS:
        cspm_adapter = get_cspm_adapter(provider)
        cnapp_adapter = get_cnapp_adapter(provider)

        # Use a placeholder account for coverage estimation
        cspm_count = 0
        cnapp_count = 0
        if cspm_adapter is not None:
            try:
                cspm_count = len(cspm_adapter.list_resources("coverage-probe"))
            except Exception:  # noqa: BLE001
                cspm_count = 0
        if cnapp_adapter is not None:
            try:
                cnapp_count = len(cnapp_adapter.list_resources("coverage-probe"))
            except Exception:  # noqa: BLE001
                cnapp_count = 0

        per_provider[provider] = {
            "cspm_supported": provider in CSPM_PROVIDERS,
            "cnapp_supported": provider in CNAPP_PROVIDERS,
            "monitoring_supported": provider in _MON_VALID_PROVIDERS or provider == "oci",
            "cspm_seeded_assets": cspm_count,
            "cnapp_seeded_workloads": cnapp_count,
        }

    return {
        "org_id": org_id,
        "providers": SUPPORTED_PROVIDERS,
        "provider_count": len(SUPPORTED_PROVIDERS),
        "coverage": per_provider,
    }


@router.get("/stats")
def stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return aggregate stats across all supported providers."""
    total_cspm_resources = 0
    total_cnapp_workloads = 0
    native_providers: List[str] = []
    adapter_providers: List[str] = []

    for provider in SUPPORTED_PROVIDERS:
        cspm_adapter = get_cspm_adapter(provider)
        cnapp_adapter = get_cnapp_adapter(provider)
        if cspm_adapter is None and cnapp_adapter is None:
            native_providers.append(provider)
        else:
            adapter_providers.append(provider)
            if cspm_adapter is not None:
                try:
                    total_cspm_resources += len(cspm_adapter.list_resources(f"stats-{org_id}"))
                except Exception:  # noqa: BLE001
                    pass
            if cnapp_adapter is not None:
                try:
                    total_cnapp_workloads += len(cnapp_adapter.list_resources(f"stats-{org_id}"))
                except Exception:  # noqa: BLE001
                    pass

    return {
        "org_id": org_id,
        "total_providers": len(SUPPORTED_PROVIDERS),
        "native_providers": native_providers,
        "adapter_providers": adapter_providers,
        "total_cspm_seeded_resources": total_cspm_resources,
        "total_cnapp_seeded_workloads": total_cnapp_workloads,
    }
