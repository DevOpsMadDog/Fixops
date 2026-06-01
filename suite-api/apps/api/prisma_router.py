"""Prisma Cloud (Palo Alto CNAPP) Router — ALDECI.

Prefix: /api/v1/prisma
Scope:  read:scans (mounted via platform_app)

Routes:
  GET   /                  capability summary (configured / not_configured)
  POST  /ingest            pull Prisma Compute vulns + alerts -> normalize -> findings + brain

SPEC-016 increment 2. Wraps the real ``PrismaCloudConnector`` (live api.prismacloud.io
REST). NO MOCKS — when PRISMA_ACCESS_KEY/PRISMA_SECRET_KEY unset, /ingest returns an
honest 503. Egress-guarded BEFORE any outbound call (no SaaS default / SSRF in enforced
air-gap). Org-scoped. Mirrors the verified wiz_router pattern.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/prisma", tags=["Prisma Cloud CNAPP"],
                   dependencies=[Depends(api_key_auth)])


def _connector():
    """Build a PrismaCloudConnector from env (no mocks)."""
    from core.security_connectors import PrismaCloudConnector

    return PrismaCloudConnector({
        "base_url": os.environ.get("PRISMA_API_URL") or "https://api.prismacloud.io",
        "access_key": os.environ.get("PRISMA_ACCESS_KEY"),
        "secret_key_env": "PRISMA_SECRET_KEY",
    })


def _norm_prisma_vuln(v: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize one Prisma Compute vulnerability into a canonical finding dict."""
    cve = str(v.get("cve") or "").strip() or None
    image = v.get("image")
    pkg = v.get("packageName") or v.get("packageName".lower())
    fid = f"prisma-vuln-{cve or v.get('id') or pkg or 'unknown'}-{image or ''}".strip("-")
    return {
        "id": fid,
        "rule_id": cve or fid,
        "title": (f"{cve} in {pkg}" if cve and pkg else (cve or pkg or "Prisma vulnerability")),
        "severity": str(v.get("severity") or "medium").lower(),
        "cve_id": cve,
        "cvss_score": v.get("cvss"),
        "asset_id": image,
        "asset_name": image,
        "asset_type": "container_image",
        "source": "prisma",
        "fixed_version": v.get("fixLink") or v.get("status"),
    }


def _norm_prisma_alert(a: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize one Prisma Cloud alert into a canonical finding dict (best-effort)."""
    policy = a.get("policy") or {}
    resource = a.get("resource") or {}
    fid = f"prisma-alert-{a.get('id') or policy.get('policyId') or 'unknown'}"
    return {
        "id": fid,
        "rule_id": str(policy.get("policyId") or fid),
        "title": policy.get("name") or "Prisma Cloud alert",
        "severity": str(policy.get("severity") or a.get("severity") or "medium").lower(),
        "cve_id": None,
        "asset_id": resource.get("id") or resource.get("rrn"),
        "asset_name": resource.get("name") or resource.get("id"),
        "asset_type": resource.get("resourceType") or "cloud_resource",
        "source": "prisma",
    }


@router.get("/")
def capability_summary() -> Dict[str, Any]:
    """Honest configured / not_configured status (no outbound call)."""
    conn = _connector()
    return {
        "connector": "prisma_cloud",
        "configured": conn.configured,
        "base_url": conn.base_url,
        "status": "configured" if conn.configured else "not_configured",
    }


class PrismaIngestBody(BaseModel):
    alert_status: str = Field(default="open", max_length=32)
    limit: int = Field(default=100, ge=1, le=1000)
    include_alerts: bool = Field(default=True)


@router.post("/ingest")
def ingest(body: Optional[PrismaIngestBody] = None,
           org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Pull Prisma Compute vulns (+ alerts) -> normalize -> findings + correlation brain.

    SPEC-016 REQ-016-02/03/06/07. Org-scoped. Egress-guarded before any outbound call.
    Honest 503 when PRISMA_* unset. Calls the connector's typed methods (no raw proxy).
    """
    from core.airgap_config import assert_egress_allowed, EgressBlocked

    body = body or PrismaIngestBody()
    conn = _connector()

    # REQ-016-07: pre-flight egress guard BEFORE opening any socket.
    try:
        assert_egress_allowed(conn.base_url, "prisma")
    except EgressBlocked as exc:
        raise HTTPException(status_code=503, detail=f"prisma unavailable: {exc}") from exc

    # NO MOCKS: unconfigured -> honest 503 (never fake findings).
    if not conn.configured:
        raise HTTPException(
            status_code=503,
            detail="prisma not_configured: set PRISMA_ACCESS_KEY + PRISMA_SECRET_KEY",
        )

    findings: List[Dict[str, Any]] = []

    vuln_out = conn.get_vulnerabilities(limit=body.limit)
    if vuln_out.status == "fetched":
        for v in vuln_out.details.get("vulnerabilities", []) or []:
            findings.append(_norm_prisma_vuln(v))
    elif vuln_out.status == "failed":
        raise HTTPException(status_code=502,
                            detail=f"prisma vulnerabilities fetch failed: {vuln_out.details}")

    if body.include_alerts:
        alert_out = conn.get_alerts(status=body.alert_status, limit=body.limit)
        if alert_out.status == "fetched":
            for a in alert_out.details.get("alerts", []) or []:
                findings.append(_norm_prisma_alert(a))

    from apps.api.scanner_ingest_router import (
        _index_findings_into_brain,
        _promote_findings_to_issues,
    )

    promoted = 0
    if findings:
        try:
            promoted = _promote_findings_to_issues(findings, "prisma", org_id)
        except Exception as exc:  # noqa: BLE001 - never 500 the ingest path
            _logger.warning("prisma ingest promote failed: %s", type(exc).__name__)
    brain = _index_findings_into_brain(findings, org_id)

    return {
        "ingested": len(findings),
        "promoted": promoted,
        "brain_nodes_added": brain.get("nodes_added", 0),
        "brain_edges_added": brain.get("edges_added", 0),
        "correlated": brain.get("nodes_added", 0) > 0,
        "source": "prisma",
    }
