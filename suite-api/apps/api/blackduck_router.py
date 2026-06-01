"""Black Duck (Synopsys) SCA Router — ALDECI (SPEC-016 REQ-016-13).

Prefix: /api/v1/blackduck
Scope:  read:scans (mounted via platform_app)

Routes:
  GET   /            capability summary (configured / not_configured)
  POST  /ingest      pull vulnerable BOM components -> normalize -> findings + brain

Wraps the real ``BlackDuckConnector`` (live Hub REST). NO MOCKS — honest 503 when
BLACKDUCK_API_TOKEN / BLACKDUCK_VULNERABLE_BOM_URL unset. Egress-guarded before any
outbound call. Org-scoped. Mirrors the verified wiz/prisma router pattern.
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

router = APIRouter(prefix="/api/v1/blackduck", tags=["Black Duck SCA"],
                   dependencies=[Depends(api_key_auth)])


def _connector():
    from core.security_connectors import BlackDuckConnector

    return BlackDuckConnector({
        "base_url": os.environ.get("BLACKDUCK_API_URL") or os.environ.get("BLACKDUCK_BASE_URL"),
        "api_token_env": "BLACKDUCK_API_TOKEN",
        "vulnerable_bom_url": os.environ.get("BLACKDUCK_VULNERABLE_BOM_URL"),
    })


def _norm_bd_item(it: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize one Black Duck vulnerable-bom-component into a canonical finding dict."""
    vuln = it.get("vulnerabilityWithRemediation") or it.get("vulnerability") or {}
    comp = it.get("componentName") or it.get("component") or ""
    cver = it.get("componentVersionName") or it.get("componentVersion") or ""
    vname = str(vuln.get("vulnerabilityName") or vuln.get("name") or "").strip()
    cve = vname if vname.upper().startswith("CVE-") else None
    score = vuln.get("baseScore") or vuln.get("overallScore") or vuln.get("cvss")
    asset = f"{comp}@{cver}".strip("@") or comp or "component"
    fid = f"blackduck-{vname or comp}-{cver}".strip("-")
    return {
        "id": fid,
        "rule_id": vname or fid,
        "title": f"{vname or 'Black Duck vulnerability'} in {comp}@{cver}".strip(),
        "severity": str(vuln.get("severity") or "medium").lower(),
        "cve_id": cve,
        "cvss_score": float(score) if score not in (None, "") else None,
        "asset_id": asset,
        "asset_name": asset,
        "asset_type": "dependency",
        "source": "blackduck",
    }


@router.get("/")
def capability_summary() -> Dict[str, Any]:
    conn = _connector()
    return {
        "connector": "blackduck",
        "configured": conn.configured,
        "base_url": conn.base_url,
        "status": "configured" if conn.configured else "not_configured",
    }


class BlackDuckIngestBody(BaseModel):
    limit: int = Field(default=500, ge=1, le=5000)


@router.post("/ingest")
def ingest(body: Optional[BlackDuckIngestBody] = None,
           org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Pull Black Duck vulnerable BOM components -> normalize -> findings + correlation brain."""
    from core.airgap_config import assert_egress_allowed, EgressBlocked

    body = body or BlackDuckIngestBody()
    conn = _connector()

    # REQ-016-07: egress guard before any outbound call (base + the BOM URL).
    try:
        assert_egress_allowed(conn.base_url, "blackduck")
        if conn.vulnerable_bom_url:
            assert_egress_allowed(conn.vulnerable_bom_url, "blackduck")
    except EgressBlocked as exc:
        raise HTTPException(status_code=503, detail=f"blackduck unavailable: {exc}") from exc

    if not conn.configured:
        raise HTTPException(
            status_code=503,
            detail="blackduck not_configured: set BLACKDUCK_API_URL + BLACKDUCK_API_TOKEN + BLACKDUCK_VULNERABLE_BOM_URL",
        )

    out = conn.get_vulnerable_components(limit=body.limit)
    if out.status == "failed":
        raise HTTPException(status_code=502, detail=f"blackduck fetch failed: {out.details}")

    findings: List[Dict[str, Any]] = [
        _norm_bd_item(it) for it in (out.details.get("items", []) or []) if isinstance(it, dict)
    ]

    from apps.api.scanner_ingest_router import (
        _index_findings_into_brain,
        _promote_findings_to_issues,
    )

    promoted = 0
    if findings:
        try:
            promoted = _promote_findings_to_issues(findings, "blackduck", org_id)
        except Exception as exc:  # noqa: BLE001
            _logger.warning("blackduck ingest promote failed: %s", type(exc).__name__)
    brain = _index_findings_into_brain(findings, org_id)

    return {
        "ingested": len(findings),
        "promoted": promoted,
        "brain_nodes_added": brain.get("nodes_added", 0),
        "brain_edges_added": brain.get("edges_added", 0),
        "correlated": brain.get("nodes_added", 0) > 0,
        "source": "blackduck",
    }
