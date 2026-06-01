"""Wiz CNAPP/CSPM Router — ALDECI.

Prefix: /api/v1/wiz
Scope:  read:scans (mounted via platform_app)

Routes:
  GET   /                            capability summary
  POST  /graphql                     raw GraphQL passthrough
  GET   /issues                      list issues (filtered)
  GET   /inventory                   list cloud resources / inventory
  GET   /vulnerabilities             list vulnerability findings
  GET   /threats                     list threat-detection signals

Returns 503 on lookup endpoints when WIZ_CLIENT_ID/WIZ_CLIENT_SECRET/
WIZ_API_URL unset. NO MOCKS — engine raises RuntimeError → mapped to 503.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Depends, APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/wiz", tags=["Wiz CNAPP"],
    dependencies=[Depends(api_key_auth)]
)


def _engine():
    from core.wiz_cnapp_engine import get_wiz_cnapp_engine

    return get_wiz_cnapp_engine()


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class GraphQLRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=64 * 1024, description="GraphQL query")
    variables: Optional[Dict[str, Any]] = Field(default=None, description="GraphQL variables")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _handle_engine_call(callable_):
    """Invoke an engine call and translate errors to HTTPException."""
    try:
        return callable_()
    except RuntimeError as exc:
        # NO MOCKS — when env not set
        raise HTTPException(status_code=503, detail=f"wiz unavailable: {exc}") from exc
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        raise HTTPException(status_code=status, detail=f"wiz error: {exc}") from exc
    except (httpx.HTTPError, OSError) as exc:
        raise HTTPException(status_code=502, detail=f"wiz transport error: {exc}") from exc


def _split_csv(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/")
def capability_summary() -> Dict[str, Any]:
    """Return capability/health summary for the Wiz integration."""
    eng = _engine()
    return eng.capability_summary()


# ---------------------------------------------------------------------------
# Ingest → normalize → findings + correlation brain (SPEC-016 increment 1)
# ---------------------------------------------------------------------------


def _norm_wiz_issue(node: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize one Wiz issue node into a canonical finding dict.

    Uses the engine's typed query output (NOT the raw /graphql passthrough — SPEC-016
    REQ-016-12). Asset comes from the issue's entitySnapshot.
    """
    rule = node.get("sourceRule") or {}
    entity = node.get("entitySnapshot") or {}
    fid = f"wiz-issue-{node.get('id')}"
    return {
        "id": fid,
        "rule_id": str(rule.get("id") or node.get("type") or fid),
        "title": rule.get("name") or node.get("type") or "Wiz issue",
        "severity": str(node.get("severity") or "medium").lower(),
        "cve_id": None,  # Wiz issues are policy/posture, not CVE-keyed
        "asset_id": entity.get("id"),
        "asset_name": entity.get("name"),
        "asset_type": entity.get("type") or "cloud_resource",
        "source": "wiz",
        "status": str(node.get("status") or "open").lower(),
    }


def _norm_wiz_vuln(node: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize one Wiz vulnerabilityFindings node into a canonical finding dict."""
    name = str(node.get("name") or "").strip()
    cve = name if name.upper().startswith("CVE-") else None
    cvss = node.get("cvss31") or {}
    fid = f"wiz-vuln-{node.get('id')}"
    return {
        "id": fid,
        "rule_id": cve or fid,
        "title": name or fid,
        "severity": str(node.get("vendorSeverity") or "medium").lower(),
        "cve_id": cve,
        "cvss_score": cvss.get("score") or node.get("score"),
        "source": "wiz",
        "fixed_version": node.get("fixedVersion"),
    }


class WizIngestBody(BaseModel):
    severity: Optional[List[str]] = Field(
        default=None, description="Severity filter, e.g. ['CRITICAL','HIGH']. Default CRITICAL,HIGH."
    )
    max_pages: int = Field(default=5, ge=1, le=50, description="Page cap per stream (bounded).")
    page_size: int = Field(default=100, ge=1, le=500)


@router.post("/ingest")
def ingest(body: Optional[WizIngestBody] = None,
           org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Pull Wiz issues + vulnerabilities → normalize → findings + correlation brain.

    SPEC-016 REQ-016-01/06/07/12. Org-scoped. Egress-guarded BEFORE any outbound call
    (no SaaS default / SSRF in enforced air-gap). Honest 503 when WIZ env unset.
    Calls the engine's typed methods (never the raw /graphql passthrough).
    """
    from core.airgap_config import assert_egress_allowed, EgressBlocked

    # REQ-016-07: pre-flight egress guard BEFORE opening any socket. Unset URL → 503.
    try:
        assert_egress_allowed(os.environ.get("WIZ_API_URL"), "wiz")
    except EgressBlocked as exc:
        raise HTTPException(status_code=503, detail=f"wiz unavailable: {exc}") from exc

    body = body or WizIngestBody()
    sev = body.severity or ["CRITICAL", "HIGH"]
    eng = _engine()
    findings: List[Dict[str, Any]] = []

    # --- Issues (paginated, bounded) ---
    after: Optional[str] = None
    for _ in range(body.max_pages):
        page = _handle_engine_call(
            lambda a=after: eng.list_issues(severity=sev, first=body.page_size, after=a)
        )
        for n in page.get("issues", []) or []:
            findings.append(_norm_wiz_issue(n))
        pi = page.get("pageInfo") or {}
        if not pi.get("hasNextPage"):
            break
        after = pi.get("endCursor")

    # --- Vulnerabilities (paginated, bounded) ---
    after = None
    for _ in range(body.max_pages):
        page = _handle_engine_call(
            lambda a=after: eng.list_vulnerabilities(severity=sev, first=body.page_size, after=a)
        )
        for n in page.get("nodes", []) or []:
            findings.append(_norm_wiz_vuln(n))
        pi = page.get("pageInfo") or {}
        if not pi.get("hasNextPage"):
            break
        after = pi.get("endCursor")

    # --- Promote to findings store + index into correlation brain (Store B) ---
    from apps.api.scanner_ingest_router import (
        _promote_findings_to_issues,
        _index_findings_into_brain,
    )

    promoted = 0
    if findings:
        try:
            promoted = _promote_findings_to_issues(findings, "wiz", org_id)
        except Exception as exc:  # noqa: BLE001 - never 500 the ingest path
            _logger.warning("wiz ingest promote failed: %s", type(exc).__name__)
    brain = _index_findings_into_brain(findings, org_id)

    return {
        "ingested": len(findings),
        "promoted": promoted,
        "brain_nodes_added": brain.get("nodes_added", 0),
        "brain_edges_added": brain.get("edges_added", 0),
        "correlated": brain.get("nodes_added", 0) > 0,
        "source": "wiz",
    }


# ---------------------------------------------------------------------------
# Raw GraphQL
# ---------------------------------------------------------------------------


@router.post("/graphql")
def graphql(req: GraphQLRequest) -> Dict[str, Any]:
    """Raw GraphQL passthrough — POST {query, variables?} → {data, errors?}."""
    eng = _engine()
    payload = _handle_engine_call(lambda: eng.graphql(req.query, req.variables))
    out: Dict[str, Any] = {"data": payload.get("data") or {}}
    if payload.get("errors"):
        out["errors"] = payload["errors"]
    return out


# ---------------------------------------------------------------------------
# Issues
# ---------------------------------------------------------------------------


@router.get("/issues")
def list_issues(
    status: str = Query(default="OPEN", max_length=64),
    severity: Optional[str] = Query(
        default="CRITICAL,HIGH",
        description="Comma-separated list, e.g. CRITICAL,HIGH",
        max_length=256,
    ),
    projectId: Optional[str] = Query(default=None, max_length=256),  # noqa: N803
    first: int = Query(default=50, ge=1, le=500),
    after: Optional[str] = Query(default=None, max_length=2048),
) -> Dict[str, Any]:
    """List Wiz issues, paginated."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_issues(
            status=status,
            severity=_split_csv(severity),
            project_id=projectId,
            first=first,
            after=after,
        )
    )


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


@router.get("/inventory")
def list_inventory(
    type: Optional[str] = Query(  # noqa: A002
        default=None,
        description="Comma-separated list, e.g. CONTAINER_IMAGE,VIRTUAL_MACHINE",
        max_length=512,
    ),
    projectId: Optional[str] = Query(default=None, max_length=256),  # noqa: N803
    first: int = Query(default=50, ge=1, le=500),
    after: Optional[str] = Query(default=None, max_length=2048),
) -> Dict[str, Any]:
    """List Wiz cloud-resource inventory, paginated."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_inventory(
            types=_split_csv(type),
            project_id=projectId,
            first=first,
            after=after,
        )
    )


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------


@router.get("/vulnerabilities")
def list_vulnerabilities(
    severity: Optional[str] = Query(
        default="CRITICAL,HIGH",
        description="Comma-separated list",
        max_length=256,
    ),
    first: int = Query(default=50, ge=1, le=500),
    after: Optional[str] = Query(default=None, max_length=2048),
) -> Dict[str, Any]:
    """List Wiz vulnerability findings, paginated."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_vulnerabilities(
            severity=_split_csv(severity),
            first=first,
            after=after,
        )
    )


# ---------------------------------------------------------------------------
# Threats
# ---------------------------------------------------------------------------


@router.get("/threats")
def list_threats(
    first: int = Query(default=50, ge=1, le=500),
    after: Optional[str] = Query(default=None, max_length=2048),
) -> Dict[str, Any]:
    """List Wiz threat-detection signals, paginated."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_threats(first=first, after=after)
    )
