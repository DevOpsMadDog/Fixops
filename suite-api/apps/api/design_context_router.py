"""Design-Context Import Router — ALDECI (SPEC-016 increment 4).

Prefix: /api/v1/design-context

Imports a Confluence ADR / architecture / solution-design page into the correlation
brain as a design-time context node (EntityType.EVIDENCE, context_type=design_adr) and
links it to findings — establishing design→runtime provenance (the ADR that governs a
service connects to the findings on that service). Reuses the EXISTING real
``ConfluenceConnector`` read methods (REQ-016-04) — no new auth code.

NO MOCKS: honest 503 when CONFLUENCE_* unset. Egress-guarded. Org-scoped — findings are
only linked when they exist for the caller's org (SecurityFindingsEngine.get_finding).
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

router = APIRouter(prefix="/api/v1/design-context", tags=["Design Context"],
                   dependencies=[Depends(api_key_auth)])


def _confluence():
    from core.connectors import ConfluenceConnector

    return ConfluenceConnector({
        "base_url": os.environ.get("CONFLUENCE_BASE_URL") or os.environ.get("CONFLUENCE_URL"),
        "space_key": os.environ.get("CONFLUENCE_SPACE_KEY"),
        "user": os.environ.get("CONFLUENCE_USER") or os.environ.get("CONFLUENCE_USER_EMAIL"),
        "token_env": "CONFLUENCE_TOKEN",
    })


@router.get("/")
def capability_summary() -> Dict[str, Any]:
    conn = _confluence()
    return {
        "connector": "confluence",
        "configured": conn.configured,
        "base_url": conn.base_url,
        "status": "configured" if conn.configured else "not_configured",
    }


class ConfluenceImportBody(BaseModel):
    page_id: str = Field(..., min_length=1, max_length=128)
    context_type: str = Field(default="design_adr", max_length=64)
    link_finding_ids: List[str] = Field(default_factory=list)


@router.post("/confluence/import")
def import_confluence(body: ConfluenceImportBody,
                      org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Import a Confluence ADR/arch page -> design-context node -> link to org findings."""
    from core.airgap_config import assert_egress_allowed, EgressBlocked

    conn = _confluence()
    try:
        assert_egress_allowed(conn.base_url, "confluence")
    except EgressBlocked as exc:
        raise HTTPException(status_code=503, detail=f"confluence unavailable: {exc}") from exc
    if not conn.configured:
        raise HTTPException(
            status_code=503,
            detail="confluence not_configured: set CONFLUENCE_BASE_URL + CONFLUENCE_SPACE_KEY + CONFLUENCE_USER + CONFLUENCE_TOKEN",
        )

    out = conn.get_page(body.page_id)
    if out.status == "skipped":
        raise HTTPException(status_code=503, detail="confluence not_configured")
    if out.status == "failed":
        raise HTTPException(status_code=502, detail=f"confluence fetch failed: {out.details}")
    page_id = out.details.get("page_id") or body.page_id
    title = out.details.get("title") or f"Confluence page {page_id}"

    # Create the design-context node in the brain (best-effort, org-scoped, classified).
    classification = os.environ.get("FIXOPS_DEFAULT_CLASSIFICATION") or "UNCLASSIFIED"
    node_id = f"design-confluence-{page_id}"
    context_nodes = 0
    linked = 0
    try:
        from core.knowledge_brain import (
            EdgeType, EntityType, GraphEdge, GraphNode, get_brain,
        )

        brain = get_brain()
        brain.upsert_node(GraphNode(
            node_id=node_id,
            node_type=EntityType.EVIDENCE,
            org_id=org_id,
            properties={
                "title": title,
                "source": "confluence",
                "context_type": body.context_type,
                "page_id": page_id,
                "classification_level": classification,
            },
        ))
        context_nodes = 1

        # Link to findings — ONLY those that exist for this org (REQ-016-06 org-scope).
        if body.link_finding_ids:
            from core.security_findings_engine import SecurityFindingsEngine
            sfe = SecurityFindingsEngine()
            for fid in body.link_finding_ids:
                if not sfe.get_finding(fid, org_id):
                    continue  # never link to another org's / nonexistent finding
                try:
                    brain.add_edge(GraphEdge(
                        source_id=node_id,        # design-context -> finding (governs)
                        target_id=str(fid),
                        edge_type=EdgeType.REFERENCES,
                    ))
                    linked += 1
                except Exception:  # noqa: BLE001
                    pass
    except ImportError as exc:
        _logger.warning("design-context: knowledge_brain unavailable: %s", exc)
    except Exception as exc:  # noqa: BLE001
        _logger.warning("design-context import failed: %s", type(exc).__name__)

    return {
        "page_id": page_id,
        "title": title,
        "context_nodes": context_nodes,
        "linked_findings": linked,
        "source": "confluence",
    }
