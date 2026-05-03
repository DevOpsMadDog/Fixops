"""SigmaHQ Detection Rule Router — ALDECI.

Provides endpoints to import and query SigmaHQ detection rules.

Prefix: /api/v1/sigmahq
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/sigmahq/import          trigger_import
  GET  /api/v1/sigmahq/rules           list_rules
  GET  /api/v1/sigmahq/stats           get_stats
  POST /api/v1/sigmahq/custom-rules    upsert_custom_rule_endpoint
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sigmahq",
    tags=["SigmaHQ"],
)


def _get_importer():
    """Lazy import to avoid heavy deps at process start."""
    from feeds.sigmahq.importer import get_store_stats, list_rules, run_import
    return run_import, list_rules, get_store_stats


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import() -> Dict[str, Any]:
    """Download and import all SigmaHQ detection rules from master branch.

    Downloads https://github.com/SigmaHQ/sigma/archive/refs/heads/master.tar.gz,
    extracts the rules/ directory, and upserts all YAML rules into the local
    sigmahq_rules.db.  Skips tests/, deprecated/, and unsupported/ sub-dirs.

    Returns a summary with total rule count broken down by severity level and
    platform.
    """
    try:
        run_import, _list, _stats = _get_importer()
        result = run_import()
        return result
    except Exception as exc:
        logger.exception("SigmaHQ import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/rules", dependencies=[Depends(api_key_auth)])
def list_sigma_rules(
    level: Optional[str] = Query(
        default=None,
        description="Filter by severity level: informational | low | medium | high | critical. "
                    "'high' also returns critical rules.",
    ),
    technique: Optional[str] = Query(
        default=None,
        description="Filter by ATT&CK technique substring, e.g. t1059.001",
    ),
    platform: Optional[str] = Query(
        default=None,
        description="Filter by logsource product/platform, e.g. windows | linux | web",
    ),
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List SigmaHQ detection rules from the local DB with optional filters."""
    try:
        _run, list_rules, _stats = _get_importer()
        rules = list_rules(
            level=level,
            technique=technique,
            platform=platform,
            limit=limit,
            offset=offset,
        )
        return {"rules": rules, "total": len(rules), "offset": offset, "limit": limit}
    except Exception as exc:
        logger.exception("Failed to list SigmaHQ rules")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats() -> Dict[str, Any]:
    """Return total SigmaHQ rule count and breakdowns by level and platform."""
    try:
        _run, _list, get_store_stats = _get_importer()
        return get_store_stats()
    except Exception as exc:
        logger.exception("Failed to get SigmaHQ stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Custom rule upsert
# ---------------------------------------------------------------------------

class CustomRuleRequest(BaseModel):
    """Payload for submitting a user-defined Sigma-format rule."""

    yaml_text: str
    source_label: str = "custom"


@router.post("/custom-rules", status_code=201, dependencies=[Depends(api_key_auth)])
def upsert_custom_rule_endpoint(body: CustomRuleRequest) -> Dict[str, Any]:
    """Submit a single user-defined Sigma-format YAML rule for storage.

    The rule must be valid Sigma YAML with at least: id, title, detection.
    On success, the normalised rule dict is returned with HTTP 201.
    Duplicate IDs overwrite the existing rule (upsert semantics).

    Raises 422 for invalid/missing fields, 500 for unexpected errors.
    """
    try:
        from feeds.sigmahq.importer import (
            CustomRuleValidationError,
            upsert_custom_rule,
        )
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="SigmaHQ importer unavailable") from exc

    try:
        rule = upsert_custom_rule(body.yaml_text, source_label=body.source_label)
        return rule
    except CustomRuleValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to upsert custom rule")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
