"""Dynamic Rule DSL Router — ALDECI (GAP-069).

User-authored YAML/JSON security rule lifecycle.

Prefix: /api/v1/rules/dsl
Auth:   api_key_auth (router-level dependency)

Routes:
  POST   /api/v1/rules/dsl/validate            validate DSL text, return compiled JSON
  POST   /api/v1/rules/dsl/publish             validate + publish (bumps version)
  GET    /api/v1/rules/dsl                     list rules (optional ?status=)
  GET    /api/v1/rules/dsl/schema              schema descriptor for UI
  GET    /api/v1/rules/dsl/{key}               get latest rule by key
  DELETE /api/v1/rules/dsl/{key}               retire all versions for key
  POST   /api/v1/rules/dsl/{key}/evaluate      evaluate rule against input_doc
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/rules/dsl",
    tags=["Dynamic Rule DSL"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.dynamic_rule_dsl_engine import DynamicRuleDSLEngine
        _engine = DynamicRuleDSLEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ValidateDSLIn(BaseModel):
    dsl_text: str = Field(..., description="Raw YAML or JSON rule text")
    dsl_format: str = Field("yaml", description="'yaml' or 'json'")


class PublishDSLIn(BaseModel):
    key: str = Field(..., description="Stable rule key (matched against DSL `key`)")
    dsl_text: str = Field(..., description="Raw YAML or JSON rule text")
    dsl_format: str = Field("yaml", description="'yaml' or 'json'")
    severity: Optional[str] = Field(
        None,
        description="Override severity; defaults to the DSL value.",
    )
    authored_by: str = Field("", description="User/service that authored the rule")


class EvaluateDSLIn(BaseModel):
    input_doc: Dict[str, Any] = Field(
        default_factory=dict,
        description="Input document to evaluate against the rule's `when` block.",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/validate", summary="Validate DSL text")
def validate_dsl(req: ValidateDSLIn) -> Dict[str, Any]:
    """Parse + validate DSL text; return compiled JSON or error list."""
    try:
        return _get_engine().validate_dsl(req.dsl_text, dsl_format=req.dsl_format)
    except Exception as exc:  # pragma: no cover - validator returns ok=false on bad input
        _logger.exception("DSL validate failure: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/publish", summary="Publish DSL rule (bumps version)")
def publish_rule(
    req: PublishDSLIn,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Validate and publish. A new version is allocated for (org_id, key)."""
    try:
        return _get_engine().publish_rule(
            org_id,
            req.key,
            req.dsl_text,
            dsl_format=req.dsl_format,
            authored_by=req.authored_by,
            severity=req.severity,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Publish DSL rule failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("", summary="List DSL rules")
def list_rules(
    org_id: str = Query("default", description="Organisation ID"),
    status: Optional[str] = Query(None, description="draft|published|retired"),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_rules(org_id, status=status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/schema", summary="DSL schema descriptor (for UI autocomplete)")
def get_schema() -> Dict[str, Any]:
    return _get_engine().get_schema()


@router.get("/stats", summary="DSL rule stats per org")
def get_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    return _get_engine().stats(org_id)


@router.get("/{key}", summary="Get DSL rule by key (latest version)")
def get_rule(
    key: str,
    org_id: str = Query("default", description="Organisation ID"),
    version: Optional[int] = Query(None, description="Specific version"),
) -> Dict[str, Any]:
    rule = _get_engine().get_rule(org_id, key, version=version)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {key!r} not found.")
    return rule


@router.delete("/{key}", summary="Retire DSL rule (all versions)")
def retire_rule(
    key: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    try:
        return _get_engine().retire_rule(org_id, key)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{key}/evaluate", summary="Evaluate rule against input document")
def evaluate_rule(
    key: str,
    req: EvaluateDSLIn,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    try:
        return _get_engine().evaluate_rule(org_id, key, req.input_doc)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Evaluate DSL rule failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
