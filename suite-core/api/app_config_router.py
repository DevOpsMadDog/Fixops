"""
app_config_router.py — APP_ID Configuration API Router
FixOps Enterprise Security Platform

Provides the /api/v1/apps REST API for managing ALdeci application
configurations. All endpoints trace findings, policies, and evidence
back through the App → Component → Feature hierarchy.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.app_config import (
    AppConfig,
    AppConfigManager,
    get_default_manager,
)
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/apps", tags=["APP_ID Configuration"])

# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def get_manager() -> AppConfigManager:
    """FastAPI dependency: returns the shared AppConfigManager instance."""
    return get_default_manager()


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class RegisterAppRequest(BaseModel):
    """Payload for registering an app via raw aldeci.yaml text or a dict."""

    yaml_content: Optional[str] = Field(
        None, description="Raw aldeci.yaml content as a string"
    )
    config: Optional[Dict[str, Any]] = Field(
        None, description="Parsed config dict (alternative to yaml_content)"
    )


class UpdateAppRequest(BaseModel):
    """Partial update payload — any top-level keys will be merged."""

    updates: Dict[str, Any] = Field(..., description="Keys to update in the config")


class AppSummary(BaseModel):
    """Lightweight app listing entry."""

    app_id: str
    name: str
    org_id: Optional[str]
    criticality: str
    data_classification: str
    compliance: List[str]
    component_count: int
    created_at: Optional[str]
    updated_at: Optional[str]


class SLAResponse(BaseModel):
    app_id: str
    component: Optional[str]
    severity: str
    sla_string: str
    deadline_utc: str


class ClassificationValidationResponse(BaseModel):
    app_id: str
    valid: bool
    data_classification: str
    policy_classification_level: str
    issues: List[str]


class HealthResponse(BaseModel):
    status: str
    db_path: str
    apps: Optional[int] = None
    components: Optional[int] = None
    detail: Optional[str] = None


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _app_to_summary(config: AppConfig) -> AppSummary:
    return AppSummary(
        app_id=config.app_id,
        name=config.name,
        org_id=config.org_id,
        criticality=config.criticality.value,
        data_classification=config.data_classification.value,
        compliance=config.compliance,
        component_count=len(config.components),
        created_at=config.created_at.isoformat() if config.created_at else None,
        updated_at=config.updated_at.isoformat() if config.updated_at else None,
    )


def _config_to_dict(config: AppConfig) -> Dict[str, Any]:
    """Serialize AppConfig to a JSON-safe dict for API responses."""
    return {
        "app_id": config.app_id,
        "name": config.name,
        "org_id": config.org_id,
        "description": config.description,
        "criticality": config.criticality.value,
        "data_classification": config.data_classification.value,
        "compliance": config.compliance,
        "components": [
            {
                "name": c.name,
                "language": c.language,
                "owner": c.owner,
                "repo_url": c.repo_url,
                "sla": {
                    "critical": c.sla.critical,
                    "high": c.sla.high,
                    "medium": c.sla.medium,
                    "low": c.sla.low,
                },
                "tags": c.tags,
            }
            for c in config.components
        ],
        "scanners": config.scanners.all_scanners(),
        "policies": {
            "block_on_critical": config.policies.block_on_critical,
            "require_mpte_for": [r.value for r in config.policies.require_mpte_for],
            "auto_fix": config.policies.auto_fix,
            "evidence_retention": config.policies.evidence_retention,
            "classification_level": config.policies.classification_level.value,
            "air_gapped": config.policies.air_gapped,
            "itar_controlled": config.policies.itar_controlled,
        },
        "created_at": config.created_at.isoformat() if config.created_at else None,
        "updated_at": config.updated_at.isoformat() if config.updated_at else None,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/health", response_model=HealthResponse, summary="Health check")
def health_check(mgr: AppConfigManager = Depends(get_manager)) -> HealthResponse:
    """Return API and database health status."""
    result = mgr.health_check()
    return HealthResponse(**result)


@router.post(
    "/",
    response_model=Dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Register a new app from aldeci.yaml",
)
def register_app(
    request: RegisterAppRequest,
    mgr: AppConfigManager = Depends(get_manager),
) -> Dict[str, Any]:
    """Register a new application from an aldeci.yaml payload.

    Accepts either ``yaml_content`` (raw YAML string) or ``config`` (parsed dict).
    """
    if not request.yaml_content and not request.config:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide either yaml_content or config in the request body",
        )
    try:
        if request.yaml_content:
            config = mgr.load_from_string(request.yaml_content)
        else:
            config = mgr.load_from_dict(request.config)  # type: ignore[arg-type]
        registered = mgr.register_app(config)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Unexpected error registering app")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=type(exc).__name__)

    return {"message": "App registered successfully", "app": _config_to_dict(registered)}


@router.get(
    "/",
    response_model=List[AppSummary],
    summary="List all apps",
)
def list_apps(
    org_id: Optional[str] = Query(None, description="Filter by organisation ID"),
    mgr: AppConfigManager = Depends(get_manager),
) -> List[AppSummary]:
    """Return a list of all registered, non-deleted apps.

    Optionally filter by ``org_id``.
    """
    configs = mgr.list_apps(org_id=org_id)
    return [_app_to_summary(c) for c in configs]


@router.get(
    "/{app_id}",
    response_model=Dict[str, Any],
    summary="Get app details with components",
)
def get_app(
    app_id: str,
    mgr: AppConfigManager = Depends(get_manager),
) -> Dict[str, Any]:
    """Retrieve the full configuration for a given ``app_id``."""
    config = mgr.get_app(app_id)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"App '{app_id}' not found")
    return _config_to_dict(config)


@router.put(
    "/{app_id}",
    response_model=Dict[str, Any],
    summary="Update app config",
)
def update_app(
    app_id: str,
    request: UpdateAppRequest,
    mgr: AppConfigManager = Depends(get_manager),
) -> Dict[str, Any]:
    """Apply a partial update to an existing app config.

    Top-level keys in ``updates`` are merged into the current config.
    Nested dicts (e.g. ``policies``) are shallow-merged.
    """
    try:
        updated = mgr.update_app(app_id, request.updates)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Unexpected error updating app '%s'", app_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=type(exc).__name__)
    return {"message": "App updated successfully", "app": _config_to_dict(updated)}


@router.delete(
    "/{app_id}",
    status_code=status.HTTP_200_OK,
    summary="Soft delete an app",
)
def delete_app(
    app_id: str,
    mgr: AppConfigManager = Depends(get_manager),
) -> Dict[str, str]:
    """Soft-delete an application by setting its ``deleted_at`` timestamp.

    The config is retained in the database for audit and evidence retention purposes.
    """
    deleted = mgr.delete_app(app_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"App '{app_id}' not found or already deleted",
        )
    return {"message": f"App '{app_id}' soft-deleted successfully"}


@router.get(
    "/{app_id}/components",
    response_model=List[Dict[str, Any]],
    summary="List components for an app",
)
def list_components(
    app_id: str,
    mgr: AppConfigManager = Depends(get_manager),
) -> List[Dict[str, Any]]:
    """Return all component configurations for the given ``app_id``."""
    config = mgr.get_app(app_id)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"App '{app_id}' not found")
    return [
        {
            "name": c.name,
            "language": c.language,
            "owner": c.owner,
            "repo_url": c.repo_url,
            "sla": {
                "critical": c.sla.critical,
                "high": c.sla.high,
                "medium": c.sla.medium,
                "low": c.sla.low,
            },
            "tags": c.tags,
        }
        for c in config.components
    ]


@router.get(
    "/{app_id}/components/{name}",
    response_model=Dict[str, Any],
    summary="Get a specific component",
)
def get_component(
    app_id: str,
    name: str,
    mgr: AppConfigManager = Depends(get_manager),
) -> Dict[str, Any]:
    """Retrieve configuration for a single named component."""
    comp = mgr.get_component(app_id, name)
    if comp is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Component '{name}' not found in app '{app_id}'",
        )
    return {
        "app_id": app_id,
        "name": comp.name,
        "language": comp.language,
        "owner": comp.owner,
        "repo_url": comp.repo_url,
        "sla": {
            "critical": comp.sla.critical,
            "high": comp.sla.high,
            "medium": comp.sla.medium,
            "low": comp.sla.low,
        },
        "tags": comp.tags,
    }


@router.get(
    "/{app_id}/sla/{severity}",
    response_model=SLAResponse,
    summary="Get SLA deadline for a severity",
)
def get_sla(
    app_id: str,
    severity: str,
    component: Optional[str] = Query(None, description="Component name for component-specific SLA"),
    mgr: AppConfigManager = Depends(get_manager),
) -> SLAResponse:
    """Return the SLA configuration and computed deadline UTC timestamp for the given severity.

    Optionally scoped to a specific ``component``.
    """
    try:
        result = mgr.get_sla(app_id, severity, component_name=component)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=type(exc).__name__)
    return SLAResponse(**result)


@router.get(
    "/{app_id}/scanners",
    response_model=Dict[str, Any],
    summary="Get scanner assignments",
)
def get_scanners(
    app_id: str,
    mgr: AppConfigManager = Depends(get_manager),
) -> Dict[str, Any]:
    """Return all scanner category assignments for the given app."""
    scanners = mgr.get_scanners(app_id)
    if scanners is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"App '{app_id}' not found")
    return {"app_id": app_id, "scanners": scanners.all_scanners()}


@router.get(
    "/{app_id}/policies",
    response_model=Dict[str, Any],
    summary="Get policy config",
)
def get_policies(
    app_id: str,
    mgr: AppConfigManager = Depends(get_manager),
) -> Dict[str, Any]:
    """Return the security and compliance policies for the given app."""
    policies = mgr.get_policies(app_id)
    if policies is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"App '{app_id}' not found")
    return {
        "app_id": app_id,
        "policies": {
            "block_on_critical": policies.block_on_critical,
            "require_mpte_for": [r.value for r in policies.require_mpte_for],
            "auto_fix": policies.auto_fix,
            "evidence_retention": policies.evidence_retention,
            "classification_level": policies.classification_level.value,
            "air_gapped": policies.air_gapped,
            "itar_controlled": policies.itar_controlled,
        },
    }


@router.post(
    "/{app_id}/validate",
    response_model=ClassificationValidationResponse,
    summary="Validate classification consistency",
)
def validate_classification(
    app_id: str,
    mgr: AppConfigManager = Depends(get_manager),
) -> ClassificationValidationResponse:
    """Validate that policy classification level is appropriate for data classification.

    Checks include:
    - Policy level must meet minimum required by data type (PHI/PCI/PII → CUI minimum)
    - TOP_SECRET/SCI data cannot have UNCLASSIFIED policies
    - ITAR in compliance list must have itar_controlled = true
    - Air-gapped environments should not reference cloud-only scanners
    """
    try:
        result = mgr.validate_classification(app_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=type(exc).__name__)
    return ClassificationValidationResponse(**result)


@router.get(
    "/{app_id}/export",
    response_class=PlainTextResponse,
    summary="Export config as aldeci.yaml",
)
def export_config(
    app_id: str,
    mgr: AppConfigManager = Depends(get_manager),
) -> PlainTextResponse:
    """Export the full app configuration as a downloadable ``aldeci.yaml`` string.

    The response is plain text with content-type ``text/yaml``.
    """
    try:
        yaml_str = mgr.export_config(app_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=type(exc).__name__)
    return PlainTextResponse(
        content=yaml_str,
        media_type="text/yaml",
        headers={"Content-Disposition": f'attachment; filename="aldeci-{app_id}.yaml"'},
    )
