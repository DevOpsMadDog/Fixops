"""Quantum-Safe Crypto Router — ALDECI.

Cryptographic asset inventory, quantum vulnerability tracking, and PQC
migration management.

Prefix: /api/v1/quantum-crypto
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/quantum-crypto/assets                         register_asset
  GET    /api/v1/quantum-crypto/assets                         list_assets
  GET    /api/v1/quantum-crypto/assets/{id}                    get_asset
  PUT    /api/v1/quantum-crypto/assets/{id}/migration-status   update_migration_status
  POST   /api/v1/quantum-crypto/assessments                    create_assessment
  PUT    /api/v1/quantum-crypto/assessments/{id}/complete      complete_assessment
  GET    /api/v1/quantum-crypto/assessments                    list_assessments
  POST   /api/v1/quantum-crypto/migrations                     create_migration
  GET    /api/v1/quantum-crypto/migrations                     list_migrations
  GET    /api/v1/quantum-crypto/stats                          get_quantum_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/quantum-crypto",
    tags=["Quantum-Safe Crypto"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.quantum_safe_crypto_engine import QuantumSafeCryptoEngine
        _engine = QuantumSafeCryptoEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterAssetRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    asset_name: str = Field(..., description="Name of the cryptographic asset")
    asset_type: str = Field(
        ...,
        description="Type: tls_certificate, vpn, signing_key, encryption_key, "
                    "code_signing, database_encryption, api_key, ssh_key"
    )
    current_algorithm: str = Field(
        ...,
        description="Current algorithm: rsa, ecdsa, dh, aes, 3des, sha1, sha256, sha384, sha512"
    )
    key_size: int = Field(default=0, ge=0, description="Key size in bits")
    risk_level: str = Field(default="low", description="Risk level: critical, high, medium, low")
    migration_status: str = Field(
        default="not_started",
        description="Migration status: not_started, planned, in_progress, completed, exempt"
    )
    discovered_at: Optional[str] = Field(default=None, description="ISO 8601 discovery timestamp")


class UpdateMigrationStatusRequest(BaseModel):
    org_id: str = Field(default="default")
    migration_status: str = Field(
        ...,
        description="New status: not_started, planned, in_progress, completed, exempt"
    )
    migrated_at: Optional[str] = Field(default=None, description="ISO 8601 migration timestamp")


class CreateAssessmentRequest(BaseModel):
    org_id: str = Field(default="default")
    assessment_name: str = Field(..., description="Assessment name")
    scope: str = Field(default="", description="Assessment scope description")


class CompleteAssessmentRequest(BaseModel):
    org_id: str = Field(default="default")
    total_assets: int = Field(..., ge=0)
    vulnerable_assets: int = Field(..., ge=0)
    migrated_assets: int = Field(..., ge=0)


class CreateMigrationRequest(BaseModel):
    org_id: str = Field(default="default")
    asset_id: str = Field(..., description="Asset to migrate")
    from_algorithm: str = Field(default="", description="Source algorithm")
    to_algorithm: str = Field(default="", description="Target PQC algorithm")
    priority: str = Field(
        default="medium",
        description="Priority: immediate, high, medium, low, scheduled"
    )
    planned_date: Optional[str] = Field(default=None, description="ISO 8601 planned date")
    migrated_by: str = Field(default="", description="Operator or system performing migration")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/assets", dependencies=[Depends(api_key_auth)])
def register_asset(req: RegisterAssetRequest) -> Dict[str, Any]:
    """Register a cryptographic asset for quantum vulnerability tracking."""
    try:
        return _get_engine().register_asset(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("register_asset failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/assets", dependencies=[Depends(api_key_auth)])
def list_assets(
    org_id: str = Query(default="default"),
    asset_type: Optional[str] = Query(default=None),
    quantum_vulnerable: Optional[bool] = Query(default=None),
    migration_status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List cryptographic assets, optionally filtered."""
    try:
        return _get_engine().list_assets(
            org_id,
            asset_type=asset_type,
            quantum_vulnerable=quantum_vulnerable,
            migration_status=migration_status,
        )
    except Exception as exc:
        _logger.exception("list_assets failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/assets/{asset_id}", dependencies=[Depends(api_key_auth)])
def get_asset(
    asset_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a single cryptographic asset by ID."""
    try:
        result = _get_engine().get_asset(org_id, asset_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("get_asset failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/assets/{asset_id}/migration-status", dependencies=[Depends(api_key_auth)])
def update_migration_status(
    asset_id: str,
    req: UpdateMigrationStatusRequest,
) -> Dict[str, Any]:
    """Update the migration status of a cryptographic asset."""
    try:
        result = _get_engine().update_migration_status(
            req.org_id, asset_id, req.migration_status, req.migrated_at
        )
        if result is None:
            raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("update_migration_status failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/assessments", dependencies=[Depends(api_key_auth)])
def create_assessment(req: CreateAssessmentRequest) -> Dict[str, Any]:
    """Create a quantum readiness assessment."""
    try:
        return _get_engine().create_assessment(req.org_id, req.model_dump(exclude={"org_id"}))
    except Exception as exc:
        _logger.exception("create_assessment failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/assessments/{assessment_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_assessment(
    assessment_id: str,
    req: CompleteAssessmentRequest,
) -> Dict[str, Any]:
    """Complete an assessment and compute the quantum readiness score."""
    try:
        result = _get_engine().complete_assessment(
            req.org_id, assessment_id,
            req.total_assets, req.vulnerable_assets, req.migrated_assets
        )
        if not result:
            raise HTTPException(status_code=404, detail=f"Assessment {assessment_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("complete_assessment failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/assessments", dependencies=[Depends(api_key_auth)])
def list_assessments(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List quantum readiness assessments."""
    try:
        return _get_engine().list_assessments(org_id, status=status)
    except Exception as exc:
        _logger.exception("list_assessments failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/migrations", dependencies=[Depends(api_key_auth)])
def create_migration(req: CreateMigrationRequest) -> Dict[str, Any]:
    """Create a PQC migration plan for an asset."""
    try:
        return _get_engine().create_migration(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("create_migration failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/migrations", dependencies=[Depends(api_key_auth)])
def list_migrations(
    org_id: str = Query(default="default"),
    asset_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    priority: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List PQC migration plans, optionally filtered."""
    try:
        return _get_engine().list_migrations(
            org_id, asset_id=asset_id, status=status, priority=priority
        )
    except Exception as exc:
        _logger.exception("list_migrations failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_quantum_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregate quantum crypto statistics for the org."""
    try:
        return _get_engine().get_quantum_stats(org_id)
    except Exception as exc:
        _logger.exception("get_quantum_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
