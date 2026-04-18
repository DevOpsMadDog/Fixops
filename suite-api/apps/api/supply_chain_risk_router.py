"""Supply Chain Risk API Router — ALDECI.

Endpoints (all under /api/v1/supply-chain):

  Suppliers:
    GET  /suppliers              — list suppliers (filter: risk_tier)
    POST /suppliers              — register a supplier

  Components:
    GET  /components             — list components (filter: supplier_id, is_eol)
    POST /components             — add a component

  Risks:
    GET  /risks                  — list supply-chain risks (filter: status)
    POST /risks                  — register a risk

  SBOM:
    POST /sbom/import            — import an SBOM document

  Stats:
    GET  /stats                  — aggregated supply-chain statistics

Auth: Depends(_verify_api_key) injected at app.include_router() level.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.supply_chain_risk_engine import SupplyChainRiskEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/supply-chain", tags=["supply-chain"])

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = SupplyChainRiskEngine()
    return _engine

# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class SupplierIn(BaseModel):
    name: str
    category: str = "software"
    country: str = ""
    risk_tier: str = "medium"
    compliance_score: float = 0.0
    last_assessed: Optional[str] = None
    contacts: List[str] = Field(default_factory=list)


class ComponentIn(BaseModel):
    supplier_id: str
    name: str
    version: str = ""
    component_type: str = "library"
    license: str = ""
    cve_count: int = 0
    is_eol: bool = False
    purl: str = ""


class RiskIn(BaseModel):
    supplier_id: str = ""
    risk_type: str = "single_source"
    severity: str = "medium"
    description: str = ""
    status: str = "open"


class SBOMImportIn(BaseModel):
    components: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Suppliers
# ---------------------------------------------------------------------------


@router.get("/suppliers")
def list_suppliers(
    org_id: str = Query("default"),
    risk_tier: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List registered suppliers for an org, optionally filtered by risk tier."""
    try:
        return _get_engine().list_suppliers(org_id, risk_tier=risk_tier)
    except Exception as exc:
        logger.exception("list_suppliers failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/suppliers", status_code=201)
def add_supplier(
    payload: SupplierIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Register a new supplier in the supply-chain registry."""
    try:
        return _get_engine().add_supplier(org_id, payload.model_dump())
    except Exception as exc:
        logger.exception("add_supplier failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------


@router.get("/components")
def list_components(
    org_id: str = Query("default"),
    supplier_id: Optional[str] = Query(None),
    is_eol: Optional[bool] = Query(None),
) -> List[Dict[str, Any]]:
    """List software/hardware components, optionally filtered by supplier or EOL status."""
    try:
        return _get_engine().list_components(org_id, supplier_id=supplier_id, is_eol=is_eol)
    except Exception as exc:
        logger.exception("list_components failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/components", status_code=201)
def add_component(
    payload: ComponentIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Add a software or hardware component for a supplier."""
    try:
        data = payload.model_dump()
        supplier_id = data.pop("supplier_id")
        return _get_engine().add_component(org_id, supplier_id, data)
    except Exception as exc:
        logger.exception("add_component failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Risks
# ---------------------------------------------------------------------------


@router.get("/risks")
def list_risks(
    org_id: str = Query("default"),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List supply-chain risks, optionally filtered by status."""
    try:
        return _get_engine().list_risks(org_id, status=status)
    except Exception as exc:
        logger.exception("list_risks failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/risks", status_code=201)
def add_risk(
    payload: RiskIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Register a new supply-chain risk."""
    try:
        return _get_engine().add_risk(org_id, payload.model_dump())
    except Exception as exc:
        logger.exception("add_risk failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# SBOM Import
# ---------------------------------------------------------------------------


@router.post("/sbom/import", status_code=201)
def import_sbom(
    payload: SBOMImportIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Import an SBOM document (CycloneDX-style component list) and store entries."""
    try:
        return _get_engine().import_sbom(org_id, payload.model_dump())
    except Exception as exc:
        logger.exception("import_sbom failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_stats(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return aggregated supply-chain statistics for an org."""
    try:
        return _get_engine().get_supply_chain_stats(org_id)
    except Exception as exc:
        logger.exception("get_stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
