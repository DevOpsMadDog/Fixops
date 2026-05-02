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

from core.supply_chain_risk_engine import SupplyChainRiskEngine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

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
    """List software/hardware components, optionally filtered by supplier or EOL status.

    Falls back to the SBOM/brain-synced SupplyChainEngine when the risk engine
    has no data for this org (e.g. after a brain sync but before manual entry).
    """
    try:
        results = _get_engine().list_components(org_id, supplier_id=supplier_id, is_eol=is_eol)
        if results:
            return results
        # Fall back to the brain-synced SBOM engine
        try:
            from core.supply_chain_security import SupplyChainEngine as _SBOMEngine
            sbom_engine = _SBOMEngine()
            sbom_components = sbom_engine.list_components(org_id=org_id, limit=1000)
            # Normalize to the risk-router shape expected by the dashboard
            normalized = []
            for c in sbom_components:
                normalized.append({
                    "id": c.get("id"),
                    "org_id": c.get("org_id", org_id),
                    "name": c.get("name", ""),
                    "version": c.get("version", "unknown"),
                    "ecosystem": c.get("ecosystem", "unknown"),
                    "purl": c.get("purl"),
                    "license_id": c.get("license_id", "UNKNOWN"),
                    "license_risk": c.get("license_risk", "unknown"),
                    "description": c.get("description"),
                    "supplier_id": None,
                    "component_type": "library",
                    "is_eol": False,
                    "risk_tier": "low",
                    "cve_count": 0,
                    "risk_score": (c.get("risk_score") or {}).get("overall_score", 0),
                    "source": "brain-sync",
                    "created_at": c.get("created_at"),
                })
            return normalized
        except Exception as _fb_exc:
            logger.debug("supply_chain_security fallback failed: %s", _fb_exc)
        return results
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
    """Return aggregated supply-chain statistics for an org.

    Falls back to the SBOM/brain-synced SupplyChainEngine when the risk engine
    has no suppliers for this org.
    """
    try:
        stats = _get_engine().get_supply_chain_stats(org_id)
        # If risk engine has no data, compute stats from the brain-synced SBOM engine
        if stats.get("total_suppliers", 0) == 0 and stats.get("total_components", 0) == 0:
            try:
                from core.supply_chain_security import SupplyChainEngine as _SBOMEngine
                sbom_engine = _SBOMEngine()
                comps = sbom_engine.list_components(org_id=org_id, limit=5000)
                if comps:
                    ecosystems = {c.get("ecosystem", "unknown") for c in comps}
                    critical_count = sum(
                        1 for c in comps
                        if (c.get("risk_score") or {}).get("risk_level") in ("critical", "high")
                    )
                    stats = {
                        "total_suppliers": len(ecosystems),
                        "critical_tier": critical_count,
                        "total_components": len(comps),
                        "eol_components": 0,
                        "open_risks": critical_count,
                        "avg_compliance_score": 0.0,
                        "source": "brain-sync",
                    }
            except Exception as _fb_exc:
                logger.debug("supply_chain_security stats fallback failed: %s", _fb_exc)
        return stats
    except Exception as exc:
        logger.exception("get_stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
