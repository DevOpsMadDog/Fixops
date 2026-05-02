"""Data Security / DLP Router — Classification, Scanning, Masking, Residency, Breach Assessment.

Endpoints expose the DataSecurityEngine from suite-core/core/data_security.py.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/data", tags=["Data Security"])

# ---------------------------------------------------------------------------
# Lazy engine import (avoids circular import at startup)
# ---------------------------------------------------------------------------

def _get_engine():
    try:
        from core.data_security import get_engine
        return get_engine()
    except ImportError as exc:
        _logger.error("data_security engine unavailable: %s", exc)
        raise HTTPException(status_code=503, detail="Data Security engine not available")


# ---------------------------------------------------------------------------
# Request / Response models (router-layer — thin wrappers for OpenAPI docs)
# ---------------------------------------------------------------------------

class ScanPayload(BaseModel):
    """POST /scan — scan content or a virtual source for sensitive data."""
    content: Optional[str] = None
    source_type: str = "file"
    source_path: Optional[str] = None
    column_names: Optional[List[str]] = None
    deep_scan: bool = False


class MaskPayload(BaseModel):
    """POST /mask — mask sensitive data in the supplied text."""
    content: str
    categories: Optional[List[str]] = None  # DataCategory values
    tokenize: bool = False


class BreachPayload(BaseModel):
    """POST /breach-impact — assess regulatory impact of a breach."""
    breach_id: Optional[str] = None
    affected_systems: List[str] = []
    estimated_records: int
    data_categories: List[str]  # DataCategory values
    storage_regions: Optional[List[str]] = None
    discovery_date: Optional[str] = None


class ResidencyPayload(BaseModel):
    """POST /residency/register — register a dataset for residency tracking."""
    dataset_name: str
    data_categories: List[str]
    storage_region: str
    approved_regions: Optional[List[str]] = None


class FlowPayload(BaseModel):
    """POST /flows/register — register a new data flow."""
    source: Dict[str, Any]
    processors: List[Dict[str, Any]] = []
    destination: Dict[str, Any]
    data_categories: List[str]


# ---------------------------------------------------------------------------
# Helper — convert raw dicts to engine model objects
# ---------------------------------------------------------------------------

def _make_node(d: Dict[str, Any]):
    from core.data_security import DataFlowNode, Region, StorageType
    return DataFlowNode(
        node_id=d.get("node_id", ""),
        name=d.get("name", "unknown"),
        node_type=d.get("node_type", "source"),
        storage_type=StorageType(d["storage_type"]) if d.get("storage_type") else None,
        region=Region(d.get("region", "unknown")),
        encrypted=d.get("encrypted", False),
        external=d.get("external", False),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/classifications",
    summary="Data classification inventory",
    response_model=Dict[str, Any],
)
async def get_classifications():
    """Return the full catalog of supported data classification types and their patterns."""
    from core.data_security import _PATTERNS

    catalog: List[Dict[str, Any]] = []
    for data_type, (pattern, category, sensitivity, confidence) in _PATTERNS.items():
        catalog.append({
            "data_type": data_type,
            "category": category.value,
            "sensitivity": sensitivity.value,
            "confidence_score": confidence,
            "pattern_hint": pattern.pattern[:60] + ("..." if len(pattern.pattern) > 60 else ""),
        })

    by_category: Dict[str, List[str]] = {}
    for entry in catalog:
        cat = entry["category"]
        by_category.setdefault(cat, []).append(entry["data_type"])

    return {
        "total_types": len(catalog),
        "categories": by_category,
        "catalog": catalog,
    }


@router.post(
    "/scan",
    summary="Scan for sensitive data",
    response_model=Dict[str, Any],
)
async def scan_for_sensitive_data(payload: ScanPayload):
    """Scan text content or a virtual source for sensitive data using regex, column heuristics, and entropy detection."""
    engine = _get_engine()
    try:
        from core.data_security import ScanRequest, StorageType
        request = ScanRequest(
            content=payload.content,
            source_type=StorageType(payload.source_type),
            source_path=payload.source_path,
            column_names=payload.column_names,
            deep_scan=payload.deep_scan,
        )
        result = engine.scan(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return {
        "scan_id": result.scan_id,
        "source_type": result.source_type.value,
        "source_path": result.source_path,
        "total_sensitive_fields": result.total_sensitive_fields,
        "matches": [
            {
                "data_type": m.data_type,
                "category": m.category.value,
                "sensitivity": m.sensitivity.value,
                "value_masked": m.value_masked,
                "confidence": m.confidence,
                "position": [m.position_start, m.position_end],
            }
            for m in result.matches
        ],
        "column_hits": result.column_hits,
        "entropy_hits": result.entropy_hits,
        "scanned_at": result.scanned_at.isoformat(),
    }


@router.get(
    "/flows",
    summary="Data flow map",
    response_model=Dict[str, Any],
)
async def get_data_flows(risk_filter: Optional[str] = None):
    """Return the registered data flow map. Optionally filter by minimum risk level (low|medium|high|critical)."""
    engine = _get_engine()
    from core.data_security import DataFlowRisk

    if risk_filter:
        try:
            min_risk = DataFlowRisk(risk_filter.lower())
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid risk_filter. Use: {[r.value for r in DataFlowRisk]}")
        flows = engine.flow_mapper.get_risky_flows(min_risk)
    else:
        flows = engine.get_flows()

    serialized = []
    for f in flows:
        serialized.append({
            "flow_id": f.flow_id,
            "source": f.source.model_dump(),
            "processors": [p.model_dump() for p in f.processors],
            "destination": f.destination.model_dump(),
            "data_categories": [c.value for c in f.data_categories],
            "risk_level": f.risk_level.value,
            "risk_reasons": f.risk_reasons,
            "created_at": f.created_at.isoformat(),
        })

    return {
        "total_flows": len(serialized),
        "risk_filter": risk_filter,
        "flows": serialized,
    }


@router.post(
    "/flows/register",
    summary="Register a data flow",
    response_model=Dict[str, Any],
    status_code=201,
)
async def register_data_flow(payload: FlowPayload):
    """Register a new data flow for tracking and risk assessment."""
    engine = _get_engine()
    try:
        from core.data_security import DataCategory
        source_node = _make_node(payload.source)
        dest_node = _make_node(payload.destination)
        proc_nodes = [_make_node(p) for p in payload.processors]
        cats = [DataCategory(c) for c in payload.data_categories]
        flow = engine.register_flow(source_node, proc_nodes, dest_node, cats)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return {
        "flow_id": flow.flow_id,
        "risk_level": flow.risk_level.value,
        "risk_reasons": flow.risk_reasons,
        "data_categories": [c.value for c in flow.data_categories],
        "created_at": flow.created_at.isoformat(),
    }


@router.get(
    "/policies",
    summary="DLP policies",
    response_model=Dict[str, Any],
)
async def get_dlp_policies():
    """Return all active DLP policies."""
    engine = _get_engine()
    policies = engine.get_policies()

    return {
        "total_policies": len(policies),
        "policies": [
            {
                "policy_id": p.policy_id,
                "name": p.name,
                "description": p.description,
                "data_categories": [c.value for c in p.data_categories],
                "action": p.action.value,
                "conditions": p.conditions,
                "enabled": p.enabled,
                "severity": p.severity,
            }
            for p in policies
        ],
    }


@router.post(
    "/policies/evaluate",
    summary="Evaluate DLP policies against content",
    response_model=Dict[str, Any],
)
async def evaluate_policies(payload: ScanPayload, destination_type: Optional[str] = None, external_destination: bool = False, record_count: int = 0):
    """Evaluate all applicable DLP policies against the supplied content."""
    engine = _get_engine()
    if not payload.content:
        raise HTTPException(status_code=422, detail="content is required for policy evaluation")

    ctx: Dict[str, Any] = {
        "destination_type": destination_type,
        "external_destination": external_destination,
        "record_count": record_count,
    }
    result = engine.evaluate_policy(payload.content, ctx)

    return {
        "content_id": result.content_id,
        "blocked": result.blocked,
        "actions": [a.value for a in result.actions],
        "alerts": result.alerts,
        "triggered_policies": [
            {
                "policy_id": p.policy_id,
                "name": p.name,
                "action": p.action.value,
                "severity": p.severity,
            }
            for p in result.triggered_policies
        ],
        "evaluated_at": result.evaluated_at.isoformat(),
    }


@router.post(
    "/mask",
    summary="Mask sensitive data",
    response_model=Dict[str, Any],
)
async def mask_sensitive_data(payload: MaskPayload):
    """Mask or tokenize sensitive data in the supplied text. Returns masked content and optional token map."""
    engine = _get_engine()
    try:
        from core.data_security import DataCategory, MaskRequest
        cats = [DataCategory(c) for c in payload.categories] if payload.categories else None
        request = MaskRequest(
            content=payload.content,
            categories=cats,
            tokenize=payload.tokenize,
        )
        result = engine.mask(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return {
        "original_length": result.original_length,
        "masked_content": result.masked_content,
        "fields_masked": result.fields_masked,
        "categories_found": [c.value for c in result.categories_found],
        "tokens": result.tokens if payload.tokenize else {},
    }


@router.get(
    "/residency",
    summary="Data residency status",
    response_model=Dict[str, Any],
)
async def get_residency_status(violations_only: bool = False):
    """Return data residency records. Set violations_only=true to see only non-compliant datasets."""
    engine = _get_engine()

    if violations_only:
        records = engine.residency_tracker.get_violations()
    else:
        records = engine.get_residency_status()

    return {
        "total_datasets": len(records),
        "violations_only": violations_only,
        "compliant_count": sum(1 for r in records if r.compliant),
        "violation_count": sum(1 for r in records if not r.compliant),
        "records": [
            {
                "record_id": r.record_id,
                "dataset_name": r.dataset_name,
                "data_categories": [c.value for c in r.data_categories],
                "storage_region": r.storage_region.value,
                "approved_regions": [reg.value for reg in r.approved_regions],
                "compliant": r.compliant,
                "violations": r.violations,
                "regulations_at_risk": [reg.value for reg in r.regulations_at_risk],
                "checked_at": r.checked_at.isoformat(),
            }
            for r in records
        ],
    }


@router.post(
    "/residency/register",
    summary="Register dataset for residency tracking",
    response_model=Dict[str, Any],
    status_code=201,
)
async def register_residency(payload: ResidencyPayload):
    """Register a dataset and immediately evaluate its geographic compliance."""
    engine = _get_engine()
    try:
        from core.data_security import DataCategory, Region
        cats = [DataCategory(c) for c in payload.data_categories]
        region = Region(payload.storage_region)
        approved = [Region(r) for r in payload.approved_regions] if payload.approved_regions else None
        record = engine.register_dataset(payload.dataset_name, cats, region, approved)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return {
        "record_id": record.record_id,
        "dataset_name": record.dataset_name,
        "compliant": record.compliant,
        "violations": record.violations,
        "regulations_at_risk": [r.value for r in record.regulations_at_risk],
        "checked_at": record.checked_at.isoformat(),
    }


@router.post(
    "/breach-impact",
    summary="Breach impact assessment",
    response_model=Dict[str, Any],
)
async def assess_breach_impact(payload: BreachPayload):
    """Assess the regulatory and financial impact of a data breach."""
    engine = _get_engine()
    try:
        import uuid as _uuid
        from datetime import datetime

        from core.data_security import BreachImpactRequest, DataCategory, Region

        cats = [DataCategory(c) for c in payload.data_categories]
        regions = [Region(r) for r in (payload.storage_regions or [])]
        discovery = None
        if payload.discovery_date:
            discovery = datetime.fromisoformat(payload.discovery_date.replace("Z", "+00:00"))

        request = BreachImpactRequest(
            breach_id=payload.breach_id or str(_uuid.uuid4()),
            affected_systems=payload.affected_systems,
            estimated_records=payload.estimated_records,
            data_categories=cats,
            storage_regions=regions,
            discovery_date=discovery,
        )
        result = engine.assess_breach(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return {
        "breach_id": result.breach_id,
        "severity": result.severity,
        "exposed_records": result.exposed_records,
        "data_categories": [c.value for c in result.data_categories],
        "applicable_regulations": [r.value for r in result.applicable_regulations],
        "notification_deadlines": result.notification_deadlines,
        "estimated_penalty_min_usd": result.estimated_penalty_min_usd,
        "estimated_penalty_max_usd": result.estimated_penalty_max_usd,
        "required_actions": result.required_actions,
        "assessed_at": result.assessed_at.isoformat(),
    }
