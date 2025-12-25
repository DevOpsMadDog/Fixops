"""API endpoints for managing canonical findings."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from src.api.dependencies import authenticate, authenticated_payload
from src.models.canonical import CanonicalFinding, CanonicalTool
from src.services.correlation_engine import get_correlation_engine, correlate_finding_async

router = APIRouter(tags=["findings"])

# In-memory store for demonstration (in real app, this would be DB)
_FINDINGS_STORE: Dict[str, CanonicalFinding] = {}


@router.post("/ingest", response_model=Dict[str, Any])
async def ingest_findings(
    findings: List[Dict[str, Any]],
    background_tasks: BackgroundTasks,
    payload: Dict[str, Any] = Depends(authenticated_payload),
) -> Dict[str, Any]:
    """
    Ingest raw findings, convert to canonical format, and schedule correlation.
    """
    processed = []
    engine = get_correlation_engine(enabled=True)
    
    for raw in findings:
        try:
            # Basic validation/conversion (in real app, use Pydantic parsing)
            # Assuming raw input mimics CanonicalFinding structure or close to it
            # For robustness, we'd have a mapper here.
            # Using a simplified mapping for now.
            
            tool_data = raw.get("tool", {"name": "unknown"})
            tool_obj = CanonicalTool(name=tool_data.get("name"), version=tool_data.get("version"), vendor=tool_data.get("vendor")) if isinstance(tool_data, dict) else CanonicalTool(name="unknown")

            canonical = CanonicalFinding(
                id=raw.get("id"),
                title=raw.get("title"),
                description=raw.get("description", ""),
                severity=raw.get("severity"),
                stage=raw.get("stage", "runtime"),
                tool=tool_obj,
                status=raw.get("status", "open"),
                cve_id=raw.get("cve_id"),
                component_name=raw.get("component_name")
            )
            
            # Save to store
            _FINDINGS_STORE[canonical.id] = canonical
            processed.append(canonical.id)
            
            # Schedule correlation
            all_findings_list = list(_FINDINGS_STORE.values())
            background_tasks.add_task(correlate_finding_async, canonical, all_findings_list, enabled=True)
            
        except Exception as e:
            # Log error but continue
            continue
            
    return {
        "status": "success", 
        "ingested_count": len(processed),
        "processed_ids": processed
    }


@router.get("/{finding_id}/correlations", response_model=Dict[str, Any])
async def get_finding_correlations(
    finding_id: str,
    payload: Dict[str, Any] = Depends(authenticated_payload),
) -> Dict[str, Any]:
    """Get correlations for a specific finding."""
    
    if finding_id not in _FINDINGS_STORE:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    finding = _FINDINGS_STORE[finding_id]
    all_findings_list = list(_FINDINGS_STORE.values())
    
    # Run on-demand correlation
    engine = get_correlation_engine(enabled=True)
    result = await engine.correlate_finding(finding, all_findings_list)
    
    if result:
        return {
            "finding_id": finding_id,
            "correlations": result.correlated_findings,
            "strategy": result.correlation_type,
            "confidence": result.confidence_score,
            "root_cause": result.root_cause
        }
    
    return {
        "finding_id": finding_id,
        "correlations": [],
        "message": "No strong correlations found"
    }
