"""Zero-Gravity Data Engine Router (V9).

Exposes 4-tier data aging, ingestion, retrieval, migration, and storage analytics.
Designed for <1 GB/year on-prem storage with air-gapped deployment.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/zero-gravity", tags=["Zero-Gravity Data"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class IngestRequest(BaseModel):
    data_id: str = Field(..., description="Unique data identifier")
    category: str = Field(..., description="Data category: evidence, findings, scans, etc.")
    content: str = Field(..., description="Data content (string or JSON)")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RetrieveRequest(BaseModel):
    data_id: str = Field(..., description="Data identifier to retrieve")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/health")
async def zero_gravity_health() -> Dict[str, Any]:
    """Health check alias for Zero-Gravity engine (mirrors /status)."""
    return await zero_gravity_status()


@router.get("/status")
async def zero_gravity_status() -> Dict[str, Any]:
    """Get Zero-Gravity engine status and storage stats."""
    try:
        from core.zero_gravity import ZeroGravityEngine
        engine = ZeroGravityEngine()
        status = engine.get_status()
        return {
            "status": "operational",
            "engine": "zero-gravity",
            "version": "1.0.0",
            **status,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        return {
            "status": "degraded",
            "engine": "zero-gravity",
            "error": type(e).__name__,
        }


@router.post("/ingest")
async def ingest_data(req: IngestRequest) -> Dict[str, Any]:
    """Ingest data into the hot tier."""
    try:
        from core.zero_gravity import ZeroGravityEngine
        engine = ZeroGravityEngine()
        result = engine.ingest(
            data_id=req.data_id,
            category=req.category,
            content=req.content.encode() if isinstance(req.content, str) else req.content,
            metadata=req.metadata,
        )
        return {"ingested": True, **result}
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {e}")


@router.get("/retrieve/{data_id}")
async def retrieve_data(data_id: str) -> Dict[str, Any]:
    """Retrieve data from any tier."""
    try:
        from core.zero_gravity import ZeroGravityEngine
        engine = ZeroGravityEngine()
        result = engine.retrieve(data_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Data {data_id} not found")
        # Convert bytes to string for JSON response
        if isinstance(result, bytes):
            result = result.decode(errors="replace")
        return {"data_id": data_id, "content": result, "found": True}
    except HTTPException:
        raise
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.post("/migrate")
async def run_migration() -> Dict[str, Any]:
    """Run a migration cycle (move aged data between tiers)."""
    try:
        from core.zero_gravity import ZeroGravityEngine
        engine = ZeroGravityEngine()
        result = engine.run_migration_cycle()
        return {"migration": "completed", **result}
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Migration failed: {e}")


@router.get("/forecast")
async def storage_forecast(days: int = Query(365, ge=1, le=3650)) -> Dict[str, Any]:
    """Forecast storage usage over time."""
    try:
        from core.zero_gravity import ZeroGravityEngine
        engine = ZeroGravityEngine()
        return engine.forecast_storage(days)
    except ImportError as e:
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/tiers")
async def get_tier_info() -> Dict[str, Any]:
    """Get information about all data tiers."""
    return {
        "tiers": [
            {"name": "hot", "age_days": "0-30", "format": "SQLite WAL", "resolution": "full"},
            {"name": "warm", "age_days": "30-90", "format": "compressed", "resolution": "full"},
            {"name": "cold", "age_days": "90-365", "format": "compressed+summarized", "resolution": "reduced"},
            {"name": "archive", "age_days": "365+", "format": "sealed WORM bundles", "resolution": "summary only"},
        ],
        "compression": "zstd/zlib",
        "deduplication": "MinHash LSH",
        "target_storage": "<1 GB/year",
    }
