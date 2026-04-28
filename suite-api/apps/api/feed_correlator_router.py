"""Feed Correlator Router — unified ALDECI vulnerability score across 8 feeds.

Endpoints under /api/v1/correlate:

    GET  /api/v1/correlate/{cve_id}     correlate a single CVE
    POST /api/v1/correlate/batch        correlate up to 50 CVEs in one call

The correlator joins data on demand from CISA KEV + NVD CVE + EPSS + GHSA +
OSV + ExploitDB + AbuseIPDB + OTX importers and returns a unified record per
CVE with a 0..100 ALDECI risk score plus the per-component breakdown.

Auth: api_key_auth from apps.api.auth_deps.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# suite-core may not be on sys.path in every deployment context.
_HERE = Path(__file__).resolve()
_SUITE_CORE = str(_HERE.parents[3] / "suite-core")
if _SUITE_CORE not in sys.path:
    sys.path.insert(0, _SUITE_CORE)

try:
    from apps.api.auth_deps import api_key_auth
except ImportError:  # pragma: no cover — keep router import-clean in stripped envs
    async def api_key_auth() -> bool:  # type: ignore[no-redef]
        return True


router = APIRouter(
    prefix="/api/v1/correlate",
    tags=["Feed Correlator"],
)


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------

class BatchIn(BaseModel):
    cve_ids: List[str] = Field(
        ...,
        description="List of CVE ids to correlate, e.g. ['CVE-2024-12345', 'CVE-2024-67890']",
        min_length=1,
        max_length=50,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/{cve_id}", dependencies=[Depends(api_key_auth)])
async def correlate_one(cve_id: str) -> Dict[str, Any]:
    """Return the unified correlation record for *cve_id*.

    Missing feeds (e.g. ExploitDB / OTX / AbuseIPDB before their importers
    land) return ``null`` for their section but never raise an error.
    """
    cve_id = (cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        raise HTTPException(status_code=400,
                            detail="cve_id must look like 'CVE-YYYY-NNNN'")
    try:
        from core.feed_correlator import get_correlator
        return await get_correlator().correlate(cve_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Feed correlation failed for %s", cve_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/batch", dependencies=[Depends(api_key_auth)])
async def correlate_batch(payload: BatchIn) -> Dict[str, Any]:
    """Correlate up to 50 CVE ids in parallel and return a list of records."""
    try:
        from core.feed_correlator import get_correlator
        results = await get_correlator().correlate_batch(payload.cve_ids)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Batch feed correlation failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {
        "count": len(results),
        "results": results,
    }
