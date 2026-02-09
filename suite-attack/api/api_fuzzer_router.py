"""API Fuzzer Router — API Discovery & Fuzzing endpoints."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/api-fuzzer", tags=["API Fuzzer"])


class DiscoverRequest(BaseModel):
    openapi_spec: Dict[str, Any]


class FuzzRequest(BaseModel):
    base_url: str
    openapi_spec: Dict[str, Any]
    headers: Optional[Dict[str, str]] = None
    max_per_endpoint: int = 5


@router.post("/discover")
async def discover_endpoints(req: DiscoverRequest) -> Dict[str, Any]:
    """Discover API endpoints from an OpenAPI/Swagger spec."""
    from core.api_fuzzer import get_api_fuzzer_engine

    engine = get_api_fuzzer_engine()
    endpoints = engine.discover_from_openapi(req.openapi_spec)
    return {
        "endpoints": [e.to_dict() for e in endpoints],
        "total": len(endpoints),
    }


@router.post("/fuzz")
async def fuzz_endpoints(req: FuzzRequest) -> Dict[str, Any]:
    """Discover and fuzz API endpoints."""
    from core.api_fuzzer import get_api_fuzzer_engine

    engine = get_api_fuzzer_engine()
    endpoints = engine.discover_from_openapi(req.openapi_spec)
    result = await engine.fuzz_endpoints(
        base_url=req.base_url, endpoints=endpoints,
        headers=req.headers, max_per_endpoint=req.max_per_endpoint,
    )
    return result.to_dict()


@router.get("/status")
async def fuzzer_status() -> Dict[str, Any]:
    return {"engine": "api_fuzzer", "status": "ready", "version": "1.0.0"}

