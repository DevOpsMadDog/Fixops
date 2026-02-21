"""DAST Router — Dynamic Application Security Testing endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/dast", tags=["DAST"])


class DastScanRequest(BaseModel):
    target_url: str
    headers: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None
    crawl: bool = True
    max_depth: int = 3


@router.post("/scan")
async def dast_scan(req: DastScanRequest) -> Dict[str, Any]:
    """Launch a DAST scan against a live target."""
    from core.dast_engine import get_dast_engine

    engine = get_dast_engine()
    result = await engine.scan(
        target_url=req.target_url,
        headers=req.headers,
        cookies=req.cookies,
        crawl=req.crawl,
        max_depth=req.max_depth,
    )
    return result.to_dict()


@router.get("/status")
async def dast_status() -> Dict[str, Any]:
    return {"engine": "dast", "status": "ready", "version": "1.0.0"}
