"""Threat Feed Aggregator API Router — ALDECI."""
from __future__ import annotations

from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/threat-feeds", tags=["threat-feeds"])

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_feed_aggregator import ThreatFeedAggregator
        _engine = ThreatFeedAggregator()
    return _engine


class FeedSourceCreate(BaseModel):
    name: str
    url: str = ""
    feed_type: str = "cve"
    format: str = "json"
    frequency_hours: int = 24
    reliability_score: float = 0.8
    tags: list = []


class FeedItemCreate(BaseModel):
    source_id: str
    feed_type: str = "cve"
    title: str = ""
    description: str = ""
    severity: str = "medium"
    iocs: list = []
    cves: list = []
    tags: list = []
    raw_data: dict = {}


@router.get("/sources")
async def list_sources(
    org_id: str = Query(default="default"),
    feed_type: Optional[str] = Query(default=None),
    auth=Depends(api_key_auth),
):
    try:
        return _get_engine().list_feed_sources(org_id=org_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/sources")
async def add_source(body: FeedSourceCreate, org_id: str = Query(default="default"), auth=Depends(api_key_auth)):
    try:
        return _get_engine().add_feed_source(org_id=org_id, data=body.model_dump())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/items")
async def ingest_item(body: FeedItemCreate, org_id: str = Query(default="default"), auth=Depends(api_key_auth)):
    try:
        return _get_engine().ingest_feed_item(org_id=org_id, data=body.model_dump())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/items")
async def list_items(
    org_id: str = Query(default="default"),
    feed_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=50),
    auth=Depends(api_key_auth),
):
    try:
        return _get_engine().list_feed_items(org_id=org_id, feed_type=feed_type, severity=severity)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/search")
async def search_iocs(
    org_id: str = Query(default="default"),
    q: str = Query(default=""),
    auth=Depends(api_key_auth),
):
    try:
        return _get_engine().search_iocs(org_id=org_id, query=q)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats")
async def get_stats(org_id: str = Query(default="default"), auth=Depends(api_key_auth)):
    try:
        return _get_engine().get_feed_stats(org_id=org_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
