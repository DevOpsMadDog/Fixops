"""
External feeds endpoints (EPSS, KEV) using FeedsService
"""
from pathlib import Path

import structlog
from fastapi import APIRouter, HTTPException, Response
from src.config.settings import get_settings
from src.services.feeds_service import FEEDS_DIR, FeedsService

logger = structlog.get_logger()
router = APIRouter(prefix="/feeds", tags=["external-feeds"])
settings = get_settings()


@router.get("/status")
async def feeds_status():
    try:
        st = FeedsService.status(settings.ENABLED_EPSS, settings.ENABLED_KEV)
        return {
            "status": "success",
            "data": {
                "enabled_epss": st.enabled_epss,
                "enabled_kev": st.enabled_kev,
                "last_updated_epss": st.last_updated_epss,
                "last_updated_kev": st.last_updated_kev,
                "epss_count": st.epss_count,
                "kev_count": st.kev_count,
            },
        }
    except Exception:
        logger.exception("feeds_status failed")
        raise HTTPException(status_code=500, detail="Failed to get feeds status")


@router.post("/epss/refresh")
async def epss_refresh():
    try:
        if not settings.ENABLED_EPSS:
            return {"status": "disabled", "message": "EPSS integration disabled"}
        res = await FeedsService.refresh_epss()
        return res
    except Exception:
        logger.exception("epss_refresh failed")
        raise HTTPException(status_code=500, detail="EPSS refresh failed")


@router.post("/kev/refresh")
async def kev_refresh():
    try:
        if not settings.ENABLED_KEV:
            return {"status": "disabled", "message": "KEV integration disabled"}
        res = await FeedsService.refresh_kev()
        return res
    except Exception:
        logger.exception("kev_refresh failed")
        raise HTTPException(status_code=500, detail="Failed to refresh KEV feed")


@router.get("/download/{feed}")
async def download_feed(feed: str):
    try:
        safe = feed.lower()
        if safe not in ("epss", "kev"):
            raise HTTPException(status_code=404, detail="Unknown feed")
        path = FEEDS_DIR / f"{safe}.json"
        if not path.exists():
            raise HTTPException(status_code=404, detail="Feed snapshot not available")
        content = path.read_text(encoding="utf-8")
        return Response(content=content, media_type="application/json")
    except HTTPException:
        raise
    except Exception:
        logger.exception("download_feed failed")
        raise HTTPException(status_code=500, detail="Failed to download feed")
