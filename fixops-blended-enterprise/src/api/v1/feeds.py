"""
External feeds endpoints (EPSS, KEV) using FeedsService
"""
from fastapi import APIRouter, HTTPException
import structlog

from src.config.settings import get_settings
from src.services.feeds_service import FeedsService

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
            }
        }
    except Exception as e:
        logger.error(f"feeds_status failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/epss/refresh")
async def epss_refresh():
    try:
        if not settings.ENABLED_EPSS:
            return {"status": "disabled", "message": "EPSS integration disabled"}
        res = await FeedsService.refresh_epss()
        return res
    except Exception as e:
        logger.error(f"epss_refresh failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/kev/refresh")
async def kev_refresh():
    try:
        if not settings.ENABLED_KEV:
            return {"status": "disabled", "message": "KEV integration disabled"}
        res = await FeedsService.refresh_kev()
        return res
    except Exception as e:
        logger.error(f"kev_refresh failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
