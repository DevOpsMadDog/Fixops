"""
External feeds stubs aligned to SSVC deck (EPSS, KEV) and status
"""
from fastapi import APIRouter, HTTPException
from src.config.settings import get_settings
import structlog

logger = structlog.get_logger()
router = APIRouter(prefix="/feeds", tags=["external-feeds-stub"])
settings = get_settings()

@router.get("/status")
async def feeds_status():
    try:
        return {
            "status": "success",
            "data": {
                "enabled_epss": settings.ENABLED_EPSS,
                "enabled_kev": settings.ENABLED_KEV,
                "enabled_vex": settings.ENABLED_VEX,
                "enabled_rss_sidecar": settings.ENABLED_RSS_SIDECAR,
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
        # TODO: implement EPSS ingestion
        return {"status": "success", "message": "EPSS refresh queued"}
    except Exception as e:
        logger.error(f"epss_refresh failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/kev/refresh")
async def kev_refresh():
    try:
        if not settings.ENABLED_KEV:
            return {"status": "disabled", "message": "KEV integration disabled"}
        # TODO: implement KEV ingestion
        return {"status": "success", "message": "KEV refresh queued"}
    except Exception as e:
        logger.error(f"kev_refresh failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
