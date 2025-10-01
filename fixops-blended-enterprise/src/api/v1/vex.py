"""
VEX ingestion stub aligned to SSVC deck
"""
from fastapi import APIRouter, HTTPException, UploadFile, File
from src.config.settings import get_settings
import structlog
import json

logger = structlog.get_logger()
router = APIRouter(prefix="/vex", tags=["vex-stub"])
settings = get_settings()

@router.post("/ingest")
async def vex_ingest(file: UploadFile = File(...)):
    try:
        if not settings.ENABLED_VEX:
            return {"status": "disabled", "message": "VEX integration disabled"}
        data = await file.read()
        try:
            payload = json.loads(data.decode('utf-8'))
        except Exception:
            payload = {"raw": data[:200].decode('utf-8', errors='ignore')}
        # TODO: validate against CycloneDX/SPDX VEX and persist
        return {"status": "success", "message": "VEX document accepted (stub)", "summary": {
            "size": len(data),
            "file_name": file.filename,
            "detected_format": payload.get("bomFormat") or payload.get("@context", "unknown")
        }}
    except Exception as e:
        logger.error(f"vex_ingest failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
