"""
Serve documentation markdown files via API for easy linking from UI
"""
import os
from pathlib import Path

import structlog
from fastapi import APIRouter, HTTPException, Response

logger = structlog.get_logger()
router = APIRouter(prefix="/docs", tags=["documentation"])

DOCS_DIR = Path(os.environ.get("FIXOPS_DOCS_DIR", "docs"))


@router.get("/{name}")
async def get_doc(name: str):
    try:
        safe = "".join(c for c in name if c.isalnum() or c in ("-", "_"))
        mapping = {
            "install": "INSTALL.md",
            "requirements": "REQUIREMENTS.md",
            "ssvc": "SSVC.md",
            "roadmap": "ROADMAP.md",
            "architecture": "ARCHITECTURE.md",
        }
        filename = mapping.get(safe, None)
        if not filename:
            raise HTTPException(status_code=404, detail="Document not found")
        path = DOCS_DIR / filename
        if not path.exists():
            raise HTTPException(status_code=404, detail="Document missing")
        content = path.read_text(encoding="utf-8")
        return Response(content=content, media_type="text/markdown; charset=utf-8")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"get_doc failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
