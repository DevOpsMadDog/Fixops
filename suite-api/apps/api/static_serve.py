"""Serve the frontend static files from FastAPI."""
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

DIST_DIR = Path(__file__).parent.parent.parent.parent / "suite-ui" / "aldeci-ui-new" / "dist"

def mount_frontend(app: FastAPI):
    """Mount the frontend dist directory on the FastAPI app."""
    if DIST_DIR.exists():
        app.mount("/assets", StaticFiles(directory=str(DIST_DIR / "assets")), name="static-assets")
        
        @app.get("/", include_in_schema=False)
        @app.get("/index.html", include_in_schema=False)
        async def serve_index():
            return FileResponse(str(DIST_DIR / "index.html"))
