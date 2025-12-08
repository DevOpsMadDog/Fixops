"""Health check router for FixOps API."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "fixops-api",
        "version": "1.0.0",
    }
