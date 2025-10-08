"""Versioned API routers."""

from fastapi import APIRouter

from . import cicd, evidence

router = APIRouter()
router.include_router(cicd.router, prefix="/cicd")
router.include_router(evidence.router, prefix="/evidence")

__all__ = ["router"]

