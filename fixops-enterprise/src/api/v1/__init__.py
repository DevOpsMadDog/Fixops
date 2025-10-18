"""Versioned API routers."""

from fastapi import APIRouter

from . import artefacts, cicd, enhanced, evidence, marketplace

router = APIRouter()
router.include_router(cicd.router, prefix="/cicd")
router.include_router(evidence.router, prefix="/evidence")
router.include_router(artefacts.router, prefix="/artefacts")
router.include_router(enhanced.router, prefix="/enhanced")
router.include_router(marketplace.router, prefix="/marketplace")

__all__ = ["router"]
