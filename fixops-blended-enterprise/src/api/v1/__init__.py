"""Versioned API routers."""

from fastapi import APIRouter

from . import artefacts, cicd, evidence

router = APIRouter()
router.include_router(cicd.router, prefix="/cicd")
router.include_router(evidence.router, prefix="/evidence")
router.include_router(artefacts.router, prefix="/artefacts")

__all__ = ["router"]

