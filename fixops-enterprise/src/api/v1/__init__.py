"""Versioned API routers."""

from fastapi import APIRouter

from . import (
    advanced_pentest,
    artefacts,
    automated_pentest,
    cicd,
    enhanced,
    evidence,
    findings,
    marketplace,
    micro_pentest,
    pentagi,
)

router = APIRouter()
router.include_router(cicd.router, prefix="/cicd")
router.include_router(evidence.router, prefix="/evidence")
router.include_router(findings.router, prefix="/findings")
router.include_router(artefacts.router, prefix="/artefacts")
router.include_router(enhanced.router, prefix="/enhanced")
router.include_router(marketplace.router, prefix="/marketplace")
router.include_router(pentagi.router, prefix="/pentagi")
router.include_router(micro_pentest.router, prefix="/micro-pentest")
router.include_router(automated_pentest.router, prefix="/automated-pentest")
router.include_router(advanced_pentest.router, prefix="/advanced-pentest")

__all__ = ["router"]
