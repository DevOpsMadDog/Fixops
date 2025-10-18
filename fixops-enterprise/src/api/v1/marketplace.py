"""Marketplace API exposing remediation packs."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from src.api.dependencies import authenticate
from src.services.marketplace import get_pack

router = APIRouter(tags=["marketplace"])


@router.get("/packs/{framework}/{control}")
async def fetch_pack(
    framework: str, control: str, _: None = Depends(authenticate)
) -> dict:
    try:
        pack = get_pack(framework, control)
    except FileNotFoundError as exc:  # pragma: no cover - defensive
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Pack not found"
        ) from exc
    return dict(pack)


__all__ = ["router"]
