"""Background feed refresh scheduler used by the demo application."""

from __future__ import annotations

import asyncio
from typing import Any


class FeedsService:
    """Lightweight shim replacing the legacy scheduler."""

    @staticmethod
    async def scheduler(settings: Any, interval_hours: int) -> None:  # pragma: no cover - background task
        delay = max(1, int(interval_hours)) * 3600
        while True:
            await asyncio.sleep(delay)


__all__ = ["FeedsService"]

