"""
EPSS/KEV feeds ingestion service with file-based persistence
- Stores latest snapshots under /app/data/feeds
- Provides counts and timestamps for UI badges
- Scheduled daily refresh when enabled
"""
from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

import aiohttp
import structlog

logger = structlog.get_logger()

FEEDS_DIR = Path("/app/data/feeds")
FEEDS_DIR.mkdir(parents=True, exist_ok=True)

EPSS_URL = "https://api.first.org/data/v1/epss?pretty=true"  # summary sample
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

@dataclass
class FeedStatus:
    enabled_epss: bool
    enabled_kev: bool
    last_updated_epss: str | None
    last_updated_kev: str | None
    epss_count: int
    kev_count: int

class FeedsService:
    @staticmethod
    async def fetch_json(url: str) -> Dict[str, Any]:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                resp.raise_for_status()
                return await resp.json()

    @staticmethod
    def _write(path: Path, payload: Dict[str, Any]):
        path.write_text(json.dumps(payload, indent=2), encoding='utf-8')

    @staticmethod
    def _read(path: Path) -> Dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            return None

    @classmethod
    async def refresh_epss(cls) -> Dict[str, Any]:
        try:
            data = await cls.fetch_json(EPSS_URL)
            snapshot = {
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "source": EPSS_URL,
                "data": data,
            }
            cls._write(FEEDS_DIR / "epss.json", snapshot)
            count = len(data.get("data", [])) if isinstance(data.get("data"), list) else 0
            return {"status": "success", "count": count}
        except Exception as e:
            logger.error(f"EPSS refresh error: {e}")
            return {"status": "error", "message": str(e)}

    @classmethod
    async def refresh_kev(cls) -> Dict[str, Any]:
        try:
            data = await cls.fetch_json(KEV_URL)
            snapshot = {
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "source": KEV_URL,
                "data": data,
            }
            cls._write(FEEDS_DIR / "kev.json", snapshot)
            # KEV format contains {"vulnerabilities": [ ... ]}
            count = len(data.get("vulnerabilities", []))
            return {"status": "success", "count": count}
        except Exception as e:
            logger.error(f"KEV refresh error: {e}")
            return {"status": "error", "message": str(e)}

    @classmethod
    def status(cls, enabled_epss: bool, enabled_kev: bool) -> FeedStatus:
        epss_json = cls._read(FEEDS_DIR / "epss.json") or {}
        kev_json = cls._read(FEEDS_DIR / "kev.json") or {}
        return FeedStatus(
            enabled_epss=enabled_epss,
            enabled_kev=enabled_kev,
            last_updated_epss=(epss_json.get("fetched_at")),
            last_updated_kev=(kev_json.get("fetched_at")),
            epss_count=len((epss_json.get("data", {}) or {}).get("data", []) if isinstance((epss_json.get("data", {}) or {}).get("data", []), list) else 0),
            kev_count=len((kev_json.get("data", {}) or {}).get("vulnerabilities", [])),
        )

    @classmethod
    async def scheduler(cls, settings):
        """Daily scheduler for EPSS/KEV refresh (if enabled)"""
        # initial small delay to allow app startup
        await asyncio.sleep(5)
        while True:
            try:
                if settings.ENABLED_EPSS:
                    await cls.refresh_epss()
                if settings.ENABLED_KEV:
                    await cls.refresh_kev()
            except Exception as e:
                logger.error(f"Feed scheduler error: {e}")
            # sleep for 24h
            await asyncio.sleep(60 * 60 * 24)
