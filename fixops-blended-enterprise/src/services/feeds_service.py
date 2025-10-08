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
from typing import Dict, Any, Iterable, List, Mapping

import aiohttp
import structlog

from src.services.vex_ingestion import VEXIngestor

logger = structlog.get_logger()

def _resolve_feeds_dir() -> Path:
    """Return the directory that should contain feed snapshots."""

    base = Path(os.getenv("FIXOPS_FEEDS_DIR", "/app/data/feeds"))
    base.mkdir(parents=True, exist_ok=True)
    return base


FEEDS_DIR = _resolve_feeds_dir()

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
    def _path(name: str) -> Path:
        """Return the fully-qualified path for the stored snapshot."""

        if not name.endswith(".json"):
            name = f"{name}.json"
        return _resolve_feeds_dir() / name

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
            cls._write(cls._path("epss"), snapshot)
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
            cls._write(cls._path("kev"), snapshot)
            # KEV format contains {"vulnerabilities": [ ... ]}
            count = len(data.get("vulnerabilities", []))
            return {"status": "success", "count": count}
        except Exception as e:
            logger.error(f"KEV refresh error: {e}")
            return {"status": "error", "message": str(e)}

    @classmethod
    def status(cls, enabled_epss: bool, enabled_kev: bool) -> FeedStatus:
        epss_json = cls._read(cls._path("epss")) or {}
        kev_json = cls._read(cls._path("kev")) or {}
        return FeedStatus(
            enabled_epss=enabled_epss,
            enabled_kev=enabled_kev,
            last_updated_epss=(epss_json.get("fetched_at")),
            last_updated_kev=(kev_json.get("fetched_at")),
            epss_count=len(
                (epss_json.get("data", {}) or {}).get("data", [])
                if isinstance((epss_json.get("data", {}) or {}).get("data", []), list)
                else 0
            ),
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

    # ------------------------------------------------------------------
    # Enrichment helpers
    # ------------------------------------------------------------------

    @classmethod
    def _load_epss_scores(cls) -> Dict[str, float]:
        """Return a mapping of CVE -> EPSS score from the cached snapshot."""

        snapshot = cls._read(cls._path("epss")) or {}
        data = snapshot.get("data", {})
        rows: Iterable[Mapping[str, Any]]
        if isinstance(data, Mapping):
            rows = data.get("data") or []
        else:
            rows = data or []  # type: ignore[assignment]

        scores: Dict[str, float] = {}
        for entry in rows:
            if not isinstance(entry, Mapping):
                continue
            cve = entry.get("cve") or entry.get("cveID") or entry.get("cve_id")
            if not isinstance(cve, str):
                continue
            try:
                score = float(entry.get("epss") or entry.get("epssScore") or entry.get("epss_score") or entry.get("score"))
            except (TypeError, ValueError):
                continue
            scores[cve.strip().upper()] = max(0.0, min(score, 1.0))
        return scores

    @classmethod
    def _load_kev_identifiers(cls) -> Dict[str, Dict[str, Any]]:
        """Return a mapping of CVE -> KEV metadata from the cached snapshot."""

        snapshot = cls._read(cls._path("kev")) or {}
        payload = snapshot.get("data", {})
        entries = payload.get("vulnerabilities") if isinstance(payload, Mapping) else None
        if not isinstance(entries, list):
            return {}

        kev_index: Dict[str, Dict[str, Any]] = {}
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            cve = entry.get("cveID") or entry.get("cve_id") or entry.get("cve")
            if isinstance(cve, str) and cve.strip():
                kev_index[cve.strip().upper()] = dict(entry)
        return kev_index

    @classmethod
    def enrich_findings(cls, findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge cached EPSS/KEV intelligence into security findings."""

        epss_scores = cls._load_epss_scores()
        kev_index = cls._load_kev_identifiers()
        enriched: List[Dict[str, Any]] = []

        for finding in findings or []:
            if not isinstance(finding, dict):
                continue
            clone = dict(finding)
            cve = clone.get("cve_id") or clone.get("cve") or clone.get("id") or clone.get("kev_reference")
            if isinstance(cve, str):
                normalised = cve.strip().upper()
            else:
                normalised = None

            if normalised:
                if "epss_score" not in clone and normalised in epss_scores:
                    clone["epss_score"] = epss_scores[normalised]
                if normalised in kev_index:
                    clone.setdefault("kev_flag", True)
                    clone.setdefault("kev", True)
                    clone.setdefault("kev_reference", normalised)
                    clone.setdefault("kev_metadata", kev_index[normalised])
            enriched.append(clone)

        enriched = VEXIngestor.apply_assertions(enriched)

        return enriched
