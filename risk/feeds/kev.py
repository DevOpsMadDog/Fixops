"""CISA KEV feed helpers."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Callable, Dict, Iterable, Mapping, Set
from urllib.error import URLError
from urllib.request import urlopen

from . import FEEDS_DIR

DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_FILENAME = "kev.json"
KEV_CACHE_FILENAME = "kev-cache.json"

Fetcher = Callable[[str], bytes]

LOGGER = logging.getLogger(__name__)


def _default_fetcher(url: str) -> bytes:
    with urlopen(url, timeout=30) as response:  # nosec - controlled URL
        return response.read()


def _write_cache(cache_path: Path, payload: dict) -> None:
    cache_file = cache_path / KEV_CACHE_FILENAME
    cache_file.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )


def _load_cache(cache_path: Path) -> dict | None:
    cache_file = cache_path / KEV_CACHE_FILENAME
    if not cache_file.is_file():
        return None
    try:
        with cache_file.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except json.JSONDecodeError as exc:  # pragma: no cover - corrupted cache
        LOGGER.error("Failed to parse KEV JSON cache %s: %s", cache_file, exc)
        return None
    if isinstance(payload, dict):
        return payload
    return None


def update_kev_feed(
    *,
    cache_dir: str | Path = FEEDS_DIR,
    url: str = DEFAULT_KEV_URL,
    fetcher: Fetcher | None = None,
) -> Path:
    """Fetch the KEV JSON feed and cache it under ``cache_dir``."""

    cache_path = Path(cache_dir)
    cache_path.mkdir(parents=True, exist_ok=True)
    destination = cache_path / KEV_FILENAME
    fetch = fetcher or _default_fetcher
    try:
        payload = fetch(url)
        destination.write_bytes(payload)
        with destination.open("r", encoding="utf-8") as handle:
            parsed = json.load(handle)
        _write_cache(cache_path, parsed)
        return destination
    except (URLError, TimeoutError, OSError) as exc:
        LOGGER.warning("Failed to refresh KEV feed (%s). Using cached JSON.", exc)
        cached = _load_cache(cache_path)
        if cached is None:
            raise
        _write_cache(cache_path, cached)
        return cache_path / KEV_CACHE_FILENAME


def load_kev_catalog(
    path: str | Path | None = None,
    *,
    cache_dir: str | Path = FEEDS_DIR,
) -> Dict[str, dict]:
    """Load KEV entries into a mapping keyed by CVE."""

    cache_path = Path(cache_dir)
    if path is None:
        path = cache_path / KEV_FILENAME
    data_path = Path(path)
    payload: dict | None = None
    if data_path.is_file():
        with data_path.open("r", encoding="utf-8") as handle:
            try:
                payload = json.load(handle)
            except json.JSONDecodeError as exc:
                LOGGER.error("Failed to parse KEV feed %s: %s", data_path, exc)
                payload = None

    if payload is None:
        payload = _load_cache(cache_path)
    if payload is None:
        raise FileNotFoundError(f"KEV feed not found at {data_path} or cache")

    vulnerabilities: Iterable[dict] = ()
    data_obj = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data_obj, dict):
        vulnerabilities = data_obj.get("vulnerabilities", [])
    elif isinstance(payload, dict):
        vulnerabilities = payload.get("vulnerabilities", [])

    kev_entries: Dict[str, dict] = {}
    for entry in vulnerabilities or []:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("cveID") or entry.get("cve") or entry.get("id")
        if not isinstance(cve, str):
            LOGGER.warning("KEV entry missing CVE identifier: %s", entry)
            continue
        kev_entries[cve.strip().upper()] = entry
    return kev_entries


def kev_cves(catalog: Mapping[str, dict]) -> Set[str]:
    """Return a set of CVE identifiers present in the KEV catalog."""

    return set(catalog.keys())


__all__ = [
    "update_kev_feed",
    "load_kev_catalog",
    "kev_cves",
    "DEFAULT_KEV_URL",
    "KEV_FILENAME",
    "KEV_CACHE_FILENAME",
]
