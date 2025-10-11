"""CISA KEV feed helpers."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Dict, Iterable, Mapping, Set
from urllib.request import urlopen

from . import FEEDS_DIR

DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_FILENAME = "kev.json"

Fetcher = Callable[[str], bytes]


def _default_fetcher(url: str) -> bytes:
    with urlopen(url, timeout=30) as response:  # nosec - controlled URL
        return response.read()


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
    payload = fetch(url)
    destination.write_bytes(payload)
    return destination


def load_kev_catalog(
    path: str | Path | None = None,
    *,
    cache_dir: str | Path = FEEDS_DIR,
) -> Dict[str, dict]:
    """Load KEV entries into a mapping keyed by CVE."""

    if path is None:
        path = Path(cache_dir) / KEV_FILENAME
    data_path = Path(path)
    if not data_path.is_file():
        raise FileNotFoundError(f"KEV feed not found at {data_path}")

    with data_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

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
]
