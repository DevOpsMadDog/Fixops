"""EPSS feed helpers."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Callable, Dict
from urllib.request import urlopen

from . import FEEDS_DIR

DEFAULT_EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv"
EPSS_FILENAME = "epss.csv"

Fetcher = Callable[[str], bytes]


def _default_fetcher(url: str) -> bytes:
    with urlopen(url, timeout=30) as response:  # nosec - controlled URL
        return response.read()


def update_epss_feed(
    *,
    cache_dir: str | Path = FEEDS_DIR,
    url: str = DEFAULT_EPSS_URL,
    fetcher: Fetcher | None = None,
) -> Path:
    """Fetch the EPSS CSV feed and cache it under ``cache_dir``."""

    cache_path = Path(cache_dir)
    cache_path.mkdir(parents=True, exist_ok=True)
    destination = cache_path / EPSS_FILENAME
    fetch = fetcher or _default_fetcher
    payload = fetch(url)
    destination.write_bytes(payload)
    return destination


def load_epss_scores(
    path: str | Path | None = None,
    *,
    cache_dir: str | Path = FEEDS_DIR,
) -> Dict[str, float]:
    """Load EPSS scores from a cached CSV into a mapping of CVE -> score."""

    if path is None:
        path = Path(cache_dir) / EPSS_FILENAME
    data_path = Path(path)
    if not data_path.is_file():
        raise FileNotFoundError(f"EPSS feed not found at {data_path}")

    scores: Dict[str, float] = {}
    with data_path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if not row:
                continue
            cve = row.get("cve") or row.get("CVE") or row.get("cve_id")
            score_value = row.get("epss") or row.get("score")
            if not cve or score_value is None:
                continue
            try:
                score = float(str(score_value).strip())
            except (TypeError, ValueError):
                continue
            scores[cve.strip().upper()] = max(0.0, min(score, 1.0))
    return scores


__all__ = ["update_epss_feed", "load_epss_scores", "DEFAULT_EPSS_URL", "EPSS_FILENAME"]
