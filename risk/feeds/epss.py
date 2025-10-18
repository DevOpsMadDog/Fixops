"""EPSS feed helpers."""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Callable, Dict
from urllib.error import URLError
from urllib.request import urlopen

from . import FEEDS_DIR

DEFAULT_EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv"
EPSS_FILENAME = "epss.csv"
EPSS_JSON_FILENAME = "epss.json"

Fetcher = Callable[[str], bytes]

LOGGER = logging.getLogger(__name__)


def _default_fetcher(url: str) -> bytes:
    with urlopen(url, timeout=30) as response:  # nosec - controlled URL
        return response.read()


def _write_json_cache(cache_path: Path, scores: Dict[str, float]) -> None:
    json_path = cache_path / EPSS_JSON_FILENAME
    json_path.write_text(json.dumps(scores, indent=2, sort_keys=True), encoding="utf-8")


def _load_json_cache(cache_path: Path) -> Dict[str, float] | None:
    json_path = cache_path / EPSS_JSON_FILENAME
    if not json_path.is_file():
        return None
    try:
        with json_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except json.JSONDecodeError as exc:  # pragma: no cover - corrupted cache
        LOGGER.error("Failed to parse EPSS JSON cache %s: %s", json_path, exc)
        return None
    if not isinstance(payload, dict):
        return None
    scores: Dict[str, float] = {}
    for key, value in payload.items():
        try:
            scores[str(key).upper()] = float(value)
        except (TypeError, ValueError):
            LOGGER.debug("Skipping invalid EPSS cache entry %s=%s", key, value)
            continue
    return scores


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
    try:
        payload = fetch(url)
        destination.write_bytes(payload)
    except (URLError, TimeoutError, OSError) as exc:
        LOGGER.warning("Failed to refresh EPSS feed (%s). Using cached JSON.", exc)
        cached_scores = _load_json_cache(cache_path)
        if cached_scores is None:
            raise
        _write_json_cache(cache_path, cached_scores)
        return cache_path / EPSS_JSON_FILENAME

    scores = _parse_epss_csv(destination)
    _write_json_cache(cache_path, scores)
    return destination


def _parse_epss_csv(path: Path) -> Dict[str, float]:
    scores: Dict[str, float] = {}
    with path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if not row:
                continue
            cve = row.get("cve") or row.get("CVE") or row.get("cve_id")
            score_value = row.get("epss") or row.get("score")
            if not cve:
                LOGGER.debug("Skipping EPSS row without CVE: %s", row)
                continue
            if score_value is None:
                LOGGER.debug("Skipping EPSS row without score: %s", row)
                continue
            try:
                score = float(str(score_value).strip())
            except (TypeError, ValueError):
                LOGGER.debug("Invalid EPSS score %s for %s", score_value, cve)
                continue
            scores[cve.strip().upper()] = max(0.0, min(score, 1.0))
    return scores


def load_epss_scores(
    path: str | Path | None = None,
    *,
    cache_dir: str | Path = FEEDS_DIR,
) -> Dict[str, float]:
    """Load EPSS scores from cache, falling back to JSON if necessary."""

    cache_path = Path(cache_dir)
    if path is None:
        csv_path = cache_path / EPSS_FILENAME
    else:
        csv_path = Path(path)

    if csv_path.suffix == ".json":
        scores = _load_json_cache(csv_path.parent)
        if scores is not None:
            return scores
    if csv_path.is_file():
        scores = _parse_epss_csv(csv_path)
        if scores:
            return scores
        LOGGER.warning(
            "EPSS CSV %s contained no scores; falling back to JSON cache", csv_path
        )

    scores = _load_json_cache(cache_path)
    if scores is not None:
        return scores

    raise FileNotFoundError(f"EPSS feed not found at {csv_path} or JSON cache")


__all__ = [
    "update_epss_feed",
    "load_epss_scores",
    "DEFAULT_EPSS_URL",
    "EPSS_FILENAME",
    "EPSS_JSON_FILENAME",
]
