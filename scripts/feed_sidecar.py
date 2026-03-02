#!/usr/bin/env python3
"""
ALdeci CVE Intelligence Feed Sidecar
=====================================

Production-grade threat-intelligence pipeline that fetches, correlates, and
pushes enriched CVE data into the ALdeci FAIL scoring engine.

Data sources:
    * NIST NVD 2.0 API  -- CVE details, CVSS scores, CWE IDs
    * CISA KEV catalog   -- Known Exploited Vulnerabilities
    * FIRST EPSS API     -- Exploit Prediction Scoring System probabilities

Modes:
    continuous  -- Loop every --interval seconds (default 3600)
    once        -- Single fetch-correlate-push cycle, then exit
    demo        -- Generate realistic synthetic CVE data (offline/demo)
    health      -- Probe all feed sources and the ALdeci API

Architecture:
    NVD ──┐
    KEV ──┼── Correlator ── FAIL /score/batch ── ALdeci DB
    EPSS ─┘

Docker usage (via docker-compose):
    python scripts/feed_sidecar.py continuous --interval 3600
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import random
import signal
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Logging -- structured JSON in production, human-readable in dev
# ---------------------------------------------------------------------------

LOG_FORMAT = os.getenv("LOG_FORMAT", "text")  # "text" or "json"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


class _JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for container environments."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def _setup_logging() -> logging.Logger:
    root = logging.getLogger()
    root.setLevel(LOG_LEVEL)
    handler = logging.StreamHandler(sys.stdout)
    if LOG_FORMAT == "json":
        handler.setFormatter(_JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
    root.handlers = [handler]
    # Suppress noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    return logging.getLogger("feed_sidecar")


logger = _setup_logging()

# ---------------------------------------------------------------------------
# Lazy import -- httpx may not be installed in every environment
# ---------------------------------------------------------------------------

try:
    import httpx
except ImportError:
    logger.error("httpx is required: pip install httpx")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration (env-driven, 12-factor)
# ---------------------------------------------------------------------------

BASE_URL: str = os.getenv("FIXOPS_BASE_URL", "http://localhost:8000")
API_TOKEN: str = os.getenv("FIXOPS_API_TOKEN", "")
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")

# Feed source URLs
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# Paths
DATA_DIR = Path(os.getenv("FEED_DATA_DIR", ""))
if not DATA_DIR.name:
    # Resolve relative to the repo root (two levels up from scripts/)
    DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "feeds"

STATE_FILE = DATA_DIR / "feed_state.json"
NVD_CACHE_FILE = DATA_DIR / "nvd_cache.json"
KEV_CACHE_FILE = DATA_DIR / "kev_cache.json"
EPSS_CACHE_FILE = DATA_DIR / "epss_cache.json"
CORRELATED_FILE = DATA_DIR / "correlated_cves.json"

# Tuning
NVD_PAGE_SIZE = 2000  # NVD max per request
NVD_RATE_LIMIT_DELAY = 6.0  # seconds between NVD calls (no API key)
NVD_RATE_LIMIT_DELAY_WITH_KEY = 0.6  # seconds with API key
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2.0  # exponential backoff base (seconds)
BATCH_PUSH_SIZE = 100  # findings per FAIL batch request
HTTP_TIMEOUT = 60.0


# ---------------------------------------------------------------------------
# Data model -- one record per correlated CVE
# ---------------------------------------------------------------------------


@dataclass
class EnrichedCVE:
    """A CVE record enriched with NVD + KEV + EPSS data."""

    cve_id: str
    # NVD fields
    description: str = ""
    cvss_v31_score: Optional[float] = None
    cvss_v31_vector: str = ""
    cvss_v31_severity: str = ""
    cvss_v2_score: Optional[float] = None
    cwe_ids: List[str] = field(default_factory=list)
    published: str = ""
    last_modified: str = ""
    references: List[str] = field(default_factory=list)
    # KEV fields
    is_kev: bool = False
    kev_vendor: str = ""
    kev_product: str = ""
    kev_date_added: str = ""
    kev_due_date: str = ""
    kev_description: str = ""
    kev_required_action: str = ""
    # EPSS fields
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    # Derived
    has_exploit: bool = False
    exploit_maturity: str = "unknown"
    # Metadata
    feed_timestamp: str = ""
    source_feeds: List[str] = field(default_factory=list)

    def to_fail_payload(self) -> Dict[str, Any]:
        """Convert to the FAIL engine batch scoring request schema."""
        return {
            "cve_id": self.cve_id,
            "title": self.description[:200] if self.description else self.cve_id,
            "cvss_score": self.cvss_v31_score or self.cvss_v2_score,
            "epss_score": self.epss_score,
            "is_kev": self.is_kev,
            "has_exploit": self.has_exploit or self.is_kev,
            "exploit_maturity": self.exploit_maturity,
            "active_campaigns": 1 if self.is_kev else 0,
            "asset_criticality": "unknown",
            "data_classification": "none",
            "is_reachable": False,
            "is_internet_facing": False,
            "has_compensating_controls": False,
            "affected_assets": 1,
            "affected_users": 0,
            "compliance_frameworks": [],
            "sla_hours": None,
            "metadata": {
                "cwe_ids": self.cwe_ids,
                "cvss_vector": self.cvss_v31_vector,
                "published": self.published,
                "source_feeds": self.source_feeds,
                "kev_due_date": self.kev_due_date,
                "epss_percentile": self.epss_percentile,
            },
        }


# ---------------------------------------------------------------------------
# Feed state persistence (avoid duplicate processing)
# ---------------------------------------------------------------------------


class FeedState:
    """Tracks last-fetch timestamps and processed CVE IDs to avoid re-work."""

    def __init__(self, state_path: Path = STATE_FILE):
        self._path = state_path
        self._data: Dict[str, Any] = {
            "last_nvd_fetch": None,
            "last_kev_fetch": None,
            "last_epss_fetch": None,
            "last_push": None,
            "processed_cve_ids": [],
            "total_pushed": 0,
            "total_iterations": 0,
        }
        self._load()

    def _load(self):
        if self._path.exists():
            try:
                with open(self._path) as f:
                    stored = json.load(f)
                self._data.update(stored)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Could not load feed state: %s", exc)

    def save(self):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(self._data, f, indent=2, default=str)
        tmp.replace(self._path)

    def get(self, key: str) -> Any:
        return self._data.get(key)

    def set(self, key: str, value: Any):
        self._data[key] = value

    @property
    def processed_ids(self) -> Set[str]:
        return set(self._data.get("processed_cve_ids", []))

    def mark_processed(self, cve_ids: List[str]):
        existing = set(self._data.get("processed_cve_ids", []))
        existing.update(cve_ids)
        # Keep only the most recent 50_000 IDs to bound memory
        if len(existing) > 50_000:
            existing = set(list(existing)[-50_000:])
        self._data["processed_cve_ids"] = list(existing)

    def increment_pushed(self, count: int):
        self._data["total_pushed"] = self._data.get("total_pushed", 0) + count

    def increment_iterations(self):
        self._data["total_iterations"] = self._data.get("total_iterations", 0) + 1


# ---------------------------------------------------------------------------
# HTTP helpers with retry + exponential backoff
# ---------------------------------------------------------------------------


async def _request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_retries: int = MAX_RETRIES,
    base_delay: float = RETRY_BASE_DELAY,
    **kwargs,
) -> httpx.Response:
    """Make an HTTP request with retries and exponential backoff.

    Raises httpx.HTTPStatusError on persistent failure.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = await client.request(method, url, **kwargs)
            # Retry on 429 (rate limited) and 5xx server errors
            if resp.status_code == 429 or resp.status_code >= 500:
                retry_after = float(resp.headers.get("Retry-After", 0))
                delay = max(retry_after, base_delay * (2 ** (attempt - 1)))
                logger.warning(
                    "HTTP %d from %s (attempt %d/%d), retrying in %.1fs",
                    resp.status_code,
                    url,
                    attempt,
                    max_retries,
                    delay,
                )
                await asyncio.sleep(delay)
                continue
            return resp
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout) as exc:
            last_exc = exc
            delay = base_delay * (2 ** (attempt - 1))
            logger.warning(
                "Connection error to %s (attempt %d/%d): %s — retrying in %.1fs",
                url,
                attempt,
                max_retries,
                exc,
                delay,
            )
            await asyncio.sleep(delay)
        except httpx.HTTPError as exc:
            last_exc = exc
            delay = base_delay * (2 ** (attempt - 1))
            logger.warning(
                "HTTP error from %s (attempt %d/%d): %s — retrying in %.1fs",
                url,
                attempt,
                max_retries,
                exc,
                delay,
            )
            await asyncio.sleep(delay)

    raise httpx.ConnectError(
        f"All {max_retries} retries exhausted for {url}: {last_exc}"
    )


# ---------------------------------------------------------------------------
# NVD Feed Fetcher
# ---------------------------------------------------------------------------


async def fetch_nvd_cves(
    client: httpx.AsyncClient,
    days: int = 7,
    nvd_api_key: str = "",
) -> List[Dict[str, Any]]:
    """Fetch CVEs published in the last `days` from the NVD 2.0 API.

    Handles pagination and respects NVD rate limits:
      - Without API key: 1 request per 6 seconds
      - With API key: 1 request per 0.6 seconds

    Returns the raw NVD "vulnerabilities" list.
    """
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)

    params: Dict[str, Any] = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": NVD_PAGE_SIZE,
        "startIndex": 0,
    }

    headers: Dict[str, str] = {}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key

    rate_delay = NVD_RATE_LIMIT_DELAY_WITH_KEY if nvd_api_key else NVD_RATE_LIMIT_DELAY
    all_vulns: List[Dict[str, Any]] = []
    total_results = None

    while True:
        logger.info(
            "NVD: fetching page at startIndex=%d (collected %d so far)",
            params["startIndex"],
            len(all_vulns),
        )

        try:
            resp = await _request_with_retry(
                client,
                "GET",
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=httpx.Timeout(HTTP_TIMEOUT),
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.error("NVD fetch failed at index %d: %s", params["startIndex"], exc)
            break

        vulns = data.get("vulnerabilities", [])
        all_vulns.extend(vulns)

        if total_results is None:
            total_results = data.get("totalResults", 0)
            logger.info("NVD: total results for query: %d", total_results)

        # Check if we have all pages
        if len(all_vulns) >= (total_results or 0):
            break

        params["startIndex"] += NVD_PAGE_SIZE

        # Rate limit
        await asyncio.sleep(rate_delay)

    logger.info("NVD: fetched %d CVEs total", len(all_vulns))
    return all_vulns


def parse_nvd_entry(entry: Dict[str, Any]) -> EnrichedCVE:
    """Parse a single NVD vulnerability entry into an EnrichedCVE."""
    cve = entry.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    # Description (English preferred)
    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description:
        descs = cve.get("descriptions", [])
        description = descs[0].get("value", "") if descs else ""

    # CVSS v3.1
    cvss31_score = None
    cvss31_vector = ""
    cvss31_severity = ""
    metrics = cve.get("metrics", {})
    for metric_key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(metric_key, [])
        if metric_list:
            primary = metric_list[0]
            cvss_data = primary.get("cvssData", {})
            cvss31_score = cvss_data.get("baseScore")
            cvss31_vector = cvss_data.get("vectorString", "")
            cvss31_severity = cvss_data.get("baseSeverity", "")
            break

    # CVSS v2 fallback
    cvss2_score = None
    v2_list = metrics.get("cvssMetricV2", [])
    if v2_list:
        cvss2_score = v2_list[0].get("cvssData", {}).get("baseScore")

    # CWE IDs
    cwe_ids: List[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc_item in weakness.get("description", []):
            val = desc_item.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    # References
    refs: List[str] = []
    for ref in cve.get("references", [])[:10]:
        url = ref.get("url", "")
        if url:
            refs.append(url)
        # Detect exploit references
        tags = ref.get("tags", [])
        has_exploit = any(
            t.lower() in ("exploit", "third party advisory") for t in tags
        )

    # Exploit maturity heuristic
    exploit_maturity = "unknown"
    if has_exploit:
        exploit_maturity = "poc_public"

    published = cve.get("published", "")
    last_modified = cve.get("lastModified", "")

    return EnrichedCVE(
        cve_id=cve_id,
        description=description,
        cvss_v31_score=cvss31_score,
        cvss_v31_vector=cvss31_vector,
        cvss_v31_severity=cvss31_severity,
        cvss_v2_score=cvss2_score,
        cwe_ids=cwe_ids,
        published=published,
        last_modified=last_modified,
        references=refs,
        has_exploit=has_exploit,
        exploit_maturity=exploit_maturity,
        feed_timestamp=datetime.now(timezone.utc).isoformat(),
        source_feeds=["nvd"],
    )


# ---------------------------------------------------------------------------
# CISA KEV Feed Fetcher
# ---------------------------------------------------------------------------


async def fetch_kev_catalog(
    client: httpx.AsyncClient,
) -> Dict[str, Dict[str, Any]]:
    """Fetch the full CISA KEV catalog.

    Returns a dict keyed by CVE ID for O(1) correlation lookup.
    """
    logger.info("KEV: fetching CISA Known Exploited Vulnerabilities catalog")

    try:
        resp = await _request_with_retry(
            client,
            "GET",
            CISA_KEV_URL,
            timeout=httpx.Timeout(HTTP_TIMEOUT),
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.error("KEV fetch failed: %s", exc)
        return {}

    vulnerabilities = data.get("vulnerabilities", [])
    kev_map: Dict[str, Dict[str, Any]] = {}

    for vuln in vulnerabilities:
        cve_id = vuln.get("cveID", "")
        if cve_id:
            kev_map[cve_id] = vuln

    logger.info(
        "KEV: loaded %d entries (catalog version: %s, released: %s)",
        len(kev_map),
        data.get("catalogVersion", "?"),
        data.get("dateReleased", "?"),
    )
    return kev_map


# ---------------------------------------------------------------------------
# EPSS Feed Fetcher
# ---------------------------------------------------------------------------


async def fetch_epss_scores(
    client: httpx.AsyncClient,
    cve_ids: List[str],
) -> Dict[str, Dict[str, float]]:
    """Fetch EPSS scores for a list of CVE IDs.

    The FIRST EPSS API accepts up to ~100 CVEs per request via the
    `cve` query parameter (comma-separated).

    Returns a dict keyed by CVE ID: {"score": float, "percentile": float}.
    """
    if not cve_ids:
        return {}

    epss_map: Dict[str, Dict[str, float]] = {}

    # Process in chunks of 100 (EPSS API limit)
    chunk_size = 100
    chunks = [cve_ids[i : i + chunk_size] for i in range(0, len(cve_ids), chunk_size)]

    for i, chunk in enumerate(chunks):
        cve_param = ",".join(chunk)
        logger.info(
            "EPSS: fetching scores for chunk %d/%d (%d CVEs)",
            i + 1,
            len(chunks),
            len(chunk),
        )

        try:
            resp = await _request_with_retry(
                client,
                "GET",
                EPSS_API_URL,
                params={"cve": cve_param},
                timeout=httpx.Timeout(HTTP_TIMEOUT),
            )
            resp.raise_for_status()
            data = resp.json()

            for entry in data.get("data", []):
                cve_id = entry.get("cve", "")
                if cve_id:
                    try:
                        epss_map[cve_id] = {
                            "score": float(entry.get("epss", 0)),
                            "percentile": float(entry.get("percentile", 0)),
                        }
                    except (ValueError, TypeError):
                        pass
        except Exception as exc:
            logger.warning("EPSS fetch failed for chunk %d: %s", i + 1, exc)

        # Small delay between EPSS requests to be polite
        if i < len(chunks) - 1:
            await asyncio.sleep(1.0)

    logger.info("EPSS: retrieved scores for %d / %d CVEs", len(epss_map), len(cve_ids))
    return epss_map


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------


def correlate_feeds(
    nvd_cves: List[EnrichedCVE],
    kev_map: Dict[str, Dict[str, Any]],
    epss_map: Dict[str, Dict[str, float]],
) -> List[EnrichedCVE]:
    """Merge NVD + KEV + EPSS data per CVE ID.

    Each CVE from NVD is enriched with KEV and EPSS data where available.
    """
    correlated: List[EnrichedCVE] = []

    for cve in nvd_cves:
        # Enrich with KEV data
        kev_entry = kev_map.get(cve.cve_id)
        if kev_entry:
            cve.is_kev = True
            cve.kev_vendor = kev_entry.get("vendorProject", "")
            cve.kev_product = kev_entry.get("product", "")
            cve.kev_date_added = kev_entry.get("dateAdded", "")
            cve.kev_due_date = kev_entry.get("dueDate", "")
            cve.kev_description = kev_entry.get("shortDescription", "")
            cve.kev_required_action = kev_entry.get("requiredAction", "")
            cve.has_exploit = True
            if cve.exploit_maturity in ("unknown", "theoretical"):
                cve.exploit_maturity = "weaponized"
            if "kev" not in cve.source_feeds:
                cve.source_feeds.append("kev")

        # Enrich with EPSS data
        epss_entry = epss_map.get(cve.cve_id)
        if epss_entry:
            cve.epss_score = epss_entry.get("score")
            cve.epss_percentile = epss_entry.get("percentile")
            if "epss" not in cve.source_feeds:
                cve.source_feeds.append("epss")

        correlated.append(cve)

    # Sort by risk: KEV first, then by EPSS desc, then by CVSS desc
    correlated.sort(
        key=lambda c: (
            -(1 if c.is_kev else 0),
            -(c.epss_score or 0),
            -(c.cvss_v31_score or c.cvss_v2_score or 0),
        )
    )

    kev_count = sum(1 for c in correlated if c.is_kev)
    epss_count = sum(1 for c in correlated if c.epss_score is not None)
    logger.info(
        "Correlation: %d CVEs total, %d in KEV, %d with EPSS scores",
        len(correlated),
        kev_count,
        epss_count,
    )

    return correlated


# ---------------------------------------------------------------------------
# FAIL API Push
# ---------------------------------------------------------------------------


async def push_to_fail_engine(
    client: httpx.AsyncClient,
    cves: List[EnrichedCVE],
    batch_size: int = BATCH_PUSH_SIZE,
) -> Dict[str, int]:
    """Push enriched CVEs to ALdeci FAIL scoring endpoint in batches.

    Uses POST /api/v1/fail/score/batch with up to `batch_size` findings
    per request.

    Returns {"pushed": int, "failed": int, "skipped": int}.
    """
    stats = {"pushed": 0, "failed": 0, "skipped": 0, "total_score": 0.0}

    if not cves:
        logger.info("FAIL push: no CVEs to push")
        return stats

    # Build batches
    payloads = [cve.to_fail_payload() for cve in cves]
    batches = [
        payloads[i : i + batch_size] for i in range(0, len(payloads), batch_size)
    ]

    for i, batch in enumerate(batches):
        logger.info(
            "FAIL push: sending batch %d/%d (%d findings)",
            i + 1,
            len(batches),
            len(batch),
        )

        body = {"findings": batch}

        try:
            resp = await _request_with_retry(
                client,
                "POST",
                f"{BASE_URL}/api/v1/fail/score/batch",
                json=body,
                timeout=httpx.Timeout(120.0),
            )

            if resp.status_code in (200, 201):
                result = resp.json()
                batch_total = result.get("total", 0)
                stats["pushed"] += batch_total

                # Log grade distribution from response
                resp_stats = result.get("stats", {})
                grade_dist = resp_stats.get("grade_distribution", {})
                if grade_dist:
                    logger.info(
                        "FAIL batch %d results: CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d INFO=%d",
                        i + 1,
                        grade_dist.get("CRITICAL", 0),
                        grade_dist.get("HIGH", 0),
                        grade_dist.get("MEDIUM", 0),
                        grade_dist.get("LOW", 0),
                        grade_dist.get("INFO", 0),
                    )
            elif resp.status_code == 422:
                logger.warning(
                    "FAIL batch %d rejected (422): %s",
                    i + 1,
                    resp.text[:500],
                )
                stats["failed"] += len(batch)
            else:
                logger.warning(
                    "FAIL batch %d returned %d: %s",
                    i + 1,
                    resp.status_code,
                    resp.text[:200],
                )
                stats["failed"] += len(batch)

        except Exception as exc:
            logger.error("FAIL batch %d push failed: %s", i + 1, exc)
            stats["failed"] += len(batch)

    logger.info(
        "FAIL push complete: pushed=%d failed=%d skipped=%d",
        stats["pushed"],
        stats["failed"],
        stats["skipped"],
    )
    return stats


# ---------------------------------------------------------------------------
# Cache helpers -- persist feed data to disk
# ---------------------------------------------------------------------------


def _save_cache(path: Path, data: Any):
    """Atomically write JSON cache to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, default=str)
    tmp.replace(path)


def _load_cache(path: Path) -> Optional[Any]:
    """Load JSON cache from disk, return None if missing or corrupt."""
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def save_correlated_cves(cves: List[EnrichedCVE]):
    """Save correlated CVE data to disk for offline access."""
    records = [asdict(cve) for cve in cves]
    _save_cache(CORRELATED_FILE, {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "count": len(records),
        "cves": records,
    })
    logger.info("Saved %d correlated CVEs to %s", len(records), CORRELATED_FILE)


# ---------------------------------------------------------------------------
# Demo Mode -- synthetic data for offline / demo environments
# ---------------------------------------------------------------------------

# Realistic CVE templates based on real-world patterns
_DEMO_CVES = [
    {
        "cve_id": "CVE-2024-3094",
        "description": "Malicious code was discovered in the upstream tarballs of xz-utils, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file that modifies specific functions in the code.",
        "cvss_v31_score": 10.0,
        "cvss_v31_severity": "CRITICAL",
        "cwe_ids": ["CWE-506"],
        "is_kev": True,
        "epss_score": 0.97,
        "epss_percentile": 0.999,
        "exploit_maturity": "weaponized",
        "kev_vendor": "Tukaani",
        "kev_product": "xz-utils",
    },
    {
        "cve_id": "CVE-2024-21762",
        "description": "A out-of-bounds write vulnerability in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13 allows attacker to execute unauthorized code via specially crafted requests.",
        "cvss_v31_score": 9.8,
        "cvss_v31_severity": "CRITICAL",
        "cwe_ids": ["CWE-787"],
        "is_kev": True,
        "epss_score": 0.94,
        "epss_percentile": 0.998,
        "exploit_maturity": "weaponized",
        "kev_vendor": "Fortinet",
        "kev_product": "FortiOS",
    },
    {
        "cve_id": "CVE-2024-1709",
        "description": "ConnectWise ScreenConnect 23.9.7 and prior are affected by an Authentication Bypass Using an Alternate Path or Channel vulnerability, which may allow an attacker direct access to confidential information or critical systems.",
        "cvss_v31_score": 10.0,
        "cvss_v31_severity": "CRITICAL",
        "cwe_ids": ["CWE-288"],
        "is_kev": True,
        "epss_score": 0.96,
        "epss_percentile": 0.998,
        "exploit_maturity": "weaponized",
        "kev_vendor": "ConnectWise",
        "kev_product": "ScreenConnect",
    },
    {
        "cve_id": "CVE-2023-44487",
        "description": "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023 (Rapid Reset Attack).",
        "cvss_v31_score": 7.5,
        "cvss_v31_severity": "HIGH",
        "cwe_ids": ["CWE-400"],
        "is_kev": True,
        "epss_score": 0.82,
        "epss_percentile": 0.98,
        "exploit_maturity": "weaponized",
        "kev_vendor": "IETF",
        "kev_product": "HTTP/2",
    },
    {
        "cve_id": "CVE-2024-23897",
        "description": "Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files.",
        "cvss_v31_score": 9.8,
        "cvss_v31_severity": "CRITICAL",
        "cwe_ids": ["CWE-22"],
        "is_kev": True,
        "epss_score": 0.89,
        "epss_percentile": 0.995,
        "exploit_maturity": "poc_public",
        "kev_vendor": "Jenkins",
        "kev_product": "Jenkins",
    },
    {
        "cve_id": "CVE-2024-6387",
        "description": "A signal handler race condition was found in OpenSSH's server (sshd), where a client does not authenticate within LoginGraceTime seconds (120 by default, 600 in old OpenSSH versions), then sshd's SIGALRM handler is called asynchronously.",
        "cvss_v31_score": 8.1,
        "cvss_v31_severity": "HIGH",
        "cwe_ids": ["CWE-362", "CWE-364"],
        "is_kev": False,
        "epss_score": 0.45,
        "epss_percentile": 0.95,
        "exploit_maturity": "poc_public",
        "kev_vendor": "OpenSSH",
        "kev_product": "OpenSSH",
    },
    {
        "cve_id": "CVE-2024-27198",
        "description": "In JetBrains TeamCity before 2023.11.4, authentication bypass was possible, allowing an attacker to perform admin actions.",
        "cvss_v31_score": 9.8,
        "cvss_v31_severity": "CRITICAL",
        "cwe_ids": ["CWE-288"],
        "is_kev": True,
        "epss_score": 0.92,
        "epss_percentile": 0.997,
        "exploit_maturity": "weaponized",
        "kev_vendor": "JetBrains",
        "kev_product": "TeamCity",
    },
    {
        "cve_id": "CVE-2024-4577",
        "description": "In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use \"Best-Fit\" behavior to replace characters in command line given to Win32 API functions.",
        "cvss_v31_score": 9.8,
        "cvss_v31_severity": "CRITICAL",
        "cwe_ids": ["CWE-78"],
        "is_kev": True,
        "epss_score": 0.88,
        "epss_percentile": 0.994,
        "exploit_maturity": "weaponized",
        "kev_vendor": "PHP Group",
        "kev_product": "PHP",
    },
    {
        "cve_id": "CVE-2024-47575",
        "description": "A missing authentication for critical function vulnerability in FortiManager fgfmd daemon may allow a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted requests.",
        "cvss_v31_score": 9.8,
        "cvss_v31_severity": "CRITICAL",
        "cwe_ids": ["CWE-306"],
        "is_kev": True,
        "epss_score": 0.91,
        "epss_percentile": 0.996,
        "exploit_maturity": "weaponized",
        "kev_vendor": "Fortinet",
        "kev_product": "FortiManager",
    },
    {
        "cve_id": "CVE-2024-0012",
        "description": "An authentication bypass in Palo Alto Networks PAN-OS software enables an unauthenticated attacker with network access to the management web interface to gain PAN-OS administrator privileges.",
        "cvss_v31_score": 9.8,
        "cvss_v31_severity": "CRITICAL",
        "cwe_ids": ["CWE-306"],
        "is_kev": True,
        "epss_score": 0.87,
        "epss_percentile": 0.993,
        "exploit_maturity": "weaponized",
        "kev_vendor": "Palo Alto Networks",
        "kev_product": "PAN-OS",
    },
    {
        "cve_id": "CVE-2024-20353",
        "description": "A vulnerability in the management and VPN web servers for Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause the device to reload unexpectedly.",
        "cvss_v31_score": 8.6,
        "cvss_v31_severity": "HIGH",
        "cwe_ids": ["CWE-835"],
        "is_kev": True,
        "epss_score": 0.74,
        "epss_percentile": 0.97,
        "exploit_maturity": "poc_public",
        "kev_vendor": "Cisco",
        "kev_product": "ASA",
    },
    {
        "cve_id": "CVE-2024-29824",
        "description": "An unspecified SQL Injection vulnerability in Core server of Ivanti EPM 2022 SU5 and prior allows an unauthenticated attacker within the same network to execute arbitrary code.",
        "cvss_v31_score": 9.6,
        "cvss_v31_severity": "CRITICAL",
        "cwe_ids": ["CWE-89"],
        "is_kev": True,
        "epss_score": 0.85,
        "epss_percentile": 0.99,
        "exploit_maturity": "weaponized",
        "kev_vendor": "Ivanti",
        "kev_product": "EPM",
    },
    {
        "cve_id": "CVE-2024-38812",
        "description": "The vCenter Server contains a heap-overflow vulnerability in the implementation of the DCERPC protocol. A malicious actor with network access to vCenter Server may trigger this vulnerability by sending a specially crafted network packet.",
        "cvss_v31_score": 9.8,
        "cvss_v31_severity": "CRITICAL",
        "cwe_ids": ["CWE-122"],
        "is_kev": False,
        "epss_score": 0.55,
        "epss_percentile": 0.96,
        "exploit_maturity": "poc_public",
        "kev_vendor": "VMware",
        "kev_product": "vCenter Server",
    },
    {
        "cve_id": "CVE-2024-9474",
        "description": "A privilege escalation vulnerability in Palo Alto Networks PAN-OS software allows a PAN-OS administrator with access to the management web interface to perform actions on the firewall with root privileges.",
        "cvss_v31_score": 7.2,
        "cvss_v31_severity": "HIGH",
        "cwe_ids": ["CWE-78"],
        "is_kev": True,
        "epss_score": 0.67,
        "epss_percentile": 0.97,
        "exploit_maturity": "poc_public",
        "kev_vendor": "Palo Alto Networks",
        "kev_product": "PAN-OS",
    },
    {
        "cve_id": "CVE-2024-50623",
        "description": "In Cleo Harmony, VLTrader, and LexiCom before specified versions, there is unrestricted file upload and download that could lead to remote code execution.",
        "cvss_v31_score": 9.8,
        "cvss_v31_severity": "CRITICAL",
        "cwe_ids": ["CWE-434"],
        "is_kev": True,
        "epss_score": 0.90,
        "epss_percentile": 0.996,
        "exploit_maturity": "weaponized",
        "kev_vendor": "Cleo",
        "kev_product": "Harmony/VLTrader/LexiCom",
    },
    # Medium-severity vulns for realistic distribution
    {
        "cve_id": "CVE-2024-12345",
        "description": "A cross-site scripting (XSS) vulnerability in the admin panel of ExampleApp allows authenticated attackers to inject arbitrary web scripts via the username parameter.",
        "cvss_v31_score": 5.4,
        "cvss_v31_severity": "MEDIUM",
        "cwe_ids": ["CWE-79"],
        "is_kev": False,
        "epss_score": 0.12,
        "epss_percentile": 0.60,
        "exploit_maturity": "theoretical",
    },
    {
        "cve_id": "CVE-2024-12346",
        "description": "A server-side request forgery vulnerability in API gateway component allows attackers to scan internal network resources via crafted URL parameters.",
        "cvss_v31_score": 6.5,
        "cvss_v31_severity": "MEDIUM",
        "cwe_ids": ["CWE-918"],
        "is_kev": False,
        "epss_score": 0.08,
        "epss_percentile": 0.45,
        "exploit_maturity": "theoretical",
    },
    {
        "cve_id": "CVE-2024-12347",
        "description": "Improper input validation in file upload functionality allows authenticated users to upload files with dangerous types, potentially leading to code execution.",
        "cvss_v31_score": 7.2,
        "cvss_v31_severity": "HIGH",
        "cwe_ids": ["CWE-434"],
        "is_kev": False,
        "epss_score": 0.22,
        "epss_percentile": 0.75,
        "exploit_maturity": "poc_public",
    },
    {
        "cve_id": "CVE-2024-12348",
        "description": "An insecure direct object reference in the user profile API endpoint allows authenticated users to access other users' personal data by modifying the user_id parameter.",
        "cvss_v31_score": 4.3,
        "cvss_v31_severity": "MEDIUM",
        "cwe_ids": ["CWE-639"],
        "is_kev": False,
        "epss_score": 0.03,
        "epss_percentile": 0.30,
        "exploit_maturity": "theoretical",
    },
    {
        "cve_id": "CVE-2024-12349",
        "description": "Information disclosure vulnerability in error handling reveals internal file paths, database connection strings, and stack traces to unauthenticated users.",
        "cvss_v31_score": 3.7,
        "cvss_v31_severity": "LOW",
        "cwe_ids": ["CWE-209"],
        "is_kev": False,
        "epss_score": 0.01,
        "epss_percentile": 0.15,
        "exploit_maturity": "theoretical",
    },
]


def generate_demo_cves(count: int = 20) -> List[EnrichedCVE]:
    """Generate realistic synthetic CVE data for demo / offline mode.

    Uses real-world CVE patterns with actual CWE IDs and realistic
    CVSS/EPSS score distributions.
    """
    now = datetime.now(timezone.utc)
    cves: List[EnrichedCVE] = []

    templates = _DEMO_CVES[:count]
    for tmpl in templates:
        # Add some randomness to timestamps
        published_offset = random.randint(0, 30)
        published = (now - timedelta(days=published_offset)).isoformat()

        cve = EnrichedCVE(
            cve_id=tmpl["cve_id"],
            description=tmpl["description"],
            cvss_v31_score=tmpl.get("cvss_v31_score"),
            cvss_v31_severity=tmpl.get("cvss_v31_severity", ""),
            cwe_ids=tmpl.get("cwe_ids", []),
            published=published,
            last_modified=now.isoformat(),
            is_kev=tmpl.get("is_kev", False),
            kev_vendor=tmpl.get("kev_vendor", ""),
            kev_product=tmpl.get("kev_product", ""),
            kev_date_added=(now - timedelta(days=random.randint(1, 90))).strftime(
                "%Y-%m-%d"
            ),
            kev_due_date=(now + timedelta(days=random.randint(7, 30))).strftime(
                "%Y-%m-%d"
            )
            if tmpl.get("is_kev")
            else "",
            epss_score=tmpl.get("epss_score"),
            epss_percentile=tmpl.get("epss_percentile"),
            has_exploit=tmpl.get("is_kev", False)
            or tmpl.get("exploit_maturity", "unknown") != "unknown",
            exploit_maturity=tmpl.get("exploit_maturity", "unknown"),
            feed_timestamp=now.isoformat(),
            source_feeds=["demo"],
        )
        cves.append(cve)

    logger.info("Demo: generated %d synthetic CVEs", len(cves))
    return cves


# ---------------------------------------------------------------------------
# Main pipeline orchestrator
# ---------------------------------------------------------------------------


async def run_pipeline(
    days: int = 7,
    push: bool = True,
    demo: bool = False,
) -> Dict[str, Any]:
    """Execute the full feed pipeline: fetch -> correlate -> push.

    Returns a summary dict with counts and timing.
    """
    pipeline_start = time.monotonic()
    state = FeedState()
    summary: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "demo" if demo else "live",
        "days": days,
        "nvd_count": 0,
        "kev_count": 0,
        "epss_count": 0,
        "correlated_count": 0,
        "new_count": 0,
        "push_stats": {},
        "duration_seconds": 0,
        "errors": [],
    }

    if demo:
        # Demo mode: use synthetic data, no network calls
        cves = generate_demo_cves(count=20)
        summary["nvd_count"] = len(cves)
        summary["kev_count"] = sum(1 for c in cves if c.is_kev)
        summary["epss_count"] = sum(1 for c in cves if c.epss_score is not None)
        summary["correlated_count"] = len(cves)
        summary["new_count"] = len(cves)

        if push:
            headers = {}
            if API_TOKEN:
                headers["X-API-Key"] = API_TOKEN

            async with httpx.AsyncClient(headers=headers) as client:
                try:
                    push_stats = await push_to_fail_engine(client, cves)
                    summary["push_stats"] = push_stats
                    state.increment_pushed(push_stats.get("pushed", 0))
                except Exception as exc:
                    logger.error("Demo push failed: %s", exc)
                    summary["errors"].append(f"Push failed: {exc}")

        save_correlated_cves(cves)
        state.increment_iterations()
        state.save()

        summary["duration_seconds"] = round(time.monotonic() - pipeline_start, 2)
        return summary

    # Live mode: fetch from real APIs
    headers = {}
    if API_TOKEN:
        headers["X-API-Key"] = API_TOKEN

    async with httpx.AsyncClient(headers=headers) as client:
        # Step 1: Fetch NVD CVEs
        nvd_raw: List[Dict[str, Any]] = []
        try:
            nvd_raw = await fetch_nvd_cves(client, days=days, nvd_api_key=NVD_API_KEY)
            state.set("last_nvd_fetch", datetime.now(timezone.utc).isoformat())
        except Exception as exc:
            logger.error("NVD fetch pipeline error: %s", exc)
            summary["errors"].append(f"NVD: {exc}")

        # Parse NVD entries
        nvd_cves: List[EnrichedCVE] = []
        for entry in nvd_raw:
            try:
                cve = parse_nvd_entry(entry)
                nvd_cves.append(cve)
            except Exception as exc:
                logger.warning("Failed to parse NVD entry: %s", exc)

        summary["nvd_count"] = len(nvd_cves)
        logger.info("Parsed %d NVD CVEs", len(nvd_cves))

        # Step 2: Fetch KEV catalog
        kev_map: Dict[str, Dict[str, Any]] = {}
        try:
            kev_map = await fetch_kev_catalog(client)
            state.set("last_kev_fetch", datetime.now(timezone.utc).isoformat())
        except Exception as exc:
            logger.error("KEV fetch pipeline error: %s", exc)
            summary["errors"].append(f"KEV: {exc}")

        summary["kev_count"] = len(kev_map)

        # Step 3: Fetch EPSS scores for all NVD CVEs
        cve_ids = [c.cve_id for c in nvd_cves]
        epss_map: Dict[str, Dict[str, float]] = {}
        if cve_ids:
            try:
                epss_map = await fetch_epss_scores(client, cve_ids)
                state.set("last_epss_fetch", datetime.now(timezone.utc).isoformat())
            except Exception as exc:
                logger.error("EPSS fetch pipeline error: %s", exc)
                summary["errors"].append(f"EPSS: {exc}")

        summary["epss_count"] = len(epss_map)

        # Step 4: Correlate
        correlated = correlate_feeds(nvd_cves, kev_map, epss_map)
        summary["correlated_count"] = len(correlated)

        # Filter out previously processed CVEs
        already_processed = state.processed_ids
        new_cves = [c for c in correlated if c.cve_id not in already_processed]
        summary["new_count"] = len(new_cves)

        if not new_cves:
            logger.info("No new CVEs to process (all %d already seen)", len(correlated))
        else:
            logger.info(
                "%d new CVEs to process (%d already seen)",
                len(new_cves),
                len(correlated) - len(new_cves),
            )

        # Step 5: Push to FAIL engine
        if push and new_cves:
            try:
                push_stats = await push_to_fail_engine(client, new_cves)
                summary["push_stats"] = push_stats
                state.increment_pushed(push_stats.get("pushed", 0))
                state.mark_processed([c.cve_id for c in new_cves])
            except Exception as exc:
                logger.error("FAIL push pipeline error: %s", exc)
                summary["errors"].append(f"Push: {exc}")

        # Persist correlated data and state
        save_correlated_cves(correlated)
        state.set("last_push", datetime.now(timezone.utc).isoformat())
        state.increment_iterations()
        state.save()

    summary["duration_seconds"] = round(time.monotonic() - pipeline_start, 2)

    logger.info(
        "Pipeline complete in %.1fs: %d NVD, %d KEV matched, %d EPSS, %d new -> %s",
        summary["duration_seconds"],
        summary["nvd_count"],
        summary["kev_count"],
        summary["epss_count"],
        summary["new_count"],
        json.dumps(summary.get("push_stats", {})),
    )

    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="feed_sidecar",
        description="ALdeci CVE Intelligence Feed Sidecar",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # One-shot fetch + push
  python scripts/feed_sidecar.py once --days 7

  # Continuous mode (Docker sidecar)
  python scripts/feed_sidecar.py continuous --interval 3600

  # Demo mode (offline, synthetic data)
  python scripts/feed_sidecar.py demo

  # Health check
  python scripts/feed_sidecar.py health
        """,
    )

    sub = parser.add_subparsers(dest="command", help="Command to run")

    # --- once ---
    once_p = sub.add_parser("once", help="Single fetch-correlate-push cycle")
    once_p.add_argument(
        "--days",
        type=int,
        default=7,
        help="NVD lookback window in days (default: 7)",
    )
    once_p.add_argument(
        "--no-push",
        action="store_true",
        help="Fetch and correlate only, do not push to FAIL engine",
    )

    # --- continuous ---
    cont_p = sub.add_parser("continuous", help="Run in a loop (Docker sidecar mode)")
    cont_p.add_argument(
        "--interval",
        "-i",
        type=int,
        default=3600,
        help="Polling interval in seconds (default: 3600)",
    )
    cont_p.add_argument(
        "--days",
        type=int,
        default=1,
        help="NVD lookback window in days per iteration (default: 1)",
    )
    cont_p.add_argument(
        "--no-push",
        action="store_true",
        help="Fetch and correlate only",
    )

    # --- demo ---
    demo_p = sub.add_parser("demo", help="Generate synthetic data (offline mode)")
    demo_p.add_argument(
        "--count",
        type=int,
        default=20,
        help="Number of synthetic CVEs to generate (default: 20, max: 20)",
    )
    demo_p.add_argument(
        "--no-push",
        action="store_true",
        help="Generate data only, do not push to FAIL engine",
    )

    # --- health ---
    sub.add_parser("health", help="Check feed sources and ALdeci API health")

    return parser


async def cmd_health():
    """Probe all feed sources and the ALdeci API."""
    results: Dict[str, Dict[str, Any]] = {}

    async with httpx.AsyncClient() as client:
        # NVD
        try:
            resp = await client.get(
                NVD_API_URL, params={"resultsPerPage": 1}, timeout=10.0
            )
            results["nvd"] = {
                "status": "ok" if resp.status_code == 200 else "degraded",
                "http_code": resp.status_code,
                "url": NVD_API_URL,
            }
        except Exception as exc:
            results["nvd"] = {"status": "error", "error": str(exc), "url": NVD_API_URL}

        # KEV
        try:
            resp = await client.get(CISA_KEV_URL, timeout=10.0)
            kev_ok = resp.status_code == 200
            kev_count = 0
            if kev_ok:
                kev_count = len(resp.json().get("vulnerabilities", []))
            results["kev"] = {
                "status": "ok" if kev_ok else "degraded",
                "http_code": resp.status_code,
                "entries": kev_count,
                "url": CISA_KEV_URL,
            }
        except Exception as exc:
            results["kev"] = {
                "status": "error",
                "error": str(exc),
                "url": CISA_KEV_URL,
            }

        # EPSS
        try:
            resp = await client.get(
                EPSS_API_URL, params={"cve": "CVE-2024-3094"}, timeout=10.0
            )
            results["epss"] = {
                "status": "ok" if resp.status_code == 200 else "degraded",
                "http_code": resp.status_code,
                "url": EPSS_API_URL,
            }
        except Exception as exc:
            results["epss"] = {
                "status": "error",
                "error": str(exc),
                "url": EPSS_API_URL,
            }

        # ALdeci API
        try:
            headers = {}
            if API_TOKEN:
                headers["X-API-Key"] = API_TOKEN
            resp = await client.get(f"{BASE_URL}/health", headers=headers, timeout=5.0)
            results["aldeci_api"] = {
                "status": "ok" if resp.status_code == 200 else "degraded",
                "http_code": resp.status_code,
                "url": BASE_URL,
            }
        except Exception as exc:
            results["aldeci_api"] = {
                "status": "error",
                "error": str(exc),
                "url": BASE_URL,
            }

        # FAIL engine
        try:
            resp = await client.get(
                f"{BASE_URL}/api/v1/fail/health", headers=headers, timeout=5.0
            )
            results["fail_engine"] = {
                "status": "ok" if resp.status_code == 200 else "degraded",
                "http_code": resp.status_code,
                "data": resp.json() if resp.status_code == 200 else None,
            }
        except Exception as exc:
            results["fail_engine"] = {"status": "error", "error": str(exc)}

    # Feed state
    state = FeedState()
    results["feed_state"] = {
        "last_nvd_fetch": state.get("last_nvd_fetch"),
        "last_kev_fetch": state.get("last_kev_fetch"),
        "last_epss_fetch": state.get("last_epss_fetch"),
        "last_push": state.get("last_push"),
        "total_pushed": state.get("total_pushed"),
        "total_iterations": state.get("total_iterations"),
        "processed_ids_count": len(state.processed_ids),
    }

    # Print results
    all_ok = all(r.get("status") == "ok" for r in results.values() if "status" in r)

    print("\n=== ALdeci Feed Sidecar Health Check ===\n")
    for name, info in results.items():
        status = info.get("status", "N/A")
        marker = "[OK]" if status == "ok" else "[!!]" if status == "error" else "[??]"
        print(f"  {marker} {name}: {json.dumps(info, indent=4, default=str)}")

    overall = "HEALTHY" if all_ok else "DEGRADED"
    print(f"\n  Overall: {overall}\n")

    return results


def main():
    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Ensure data directory exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if args.command == "health":
        asyncio.run(cmd_health())

    elif args.command == "once":
        logger.info(
            "Starting one-shot pipeline (days=%d, push=%s)",
            args.days,
            not args.no_push,
        )
        summary = asyncio.run(
            run_pipeline(days=args.days, push=not args.no_push, demo=False)
        )
        print(json.dumps(summary, indent=2, default=str))

    elif args.command == "demo":
        logger.info(
            "Starting demo pipeline (count=%d, push=%s)",
            args.count,
            not args.no_push,
        )
        summary = asyncio.run(
            run_pipeline(days=0, push=not args.no_push, demo=True)
        )
        print(json.dumps(summary, indent=2, default=str))

    elif args.command == "continuous":
        interval = max(60, args.interval)  # Minimum 60 seconds
        logger.info(
            "Starting continuous pipeline (interval=%ds, days=%d, push=%s)",
            interval,
            args.days,
            not args.no_push,
        )

        # Handle graceful shutdown
        shutdown = asyncio.Event()

        def _signal_handler(signum, frame):
            logger.info("Received signal %d, shutting down gracefully...", signum)
            shutdown.set()

        signal.signal(signal.SIGTERM, _signal_handler)
        signal.signal(signal.SIGINT, _signal_handler)

        async def _continuous_loop():
            iteration = 0
            while not shutdown.is_set():
                iteration += 1
                logger.info(
                    "=== Continuous iteration %d (next in %ds) ===",
                    iteration,
                    interval,
                )

                try:
                    summary = await run_pipeline(
                        days=args.days,
                        push=not args.no_push,
                        demo=False,
                    )
                    errors = summary.get("errors", [])
                    if errors:
                        logger.warning(
                            "Iteration %d completed with %d errors: %s",
                            iteration,
                            len(errors),
                            errors,
                        )
                    else:
                        logger.info(
                            "Iteration %d completed successfully in %.1fs",
                            iteration,
                            summary.get("duration_seconds", 0),
                        )
                except Exception as exc:
                    logger.error(
                        "Iteration %d failed with unhandled exception: %s",
                        iteration,
                        exc,
                        exc_info=True,
                    )

                # Wait for the interval or shutdown signal
                try:
                    await asyncio.wait_for(
                        asyncio.ensure_future(_wait_for_event(shutdown)),
                        timeout=interval,
                    )
                    # If we get here, shutdown was signalled
                    break
                except asyncio.TimeoutError:
                    # Normal timeout, continue to next iteration
                    pass

            logger.info("Continuous loop stopped after %d iterations", iteration)

        asyncio.run(_continuous_loop())

    else:
        parser.print_help()
        sys.exit(1)


async def _wait_for_event(event: asyncio.Event):
    """Await an asyncio.Event (helper for wait_for timeout pattern)."""
    await event.wait()


if __name__ == "__main__":
    main()
