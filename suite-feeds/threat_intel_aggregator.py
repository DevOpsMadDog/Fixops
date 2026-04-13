"""Real Threat Intelligence Aggregation Engine.

Pulls live data from free public APIs:
  - NVD CVE 2.0 API  (NIST)
  - EPSS Scores      (FIRST.org)
  - CISA KEV         (Known Exploited Vulnerabilities)
  - OSV              (open-source ecosystem vulns)
  - OTX AlienVault  (file-cache fallback)

SQLite cache in suite-feeds/data/threat_intel.db avoids hammering APIs.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from requests import RequestException

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_HERE = Path(__file__).parent
DATA_DIR = _HERE / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "threat_intel.db"
OTX_SAMPLE_PATH = DATA_DIR / "otx_sample.json"

# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# Cache TTL constants (seconds)
_CVE_CACHE_TTL = 3600        # 1 hour
_KEV_CACHE_TTL = 21600       # 6 hours
_EPSS_CACHE_TTL = 86400      # 24 hours
_OSV_CACHE_TTL = 43200       # 12 hours

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class CVERecord:
    """Normalised CVE record enriched with EPSS and KEV data."""

    cve_id: str
    severity: str          # NONE / LOW / MEDIUM / HIGH / CRITICAL
    cvss_score: float
    description: str
    published: str         # ISO-8601 date string
    last_modified: str
    affected_products: List[str] = field(default_factory=list)
    epss_score: float = 0.0       # 0.0 – 1.0  exploit probability
    epss_percentile: float = 0.0
    in_kev: bool = False          # In CISA KEV catalog
    kev_due_date: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "published": self.published,
            "last_modified": self.last_modified,
            "affected_products": self.affected_products,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "in_kev": self.in_kev,
            "kev_due_date": self.kev_due_date,
        }


@dataclass
class ThreatIntelReport:
    """Daily aggregation report."""

    generated_at: str
    total_cves: int
    kev_count: int
    critical_count: int
    high_count: int
    avg_epss: float
    top_cves: List[CVERecord]
    osv_count: int = 0
    otx_pulses: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "total_cves": self.total_cves,
            "kev_count": self.kev_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "avg_epss": self.avg_epss,
            "top_cves": [c.to_dict() for c in self.top_cves],
            "osv_count": self.osv_count,
            "otx_pulses": self.otx_pulses,
        }


# ---------------------------------------------------------------------------
# SQLite cache helpers
# ---------------------------------------------------------------------------


def _get_conn(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _init_db(db_path: Path = DB_PATH) -> None:
    conn = _get_conn(db_path)
    with conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id       TEXT PRIMARY KEY,
                data_json    TEXT NOT NULL,
                fetched_at   REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS kev_cache (
                cve_id       TEXT PRIMARY KEY,
                due_date     TEXT,
                fetched_at   REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS epss_cache (
                cve_id       TEXT PRIMARY KEY,
                score        REAL NOT NULL,
                percentile   REAL NOT NULL,
                fetched_at   REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS meta (
                key          TEXT PRIMARY KEY,
                value        TEXT NOT NULL,
                updated_at   REAL NOT NULL
            );
            """
        )
    conn.close()


# ---------------------------------------------------------------------------
# Main aggregator class
# ---------------------------------------------------------------------------


class ThreatIntelAggregator:
    """Aggregates real CVE/EPSS/KEV/OSV threat intelligence with SQLite caching."""

    def __init__(self, db_path: Path = DB_PATH, request_timeout: int = 30) -> None:
        self.db_path = db_path
        self.request_timeout = request_timeout
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "ALDECI-ThreatIntel/1.0"})
        _init_db(self.db_path)

    # ------------------------------------------------------------------
    # NVD CVE feed
    # ------------------------------------------------------------------

    def refresh_cve_feed(self, days_back: int = 7) -> List[CVERecord]:
        """Pull CVEs from NVD published in the last *days_back* days.

        Results are cached in SQLite; cached entries are returned when
        fresh enough (< _CVE_CACHE_TTL seconds old).
        """
        now = datetime.now(timezone.utc)
        pub_start = (now - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00")
        pub_end = now.strftime("%Y-%m-%dT%H:%M:%S")

        params: Dict[str, Any] = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": 100,
            "startIndex": 0,
        }

        all_records: List[CVERecord] = []
        page = 0

        while True:
            params["startIndex"] = page * 100
            try:
                resp = self._session.get(
                    NVD_CVE_URL, params=params, timeout=self.request_timeout
                )
                resp.raise_for_status()
                payload = resp.json()
            except (RequestException, ValueError) as exc:
                logger.warning("NVD CVE fetch failed (page %d): %s", page, exc)
                break

            vulnerabilities = payload.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for item in vulnerabilities:
                record = self._parse_nvd_item(item)
                if record:
                    self._cache_cve(record)
                    all_records.append(record)

            total_results = payload.get("totalResults", 0)
            if (page + 1) * 100 >= total_results:
                break
            page += 1
            time.sleep(0.6)  # NVD rate limit: ~100 req/min without key

        logger.info("NVD: fetched %d CVEs (days_back=%d)", len(all_records), days_back)
        return all_records

    def _parse_nvd_item(self, item: Dict[str, Any]) -> Optional[CVERecord]:
        """Parse a single NVD vulnerability item into a CVERecord."""
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return None

        # Description (English preferred)
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )

        published = cve_data.get("published", "")
        last_modified = cve_data.get("lastModified", "")

        # CVSS score — prefer v3.1 > v3.0 > v2
        metrics = cve_data.get("metrics", {})
        cvss_score = 0.0
        severity = "NONE"

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = float(cvss_data.get("baseScore", 0.0))
                severity = cvss_data.get("baseSeverity", "NONE").upper()
                break

        # Affected products (CPE match strings)
        affected_products: List[str] = []
        configs = cve_data.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe = cpe_match.get("criteria", "")
                    if cpe:
                        affected_products.append(cpe)

        return CVERecord(
            cve_id=cve_id,
            severity=severity,
            cvss_score=cvss_score,
            description=description[:2000],
            published=published,
            last_modified=last_modified,
            affected_products=affected_products[:20],
        )

    def _cache_cve(self, record: CVERecord) -> None:
        conn = _get_conn(self.db_path)
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache (cve_id, data_json, fetched_at) VALUES (?,?,?)",
                (record.cve_id, json.dumps(record.to_dict()), time.time()),
            )
        conn.close()

    def get_cached_cves(self, limit: int = 100) -> List[CVERecord]:
        """Return CVEs from cache (most recently fetched first)."""
        conn = _get_conn(self.db_path)
        rows = conn.execute(
            "SELECT data_json FROM cve_cache ORDER BY fetched_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        records = []
        for row in rows:
            try:
                d = json.loads(row["data_json"])
                records.append(
                    CVERecord(
                        cve_id=d["cve_id"],
                        severity=d.get("severity", "NONE"),
                        cvss_score=d.get("cvss_score", 0.0),
                        description=d.get("description", ""),
                        published=d.get("published", ""),
                        last_modified=d.get("last_modified", ""),
                        affected_products=d.get("affected_products", []),
                        epss_score=d.get("epss_score", 0.0),
                        epss_percentile=d.get("epss_percentile", 0.0),
                        in_kev=d.get("in_kev", False),
                        kev_due_date=d.get("kev_due_date"),
                    )
                )
            except (KeyError, json.JSONDecodeError) as exc:
                logger.debug("Skipping malformed cache row: %s", exc)
        return records

    # ------------------------------------------------------------------
    # EPSS enrichment
    # ------------------------------------------------------------------

    def enrich_with_epss(self, cve_ids: List[str]) -> Dict[str, float]:
        """Return EPSS scores for the given CVE IDs, keyed by CVE ID.

        Uses SQLite cache; only queries FIRST.org for IDs not already cached.
        Returns a dict: {cve_id: epss_score}.
        """
        if not cve_ids:
            return {}

        scores: Dict[str, float] = {}
        to_fetch: List[str] = []
        now = time.time()

        conn = _get_conn(self.db_path)
        for cve_id in cve_ids:
            row = conn.execute(
                "SELECT score, percentile, fetched_at FROM epss_cache WHERE cve_id=?",
                (cve_id,),
            ).fetchone()
            if row and (now - row["fetched_at"]) < _EPSS_CACHE_TTL:
                scores[cve_id] = row["score"]
            else:
                to_fetch.append(cve_id)
        conn.close()

        if not to_fetch:
            return scores

        # EPSS API accepts comma-separated CVE IDs
        batch_size = 50
        for i in range(0, len(to_fetch), batch_size):
            batch = to_fetch[i : i + batch_size]
            cve_param = ",".join(batch)
            try:
                resp = self._session.get(
                    EPSS_API_URL,
                    params={"cve": cve_param},
                    timeout=self.request_timeout,
                )
                resp.raise_for_status()
                data = resp.json()
            except (RequestException, ValueError) as exc:
                logger.warning("EPSS API failed: %s", exc)
                continue

            conn = _get_conn(self.db_path)
            with conn:
                for entry in data.get("data", []):
                    cve_id = entry.get("cve", "")
                    epss = float(entry.get("epss", 0.0))
                    pct = float(entry.get("percentile", 0.0))
                    if cve_id:
                        scores[cve_id] = epss
                        conn.execute(
                            "INSERT OR REPLACE INTO epss_cache (cve_id, score, percentile, fetched_at) VALUES (?,?,?,?)",
                            (cve_id, epss, pct, now),
                        )
            conn.close()

        return scores

    def get_epss_percentile(self, cve_id: str) -> float:
        """Return the EPSS percentile for a single CVE from cache."""
        conn = _get_conn(self.db_path)
        row = conn.execute(
            "SELECT percentile FROM epss_cache WHERE cve_id=?", (cve_id,)
        ).fetchone()
        conn.close()
        return float(row["percentile"]) if row else 0.0

    # ------------------------------------------------------------------
    # CISA KEV
    # ------------------------------------------------------------------

    def refresh_kev(self) -> Dict[str, Optional[str]]:
        """Download the full CISA KEV catalog and cache it.

        Returns a dict of {cve_id: due_date}.
        """
        try:
            resp = self._session.get(CISA_KEV_URL, timeout=self.request_timeout)
            resp.raise_for_status()
            catalog = resp.json()
        except (RequestException, ValueError) as exc:
            logger.warning("CISA KEV fetch failed: %s", exc)
            return self._load_kev_from_cache()

        vulns = catalog.get("vulnerabilities", [])
        kev_map: Dict[str, Optional[str]] = {}
        now = time.time()

        conn = _get_conn(self.db_path)
        with conn:
            for v in vulns:
                cve_id = v.get("cveID", "")
                due_date = v.get("dueDate")
                if cve_id:
                    kev_map[cve_id] = due_date
                    conn.execute(
                        "INSERT OR REPLACE INTO kev_cache (cve_id, due_date, fetched_at) VALUES (?,?,?)",
                        (cve_id, due_date, now),
                    )
            # Store last-fetched timestamp
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value, updated_at) VALUES (?,?,?)",
                ("kev_last_fetched", str(now), now),
            )
        conn.close()

        logger.info("CISA KEV: cached %d entries", len(kev_map))
        return kev_map

    def _load_kev_from_cache(self) -> Dict[str, Optional[str]]:
        conn = _get_conn(self.db_path)
        rows = conn.execute("SELECT cve_id, due_date FROM kev_cache").fetchall()
        conn.close()
        return {row["cve_id"]: row["due_date"] for row in rows}

    def check_kev(self, cve_id: str) -> bool:
        """Return True if *cve_id* is in the CISA KEV catalog (cached)."""
        conn = _get_conn(self.db_path)
        row = conn.execute(
            "SELECT 1 FROM kev_cache WHERE cve_id=?", (cve_id,)
        ).fetchone()
        conn.close()
        return row is not None

    def get_kev_due_date(self, cve_id: str) -> Optional[str]:
        """Return the KEV remediation due date for *cve_id*, or None."""
        conn = _get_conn(self.db_path)
        row = conn.execute(
            "SELECT due_date FROM kev_cache WHERE cve_id=?", (cve_id,)
        ).fetchone()
        conn.close()
        return row["due_date"] if row else None

    # ------------------------------------------------------------------
    # OSV feed (Python + npm ecosystems)
    # ------------------------------------------------------------------

    def fetch_osv_vulns(self, ecosystems: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Query OSV for recent Python/npm vulnerabilities.

        Returns raw OSV vuln dicts (up to 100 per ecosystem).
        """
        if ecosystems is None:
            ecosystems = ["PyPI", "npm"]

        results: List[Dict[str, Any]] = []
        for ecosystem in ecosystems:
            payload = {"package": {"ecosystem": ecosystem}, "page_size": 100}
            try:
                resp = self._session.post(
                    OSV_QUERY_URL, json=payload, timeout=self.request_timeout
                )
                resp.raise_for_status()
                data = resp.json()
                vulns = data.get("vulns", [])
                results.extend(vulns)
                logger.info("OSV: %d vulns for %s", len(vulns), ecosystem)
            except (RequestException, ValueError) as exc:
                logger.warning("OSV fetch failed for %s: %s", ecosystem, exc)

        return results

    # ------------------------------------------------------------------
    # OTX AlienVault (file-cache fallback)
    # ------------------------------------------------------------------

    def load_otx_pulses(self) -> List[Dict[str, Any]]:
        """Load OTX pulses from local file cache (suite-feeds/data/otx_sample.json).

        Returns an empty list if the file does not exist.
        """
        if not OTX_SAMPLE_PATH.exists():
            logger.debug("OTX sample file not found at %s — skipping", OTX_SAMPLE_PATH)
            return []
        try:
            with OTX_SAMPLE_PATH.open() as fh:
                data = json.load(fh)
            pulses = data.get("results", data) if isinstance(data, dict) else data
            logger.info("OTX: loaded %d pulses from file cache", len(pulses))
            return pulses if isinstance(pulses, list) else []
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("OTX file load failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Daily aggregation
    # ------------------------------------------------------------------

    def aggregate_daily(self) -> ThreatIntelReport:
        """Pull all feeds, enrich, and return a ThreatIntelReport.

        Suitable for scheduled execution (e.g. cron, APScheduler).
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Fetch recent CVEs
        cves = self.refresh_cve_feed(days_back=7)

        # 2. Enrich with EPSS
        cve_ids = [c.cve_id for c in cves]
        epss_map = self.enrich_with_epss(cve_ids)
        for cve in cves:
            cve.epss_score = epss_map.get(cve.cve_id, 0.0)

        # 3. Check KEV
        kev_map = self.refresh_kev()
        for cve in cves:
            if cve.cve_id in kev_map:
                cve.in_kev = True
                cve.kev_due_date = kev_map[cve.cve_id]

        # 4. OSV count
        osv_vulns = self.fetch_osv_vulns()
        osv_count = len(osv_vulns)

        # 5. OTX pulses
        otx_pulses = self.load_otx_pulses()
        otx_count = len(otx_pulses)

        # Stats
        kev_count = sum(1 for c in cves if c.in_kev)
        critical_count = sum(1 for c in cves if c.severity == "CRITICAL")
        high_count = sum(1 for c in cves if c.severity == "HIGH")
        avg_epss = (
            sum(c.epss_score for c in cves) / len(cves) if cves else 0.0
        )

        # Top 10 by EPSS score
        top_cves = sorted(cves, key=lambda c: c.epss_score, reverse=True)[:10]

        # Persist enriched records
        for cve in cves:
            self._cache_cve(cve)

        report = ThreatIntelReport(
            generated_at=now_iso,
            total_cves=len(cves),
            kev_count=kev_count,
            critical_count=critical_count,
            high_count=high_count,
            avg_epss=round(avg_epss, 4),
            top_cves=top_cves,
            osv_count=osv_count,
            otx_pulses=otx_count,
        )

        logger.info(
            "Daily report: %d CVEs, %d KEV, %d CRITICAL, avg EPSS=%.4f",
            report.total_cves,
            report.kev_count,
            report.critical_count,
            report.avg_epss,
        )
        return report

    # ------------------------------------------------------------------
    # TrustGraph integration
    # ------------------------------------------------------------------

    def save_to_trustgraph(self, records: List[CVERecord]) -> None:
        """Index CVE records into TrustGraph Knowledge Core 2 (Threat Intel).

        Emits a structured event for each record; downstream TrustGraph
        indexers consume these from the event bus if available.
        """
        try:
            from trustgraph.indexer import TrustGraphIndexer  # type: ignore

            indexer = TrustGraphIndexer()
            for rec in records:
                indexer.index(
                    core="threat_intel",
                    entity_type="cve",
                    entity_id=rec.cve_id,
                    data=rec.to_dict(),
                )
            logger.info("TrustGraph: indexed %d CVE records", len(records))
        except ImportError:
            logger.debug("TrustGraph indexer not available — skipping graph indexing")
        except Exception as exc:  # noqa: BLE001
            logger.warning("TrustGraph indexing failed: %s", exc)
