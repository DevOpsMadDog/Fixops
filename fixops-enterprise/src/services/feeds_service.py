"""CVE/KEV Feed Scheduler for enriching findings with EPSS scores and KEV flags.

This module provides background feed refresh for:
- EPSS (Exploit Prediction Scoring System) from FIRST.org
- KEV (Known Exploited Vulnerabilities) from CISA

EPSS provides probability scores (0-1) indicating likelihood of exploitation.
KEV provides a list of vulnerabilities known to be actively exploited.
"""

from __future__ import annotations

import asyncio
import csv
import gzip
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from requests import RequestException

logger = logging.getLogger(__name__)

# Feed URLs
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class EPSSScore:
    """EPSS score for a CVE."""

    cve_id: str
    epss: float  # Probability of exploitation (0-1)
    percentile: float  # Percentile ranking (0-1)
    date: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "epss": self.epss,
            "percentile": self.percentile,
            "date": self.date,
        }


@dataclass
class KEVEntry:
    """Known Exploited Vulnerability entry from CISA."""

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_campaign_use: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "date_added": self.date_added,
            "short_description": self.short_description,
            "required_action": self.required_action,
            "due_date": self.due_date,
            "known_ransomware_campaign_use": self.known_ransomware_campaign_use,
        }


@dataclass
class FeedRefreshResult:
    """Result of a feed refresh operation."""

    feed_name: str
    success: bool
    records_updated: int
    error: Optional[str] = None
    refreshed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class FeedsService:
    """CVE/KEV Feed Scheduler with EPSS and KEV enrichment."""

    def __init__(self, db_path: Optional[Path] = None, timeout: float = 60.0) -> None:
        """Initialize feeds service with database path."""
        self.db_path = db_path or Path("data/feeds/feeds.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema for feed data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # EPSS scores table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS epss_scores (
                cve_id TEXT PRIMARY KEY,
                epss REAL NOT NULL,
                percentile REAL NOT NULL,
                date TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """
        )

        # KEV entries table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS kev_entries (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                short_description TEXT,
                required_action TEXT,
                due_date TEXT,
                known_ransomware_campaign_use TEXT,
                updated_at TEXT NOT NULL
            )
        """
        )

        # Feed metadata table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS feed_metadata (
                feed_name TEXT PRIMARY KEY,
                last_refresh TEXT,
                records_count INTEGER,
                status TEXT
            )
        """
        )

        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_epss_score ON epss_scores(epss)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_epss_percentile ON epss_scores(percentile)"
        )

        conn.commit()
        conn.close()

    def refresh_epss(self) -> FeedRefreshResult:
        """Refresh EPSS scores from FIRST.org.

        Downloads the compressed CSV file containing EPSS scores for all CVEs
        and updates the local database.

        Returns:
            FeedRefreshResult with refresh status
        """
        try:
            logger.info("Refreshing EPSS scores from FIRST.org")

            # Download compressed CSV
            response = requests.get(EPSS_URL, timeout=self.timeout)
            response.raise_for_status()

            # Decompress and parse CSV
            decompressed = gzip.decompress(response.content)
            csv_content = decompressed.decode("utf-8")

            # Parse CSV (skip header comment lines starting with #)
            lines = csv_content.strip().split("\n")
            data_lines = [line for line in lines if not line.startswith("#")]

            if not data_lines:
                return FeedRefreshResult(
                    feed_name="epss",
                    success=False,
                    records_updated=0,
                    error="No data in EPSS feed",
                )

            reader = csv.DictReader(data_lines)
            records = []
            for row in reader:
                try:
                    cve_id = row.get("cve", "").strip()
                    epss = float(row.get("epss", 0))
                    percentile = float(row.get("percentile", 0))
                    date = row.get(
                        "model_version", datetime.utcnow().strftime("%Y-%m-%d")
                    )

                    if cve_id and cve_id.startswith("CVE-"):
                        records.append(EPSSScore(cve_id, epss, percentile, date))
                except (ValueError, KeyError):
                    continue

            # Batch insert into database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()

            cursor.executemany(
                """
                INSERT OR REPLACE INTO epss_scores
                (cve_id, epss, percentile, date, updated_at)
                VALUES (?, ?, ?, ?, ?)
            """,
                [(r.cve_id, r.epss, r.percentile, r.date, now) for r in records],
            )

            # Update metadata
            cursor.execute(
                """
                INSERT OR REPLACE INTO feed_metadata
                (feed_name, last_refresh, records_count, status)
                VALUES (?, ?, ?, ?)
            """,
                ("epss", now, len(records), "success"),
            )

            conn.commit()
            conn.close()

            logger.info(f"EPSS refresh complete: {len(records)} records updated")

            return FeedRefreshResult(
                feed_name="epss",
                success=True,
                records_updated=len(records),
            )

        except RequestException as exc:
            error_msg = f"Failed to fetch EPSS feed: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="epss",
                success=False,
                records_updated=0,
                error=error_msg,
            )
        except Exception as exc:
            error_msg = f"Error processing EPSS feed: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="epss",
                success=False,
                records_updated=0,
                error=error_msg,
            )

    def refresh_kev(self) -> FeedRefreshResult:
        """Refresh KEV catalog from CISA.

        Downloads the JSON catalog of Known Exploited Vulnerabilities
        and updates the local database.

        Returns:
            FeedRefreshResult with refresh status
        """
        try:
            logger.info("Refreshing KEV catalog from CISA")

            # Download JSON catalog
            response = requests.get(KEV_URL, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            records = []
            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID", "").strip()
                if not cve_id:
                    continue

                entry = KEVEntry(
                    cve_id=cve_id,
                    vendor_project=vuln.get("vendorProject", ""),
                    product=vuln.get("product", ""),
                    vulnerability_name=vuln.get("vulnerabilityName", ""),
                    date_added=vuln.get("dateAdded", ""),
                    short_description=vuln.get("shortDescription", ""),
                    required_action=vuln.get("requiredAction", ""),
                    due_date=vuln.get("dueDate", ""),
                    known_ransomware_campaign_use=vuln.get(
                        "knownRansomwareCampaignUse", "Unknown"
                    ),
                )
                records.append(entry)

            # Batch insert into database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()

            cursor.executemany(
                """
                INSERT OR REPLACE INTO kev_entries
                (cve_id, vendor_project, product, vulnerability_name, date_added,
                 short_description, required_action, due_date, known_ransomware_campaign_use, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                [
                    (
                        r.cve_id,
                        r.vendor_project,
                        r.product,
                        r.vulnerability_name,
                        r.date_added,
                        r.short_description,
                        r.required_action,
                        r.due_date,
                        r.known_ransomware_campaign_use,
                        now,
                    )
                    for r in records
                ],
            )

            # Update metadata
            cursor.execute(
                """
                INSERT OR REPLACE INTO feed_metadata
                (feed_name, last_refresh, records_count, status)
                VALUES (?, ?, ?, ?)
            """,
                ("kev", now, len(records), "success"),
            )

            conn.commit()
            conn.close()

            logger.info(f"KEV refresh complete: {len(records)} records updated")

            return FeedRefreshResult(
                feed_name="kev",
                success=True,
                records_updated=len(records),
            )

        except RequestException as exc:
            error_msg = f"Failed to fetch KEV feed: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="kev",
                success=False,
                records_updated=0,
                error=error_msg,
            )
        except Exception as exc:
            error_msg = f"Error processing KEV feed: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="kev",
                success=False,
                records_updated=0,
                error=error_msg,
            )

    def get_epss_score(self, cve_id: str) -> Optional[EPSSScore]:
        """Get EPSS score for a CVE.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            EPSSScore if found, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM epss_scores WHERE cve_id = ?", (cve_id.upper(),)
            )
            row = cursor.fetchone()
            if row:
                return EPSSScore(
                    cve_id=row["cve_id"],
                    epss=row["epss"],
                    percentile=row["percentile"],
                    date=row["date"],
                )
            return None
        finally:
            conn.close()

    def get_kev_entry(self, cve_id: str) -> Optional[KEVEntry]:
        """Get KEV entry for a CVE.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            KEVEntry if found, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM kev_entries WHERE cve_id = ?", (cve_id.upper(),)
            )
            row = cursor.fetchone()
            if row:
                return KEVEntry(
                    cve_id=row["cve_id"],
                    vendor_project=row["vendor_project"],
                    product=row["product"],
                    vulnerability_name=row["vulnerability_name"],
                    date_added=row["date_added"],
                    short_description=row["short_description"],
                    required_action=row["required_action"],
                    due_date=row["due_date"],
                    known_ransomware_campaign_use=row["known_ransomware_campaign_use"],
                )
            return None
        finally:
            conn.close()

    def is_in_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog.

        Args:
            cve_id: CVE identifier

        Returns:
            True if CVE is in KEV, False otherwise
        """
        return self.get_kev_entry(cve_id) is not None

    def enrich_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich findings with EPSS scores and KEV flags.

        Args:
            findings: List of finding dictionaries with cve_id field

        Returns:
            Enriched findings with epss_score, epss_percentile, and in_kev fields
        """
        enriched = []
        for finding in findings:
            enriched_finding = dict(finding)
            cve_id = finding.get("cve_id") or finding.get("vulnerability_id")

            if cve_id and cve_id.upper().startswith("CVE-"):
                # Add EPSS data
                epss = self.get_epss_score(cve_id)
                if epss:
                    enriched_finding["epss_score"] = epss.epss
                    enriched_finding["epss_percentile"] = epss.percentile
                else:
                    enriched_finding["epss_score"] = None
                    enriched_finding["epss_percentile"] = None

                # Add KEV flag
                kev = self.get_kev_entry(cve_id)
                enriched_finding["in_kev"] = kev is not None
                if kev:
                    enriched_finding["kev_due_date"] = kev.due_date
                    enriched_finding[
                        "kev_ransomware"
                    ] = kev.known_ransomware_campaign_use
            else:
                enriched_finding["epss_score"] = None
                enriched_finding["epss_percentile"] = None
                enriched_finding["in_kev"] = False

            enriched.append(enriched_finding)

        return enriched

    def get_high_risk_cves(
        self, epss_threshold: float = 0.5, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get CVEs with high EPSS scores that are also in KEV.

        Args:
            epss_threshold: Minimum EPSS score (default 0.5)
            limit: Maximum number of results

        Returns:
            List of high-risk CVEs with EPSS and KEV data
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT e.cve_id, e.epss, e.percentile, k.vulnerability_name,
                       k.date_added, k.due_date, k.known_ransomware_campaign_use
                FROM epss_scores e
                INNER JOIN kev_entries k ON e.cve_id = k.cve_id
                WHERE e.epss >= ?
                ORDER BY e.epss DESC
                LIMIT ?
            """,
                (epss_threshold, limit),
            )

            results = []
            for row in cursor.fetchall():
                results.append(
                    {
                        "cve_id": row["cve_id"],
                        "epss_score": row["epss"],
                        "epss_percentile": row["percentile"],
                        "vulnerability_name": row["vulnerability_name"],
                        "kev_date_added": row["date_added"],
                        "kev_due_date": row["due_date"],
                        "ransomware_use": row["known_ransomware_campaign_use"],
                    }
                )
            return results
        finally:
            conn.close()

    def get_feed_stats(self) -> Dict[str, Any]:
        """Get statistics about feed data.

        Returns:
            Dictionary with feed statistics
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            # EPSS stats
            cursor.execute("SELECT COUNT(*) as count FROM epss_scores")
            epss_count = cursor.fetchone()["count"]

            cursor.execute("SELECT AVG(epss) as avg FROM epss_scores")
            epss_avg = cursor.fetchone()["avg"] or 0

            # KEV stats
            cursor.execute("SELECT COUNT(*) as count FROM kev_entries")
            kev_count = cursor.fetchone()["count"]

            # Overlap
            cursor.execute(
                """
                SELECT COUNT(*) as count FROM epss_scores e
                INNER JOIN kev_entries k ON e.cve_id = k.cve_id
            """
            )
            overlap_count = cursor.fetchone()["count"]

            # Feed metadata
            cursor.execute("SELECT * FROM feed_metadata")
            metadata = {row["feed_name"]: dict(row) for row in cursor.fetchall()}

            return {
                "epss": {
                    "total_cves": epss_count,
                    "average_score": round(epss_avg, 4),
                    "last_refresh": metadata.get("epss", {}).get("last_refresh"),
                },
                "kev": {
                    "total_cves": kev_count,
                    "last_refresh": metadata.get("kev", {}).get("last_refresh"),
                },
                "overlap": {
                    "cves_in_both": overlap_count,
                },
            }
        finally:
            conn.close()

    @staticmethod
    async def scheduler(
        settings: Any, interval_hours: int = 24
    ) -> None:  # pragma: no cover - background task
        """Background scheduler for periodic feed refresh.

        Args:
            settings: Application settings (for database path)
            interval_hours: Refresh interval in hours (default 24)
        """
        delay = max(1, int(interval_hours)) * 3600

        # Get database path from settings if available
        db_path = None
        if hasattr(settings, "feeds_db_path"):
            db_path = Path(settings.feeds_db_path)

        service = FeedsService(db_path=db_path)

        # Initial refresh on startup
        logger.info("Starting initial feed refresh")
        service.refresh_epss()
        service.refresh_kev()

        while True:
            await asyncio.sleep(delay)
            logger.info(f"Running scheduled feed refresh (interval: {interval_hours}h)")
            service.refresh_epss()
            service.refresh_kev()


__all__ = [
    "FeedsService",
    "EPSSScore",
    "KEVEntry",
    "FeedRefreshResult",
]
