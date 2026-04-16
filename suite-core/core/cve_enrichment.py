"""CVE enrichment service — combine NVD, EPSS, KEV, CVSS, Shodan into unified records."""
import json
import sqlite3
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import structlog

_logger = structlog.get_logger()

_KEV_CACHE_TTL_HOURS = 6
_SHODAN_CACHE_TTL_DAYS = 5

# Built-in CVE database (subset of well-known CVEs for offline use)
BUILT_IN_CVES = {
    "CVE-2021-44228": {
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP...",
        "epss_score": 0.97,
        "is_kev": True,
        "kev_due_date": "2021-12-24",
        "affected_products": ["Apache Log4j 2.0-2.14.1"],
        "cwe": "CWE-917",
        "published": "2021-12-10",
    },
    "CVE-2022-0778": {
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "description": "OpenSSL infinite loop vulnerability allows denial of service...",
        "epss_score": 0.71,
        "is_kev": True,
        "kev_due_date": "2022-03-31",
        "affected_products": ["OpenSSL 1.0.2-1.0.2zc", "OpenSSL 1.1.1-1.1.1n"],
        "cwe": "CWE-835",
        "published": "2022-03-15",
    },
    "CVE-2021-26855": {
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Microsoft Exchange Server SSRF vulnerability (ProxyLogon)...",
        "epss_score": 0.97,
        "is_kev": True,
        "kev_due_date": "2021-04-16",
        "affected_products": ["Microsoft Exchange Server 2013/2016/2019"],
        "cwe": "CWE-918",
        "published": "2021-03-02",
    },
}


class CVEEnrichmentService:
    def __init__(
        self,
        db_path: str = "data/cve_enrichment.db",
        cache_ttl_hours: int = 24,
    ):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_ttl_hours = cache_ttl_hours
        self._hit_count = 0
        self._miss_count = 0
        self._init_db()

    # ------------------------------------------------------------------
    # DB setup
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cve_id           TEXT PRIMARY KEY,
                    cvss_score       REAL,
                    cvss_vector      TEXT,
                    cvss_severity    TEXT,
                    description      TEXT,
                    epss_score       REAL,
                    epss_percentile  REAL,
                    is_kev           INTEGER DEFAULT 0,
                    kev_due_date     TEXT,
                    affected_products TEXT,
                    cwe              TEXT,
                    published        TEXT,
                    source           TEXT,
                    enriched_at      TEXT,
                    expires_at       TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_cve_expires ON cve_cache(expires_at);
                CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve_cache(cvss_score);
                CREATE INDEX IF NOT EXISTS idx_cve_epss ON cve_cache(epss_score);
                CREATE INDEX IF NOT EXISTS idx_cve_kev ON cve_cache(is_kev);

                CREATE TABLE IF NOT EXISTS kev_catalog (
                    cve_id               TEXT PRIMARY KEY,
                    due_date             TEXT,
                    ransomware_use       TEXT,
                    date_added           TEXT
                );
                CREATE TABLE IF NOT EXISTS kev_meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT
                );

                CREATE TABLE IF NOT EXISTS ip_cache (
                    ip          TEXT PRIMARY KEY,
                    ports       TEXT,
                    hostnames   TEXT,
                    cpes        TEXT,
                    tags        TEXT,
                    vulns       TEXT,
                    enriched_at TEXT,
                    expires_at  TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_ip_expires ON ip_cache(expires_at);
                """
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich_cve(self, cve_id: str, use_cache: bool = True) -> dict:
        """Get enriched CVE data. Returns from cache if available and fresh.

        Falls back to built-in database if network unavailable.
        Returns dict with: cve_id, cvss_score, cvss_vector, cvss_severity,
        description, epss_score, epss_percentile, is_kev, kev_due_date,
        affected_products, cwe, published, source, enriched_at.
        """
        cve_id = cve_id.upper().strip()

        if use_cache:
            cached = self._get_from_cache(cve_id)
            if cached is not None:
                self._hit_count += 1
                return cached

        self._miss_count += 1

        # Try network fetch first
        record = self._fetch_from_network(cve_id)

        # Fall back to built-in database
        if record is None:
            record = self._from_builtin(cve_id)

        # Store in cache
        self._store_in_cache(record)
        return record

    def enrich_batch(self, cve_ids: list) -> list:
        """Enrich multiple CVEs. Returns list of enriched records."""
        if not cve_ids:
            return []
        return [self.enrich_cve(cve_id) for cve_id in cve_ids]

    def get_severity(self, cvss_score: float) -> str:
        """Map CVSS score to severity string.

        9.0-10.0 → critical, 7.0-8.9 → high, 4.0-6.9 → medium,
        0.1-3.9 → low, 0.0 → none
        """
        if cvss_score >= 9.0:
            return "critical"
        if cvss_score >= 7.0:
            return "high"
        if cvss_score >= 4.0:
            return "medium"
        if cvss_score > 0.0:
            return "low"
        return "none"

    def search_cves(
        self,
        keyword: Optional[str] = None,
        min_cvss: float = 0.0,
        is_kev: Optional[bool] = None,
        limit: int = 20,
    ) -> list:
        """Search cached CVEs by keyword and filters."""
        clauses = ["cvss_score >= ?"]
        params: list = [min_cvss]

        if is_kev is not None:
            clauses.append("is_kev = ?")
            params.append(1 if is_kev else 0)

        if keyword:
            clauses.append(
                "(cve_id LIKE ? OR description LIKE ? OR affected_products LIKE ?)"
            )
            kw = f"%{keyword}%"
            params.extend([kw, kw, kw])

        where = " AND ".join(clauses)
        params.append(limit)

        with self._get_conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM cve_cache WHERE {where} ORDER BY cvss_score DESC LIMIT ?",  # nosec B608
                params,
            ).fetchall()

        return [self._row_to_dict(r) for r in rows]

    def get_cache_stats(self) -> dict:
        """Return cached_cves count, cache_hit_rate, last_updated."""
        with self._get_conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
            last_row = conn.execute(
                "SELECT MAX(enriched_at) FROM cve_cache"
            ).fetchone()[0]

        total = self._hit_count + self._miss_count
        hit_rate = self._hit_count / total if total > 0 else 0.0

        return {
            "cached_cves": count,
            "cache_hit_rate": round(hit_rate, 4),
            "last_updated": last_row or "",
        }

    def invalidate_cache(self, cve_id: Optional[str] = None) -> int:
        """Invalidate cache for a CVE or all if cve_id=None. Returns count invalidated."""
        with self._get_conn() as conn:
            if cve_id is None:
                cur = conn.execute("DELETE FROM cve_cache")
            else:
                cur = conn.execute(
                    "DELETE FROM cve_cache WHERE cve_id = ?", (cve_id.upper().strip(),)
                )
            return cur.rowcount

    def get_top_epss(self, limit: int = 10) -> list:
        """Get CVEs with highest EPSS scores from cache."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM cve_cache ORDER BY epss_score DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_from_cache(self, cve_id: str) -> Optional[dict]:
        """Return cached record if it exists and has not expired."""
        now = datetime.utcnow().isoformat()
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM cve_cache WHERE cve_id = ? AND expires_at > ?",
                (cve_id, now),
            ).fetchone()
        if row is None:
            return None
        record = self._row_to_dict(row)
        record["source"] = "cache"
        return record

    def _store_in_cache(self, record: dict) -> None:
        """Upsert an enriched record into the cache."""
        now = datetime.utcnow().isoformat()
        expires = (
            datetime.utcnow() + timedelta(hours=self.cache_ttl_hours)
        ).isoformat()

        products = record.get("affected_products", [])
        if isinstance(products, list):
            products = json.dumps(products)

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO cve_cache
                    (cve_id, cvss_score, cvss_vector, cvss_severity, description,
                     epss_score, epss_percentile, is_kev, kev_due_date,
                     affected_products, cwe, published, source, enriched_at, expires_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    cvss_score=excluded.cvss_score,
                    cvss_vector=excluded.cvss_vector,
                    cvss_severity=excluded.cvss_severity,
                    description=excluded.description,
                    epss_score=excluded.epss_score,
                    epss_percentile=excluded.epss_percentile,
                    is_kev=excluded.is_kev,
                    kev_due_date=excluded.kev_due_date,
                    affected_products=excluded.affected_products,
                    cwe=excluded.cwe,
                    published=excluded.published,
                    source=excluded.source,
                    enriched_at=excluded.enriched_at,
                    expires_at=excluded.expires_at
                """,
                (
                    record.get("cve_id", ""),
                    record.get("cvss_score", 0.0),
                    record.get("cvss_vector", ""),
                    record.get("cvss_severity", "none"),
                    record.get("description", ""),
                    record.get("epss_score", 0.0),
                    record.get("epss_percentile", 0.0),
                    1 if record.get("is_kev") else 0,
                    record.get("kev_due_date", ""),
                    products,
                    record.get("cwe", ""),
                    record.get("published", ""),
                    record.get("source", "builtin"),
                    now,
                    expires,
                ),
            )

    def _from_builtin(self, cve_id: str) -> dict:
        """Build an enriched record from the built-in database."""
        data = BUILT_IN_CVES.get(cve_id, {})
        cvss_score = data.get("cvss_score", 0.0)
        epss_score = data.get("epss_score", 0.0)
        return {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "cvss_vector": data.get("cvss_vector", ""),
            "cvss_severity": self.get_severity(cvss_score),
            "description": data.get("description", "No description available"),
            "epss_score": epss_score,
            "epss_percentile": round(epss_score * 100, 2),
            "is_kev": data.get("is_kev", False),
            "kev_due_date": data.get("kev_due_date", ""),
            "affected_products": data.get("affected_products", []),
            "cwe": data.get("cwe", ""),
            "published": data.get("published", ""),
            "source": "builtin",
            "enriched_at": datetime.utcnow().isoformat(),
        }

    def _fetch_from_network(self, cve_id: str) -> Optional[dict]:
        """Attempt to fetch CVE data from NVD API. Returns None on failure."""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            req = urllib.request.Request(url, headers={"User-Agent": "ALDECI-CVE-Enrichment/1.0"})  # nosemgrep: dynamic-urllib-use-detected
            with urllib.request.urlopen(req, timeout=5) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                data = json.loads(resp.read().decode())

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            cve_data = vulns[0].get("cve", {})
            metrics = cve_data.get("metrics", {})

            # Extract CVSS v3.1 score
            cvss_score = 0.0
            cvss_vector = ""
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    cvss_data = entries[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    cvss_vector = cvss_data.get("vectorString", "")
                    break

            # Description
            desc = ""
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # Published date
            published = cve_data.get("published", "")[:10]

            # CWE
            cwe = ""
            for weakness in cve_data.get("weaknesses", []):
                for wd in weakness.get("description", []):
                    if wd.get("lang") == "en":
                        cwe = wd.get("value", "")
                        break

            # Affected products from configurations
            affected_products: list = []

            epss_score, epss_percentile, epss_date = self._fetch_epss(cve_id)
            is_kev, kev_due_date = self._fetch_kev(cve_id)

            return {
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "cvss_severity": self.get_severity(cvss_score),
                "description": desc,
                "epss_score": epss_score,
                "epss_percentile": epss_percentile,
                "epss_date": epss_date,
                "is_kev": is_kev,
                "kev_due_date": kev_due_date,
                "affected_products": affected_products,
                "cwe": cwe,
                "published": published,
                "source": "network",
                "enriched_at": datetime.utcnow().isoformat(),
            }
        except Exception as exc:  # noqa: BLE001
            _logger.debug("cve_network_fetch_failed", cve_id=cve_id, error=str(exc))
            return None

    def _fetch_epss(self, cve_id: str) -> tuple:
        """Fetch EPSS score from FIRST.org API. Returns (score, percentile, date)."""
        try:
            url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            req = urllib.request.Request(url, headers={"User-Agent": "ALDECI-CVE-Enrichment/1.0"})  # nosemgrep: dynamic-urllib-use-detected
            with urllib.request.urlopen(req, timeout=5) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                data = json.loads(resp.read().decode())
            entries = data.get("data", [])
            if entries:
                score = float(entries[0].get("epss", 0.0))
                percentile = float(entries[0].get("percentile", 0.0)) * 100
                epss_date = entries[0].get("date", "")
                return score, round(percentile, 2), epss_date
        except Exception:  # noqa: BLE001
            pass
        return 0.0, 0.0, ""

    def _refresh_kev_catalog(self) -> None:
        """Download CISA KEV catalog and store in SQLite. Skips if cache is fresh (<6h)."""
        now = datetime.utcnow()
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT value FROM kev_meta WHERE key = 'fetched_at'"
            ).fetchone()
            if row:
                fetched_at = datetime.fromisoformat(row["value"])
                if now - fetched_at < timedelta(hours=_KEV_CACHE_TTL_HOURS):
                    return  # catalog is still fresh

        try:
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            req = urllib.request.Request(url, headers={"User-Agent": "ALDECI-CVE-Enrichment/1.0"})  # nosemgrep: dynamic-urllib-use-detected
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                data = json.loads(resp.read().decode())

            vulns = data.get("vulnerabilities", [])
            with self._get_conn() as conn:
                conn.execute("DELETE FROM kev_catalog")
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO kev_catalog
                        (cve_id, due_date, ransomware_use, date_added)
                    VALUES (?, ?, ?, ?)
                    """,
                    [
                        (
                            v.get("cveID", "").upper(),
                            v.get("dueDate", ""),
                            v.get("knownRansomwareCampaignUse", ""),
                            v.get("dateAdded", ""),
                        )
                        for v in vulns
                    ],
                )
                conn.execute(
                    "INSERT OR REPLACE INTO kev_meta (key, value) VALUES ('fetched_at', ?)",
                    (now.isoformat(),),
                )
            _logger.debug("kev_catalog_refreshed", count=len(vulns))
        except Exception as exc:  # noqa: BLE001
            _logger.debug("kev_catalog_fetch_failed", error=str(exc))

    def _fetch_kev(self, cve_id: str) -> tuple:
        """Check CISA KEV catalog using local cache. Returns (is_kev: bool, due_date: str)."""
        self._refresh_kev_catalog()
        try:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT due_date FROM kev_catalog WHERE cve_id = ?",
                    (cve_id.upper(),),
                ).fetchone()
            if row:
                return True, row["due_date"]
        except Exception:  # noqa: BLE001
            pass
        return False, ""

    # ------------------------------------------------------------------
    # Public: KEV lookup
    # ------------------------------------------------------------------

    def is_kev(self, cve_id: str) -> dict:
        """Check if a CVE is in the CISA Known Exploited Vulnerabilities catalog.

        Returns dict with: is_kev (bool), kev_due_date (str), kev_ransomware_use (str).
        Catalog is cached for 6 hours in SQLite.
        """
        cve_id = cve_id.upper().strip()
        self._refresh_kev_catalog()
        try:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT due_date, ransomware_use FROM kev_catalog WHERE cve_id = ?",
                    (cve_id,),
                ).fetchone()
            if row:
                return {
                    "is_kev": True,
                    "kev_due_date": row["due_date"],
                    "kev_ransomware_use": row["ransomware_use"],
                }
        except Exception as exc:  # noqa: BLE001
            _logger.debug("is_kev_lookup_failed", cve_id=cve_id, error=str(exc))
        return {
            "is_kev": False,
            "kev_due_date": "",
            "kev_ransomware_use": "",
        }

    # ------------------------------------------------------------------
    # Public: IP enrichment via Shodan InternetDB
    # ------------------------------------------------------------------

    def enrich_ip(self, ip: str) -> dict:
        """Enrich an IP address using Shodan InternetDB (no auth required).

        Returns dict with: ip, ports, hostnames, cpes, tags, vulns, source, enriched_at.
        Results are cached for 5 days in SQLite. Respects 1 req/sec rate limit.
        """
        ip = ip.strip()
        now = datetime.utcnow()

        # Check cache first
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM ip_cache WHERE ip = ? AND expires_at > ?",
                (ip, now.isoformat()),
            ).fetchone()
        if row:
            return {
                "ip": row["ip"],
                "ports": json.loads(row["ports"] or "[]"),
                "hostnames": json.loads(row["hostnames"] or "[]"),
                "cpes": json.loads(row["cpes"] or "[]"),
                "tags": json.loads(row["tags"] or "[]"),
                "vulns": json.loads(row["vulns"] or "[]"),
                "source": "cache",
                "enriched_at": row["enriched_at"],
            }

        # Fetch from Shodan InternetDB — 1 req/sec limit
        time.sleep(1)
        try:
            url = f"https://internetdb.shodan.io/{ip}"
            req = urllib.request.Request(url, headers={"User-Agent": "ALDECI-CVE-Enrichment/1.0"})  # nosemgrep: dynamic-urllib-use-detected
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                data = json.loads(resp.read().decode())

            result = {
                "ip": data.get("ip", ip),
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "cpes": data.get("cpes", []),
                "tags": data.get("tags", []),
                "vulns": data.get("vulns", []),
                "source": "shodan",
                "enriched_at": now.isoformat(),
            }

            # Cache for 5 days (matching Shodan cache-control: max-age=432000)
            expires = (now + timedelta(days=_SHODAN_CACHE_TTL_DAYS)).isoformat()
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO ip_cache
                        (ip, ports, hostnames, cpes, tags, vulns, enriched_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ip,
                        json.dumps(result["ports"]),
                        json.dumps(result["hostnames"]),
                        json.dumps(result["cpes"]),
                        json.dumps(result["tags"]),
                        json.dumps(result["vulns"]),
                        now.isoformat(),
                        expires,
                    ),
                )
            return result

        except Exception as exc:  # noqa: BLE001
            _logger.debug("shodan_fetch_failed", ip=ip, error=str(exc))
            return {
                "ip": ip,
                "ports": [],
                "hostnames": [],
                "cpes": [],
                "tags": [],
                "vulns": [],
                "source": "error",
                "enriched_at": now.isoformat(),
            }

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        """Convert a sqlite3.Row to a dict, deserializing JSON fields."""
        d = dict(row)
        # Deserialize affected_products JSON
        products = d.get("affected_products", "[]") or "[]"
        try:
            d["affected_products"] = json.loads(products)
        except (json.JSONDecodeError, TypeError):
            d["affected_products"] = []
        # Convert is_kev integer to bool
        d["is_kev"] = bool(d.get("is_kev", 0))
        return d
