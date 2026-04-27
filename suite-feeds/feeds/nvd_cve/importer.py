"""NIST NVD CVE feed importer (NVD 2.0 API).

Source: https://services.nvd.nist.gov/rest/json/cves/2.0

Public, free, but rate-limited:
  * 5 requests / 30s without an API key
  * 50 requests / 30s with NVD_API_KEY env var set
NVD's max query window is 120 days (pubStartDate / pubEndDate).

Default behaviour: pull the trailing 7 days. Use ``--full-history`` for a
one-time backfill (walks 120-day windows back to 1999).

Per-CVE extraction:
    cve.id, published, lastModified, descriptions[en],
    metrics.cvssMetricV31[0].cvssData.{baseScore, baseSeverity, vectorString},
    weaknesses[].description[en] (CWE),
    references[].url,
    vulnStatus

Usage (programmatic):
    from feeds.nvd_cve.importer import NvdCveImporter
    result = NvdCveImporter().run()           # last 7 days
    result = NvdCveImporter().run(full_history=True)  # backfill

Usage (CLI):
    python -m feeds.nvd_cve.importer
    python -m feeds.nvd_cve.importer --full-history
    python -m feeds.nvd_cve.importer --days 30

DB: data/nvd_cve.db   (table: nvd_cves)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:  # pragma: no cover
    _HAS_HTTPX = False

logger = logging.getLogger(__name__)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-feeds/feeds/nvd_cve -> project root
_DEFAULT_DB = str(_PROJECT_ROOT / "data" / "nvd_cve.db")
_TABLE = "nvd_cves"

NVD_MAX_WINDOW_DAYS = 120
NVD_MAX_RESULTS_PER_PAGE = 2000
NVD_BACKFILL_START = datetime(1999, 1, 1, tzinfo=timezone.utc)

# Rate-limit cadence — sleep between requests.
# Without a key: 5 req / 30s -> 6.0s between requests.
# With a key:    50 req / 30s -> 0.6s between requests. We pad slightly.
_SLEEP_NO_KEY = 6.0
_SLEEP_WITH_KEY = 0.7

_local = threading.local()


def _get_conn(db_path: str) -> sqlite3.Connection:
    key = f"conn_{db_path}"
    conn = getattr(_local, key, None)
    if conn is None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        setattr(_local, key, conn)
    return conn


def _ensure_table(db_path: str) -> None:
    conn = _get_conn(db_path)
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {_TABLE} (
            cve_id          TEXT PRIMARY KEY,
            published       TEXT,
            last_modified   TEXT,
            description     TEXT,
            cvss_score      REAL,
            cvss_severity   TEXT,
            cvss_vector     TEXT,
            cwe_ids         TEXT,
            reference_urls  TEXT,
            vuln_status     TEXT,
            raw_json        TEXT,
            imported_at     TEXT
        )
        """
    )
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{_TABLE}_published ON {_TABLE}(published)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{_TABLE}_severity ON {_TABLE}(cvss_severity)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{_TABLE}_cvss     ON {_TABLE}(cvss_score)")
    conn.commit()


def _format_nvd_datetime(dt: datetime) -> str:
    """NVD wants ISO-8601 *without* timezone suffix in extended format.

    Example accepted form: 2026-04-01T00:00:00.000
    """
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _iter_windows(
    start: datetime,
    end: datetime,
    window_days: int = NVD_MAX_WINDOW_DAYS,
) -> Iterable[Tuple[datetime, datetime]]:
    """Yield (window_start, window_end) tuples that cover [start, end].

    The NVD API rejects windows wider than 120 days, so callers must walk
    by ``window_days`` (default 120) chunks.
    """
    cur = start
    delta = timedelta(days=window_days)
    while cur < end:
        nxt = min(cur + delta, end)
        yield cur, nxt
        cur = nxt


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _english_description(descriptions: Any) -> str:
    if not isinstance(descriptions, list):
        return ""
    for d in descriptions:
        if isinstance(d, dict) and d.get("lang") == "en":
            return d.get("value") or ""
    return ""


def _cvss_v31(metrics: Any) -> Tuple[Optional[float], str, str]:
    """Return (baseScore, baseSeverity, vectorString) from CVSS v3.1.

    Falls back to v3.0 when v3.1 is absent; returns (None, "", "") otherwise.
    """
    if not isinstance(metrics, dict):
        return None, "", ""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        rows = metrics.get(key) or []
        if not isinstance(rows, list) or not rows:
            continue
        first = rows[0] if isinstance(rows[0], dict) else None
        if not first:
            continue
        cvss = first.get("cvssData") or {}
        try:
            score = float(cvss.get("baseScore")) if cvss.get("baseScore") is not None else None
        except (TypeError, ValueError):
            score = None
        severity = (cvss.get("baseSeverity") or "").upper()
        vector = cvss.get("vectorString") or ""
        return score, severity, vector
    return None, "", ""


def _cwe_list(weaknesses: Any) -> List[str]:
    if not isinstance(weaknesses, list):
        return []
    out: List[str] = []
    for w in weaknesses:
        if not isinstance(w, dict):
            continue
        for d in w.get("description", []) or []:
            if isinstance(d, dict) and d.get("lang") == "en":
                val = (d.get("value") or "").strip()
                if val and val not in out:
                    out.append(val)
    return out


def _reference_urls(references: Any) -> List[str]:
    if not isinstance(references, list):
        return []
    out: List[str] = []
    for r in references:
        if isinstance(r, dict):
            url = r.get("url")
            if isinstance(url, str) and url:
                out.append(url)
    return out


def parse_cve(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalise one NVD 2.0 vulnerability record. ``item`` is the raw dict.

    Accepts either the wrapped form (``{"cve": {...}}``) or the inner cve
    dict directly.
    """
    cve = item.get("cve") if isinstance(item, dict) and "cve" in item else item
    if not isinstance(cve, dict):
        return None
    cve_id = (cve.get("id") or "").strip()
    if not cve_id:
        return None

    score, severity, vector = _cvss_v31(cve.get("metrics"))
    return {
        "cve_id": cve_id,
        "published": cve.get("published") or "",
        "last_modified": cve.get("lastModified") or "",
        "description": _english_description(cve.get("descriptions")),
        "cvss_score": score,
        "cvss_severity": severity,
        "cvss_vector": vector,
        "cwe_ids": _cwe_list(cve.get("weaknesses")),
        "reference_urls": _reference_urls(cve.get("references")),
        "vuln_status": cve.get("vulnStatus") or "",
    }


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------

class NvdCveImporter:
    """Import NIST NVD 2.0 CVE records into local SQLite DB.

    Args:
        db_path:     Path to the SQLite DB file.
        url:         Override the API URL (useful for tests).
        api_key:     NVD API key. Defaults to the NVD_API_KEY env var.
        timeout:     HTTP request timeout (seconds).
        sleep_seconds: Override per-request sleep. Defaults to 0.7s with a
                     key, 6.0s without one.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        url: str = NVD_CVE_URL,
        api_key: Optional[str] = None,
        timeout: float = 60.0,
        sleep_seconds: Optional[float] = None,
    ) -> None:
        self._db_path = db_path
        self._url = url
        self._api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY")
        self._timeout = timeout
        if sleep_seconds is None:
            sleep_seconds = _SLEEP_WITH_KEY if self._api_key else _SLEEP_NO_KEY
        self._sleep_seconds = max(0.0, float(sleep_seconds))
        _ensure_table(db_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        days: int = 7,
        full_history: bool = False,
        end: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Pull CVEs published in [start, end] and upsert.

        Args:
            days:         Trailing days to pull when ``full_history`` is False.
            full_history: When True, walk 120-day windows back to 1999.
            end:          Override the end-of-window timestamp (UTC). Defaults
                          to now.

        Returns:
            {"cves_imported": N, "cves_updated": N, "by_severity": {...},
             "windows": N, "source_count": N}
        """
        end = end or datetime.now(timezone.utc)
        if full_history:
            start = NVD_BACKFILL_START
        else:
            start = end - timedelta(days=max(1, int(days)))

        imported = 0
        updated = 0
        windows = 0
        source_count = 0
        by_severity: Dict[str, int] = {}

        for win_start, win_end in _iter_windows(start, end):
            windows += 1
            for cve in self._iter_window(win_start, win_end):
                source_count += 1
                action = self._upsert(cve)
                if action == "imported":
                    imported += 1
                elif action == "updated":
                    updated += 1
                sev = cve.get("cvss_severity") or "UNKNOWN"
                by_severity[sev] = by_severity.get(sev, 0) + 1

        result = {
            "cves_imported": imported,
            "cves_updated": updated,
            "by_severity": by_severity,
            "windows": windows,
            "source_count": source_count,
        }
        logger.info("NVD CVE import complete: %s", result)
        return result

    def list_cves(
        self,
        cve_id: Optional[str] = None,
        severity: Optional[str] = None,
        published_since: Optional[str] = None,
        cvss_min: Optional[float] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Dict[str, Any]:
        """Return paginated CVEs from the local DB.

        Args:
            cve_id:          Exact CVE id match (e.g. "CVE-2023-23397").
            severity:        Case-insensitive baseSeverity (LOW, MEDIUM, HIGH, CRITICAL).
            published_since: ISO-8601 timestamp; only return rows with
                             ``published >= published_since``.
            cvss_min:        Minimum CVSS base score.
            page:            1-based page number.
            page_size:       Rows per page (max 500).
        """
        page_size = min(max(1, int(page_size)), 500)
        offset = (max(1, int(page)) - 1) * page_size

        clauses: List[str] = []
        params: List[Any] = []
        if cve_id:
            clauses.append("cve_id = ?")
            params.append(cve_id)
        if severity:
            clauses.append("UPPER(cvss_severity) = ?")
            params.append(severity.upper())
        if published_since:
            clauses.append("published >= ?")
            params.append(published_since)
        if cvss_min is not None:
            clauses.append("cvss_score IS NOT NULL AND cvss_score >= ?")
            params.append(float(cvss_min))

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        conn = _get_conn(self._db_path)
        total_row = conn.execute(
            f"SELECT COUNT(*) FROM {_TABLE} {where}", params
        ).fetchone()
        total = total_row[0] if total_row else 0

        rows = conn.execute(
            f"""
            SELECT cve_id, published, last_modified, description,
                   cvss_score, cvss_severity, cvss_vector,
                   cwe_ids, reference_urls, vuln_status, imported_at
            FROM {_TABLE}
            {where}
            ORDER BY published DESC, cve_id
            LIMIT ? OFFSET ?
            """,
            (*params, page_size, offset),
        ).fetchall()

        entries: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d["cwe_ids"] = json.loads(d.get("cwe_ids") or "[]")
            d["reference_urls"] = json.loads(d.get("reference_urls") or "[]")
            entries.append(d)

        return {
            "entries": entries,
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    def total_count(self) -> int:
        conn = _get_conn(self._db_path)
        row = conn.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()
        return row[0] if row else 0

    def stats(self) -> Dict[str, Any]:
        """Return total + by_severity breakdown."""
        conn = _get_conn(self._db_path)
        total = self.total_count()
        rows = conn.execute(
            f"SELECT COALESCE(cvss_severity, '') AS sev, COUNT(*) AS n FROM {_TABLE} GROUP BY sev"
        ).fetchall()
        by_severity: Dict[str, int] = {}
        for r in rows:
            sev = (r["sev"] or "UNKNOWN") or "UNKNOWN"
            by_severity[sev] = (by_severity.get(sev, 0) + r["n"])
        return {"total": total, "by_severity": by_severity}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _iter_window(self, win_start: datetime, win_end: datetime) -> Iterable[Dict[str, Any]]:
        """Yield parsed CVE dicts for a single 120-day window, paginated."""
        start_index = 0
        while True:
            params = {
                "pubStartDate": _format_nvd_datetime(win_start),
                "pubEndDate": _format_nvd_datetime(win_end),
                "resultsPerPage": NVD_MAX_RESULTS_PER_PAGE,
                "startIndex": start_index,
            }
            payload = self._fetch(params)
            vulns = payload.get("vulnerabilities") or []
            for raw in vulns:
                parsed = parse_cve(raw)
                if parsed is not None:
                    yield parsed

            total = int(payload.get("totalResults") or 0)
            results_per_page = int(payload.get("resultsPerPage") or len(vulns) or 0)
            start_index += results_per_page or len(vulns)
            if start_index >= total or not vulns:
                break

    def _fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Issue a single NVD API call with rate-limit backoff."""
        headers: Dict[str, str] = {"User-Agent": "ALDECI-NVDImporter/1.0"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        if self._sleep_seconds:
            time.sleep(self._sleep_seconds)

        if _HAS_HTTPX:
            with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
                resp = client.get(self._url, params=params, headers=headers)
                resp.raise_for_status()
                return resp.json()

        # Stdlib fallback
        from urllib.parse import urlencode
        from urllib.request import Request, urlopen

        url = f"{self._url}?{urlencode(params)}"
        req = Request(url, headers=headers)  # nosec — controlled URL
        with urlopen(req, timeout=self._timeout) as r:
            return json.loads(r.read())

    def _upsert(self, cve: Dict[str, Any]) -> str:
        """Insert or update a single CVE row. Returns 'imported' or 'updated'."""
        conn = _get_conn(self._db_path)
        existing = conn.execute(
            f"SELECT cve_id FROM {_TABLE} WHERE cve_id = ?", (cve["cve_id"],)
        ).fetchone()
        now_iso = datetime.now(timezone.utc).isoformat()

        cwe_json = json.dumps(cve.get("cwe_ids") or [])
        ref_json = json.dumps(cve.get("reference_urls") or [])
        raw_json = json.dumps(cve)

        if existing is None:
            conn.execute(
                f"""
                INSERT INTO {_TABLE}
                    (cve_id, published, last_modified, description,
                     cvss_score, cvss_severity, cvss_vector,
                     cwe_ids, reference_urls, vuln_status, raw_json, imported_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cve["cve_id"], cve["published"], cve["last_modified"],
                    cve["description"], cve["cvss_score"], cve["cvss_severity"],
                    cve["cvss_vector"], cwe_json, ref_json, cve["vuln_status"],
                    raw_json, now_iso,
                ),
            )
            conn.commit()
            return "imported"

        conn.execute(
            f"""
            UPDATE {_TABLE}
            SET published = ?, last_modified = ?, description = ?,
                cvss_score = ?, cvss_severity = ?, cvss_vector = ?,
                cwe_ids = ?, reference_urls = ?, vuln_status = ?,
                raw_json = ?, imported_at = ?
            WHERE cve_id = ?
            """,
            (
                cve["published"], cve["last_modified"], cve["description"],
                cve["cvss_score"], cve["cvss_severity"], cve["cvss_vector"],
                cwe_json, ref_json, cve["vuln_status"], raw_json, now_iso,
                cve["cve_id"],
            ),
        )
        conn.commit()
        return "updated"


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Import NIST NVD CVEs into local DB")
    parser.add_argument("--days", type=int, default=7,
                        help="Trailing days to pull (default: 7)")
    parser.add_argument("--full-history", action="store_true",
                        help="Backfill from 1999-01-01 in 120-day windows")
    parser.add_argument("--db", default=_DEFAULT_DB, help="SQLite DB path")
    parser.add_argument("--url", default=NVD_CVE_URL, help="Override feed URL")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    importer = NvdCveImporter(db_path=args.db, url=args.url)
    result = importer.run(days=args.days, full_history=args.full_history)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
