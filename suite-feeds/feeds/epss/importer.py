"""FIRST.org EPSS (Exploit Prediction Scoring System) importer.

Pulls the public daily EPSS CSV feed and bulk-replaces a per-domain SQLite
table. EPSS is the ML-derived probability (0..1) that a CVE will be exploited
in the next 30 days, plus its percentile rank.

Source feed (~250K rows, gzipped CSV, public, no auth):
    https://epss.cyentia.com/epss_scores-current.csv.gz

Updated daily by FIRST.org. Re-import REPLACES the table — it does not append.

Usage (programmatic):
    from feeds.epss.importer import EpssImporter
    result = EpssImporter().run()

Usage (CLI):
    python -m feeds.epss.importer

DB: data/epss.db  (table: epss_scores)
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import logging
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import httpx  # noqa: F401
    _HAS_HTTPX = True
except ImportError:  # pragma: no cover
    _HAS_HTTPX = False

logger = logging.getLogger(__name__)

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_DEFAULT_DB = "data/epss.db"
_TABLE = "epss_scores"

# Thread-local SQLite connections per db_path
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
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS {_TABLE} (
            cve_id      TEXT PRIMARY KEY,
            epss_score  REAL NOT NULL,
            percentile  REAL NOT NULL,
            imported_at TEXT NOT NULL
        )
    """)
    conn.execute(
        f"CREATE INDEX IF NOT EXISTS idx_epss_score ON {_TABLE}(epss_score)"
    )
    conn.execute(
        f"CREATE INDEX IF NOT EXISTS idx_epss_percentile ON {_TABLE}(percentile)"
    )
    conn.commit()


class EpssImporter:
    """Import FIRST.org EPSS daily scores into local SQLite DB.

    Args:
        db_path: Path to the SQLite database file.
        url:     Override the EPSS feed URL (useful for tests).
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        url: str = EPSS_URL,
        timeout: int = 60,
    ) -> None:
        self._db_path = db_path
        self._url = url
        self._timeout = timeout
        _ensure_table(db_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        """Fetch feed, REPLACE all rows, return summary.

        Returns:
            {"scores_imported": N, "high_risk_count": <count where epss>0.5>,
             "source_url": EPSS_URL}
        """
        gz_bytes = self._fetch()
        rows = self._parse(gz_bytes)

        conn = _get_conn(self._db_path)
        now_iso = datetime.now(timezone.utc).isoformat()

        bulk = [
            (r["cve_id"], r["epss_score"], r["percentile"], now_iso)
            for r in rows
        ]

        # Single transaction: clear + bulk insert
        try:
            conn.execute("BEGIN")
            conn.execute(f"DELETE FROM {_TABLE}")
            conn.executemany(
                f"INSERT INTO {_TABLE} (cve_id, epss_score, percentile, imported_at) "
                f"VALUES (?, ?, ?, ?)",
                bulk,
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

        high_risk_row = conn.execute(
            f"SELECT COUNT(*) FROM {_TABLE} WHERE epss_score > 0.5"
        ).fetchone()
        high_risk_count = high_risk_row[0] if high_risk_row else 0

        result = {
            "scores_imported": len(bulk),
            "high_risk_count": high_risk_count,
            "source_url": self._url,
        }
        logger.info("EPSS import complete: %s", result)
        return result

    def list_scores(
        self,
        page: int = 1,
        page_size: int = 50,
        cve_id: Optional[str] = None,
        epss_min: Optional[float] = None,
        percentile_min: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Return paginated EPSS scores ordered by epss_score DESC.

        Args:
            page:           1-based page number.
            page_size:      Rows per page (max 500).
            cve_id:         Optional exact-match filter.
            epss_min:       Optional minimum epss_score (>=).
            percentile_min: Optional minimum percentile (>=).
        """
        page_size = min(max(1, page_size), 500)
        offset = (max(1, page) - 1) * page_size

        conn = _get_conn(self._db_path)

        clauses: List[str] = []
        params: List[Any] = []
        if cve_id is not None:
            clauses.append("cve_id = ?")
            params.append(cve_id)
        if epss_min is not None:
            clauses.append("epss_score >= ?")
            params.append(epss_min)
        if percentile_min is not None:
            clauses.append("percentile >= ?")
            params.append(percentile_min)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        count_row = conn.execute(
            f"SELECT COUNT(*) FROM {_TABLE} {where}", tuple(params)
        ).fetchone()
        total = count_row[0] if count_row else 0

        rows = conn.execute(
            f"""
            SELECT cve_id, epss_score, percentile, imported_at
            FROM {_TABLE}
            {where}
            ORDER BY epss_score DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params) + (page_size, offset),
        ).fetchall()

        return {
            "scores": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    def get_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Return single row dict for a CVE, or None if not found."""
        conn = _get_conn(self._db_path)
        row = conn.execute(
            f"SELECT cve_id, epss_score, percentile, imported_at "
            f"FROM {_TABLE} WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()
        return dict(row) if row else None

    def total_count(self) -> int:
        """Return total number of rows in the EPSS table."""
        conn = _get_conn(self._db_path)
        row = conn.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()
        return row[0] if row else 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch(self) -> bytes:
        """Download gzipped EPSS CSV. Uses httpx, falls back to urllib."""
        if _HAS_HTTPX:
            import httpx as _httpx
            resp = _httpx.get(
                self._url, timeout=self._timeout, follow_redirects=True
            )
            resp.raise_for_status()
            return resp.content
        # Fallback: stdlib urllib
        from urllib.request import urlopen  # noqa: PLC0415
        with urlopen(self._url, timeout=self._timeout) as r:  # nosec — controlled URL
            return r.read()

    @staticmethod
    def _parse(gz_bytes: bytes) -> List[Dict[str, Any]]:
        """Decompress gzipped CSV bytes and return a list of EPSS rows.

        The FIRST.org feed begins with one or more `#`-prefixed comment lines
        (e.g. `#model_version:vYYYY.MM.DD,score_date:...`), then a header
        `cve,epss,percentile`, then data rows.

        Rows where `epss` or `percentile` cannot be coerced to float are
        skipped with a warning.
        """
        raw = gzip.decompress(gz_bytes)
        text = raw.decode("utf-8", errors="replace")

        # Strip leading comment lines (`#...`) before handing to csv.DictReader.
        lines = text.splitlines()
        data_lines = [ln for ln in lines if not ln.startswith("#")]
        if not data_lines:
            return []

        reader = csv.DictReader(io.StringIO("\n".join(data_lines)))
        rows: List[Dict[str, Any]] = []
        for raw_row in reader:
            if not raw_row:
                continue
            cve_id = (raw_row.get("cve") or "").strip()
            if not cve_id:
                continue
            try:
                epss_score = float(raw_row["epss"])
                percentile = float(raw_row["percentile"])
            except (TypeError, ValueError, KeyError):
                logger.debug("EPSS: skipping malformed row: %s", raw_row)
                continue
            rows.append({
                "cve_id": cve_id,
                "epss_score": epss_score,
                "percentile": percentile,
            })
        return rows


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="Import FIRST.org EPSS daily feed into local DB"
    )
    parser.add_argument("--db", default=_DEFAULT_DB, help="SQLite DB path")
    parser.add_argument("--url", default=EPSS_URL, help="Override feed URL")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    importer = EpssImporter(db_path=args.db, url=args.url)
    result = importer.run()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
