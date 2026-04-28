"""PhishTank phishing-URL importer.

Pulls the public PhishTank online-valid JSON feed (~3 MB, ~10 K verified
phishing URLs) and upserts entries into a local SQLite DB using the
PersistentDict / raw-SQLite pattern consistent with other feed importers.

Usage (programmatic):
    from feeds.phishtank.importer import PhishTankImporter
    result = PhishTankImporter().run()

Usage (CLI):
    python -m feeds.phishtank.importer

DB:  data/phishtank.db   (table: phishes)
"""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:  # pragma: no cover
    _HAS_HTTPX = False

logger = logging.getLogger(__name__)

PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.json"
_DEFAULT_DB = "data/phishtank.db"
_TABLE = "phishes"

# Entries with online=no older than this many days are marked expired
_STALE_DAYS = 30

_local = threading.local()


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

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
            phish_id            TEXT PRIMARY KEY,
            url                 TEXT NOT NULL,
            phish_detail_url    TEXT,
            submission_time     TEXT,
            verified            TEXT,
            verification_time   TEXT,
            online              TEXT,
            target              TEXT,
            status              TEXT DEFAULT 'active',
            imported_at         TEXT,
            raw_json            TEXT
        )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_target ON {_TABLE} (target)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_online  ON {_TABLE} (online)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_status  ON {_TABLE} (status)")
    conn.commit()


# ---------------------------------------------------------------------------
# Main importer class
# ---------------------------------------------------------------------------

class PhishTankImporter:
    """Import PhishTank feed entries into local SQLite DB.

    Args:
        db_path: Path to the SQLite database file.
        url:     Override the PhishTank JSON feed URL (useful for tests).
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        url: str = PHISHTANK_URL,
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
        """Fetch feed, upsert entries, expire stale records.

        Returns:
            {
                "phishes": N,          # total after import
                "by_target": {...},    # brand -> count (top 20)
                "online": N,           # currently online
                "verified": N,         # verified entries
            }
        """
        raw_entries = self._fetch()
        parsed = self._parse(raw_entries)
        self._upsert(parsed)
        self._expire_stale()
        return self._summary()

    def list_phishes(
        self,
        page: int = 1,
        page_size: int = 50,
        target: Optional[str] = None,
        online_only: bool = False,
    ) -> Dict[str, Any]:
        """Return paginated phish entries with optional filters.

        Args:
            page:       1-based page number.
            page_size:  Entries per page (max 500).
            target:     Filter by brand name (case-insensitive).
            online_only: Return only entries where online='yes'.
        """
        page_size = min(max(1, page_size), 500)
        offset = (max(1, page) - 1) * page_size

        conn = _get_conn(self._db_path)
        conditions: list[str] = []
        params: list[Any] = []

        if target:
            conditions.append("LOWER(target) = LOWER(?)")
            params.append(target)
        if online_only:
            conditions.append("online = 'yes'")

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        total_row = conn.execute(
            f"SELECT COUNT(*) FROM {_TABLE} {where}", params
        ).fetchone()
        total = total_row[0] if total_row else 0

        rows = conn.execute(
            f"""
            SELECT phish_id, url, phish_detail_url, submission_time,
                   verified, verification_time, online, target, status, imported_at
            FROM {_TABLE}
            {where}
            ORDER BY submission_time DESC
            LIMIT ? OFFSET ?
            """,
            params + [page_size, offset],
        ).fetchall()

        return {
            "entries": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    def check_url(self, url: str) -> Dict[str, Any]:
        """Return phish record for exact URL match, or {"found": False}."""
        conn = _get_conn(self._db_path)
        row = conn.execute(
            f"""
            SELECT phish_id, url, phish_detail_url, submission_time,
                   verified, verification_time, online, target, status
            FROM {_TABLE} WHERE url = ?
            """,
            (url,),
        ).fetchone()
        if row:
            return {"found": True, **dict(row)}
        return {"found": False, "url": url}

    def total_count(self) -> int:
        conn = _get_conn(self._db_path)
        row = conn.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()
        return row[0] if row else 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch(self) -> List[Dict[str, Any]]:
        """Download PhishTank JSON feed. Returns list of raw dicts."""
        if _HAS_HTTPX:
            import httpx as _httpx
            resp = _httpx.get(self._url, timeout=self._timeout, follow_redirects=True)
            resp.raise_for_status()
            data = resp.json()
        else:
            import json as _json
            from urllib.request import urlopen  # noqa: PLC0415
            with urlopen(self._url, timeout=self._timeout) as r:  # nosec
                data = _json.loads(r.read())

        if isinstance(data, list):
            return data
        # PhishTank sometimes wraps in an object
        if isinstance(data, dict):
            for key in ("phishes", "entries", "data"):
                if key in data and isinstance(data[key], list):
                    return data[key]
        return []

    @staticmethod
    def _parse(raw_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalise raw PhishTank records."""
        parsed: List[Dict[str, Any]] = []
        for raw in raw_entries:
            if not isinstance(raw, dict):
                continue
            phish_id = str(raw.get("phish_id") or raw.get("id") or "").strip()
            if not phish_id:
                continue
            url = (raw.get("url") or "").strip()
            if not url:
                continue

            # PhishTank verified/online fields come as "yes"/"no" or bool
            def _yn(val: Any) -> str:
                if isinstance(val, bool):
                    return "yes" if val else "no"
                return str(val or "no").lower()

            # Target brand
            details = raw.get("details", [])
            target = ""
            if isinstance(details, list) and details:
                first = details[0] if isinstance(details[0], dict) else {}
                target = (first.get("brand") or "").strip()
            if not target:
                target = (raw.get("target") or raw.get("brand") or "").strip()

            parsed.append({
                "phish_id": phish_id,
                "url": url,
                "phish_detail_url": (raw.get("phish_detail_url") or "").strip(),
                "submission_time": (raw.get("submission_time") or "").strip(),
                "verified": _yn(raw.get("verified")),
                "verification_time": (raw.get("verification_time") or "").strip(),
                "online": _yn(raw.get("online")),
                "target": target,
            })
        return parsed

    def _upsert(self, entries: List[Dict[str, Any]]) -> None:
        conn = _get_conn(self._db_path)
        now_iso = datetime.now(timezone.utc).isoformat()
        for e in entries:
            conn.execute(
                f"""
                INSERT INTO {_TABLE}
                    (phish_id, url, phish_detail_url, submission_time,
                     verified, verification_time, online, target,
                     status, imported_at, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
                ON CONFLICT(phish_id) DO UPDATE SET
                    url               = excluded.url,
                    phish_detail_url  = excluded.phish_detail_url,
                    submission_time   = excluded.submission_time,
                    verified          = excluded.verified,
                    verification_time = excluded.verification_time,
                    online            = excluded.online,
                    target            = excluded.target,
                    status            = 'active',
                    imported_at       = excluded.imported_at,
                    raw_json          = excluded.raw_json
                """,
                (
                    e["phish_id"],
                    e["url"],
                    e["phish_detail_url"],
                    e["submission_time"],
                    e["verified"],
                    e["verification_time"],
                    e["online"],
                    e["target"],
                    now_iso,
                    json.dumps(e),
                ),
            )
        conn.commit()

    def _expire_stale(self) -> None:
        """Mark entries with online=no that are older than _STALE_DAYS as expired."""
        conn = _get_conn(self._db_path)
        cutoff = (datetime.now(timezone.utc) - timedelta(days=_STALE_DAYS)).isoformat()
        conn.execute(
            f"""
            UPDATE {_TABLE}
            SET status = 'expired'
            WHERE online = 'no'
              AND imported_at < ?
              AND status = 'active'
            """,
            (cutoff,),
        )
        conn.commit()

    def _summary(self) -> Dict[str, Any]:
        conn = _get_conn(self._db_path)

        total = (conn.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone() or [0])[0]
        online = (
            conn.execute(f"SELECT COUNT(*) FROM {_TABLE} WHERE online='yes'").fetchone() or [0]
        )[0]
        verified = (
            conn.execute(f"SELECT COUNT(*) FROM {_TABLE} WHERE verified='yes'").fetchone() or [0]
        )[0]

        rows = conn.execute(
            f"""
            SELECT target, COUNT(*) AS cnt
            FROM {_TABLE}
            WHERE target != ''
            GROUP BY target
            ORDER BY cnt DESC
            LIMIT 20
            """
        ).fetchall()
        by_target = {r["target"]: r["cnt"] for r in rows}

        return {
            "phishes": total,
            "by_target": by_target,
            "online": online,
            "verified": verified,
        }


# ---------------------------------------------------------------------------
# Module-level convenience functions (for registry.py)
# ---------------------------------------------------------------------------

def run_import(db_path: str = _DEFAULT_DB, url: str = PHISHTANK_URL) -> Dict[str, Any]:
    return PhishTankImporter(db_path=db_path, url=url).run()


def total_count(db_path: str = _DEFAULT_DB) -> int:
    return PhishTankImporter(db_path=db_path).total_count()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Import PhishTank phishing-URL feed")
    parser.add_argument("--db", default=_DEFAULT_DB, help="SQLite DB path")
    parser.add_argument("--url", default=PHISHTANK_URL, help="Override feed URL")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    result = run_import(db_path=args.db, url=args.url)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
