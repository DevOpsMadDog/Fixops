"""CISA KEV (Known Exploited Vulnerabilities) importer.

Pulls the public CISA KEV JSON feed and upserts entries into a per-domain
SQLite DB using the PersistentDict pattern.

Usage (programmatic):
    from feeds.cisa_kev.importer import CisaKevImporter
    importer = CisaKevImporter()
    result = importer.run(idempotent=True)

Usage (CLI):
    python -m feeds.cisa_kev.importer --idempotent

DB: data/cisa_kev.db  (table: kev_entries)
"""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:  # pragma: no cover
    _HAS_HTTPX = False

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_DEFAULT_DB = "data/cisa_kev.db"
_TABLE = "kev_entries"

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
            cve_id                     TEXT PRIMARY KEY,
            vendor_project             TEXT,
            product                    TEXT,
            vulnerability_name         TEXT,
            date_added                 TEXT,
            short_description          TEXT,
            required_action            TEXT,
            due_date                   TEXT,
            known_ransomware_use       TEXT,
            notes                      TEXT,
            raw_json                   TEXT,
            imported_at                TEXT
        )
    """)
    conn.commit()


class CisaKevImporter:
    """Import CISA KEV entries into local SQLite DB.

    Args:
        db_path: Path to the SQLite database file.
        url:     Override the CISA KEV JSON feed URL (useful for tests).
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        url: str = CISA_KEV_URL,
        timeout: int = 30,
    ) -> None:
        self._db_path = db_path
        self._url = url
        self._timeout = timeout
        _ensure_table(db_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, idempotent: bool = True) -> Dict[str, Any]:
        """Fetch feed and upsert entries.

        Args:
            idempotent: When True, skip CVE IDs already present in DB.

        Returns:
            {"imported": N, "updated": N, "skipped": N, "source_count": N}
        """
        payload = self._fetch()
        entries = self._parse(payload)
        source_count = len(entries)
        imported = updated = skipped = 0

        conn = _get_conn(self._db_path)
        now_iso = datetime.now(timezone.utc).isoformat()

        for entry in entries:
            cve_id = entry["cve_id"]
            existing = self._get_by_cve(cve_id)

            if existing is not None:
                if idempotent:
                    skipped += 1
                    continue
                # Update existing row
                conn.execute(
                    f"""
                    UPDATE {_TABLE}
                    SET vendor_project=?, product=?, vulnerability_name=?,
                        date_added=?, short_description=?, required_action=?,
                        due_date=?, known_ransomware_use=?, notes=?,
                        raw_json=?, imported_at=?
                    WHERE cve_id=?
                    """,
                    (
                        entry["vendor_project"],
                        entry["product"],
                        entry["vulnerability_name"],
                        entry["date_added"],
                        entry["short_description"],
                        entry["required_action"],
                        entry["due_date"],
                        entry["known_ransomware_use"],
                        entry["notes"],
                        json.dumps(entry),
                        now_iso,
                        cve_id,
                    ),
                )
                updated += 1
            else:
                conn.execute(
                    f"""
                    INSERT INTO {_TABLE}
                        (cve_id, vendor_project, product, vulnerability_name,
                         date_added, short_description, required_action,
                         due_date, known_ransomware_use, notes, raw_json, imported_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cve_id,
                        entry["vendor_project"],
                        entry["product"],
                        entry["vulnerability_name"],
                        entry["date_added"],
                        entry["short_description"],
                        entry["required_action"],
                        entry["due_date"],
                        entry["known_ransomware_use"],
                        entry["notes"],
                        json.dumps(entry),
                        now_iso,
                    ),
                )
                imported += 1

        conn.commit()
        result = {
            "imported": imported,
            "updated": updated,
            "skipped": skipped,
            "source_count": source_count,
        }
        logger.info("CISA KEV import complete: %s", result)
        return result

    def list_entries(
        self,
        page: int = 1,
        page_size: int = 50,
        ransomware_only: bool = False,
    ) -> Dict[str, Any]:
        """Return paginated KEV entries.

        Args:
            page:           1-based page number.
            page_size:      Entries per page (max 500).
            ransomware_only: Filter to entries with knownRansomwareCampaignUse != 'Unknown'.
        """
        page_size = min(max(1, page_size), 500)
        offset = (max(1, page) - 1) * page_size

        conn = _get_conn(self._db_path)

        where = ""
        if ransomware_only:
            where = "WHERE known_ransomware_use != 'Unknown' AND known_ransomware_use != '' AND known_ransomware_use IS NOT NULL"

        count_row = conn.execute(
            f"SELECT COUNT(*) FROM {_TABLE} {where}"
        ).fetchone()
        total = count_row[0] if count_row else 0

        rows = conn.execute(
            f"""
            SELECT cve_id, vendor_project, product, vulnerability_name,
                   date_added, short_description, required_action,
                   due_date, known_ransomware_use, notes, imported_at
            FROM {_TABLE}
            {where}
            ORDER BY date_added DESC
            LIMIT ? OFFSET ?
            """,
            (page_size, offset),
        ).fetchall()

        return {
            "entries": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    def total_count(self) -> int:
        """Return total number of entries in DB."""
        conn = _get_conn(self._db_path)
        row = conn.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()
        return row[0] if row else 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch(self) -> Dict[str, Any]:
        """Download KEV JSON. Uses httpx when available, falls back to urllib."""
        if _HAS_HTTPX:
            import httpx as _httpx
            resp = _httpx.get(self._url, timeout=self._timeout, follow_redirects=True)
            resp.raise_for_status()
            return resp.json()
        # Fallback: stdlib urllib
        from urllib.request import urlopen  # noqa: PLC0415
        with urlopen(self._url, timeout=self._timeout) as r:  # nosec — controlled URL
            return json.loads(r.read())

    @staticmethod
    def _parse(payload: Dict[str, Any]) -> list[Dict[str, Any]]:
        """Extract and normalise entries from the CISA JSON payload."""
        vulnerabilities = payload.get("vulnerabilities", [])
        entries: list[Dict[str, Any]] = []
        for raw in vulnerabilities:
            if not isinstance(raw, dict):
                continue
            cve_id = (raw.get("cveID") or "").strip()
            if not cve_id:
                logger.warning("Skipping KEV entry missing cveID: %s", raw)
                continue
            entries.append({
                "cve_id": cve_id,
                "vendor_project": raw.get("vendorProject", ""),
                "product": raw.get("product", ""),
                "vulnerability_name": raw.get("vulnerabilityName", ""),
                "date_added": raw.get("dateAdded", ""),
                "short_description": raw.get("shortDescription", ""),
                "required_action": raw.get("requiredAction", ""),
                "due_date": raw.get("dueDate", ""),
                "known_ransomware_use": raw.get("knownRansomwareCampaignUse", "Unknown"),
                "notes": raw.get("notes", ""),
            })
        return entries

    def _get_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        conn = _get_conn(self._db_path)
        row = conn.execute(
            f"SELECT cve_id FROM {_TABLE} WHERE cve_id=?", (cve_id,)
        ).fetchone()
        return dict(row) if row else None


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Import CISA KEV feed into local DB")
    parser.add_argument(
        "--idempotent",
        action="store_true",
        default=True,
        help="Skip CVE IDs already in DB (default: True)",
    )
    parser.add_argument(
        "--force-update",
        action="store_true",
        help="Update existing entries instead of skipping (sets idempotent=False)",
    )
    parser.add_argument("--db", default=_DEFAULT_DB, help="SQLite DB path")
    parser.add_argument("--url", default=CISA_KEV_URL, help="Override feed URL")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    importer = CisaKevImporter(db_path=args.db, url=args.url)
    idempotent = not args.force_update
    result = importer.run(idempotent=idempotent)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
