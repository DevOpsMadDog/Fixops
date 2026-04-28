"""Have I Been Pwned (HIBP) importer.

Three sources:
  1. Breach catalog (free, no auth):
       GET https://haveibeenpwned.com/api/v3/breaches
       Upserts ~700 breach entries into data/hibp.db.
  2. Password range proxy (free, k-anonymity, no DB write):
       GET https://api.pwnedpasswords.com/range/{first_5_chars}
       Returns suffix list + counts.  Full hash is NEVER sent or logged.
  3. Breached-account check (paid, HIBP_API_KEY required):
       GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}
       If key missing, returns status="needs_credentials".
       The full email address is NEVER logged.

Privacy rules (enforced in code):
  - Never log a full password or full email.
  - For passwords: only the 5-char SHA-1 prefix is used (k-anonymity).
  - For emails: the username portion is masked in logs.

DB: data/hibp.db  (table: breaches)
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:  # pragma: no cover
    _HAS_HTTPX = False

logger = logging.getLogger(__name__)

HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"

_DEFAULT_DB = "data/hibp.db"
_TABLE = "breaches"
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
            name            TEXT PRIMARY KEY,
            title           TEXT,
            domain          TEXT,
            breach_date     TEXT,
            added_date      TEXT,
            modified_date   TEXT,
            pwn_count       INTEGER,
            description     TEXT,
            data_classes    TEXT,
            is_verified     INTEGER,
            is_fabricated   INTEGER,
            is_sensitive    INTEGER,
            is_retired      INTEGER,
            is_spam_list    INTEGER,
            logo_path       TEXT,
            raw_json        TEXT,
            imported_at     TEXT
        )
    """)
    conn.commit()


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _http_get(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 30) -> Any:
    """GET url, return parsed JSON or raw text depending on content-type."""
    hdrs = headers or {}
    if _HAS_HTTPX:
        import httpx as _httpx
        resp = _httpx.get(url, headers=hdrs, timeout=timeout, follow_redirects=True)
        resp.raise_for_status()
        ct = resp.headers.get("content-type", "")
        return resp.json() if "json" in ct else resp.text
    from urllib.request import Request, urlopen  # noqa: PLC0415
    req = Request(url, headers=hdrs)  # nosec — controlled URL
    with urlopen(req, timeout=timeout) as r:  # nosec
        raw = r.read()
        ct = r.headers.get("Content-Type", "")
        return json.loads(raw) if "json" in ct else raw.decode()


# ---------------------------------------------------------------------------
# Main importer class
# ---------------------------------------------------------------------------

class HibpImporter:
    """Import HIBP breach catalog into local SQLite DB.

    Args:
        db_path: Path to SQLite database.
        breaches_url: Override HIBP breaches endpoint (useful for tests).
        timeout: HTTP timeout in seconds.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        breaches_url: str = HIBP_BREACHES_URL,
        timeout: int = 30,
    ) -> None:
        self._db_path = db_path
        self._breaches_url = breaches_url
        self._timeout = timeout
        _ensure_table(db_path)

    # ------------------------------------------------------------------
    # Breach catalog import
    # ------------------------------------------------------------------

    def import_breaches(self, idempotent: bool = True) -> Dict[str, Any]:
        """Fetch the HIBP breach catalog and upsert into DB.

        Returns:
            {
                "breaches_imported": N,
                "breaches_updated": N,
                "breaches_skipped": N,
                "source_count": N,
                "by_year": {"2019": 12, ...},
                "biggest_breach": "Adobe",
            }
        """
        raw_list = _http_get(self._breaches_url, timeout=self._timeout)
        if not isinstance(raw_list, list):
            raise ValueError(f"Unexpected HIBP breach catalog format: {type(raw_list)}")

        conn = _get_conn(self._db_path)
        now_iso = datetime.now(timezone.utc).isoformat()
        imported = updated = skipped = 0
        by_year: Dict[str, int] = {}
        biggest_name = ""
        biggest_count = 0

        for raw in raw_list:
            if not isinstance(raw, dict):
                continue
            name = raw.get("Name", "").strip()
            if not name:
                continue

            # Track year buckets
            breach_date = raw.get("BreachDate", "")
            if breach_date and len(breach_date) >= 4:
                year = breach_date[:4]
                by_year[year] = by_year.get(year, 0) + 1

            # Track biggest
            pwn_count = raw.get("PwnCount", 0) or 0
            if pwn_count > biggest_count:
                biggest_count = pwn_count
                biggest_name = name

            existing = self._get_by_name(name)
            row_vals = (
                raw.get("Title", ""),
                raw.get("Domain", ""),
                breach_date,
                raw.get("AddedDate", ""),
                raw.get("ModifiedDate", ""),
                pwn_count,
                raw.get("Description", ""),
                json.dumps(raw.get("DataClasses", [])),
                int(bool(raw.get("IsVerified", False))),
                int(bool(raw.get("IsFabricated", False))),
                int(bool(raw.get("IsSensitive", False))),
                int(bool(raw.get("IsRetired", False))),
                int(bool(raw.get("IsSpamList", False))),
                raw.get("LogoPath", ""),
                json.dumps(raw),
                now_iso,
            )

            if existing is not None:
                if idempotent:
                    skipped += 1
                    continue
                conn.execute(
                    f"""UPDATE {_TABLE}
                        SET title=?, domain=?, breach_date=?, added_date=?,
                            modified_date=?, pwn_count=?, description=?,
                            data_classes=?, is_verified=?, is_fabricated=?,
                            is_sensitive=?, is_retired=?, is_spam_list=?,
                            logo_path=?, raw_json=?, imported_at=?
                        WHERE name=?""",
                    row_vals + (name,),
                )
                updated += 1
            else:
                conn.execute(
                    f"""INSERT INTO {_TABLE}
                        (name, title, domain, breach_date, added_date,
                         modified_date, pwn_count, description, data_classes,
                         is_verified, is_fabricated, is_sensitive, is_retired,
                         is_spam_list, logo_path, raw_json, imported_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (name,) + row_vals,
                )
                imported += 1

        conn.commit()
        result: Dict[str, Any] = {
            "breaches_imported": imported,
            "breaches_updated": updated,
            "breaches_skipped": skipped,
            "source_count": len(raw_list),
            "by_year": dict(sorted(by_year.items())),
            "biggest_breach": biggest_name,
        }
        logger.info("HIBP breach import complete: imported=%d skipped=%d", imported, skipped)
        return result

    # ------------------------------------------------------------------
    # Password range proxy (k-anonymity — no DB write)
    # ------------------------------------------------------------------

    def check_password_range(self, prefix: str) -> Dict[str, Any]:
        """Proxy the HIBP k-anonymity password range API.

        Args:
            prefix: First 5 hex characters of a SHA-1 hash (case-insensitive).

        Returns:
            {"prefix": "ABCDE", "matches": [{"suffix": "...", "count": N}, ...]}

        Privacy: the full password hash is never sent to HIBP — only the
        5-char prefix.  This method never logs a hash of any length.
        """
        prefix = prefix.upper()[:5]
        if len(prefix) != 5:
            raise ValueError("prefix must be exactly 5 hex characters")

        url = PWNED_RANGE_URL.format(prefix=prefix)
        text = _http_get(url, timeout=self._timeout)
        matches = []
        for line in (text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(":")
            if len(parts) == 2:
                matches.append({"suffix": parts[0], "count": int(parts[1])})
        logger.info("HIBP password range: prefix=%s matches=%d", prefix, len(matches))
        return {"prefix": prefix, "matches": matches}

    # ------------------------------------------------------------------
    # Breached-account check (paid tier)
    # ------------------------------------------------------------------

    def check_email(self, email: str) -> Dict[str, Any]:
        """Check whether an email appears in any HIBP breach.

        Requires HIBP_API_KEY env var.  If missing, returns
        {"status": "needs_credentials"} without making a network call.

        Privacy: the full email address is never logged.
        """
        api_key = os.environ.get("HIBP_API_KEY", "").strip()
        if not api_key:
            logger.info("HIBP email check skipped: HIBP_API_KEY not set (status=needs_credentials)")
            return {"status": "needs_credentials"}

        # Log only the domain part for audit purposes
        domain_hint = email.split("@")[-1] if "@" in email else "<no-domain>"
        logger.info("HIBP email check: domain=%s", domain_hint)

        url = HIBP_ACCOUNT_URL.format(email=email)
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "ALDECI-HIBP-Importer/1.0",
        }
        try:
            data = _http_get(url, headers=headers, timeout=self._timeout)
        except Exception as exc:
            # 404 = not found in any breach — treat as clean
            exc_str = str(exc)
            if "404" in exc_str:
                return {"status": "not_found", "breaches": []}
            if "401" in exc_str or "403" in exc_str:
                return {"status": "needs_credentials"}
            raise
        breaches = data if isinstance(data, list) else []
        return {
            "status": "found",
            "breach_count": len(breaches),
            "breaches": [b.get("Name", "") for b in breaches],
        }

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def list_breaches(
        self,
        domain: Optional[str] = None,
        since: Optional[str] = None,
        data_class: Optional[str] = None,
        limit: int = 500,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List breach catalog with optional filters.

        Args:
            domain: Exact domain match (e.g. "adobe.com").
            since: ISO date string — only breaches on or after this date.
            data_class: Filter by data class substring (e.g. "Passwords").
            limit: Max rows to return (capped at 1000).
            offset: Pagination offset.
        """
        limit = min(max(1, limit), 1000)
        conn = _get_conn(self._db_path)
        where_clauses: List[str] = []
        params: List[Any] = []

        if domain:
            where_clauses.append("domain = ?")
            params.append(domain)
        if since:
            where_clauses.append("breach_date >= ?")
            params.append(since)
        if data_class:
            where_clauses.append("data_classes LIKE ?")
            params.append(f"%{data_class}%")

        where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        total_row = conn.execute(
            f"SELECT COUNT(*) FROM {_TABLE} {where}", params
        ).fetchone()
        total = total_row[0] if total_row else 0

        rows = conn.execute(
            f"""SELECT name, title, domain, breach_date, pwn_count,
                       data_classes, is_verified, imported_at
                FROM {_TABLE} {where}
                ORDER BY breach_date DESC
                LIMIT ? OFFSET ?""",
            params + [limit, offset],
        ).fetchall()

        return {
            "breaches": [dict(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def total_count(self) -> int:
        conn = _get_conn(self._db_path)
        row = conn.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()
        return row[0] if row else 0

    def _get_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        conn = _get_conn(self._db_path)
        row = conn.execute(
            f"SELECT name FROM {_TABLE} WHERE name=?", (name,)
        ).fetchone()
        return dict(row) if row else None
