"""Dark Web Monitoring Engine — ALDECI.

Tracks dark web mentions, leaked credentials, data exposures,
and threat actor activity across paste sites, forums, marketplaces,
and ransomware sites.

Capabilities:
  - Mention tracking: credential leaks, data dumps, phishing kits, malware/exploit sales
  - Monitored keyword registry with alert thresholds
  - Credential exposure recording with breach metadata
  - Stats: totals, by type, by severity, new mentions, active keywords, exposures

Compliance: NIST CSF DE.AE-1, ISO 27001 A.5.7 (Threat Intelligence)
"""

from __future__ import annotations

import hashlib
import json
import logging

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_MENTION_TYPES = {
    "credential_leak",
    "data_dump",
    "phishing_kit",
    "malware_sale",
    "exploit_sale",
    "brand_mention",
    "executive_mention",
}

_VALID_SOURCE_CATEGORIES = {
    "paste_site",
    "forum",
    "marketplace",
    "telegram",
    "ransomware_site",
}

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

_VALID_MENTION_STATUSES = {
    "new",
    "investigating",
    "confirmed",
    "false_positive",
    "mitigated",
}

_VALID_KEYWORD_TYPES = {
    "domain",
    "email_domain",
    "brand",
    "executive_name",
    "product",
    "ip_range",
}

_VALID_EXPOSURE_SOURCES = {"breach_db", "paste_site", "dark_forum"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DarkWebMonitoringEngine:
    """SQLite WAL-backed Dark Web Monitoring engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/dark_web_monitoring.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "dark_web_monitoring.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS dark_web_mentions (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    mention_type     TEXT NOT NULL,
                    source_category  TEXT NOT NULL,
                    keyword_matched  TEXT NOT NULL,
                    severity         TEXT NOT NULL DEFAULT 'medium',
                    content_preview  TEXT NOT NULL DEFAULT '',
                    url_hash         TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'new',
                    discovered_at    TEXT NOT NULL,
                    updated_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_dwm_org
                    ON dark_web_mentions (org_id, mention_type, status, severity, discovered_at DESC);

                CREATE TABLE IF NOT EXISTS monitored_keywords (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    keyword         TEXT NOT NULL,
                    keyword_type    TEXT NOT NULL,
                    is_active       INTEGER NOT NULL DEFAULT 1,
                    alert_threshold INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_keywords_org
                    ON monitored_keywords (org_id, keyword_type, is_active);

                CREATE TABLE IF NOT EXISTS credential_exposures (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    email_domain   TEXT NOT NULL,
                    exposure_count INTEGER NOT NULL DEFAULT 1,
                    source         TEXT NOT NULL,
                    breach_date    TEXT,
                    verified       INTEGER NOT NULL DEFAULT 0,
                    created_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_exposures_org
                    ON credential_exposures (org_id, verified, created_at DESC);

                -- GAP-030: subsidiary dark-web monitors
                CREATE TABLE IF NOT EXISTS subsidiary_monitors (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    subsidiary_name  TEXT NOT NULL,
                    keywords_json    TEXT NOT NULL DEFAULT '[]',
                    enabled          INTEGER NOT NULL DEFAULT 1,
                    created_at       TEXT NOT NULL,
                    UNIQUE(org_id, subsidiary_name)
                );

                CREATE INDEX IF NOT EXISTS idx_submon_org
                    ON subsidiary_monitors (org_id, enabled);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Mentions
    # ------------------------------------------------------------------

    def add_mention(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a new dark web mention."""
        mention_type = data.get("mention_type", "")
        if mention_type not in _VALID_MENTION_TYPES:
            raise ValueError(
                f"Invalid mention_type: {mention_type!r}. "
                f"Must be one of {sorted(_VALID_MENTION_TYPES)}"
            )

        source_category = data.get("source_category", "")
        if source_category not in _VALID_SOURCE_CATEGORIES:
            raise ValueError(
                f"Invalid source_category: {source_category!r}. "
                f"Must be one of {sorted(_VALID_SOURCE_CATEGORIES)}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity!r}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        keyword_matched = (data.get("keyword_matched") or "").strip()
        if not keyword_matched:
            raise ValueError("keyword_matched is required.")

        content_preview = (data.get("content_preview") or "")[:500]

        # SHA-256 of source URL — never store raw URL
        raw_url = data.get("source_url") or data.get("url_hash") or ""
        url_hash = (
            hashlib.sha256(raw_url.encode()).hexdigest()
            if raw_url and not (len(raw_url) == 64 and all(c in "0123456789abcdef" for c in raw_url))
            else raw_url
        )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "mention_type": mention_type,
            "source_category": source_category,
            "keyword_matched": keyword_matched,
            "severity": severity,
            "content_preview": content_preview,
            "url_hash": url_hash,
            "status": "new",
            "discovered_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO dark_web_mentions
                       (id, org_id, mention_type, source_category, keyword_matched,
                        severity, content_preview, url_hash, status, discovered_at, updated_at)
                       VALUES (:id, :org_id, :mention_type, :source_category, :keyword_matched,
                               :severity, :content_preview, :url_hash, :status,
                               :discovered_at, :updated_at)""",
                    record,
                )
        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("THREAT_DETECTED", {
                    "org_id": org_id,
                    "entity": "dark_web_mention",
                    "mention_id": record["id"],
                    "mention_type": mention_type,
                    "severity": severity,
                    "keyword_matched": keyword_matched,
                })
            except Exception:
                pass
        return record

    def list_mentions(
        self,
        org_id: str,
        mention_type: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List dark web mentions with optional filters."""
        sql = "SELECT * FROM dark_web_mentions WHERE org_id = ?"
        params: list = [org_id]
        if mention_type:
            sql += " AND mention_type = ?"
            params.append(mention_type)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY discovered_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_mention(self, org_id: str, mention_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single mention by ID. Returns None if not found or wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM dark_web_mentions WHERE org_id = ? AND id = ?",
                (org_id, mention_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_mention_status(
        self, org_id: str, mention_id: str, new_status: str
    ) -> Dict[str, Any]:
        """Update the status of a mention. Raises KeyError if not found."""
        if new_status not in _VALID_MENTION_STATUSES:
            raise ValueError(
                f"Invalid status: {new_status!r}. "
                f"Must be one of {sorted(_VALID_MENTION_STATUSES)}"
            )
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE dark_web_mentions SET status = ?, updated_at = ? "
                    "WHERE org_id = ? AND id = ?",
                    (new_status, now, org_id, mention_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"Mention not found: {mention_id}")
                row = conn.execute(
                    "SELECT * FROM dark_web_mentions WHERE org_id = ? AND id = ?",
                    (org_id, mention_id),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Monitored Keywords
    # ------------------------------------------------------------------

    def add_keyword(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a monitored keyword."""
        keyword = (data.get("keyword") or "").strip()
        if not keyword:
            raise ValueError("keyword is required.")

        keyword_type = data.get("keyword_type", "")
        if keyword_type not in _VALID_KEYWORD_TYPES:
            raise ValueError(
                f"Invalid keyword_type: {keyword_type!r}. "
                f"Must be one of {sorted(_VALID_KEYWORD_TYPES)}"
            )

        alert_threshold = int(data.get("alert_threshold", 1))

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "keyword": keyword,
            "keyword_type": keyword_type,
            "is_active": 1,
            "alert_threshold": alert_threshold,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO monitored_keywords
                       (id, org_id, keyword, keyword_type, is_active, alert_threshold, created_at)
                       VALUES (:id, :org_id, :keyword, :keyword_type, :is_active,
                               :alert_threshold, :created_at)""",
                    record,
                )
        # Return is_active as bool-like for consistency
        record["is_active"] = True
        return record

    def list_keywords(
        self,
        org_id: str,
        keyword_type: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List monitored keywords with optional filters."""
        sql = "SELECT * FROM monitored_keywords WHERE org_id = ?"
        params: list = [org_id]
        if keyword_type is not None:
            sql += " AND keyword_type = ?"
            params.append(keyword_type)
        if is_active is not None:
            sql += " AND is_active = ?"
            params.append(1 if is_active else 0)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Credential Exposures
    # ------------------------------------------------------------------

    def record_credential_exposure(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a credential exposure event."""
        email_domain = (data.get("email_domain") or "").strip()
        if not email_domain:
            raise ValueError("email_domain is required.")

        try:
            exposure_count = int(data.get("exposure_count", 1))
        except (TypeError, ValueError):
            raise ValueError("exposure_count must be an integer.")
        if exposure_count < 1:
            raise ValueError("exposure_count must be >= 1.")

        source = data.get("source", "")
        if source not in _VALID_EXPOSURE_SOURCES:
            raise ValueError(
                f"Invalid source: {source!r}. "
                f"Must be one of {sorted(_VALID_EXPOSURE_SOURCES)}"
            )

        verified = bool(data.get("verified", False))
        breach_date = data.get("breach_date")  # nullable

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "email_domain": email_domain,
            "exposure_count": exposure_count,
            "source": source,
            "breach_date": breach_date,
            "verified": 1 if verified else 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO credential_exposures
                       (id, org_id, email_domain, exposure_count, source,
                        breach_date, verified, created_at)
                       VALUES (:id, :org_id, :email_domain, :exposure_count, :source,
                               :breach_date, :verified, :created_at)""",
                    record,
                )
        return record

    def list_credential_exposures(
        self,
        org_id: str,
        verified: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List credential exposures with optional verified filter."""
        sql = "SELECT * FROM credential_exposures WHERE org_id = ?"
        params: list = [org_id]
        if verified is not None:
            sql += " AND verified = ?"
            params.append(1 if verified else 0)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_dark_web_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated dark web monitoring statistics for an org."""
        with self._conn() as conn:
            total_mentions = conn.execute(
                "SELECT COUNT(*) FROM dark_web_mentions WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT mention_type, COUNT(*) as cnt FROM dark_web_mentions "
                "WHERE org_id = ? GROUP BY mention_type",
                (org_id,),
            ).fetchall()
            by_type = {r["mention_type"]: r["cnt"] for r in type_rows}

            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM dark_web_mentions "
                "WHERE org_id = ? GROUP BY severity",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            new_mentions = conn.execute(
                "SELECT COUNT(*) FROM dark_web_mentions WHERE org_id = ? AND status = 'new'",
                (org_id,),
            ).fetchone()[0]

            active_keywords = conn.execute(
                "SELECT COUNT(*) FROM monitored_keywords WHERE org_id = ? AND is_active = 1",
                (org_id,),
            ).fetchone()[0]

            total_exposures = conn.execute(
                "SELECT COUNT(*) FROM credential_exposures WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            unverified_exposures = conn.execute(
                "SELECT COUNT(*) FROM credential_exposures WHERE org_id = ? AND verified = 0",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_mentions": total_mentions,
            "by_type": by_type,
            "by_severity": by_severity,
            "new_mentions": new_mentions,
            "active_keywords": active_keywords,
            "total_exposures": total_exposures,
            "unverified_exposures": unverified_exposures,
        }

    # ------------------------------------------------------------------
    # GAP-030: Subsidiary Dark-Web Monitors
    # ------------------------------------------------------------------

    def monitor_subsidiary_mentions(
        self,
        org_id: str,
        subsidiary_name: str,
        keywords: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Register (or update) a dark-web monitor for a subsidiary (GAP-030).

        UNIQUE(org_id, subsidiary_name) — re-registering the same subsidiary
        updates its keyword list and re-enables the monitor.
        """
        subsidiary_name = (subsidiary_name or "").strip()
        if not subsidiary_name:
            raise ValueError("subsidiary_name is required.")

        # Normalise keywords: strip, drop empties, dedupe while preserving order
        clean_keywords: List[str] = []
        seen = set()
        for k in (keywords or []):
            if not isinstance(k, str):
                raise ValueError("keywords must be a list of strings.")
            kk = k.strip()
            if kk and kk not in seen:
                clean_keywords.append(kk)
                seen.add(kk)

        now = _now_iso()
        keywords_json = json.dumps(clean_keywords)
        record_id = str(uuid.uuid4())

        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT id FROM subsidiary_monitors "
                    "WHERE org_id = ? AND subsidiary_name = ?",
                    (org_id, subsidiary_name),
                ).fetchone()
                if existing:
                    record_id = existing["id"]
                    conn.execute(
                        "UPDATE subsidiary_monitors "
                        "SET keywords_json = ?, enabled = 1 "
                        "WHERE org_id = ? AND subsidiary_name = ?",
                        (keywords_json, org_id, subsidiary_name),
                    )
                else:
                    conn.execute(
                        """INSERT INTO subsidiary_monitors
                           (id, org_id, subsidiary_name, keywords_json, enabled, created_at)
                           VALUES (?, ?, ?, ?, 1, ?)""",
                        (record_id, org_id, subsidiary_name, keywords_json, now),
                    )
                row = conn.execute(
                    "SELECT * FROM subsidiary_monitors WHERE id = ?",
                    (record_id,),
                ).fetchone()

        result = dict(row)
        result["enabled"] = bool(result["enabled"])
        try:
            result["keywords"] = json.loads(result.get("keywords_json") or "[]")
        except (json.JSONDecodeError, TypeError):
            result["keywords"] = []

        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("ASSET_DISCOVERED", {
                    "entity_type": "subsidiary_monitor",
                    "org_id": org_id,
                    "subsidiary_name": subsidiary_name,
                    "source_engine": "dark_web_monitoring",
                })
            except Exception:
                pass
        return result

    def list_subsidiary_monitors(
        self,
        org_id: str,
        enabled: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List subsidiary monitors for an org, with optional enabled filter."""
        sql = "SELECT * FROM subsidiary_monitors WHERE org_id = ?"
        params: list = [org_id]
        if enabled is not None:
            sql += " AND enabled = ?"
            params.append(1 if enabled else 0)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d["enabled"] = bool(d["enabled"])
            try:
                d["keywords"] = json.loads(d.get("keywords_json") or "[]")
            except (json.JSONDecodeError, TypeError):
                d["keywords"] = []
            out.append(d)
        return out

    def disable_subsidiary_monitor(
        self,
        org_id: str,
        subsidiary_name: str,
    ) -> bool:
        """Disable a subsidiary monitor. Returns True if found and flipped."""
        subsidiary_name = (subsidiary_name or "").strip()
        if not subsidiary_name:
            raise ValueError("subsidiary_name is required.")
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE subsidiary_monitors SET enabled = 0 "
                    "WHERE org_id = ? AND subsidiary_name = ?",
                    (org_id, subsidiary_name),
                )
                return cur.rowcount > 0
