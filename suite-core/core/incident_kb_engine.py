"""Incident Knowledge Base Engine — ALDECI.

Searchable knowledge base of incident patterns, runbooks, and resolution
playbooks. Tracks institutional knowledge from past incidents, runbook
effectiveness, and search analytics.

Compliance: NIST CSF RS.IM-1, ISO/IEC 27001 A.16.1.6, SOC 2 CC7.5
"""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "incident_kb.db"
)

_VALID_ARTICLE_TYPES = {
    "howto", "postmortem", "reference", "troubleshooting", "best-practice", "policy",
}
_VALID_INCIDENT_TYPES = {
    "ransomware", "phishing", "data-breach", "ddos",
    "insider", "supply-chain", "zero-day", "misconfiguration",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class IncidentKBEngine:
    """SQLite WAL-backed Incident Knowledge Base engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Connection helper
    # ------------------------------------------------------------------

    @contextlib.contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS kb_articles (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    title         TEXT NOT NULL DEFAULT '',
                    article_type  TEXT NOT NULL DEFAULT 'howto',
                    incident_type TEXT NOT NULL DEFAULT 'misconfiguration',
                    severity      TEXT NOT NULL DEFAULT 'medium',
                    content       TEXT NOT NULL DEFAULT '',
                    tags          TEXT NOT NULL DEFAULT '',
                    author        TEXT NOT NULL DEFAULT '',
                    view_count    INTEGER NOT NULL DEFAULT 0,
                    helpful_count INTEGER NOT NULL DEFAULT 0,
                    created_at    TEXT NOT NULL DEFAULT '',
                    updated_at    TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS kb_runbooks (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    runbook_name     TEXT NOT NULL DEFAULT '',
                    incident_type    TEXT NOT NULL DEFAULT 'misconfiguration',
                    steps            TEXT NOT NULL DEFAULT '[]',
                    estimated_minutes INTEGER NOT NULL DEFAULT 30,
                    success_rate     REAL NOT NULL DEFAULT 0.0,
                    execution_count  INTEGER NOT NULL DEFAULT 0,
                    last_executed    TEXT NOT NULL DEFAULT '',
                    created_at       TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS kb_searches (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    query             TEXT NOT NULL DEFAULT '',
                    results_count     INTEGER NOT NULL DEFAULT 0,
                    clicked_article_id TEXT NOT NULL DEFAULT '',
                    searched_at       TEXT NOT NULL DEFAULT ''
                );
            """)

    # ------------------------------------------------------------------
    # Articles
    # ------------------------------------------------------------------

    def create_article(
        self,
        org_id: str,
        title: str,
        article_type: str,
        incident_type: str,
        severity: str,
        content: str,
        tags: Any,
        author: str,
    ) -> Dict[str, Any]:
        """Create a new KB article. Tags stored as comma-separated string."""
        if isinstance(tags, list):
            tags_str = ",".join(str(t) for t in tags)
        else:
            tags_str = str(tags) if tags else ""

        now = _now()
        article_id = str(uuid.uuid4())
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO kb_articles
                    (id, org_id, title, article_type, incident_type, severity,
                     content, tags, author, view_count, helpful_count,
                     created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    article_id, org_id, title, article_type, incident_type,
                    severity, content, tags_str, author, 0, 0, now, now,
                ),
            )
            if _get_tg_bus:
                try:
                    bus = _get_tg_bus()
                    if bus and getattr(bus, "enabled", False):
                        bus.emit("INCIDENT_CREATED", {"entity_type": "incident_kb_engine", "org_id": org_id, "source_engine": "incident_kb_engine"})
                except Exception:
                    pass
            return dict(
                conn.execute(
                    "SELECT * FROM kb_articles WHERE id=?", (article_id,)
                ).fetchone()
            )

    def update_article(
        self,
        article_id: str,
        org_id: str,
        content: str,
        tags: Any,
    ) -> Dict[str, Any]:
        """Update article content and tags."""
        if isinstance(tags, list):
            tags_str = ",".join(str(t) for t in tags)
        else:
            tags_str = str(tags) if tags else ""

        now = _now()
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT id FROM kb_articles WHERE id=? AND org_id=?",
                (article_id, org_id),
            ).fetchone()
            if not row:
                raise KeyError(f"Article {article_id} not found")
            conn.execute(
                """
                UPDATE kb_articles
                SET content=?, tags=?, updated_at=?
                WHERE id=? AND org_id=?
                """,
                (content, tags_str, now, article_id, org_id),
            )
            return dict(
                conn.execute(
                    "SELECT * FROM kb_articles WHERE id=?", (article_id,)
                ).fetchone()
            )

    def view_article(self, article_id: str, org_id: str) -> Dict[str, Any]:
        """Increment view_count and return the article."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT id FROM kb_articles WHERE id=? AND org_id=?",
                (article_id, org_id),
            ).fetchone()
            if not row:
                raise KeyError(f"Article {article_id} not found")
            conn.execute(
                "UPDATE kb_articles SET view_count=view_count+1 WHERE id=? AND org_id=?",
                (article_id, org_id),
            )
            return dict(
                conn.execute(
                    "SELECT * FROM kb_articles WHERE id=?", (article_id,)
                ).fetchone()
            )

    def mark_helpful(self, article_id: str, org_id: str) -> Dict[str, Any]:
        """Increment helpful_count for an article."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT id FROM kb_articles WHERE id=? AND org_id=?",
                (article_id, org_id),
            ).fetchone()
            if not row:
                raise KeyError(f"Article {article_id} not found")
            conn.execute(
                "UPDATE kb_articles SET helpful_count=helpful_count+1 WHERE id=? AND org_id=?",
                (article_id, org_id),
            )
            return dict(
                conn.execute(
                    "SELECT * FROM kb_articles WHERE id=?", (article_id,)
                ).fetchone()
            )

    def search_articles(
        self,
        org_id: str,
        query: str,
        incident_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Case-insensitive LIKE search on title, content, and tags.

        Records the search query with result count for analytics.
        """
        like_pat = f"%{query}%"
        sql = """
            SELECT * FROM kb_articles
            WHERE org_id=?
              AND (title LIKE ? OR content LIKE ? OR tags LIKE ?)
        """
        params: List[Any] = [org_id, like_pat, like_pat, like_pat]
        if incident_type:
            sql += " AND incident_type=?"
            params.append(incident_type)
        sql += " ORDER BY view_count DESC"

        with self._lock, self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            results = [dict(r) for r in rows]

            # Record the search
            search_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO kb_searches
                    (id, org_id, query, results_count, clicked_article_id, searched_at)
                VALUES (?,?,?,?,?,?)
                """,
                (search_id, org_id, query, len(results), "", _now()),
            )

        return results

    # ------------------------------------------------------------------
    # Runbooks
    # ------------------------------------------------------------------

    def create_runbook(
        self,
        org_id: str,
        runbook_name: str,
        incident_type: str,
        steps: Any,
        estimated_minutes: int,
    ) -> Dict[str, Any]:
        """Create a new runbook. Steps stored as JSON string."""
        if isinstance(steps, (list, dict)):
            steps_json = json.dumps(steps)
        else:
            steps_json = str(steps)

        now = _now()
        runbook_id = str(uuid.uuid4())
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO kb_runbooks
                    (id, org_id, runbook_name, incident_type, steps,
                     estimated_minutes, success_rate, execution_count,
                     last_executed, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    runbook_id, org_id, runbook_name, incident_type,
                    steps_json, int(estimated_minutes), 0.0, 0, "", now,
                ),
            )
            if _get_tg_bus:
                try:
                    bus = _get_tg_bus()
                    if bus and getattr(bus, "enabled", False):
                        bus.emit("INCIDENT_CREATED", {"entity_type": "incident_kb_engine", "org_id": org_id, "source_engine": "incident_kb_engine"})
                except Exception:
                    pass
            return dict(
                conn.execute(
                    "SELECT * FROM kb_runbooks WHERE id=?", (runbook_id,)
                ).fetchone()
            )

    def execute_runbook(
        self,
        runbook_id: str,
        org_id: str,
        success: bool,
    ) -> Dict[str, Any]:
        """Record a runbook execution and recompute rolling success_rate."""
        now = _now()
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM kb_runbooks WHERE id=? AND org_id=?",
                (runbook_id, org_id),
            ).fetchone()
            if not row:
                raise KeyError(f"Runbook {runbook_id} not found")

            old_rate = float(row["success_rate"])
            old_count = int(row["execution_count"])
            new_count = old_count + 1
            new_rate = (old_rate * old_count + (1.0 if success else 0.0)) / new_count

            conn.execute(
                """
                UPDATE kb_runbooks
                SET execution_count=?, success_rate=?, last_executed=?
                WHERE id=? AND org_id=?
                """,
                (new_count, new_rate, now, runbook_id, org_id),
            )
            if _get_tg_bus:
                try:
                    bus = _get_tg_bus()
                    if bus and getattr(bus, "enabled", False):
                        bus.emit("INCIDENT_CREATED", {"entity_type": "incident_kb_engine", "org_id": org_id, "source_engine": "incident_kb_engine"})
                except Exception:
                    pass
            return dict(
                conn.execute(
                    "SELECT * FROM kb_runbooks WHERE id=?", (runbook_id,)
                ).fetchone()
            )

    def get_recommended_runbooks(
        self, org_id: str, incident_type: str
    ) -> List[Dict[str, Any]]:
        """Return runbooks for incident_type sorted by success_rate DESC."""
        with self._lock, self._conn() as conn:
            return [
                dict(r)
                for r in conn.execute(
                    """
                    SELECT * FROM kb_runbooks
                    WHERE org_id=? AND incident_type=?
                    ORDER BY success_rate DESC, execution_count DESC
                    """,
                    (org_id, incident_type),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_kb_stats(self, org_id: str) -> Dict[str, Any]:
        """Return KB-wide statistics."""
        with self._lock, self._conn() as conn:
            total_articles = conn.execute(
                "SELECT COUNT(*) FROM kb_articles WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            total_runbooks = conn.execute(
                "SELECT COUNT(*) FROM kb_runbooks WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            avg_success_row = conn.execute(
                """
                SELECT AVG(success_rate) AS avg_sr
                FROM kb_runbooks WHERE org_id=? AND execution_count > 0
                """,
                (org_id,),
            ).fetchone()
            avg_success_rate = (
                float(avg_success_row["avg_sr"])
                if avg_success_row["avg_sr"] is not None
                else 0.0
            )

            most_viewed_row = conn.execute(
                """
                SELECT title, view_count FROM kb_articles
                WHERE org_id=?
                ORDER BY view_count DESC LIMIT 1
                """,
                (org_id,),
            ).fetchone()
            most_viewed_article = dict(most_viewed_row) if most_viewed_row else None

            top_searched = [
                {"query": r["query"], "count": r["cnt"]}
                for r in conn.execute(
                    """
                    SELECT query, COUNT(*) AS cnt
                    FROM kb_searches WHERE org_id=?
                    GROUP BY query
                    ORDER BY cnt DESC
                    LIMIT 5
                    """,
                    (org_id,),
                ).fetchall()
            ]

        return {
            "total_articles": total_articles,
            "total_runbooks": total_runbooks,
            "avg_success_rate": avg_success_rate,
            "most_viewed_article": most_viewed_article,
            "top_searched_terms": top_searched,
        }
