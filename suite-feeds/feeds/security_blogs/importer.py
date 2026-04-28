"""Security Blogs RSS Aggregator Importer.

Fetches and aggregates posts from canonical security RSS/Atom feeds.
Each post is upserted by ID into a per-domain SQLite DB.

Usage (programmatic):
    from feeds.security_blogs.importer import SecurityBlogsImporter
    result = SecurityBlogsImporter().run()

Usage (CLI):
    python -m feeds.security_blogs.importer

DB: data/security_blogs.db
Sources: suite-feeds/feeds/security_blogs/sources.txt
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from time import struct_time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_HERE = Path(__file__).resolve().parent
SOURCES_FILE = _HERE / "sources.txt"

_PROJECT_ROOT = _HERE.parents[3]  # feeds/security_blogs -> suite-feeds -> project root
_DEFAULT_DB = str(_PROJECT_ROOT / "data" / "security_blogs.db")

_TABLE = "blog_posts"
_local = threading.local()

SOURCES_URL = "suite-feeds/feeds/security_blogs/sources.txt"  # for registry


# ---------------------------------------------------------------------------
# SQLite helpers
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
            id          TEXT PRIMARY KEY,
            source      TEXT NOT NULL,
            title       TEXT,
            link        TEXT,
            summary     TEXT,
            published   TEXT,
            author      TEXT,
            tags        TEXT,
            imported_at TEXT NOT NULL
        )
    """)
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_source ON {_TABLE}(source)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_published ON {_TABLE}(published)")
    conn.commit()


# ---------------------------------------------------------------------------
# Feed extraction helpers
# ---------------------------------------------------------------------------

def _struct_to_iso(ts: Optional[struct_time]) -> Optional[str]:
    """Convert a feedparser time_struct to ISO-8601 UTC string."""
    if ts is None:
        return None
    try:
        dt = datetime(*ts[:6], tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:  # noqa: BLE001
        return None


def _extract_tags(entry: Any) -> str:
    """Return comma-separated tag terms from an entry."""
    try:
        tags = getattr(entry, "tags", None) or []
        terms = [t.get("term", "") for t in tags if isinstance(t, dict) and t.get("term")]
        return ",".join(terms)
    except Exception:  # noqa: BLE001
        return ""


def _feed_name_from_url(url: str) -> str:
    """Derive a short human-readable feed name from its URL."""
    from urllib.parse import urlparse
    host = urlparse(url).hostname or url
    # strip www. prefix
    if host.startswith("www."):
        host = host[4:]
    return host


def _fetch_bytes(url: str, timeout: int = 30) -> Optional[bytes]:
    """Fetch raw bytes from *url* with httpx, returning None on failure."""
    try:
        import httpx
        resp = httpx.get(url, timeout=timeout, follow_redirects=True,
                         headers={"User-Agent": "ALDECI-SecurityBlogsFeed/1.0"})
        resp.raise_for_status()
        return resp.content
    except Exception as exc:  # noqa: BLE001
        logger.warning("security_blogs: fetch failed for %s — %s", url, exc)
        return None


def _parse_feed(url: str, source_name: str) -> List[Dict[str, Any]]:
    """Fetch + parse one RSS/Atom feed. Returns list of post dicts."""
    try:
        import feedparser
    except ImportError:
        raise RuntimeError("feedparser is required: pip install feedparser")

    raw = _fetch_bytes(url)
    if raw is None:
        return []

    try:
        feed = feedparser.parse(raw)
    except Exception as exc:  # noqa: BLE001
        logger.warning("security_blogs: feedparser error for %s — %s", url, exc)
        return []

    posts: List[Dict[str, Any]] = []
    for entry in feed.entries:
        entry_id = getattr(entry, "id", None) or getattr(entry, "link", None)
        if not entry_id:
            continue
        title = getattr(entry, "title", None) or ""
        link = getattr(entry, "link", None) or ""
        summary = getattr(entry, "summary", None) or ""
        published = _struct_to_iso(getattr(entry, "published_parsed", None))
        author = getattr(entry, "author", None) or ""
        tags = _extract_tags(entry)

        posts.append({
            "id": entry_id,
            "source": source_name,
            "title": title,
            "link": link,
            "summary": summary,
            "published": published,
            "author": author,
            "tags": tags,
        })

    return posts


def _upsert_posts(posts: List[Dict[str, Any]], db_path: str) -> int:
    """Upsert posts into the DB. Returns count of newly inserted rows."""
    if not posts:
        return 0
    conn = _get_conn(db_path)
    now = datetime.now(timezone.utc).isoformat()
    inserted = 0
    for p in posts:
        cur = conn.execute(
            f"""
            INSERT INTO {_TABLE}
                (id, source, title, link, summary, published, author, tags, imported_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                source=excluded.source,
                title=excluded.title,
                link=excluded.link,
                summary=excluded.summary,
                published=excluded.published,
                author=excluded.author,
                tags=excluded.tags,
                imported_at=excluded.imported_at
            """,
            (
                p["id"], p["source"], p["title"], p["link"],
                p["summary"], p["published"], p["author"], p["tags"], now,
            ),
        )
        if cur.rowcount:
            inserted += 1
    conn.commit()
    return inserted


# ---------------------------------------------------------------------------
# Main importer class
# ---------------------------------------------------------------------------

class SecurityBlogsImporter:
    """Aggregate security blog RSS feeds into local SQLite DB.

    Args:
        db_path: Path to SQLite database file. Defaults to data/security_blogs.db.
        sources_file: Path to newline-separated list of feed URLs.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        sources_file: Optional[str] = None,
    ) -> None:
        self.db_path = db_path
        self.sources_file = Path(sources_file) if sources_file else SOURCES_FILE
        _ensure_table(self.db_path)

    def _load_sources(self) -> List[str]:
        """Read feed URLs from sources.txt, skipping blank lines and comments."""
        if not self.sources_file.exists():
            logger.warning("security_blogs: sources file not found: %s", self.sources_file)
            return []
        lines = self.sources_file.read_text(encoding="utf-8").splitlines()
        return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]

    def run(self) -> Dict[str, Any]:
        """Import all feeds. Returns summary dict."""
        urls = self._load_sources()
        if not urls:
            return {"posts_imported": 0, "by_source": {}, "newest": None}

        total_imported = 0
        by_source: Dict[str, int] = {}
        newest_dt: Optional[str] = None

        for url in urls:
            source_name = _feed_name_from_url(url)
            logger.info("security_blogs: fetching %s (%s)", source_name, url)
            try:
                posts = _parse_feed(url, source_name)
            except Exception as exc:  # noqa: BLE001
                logger.warning("security_blogs: skipping %s — %s", url, exc)
                posts = []

            if not posts:
                by_source[source_name] = 0
                continue

            count = _upsert_posts(posts, self.db_path)
            by_source[source_name] = count
            total_imported += count

            # Track newest published date across all sources
            for p in posts:
                if p.get("published"):
                    if newest_dt is None or p["published"] > newest_dt:
                        newest_dt = p["published"]

        return {
            "posts_imported": total_imported,
            "by_source": by_source,
            "newest": newest_dt,
        }

    def total_count(self) -> int:
        """Return total post count in DB."""
        try:
            conn = _get_conn(self.db_path)
            row = conn.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()
            return int(row[0]) if row else 0
        except Exception:  # noqa: BLE001
            return 0

    def list_posts(
        self,
        source: Optional[str] = None,
        since: Optional[str] = None,
        contains_text: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Query posts with optional filters.

        Args:
            source: Filter to posts from this source domain.
            since: ISO-8601 datetime — only posts published after this.
            contains_text: Case-insensitive substring match on title+summary.
            limit: Max rows to return.
            offset: Pagination offset.
        """
        conn = _get_conn(self.db_path)
        clauses: List[str] = []
        params: List[Any] = []

        if source:
            clauses.append("source = ?")
            params.append(source)
        if since:
            clauses.append("published >= ?")
            params.append(since)
        if contains_text:
            clauses.append("(LOWER(title) LIKE ? OR LOWER(summary) LIKE ?)")
            pattern = f"%{contains_text.lower()}%"
            params.extend([pattern, pattern])

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])

        rows = conn.execute(
            f"""
            SELECT id, source, title, link, summary, published, author, tags, imported_at
            FROM {_TABLE}
            {where}
            ORDER BY published DESC
            LIMIT ? OFFSET ?
            """,
            params,
        ).fetchall()

        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Module-level helpers for registry compatibility
# ---------------------------------------------------------------------------

def run_import() -> Dict[str, Any]:
    return SecurityBlogsImporter().run()


def total_count() -> int:
    return SecurityBlogsImporter().total_count()


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    result = run_import()
    print(json.dumps(result, indent=2))
