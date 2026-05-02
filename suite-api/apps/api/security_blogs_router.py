"""Security Blogs RSS Aggregator Router — ALDECI.

Endpoints to import and query aggregated security blog posts from canonical
RSS/Atom feeds (Krebs, BleepingComputer, Dark Reading, Schneier, etc.).

Prefix: /api/v1/security-blogs
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/security-blogs/import      trigger_import
  GET  /api/v1/security-blogs/posts       list_posts
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-blogs",
    tags=["SecurityBlogs"],
)


def _get_importer():
    import sys
    from pathlib import Path
    suite_feeds = str(Path(__file__).resolve().parents[3] / "suite-feeds")
    if suite_feeds not in sys.path:
        sys.path.insert(0, suite_feeds)
    from feeds.security_blogs.importer import SecurityBlogsImporter
    return SecurityBlogsImporter()


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import() -> Dict[str, Any]:
    """Fetch all configured security blog RSS feeds and upsert posts into the DB.

    Returns a summary with posts_imported, per-source counts, and newest post date.
    """
    try:
        imp = _get_importer()
        result = imp.run()
        return result
    except Exception as exc:
        logger.exception("security_blogs import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/posts", dependencies=[Depends(api_key_auth)])
def list_posts(
    source: Optional[str] = Query(
        default=None,
        description="Filter by source domain (e.g. krebsonsecurity.com)",
    ),
    since: Optional[str] = Query(
        default=None,
        description="ISO-8601 datetime — only posts published after this timestamp",
    ),
    contains_text: Optional[str] = Query(
        default=None,
        description="Case-insensitive substring match against title and summary",
    ),
    limit: int = Query(default=100, ge=1, le=1000, description="Max results"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
) -> List[Dict[str, Any]]:
    """Return aggregated security blog posts with optional filters.

    Filters:
    - **source**: exact source domain match
    - **since**: ISO-8601 lower bound on published date
    - **contains_text**: substring search across title and summary
    """
    try:
        imp = _get_importer()
        return imp.list_posts(
            source=source,
            since=since,
            contains_text=contains_text,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        logger.exception("security_blogs list_posts failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
