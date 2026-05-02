"""Incident KB Router — ALDECI.

Endpoints for the Incident Knowledge Base engine.

Prefix: /api/v1/incident-kb
Auth:   _verify_api_key

Routes:
  POST /api/v1/incident-kb/articles                          create_article
  PUT  /api/v1/incident-kb/articles/{id}                     update_article
  POST /api/v1/incident-kb/articles/{id}/view                view_article
  POST /api/v1/incident-kb/articles/{id}/helpful             mark_helpful
  GET  /api/v1/incident-kb/search                            search_articles
  POST /api/v1/incident-kb/runbooks                          create_runbook
  POST /api/v1/incident-kb/runbooks/{id}/execute             execute_runbook
  GET  /api/v1/incident-kb/runbooks/recommended              get_recommended_runbooks
  GET  /api/v1/incident-kb/stats                             get_kb_stats
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/incident-kb",
    tags=["Incident Knowledge Base"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.incident_kb_engine import IncidentKBEngine
        _engine = IncidentKBEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ArticleCreate(BaseModel):
    title: str
    article_type: str
    incident_type: str
    severity: str = "medium"
    content: str
    tags: Any = ""
    author: str = ""


class ArticleUpdate(BaseModel):
    content: str
    tags: Any = ""


class RunbookCreate(BaseModel):
    runbook_name: str
    incident_type: str
    steps: Any = []
    estimated_minutes: int = 30


class RunbookExecute(BaseModel):
    success: bool = True


# ---------------------------------------------------------------------------
# Articles
# ---------------------------------------------------------------------------


@router.get("/", dependencies=[Depends(api_key_auth)])
def get_service_summary(org_id: str = Query(default="default")) -> dict:
    """Return incident-kb service summary (stats + available article/runbook types).

    5-state envelope: items/total/org_id/filters_applied/hint.
    """
    stats = _get_engine().get_kb_stats(org_id)
    article_types = ["runbook", "playbook", "post_mortem", "lesson_learned", "reference"]
    incident_types = ["malware", "phishing", "data_breach", "ddos", "insider_threat", "ransomware"]
    items = [
        {"key": "stats", "value": stats},
        {"key": "article_types", "value": article_types},
        {"key": "incident_types", "value": incident_types},
    ]
    envelope: dict = {
        "items": items,
        "total": len(items),
        "org_id": org_id,
        "filters_applied": {},
        "service": "incident-kb",
    }
    total_articles = stats.get("total_articles", 0) if isinstance(stats, dict) else 0
    if total_articles == 0:
        envelope["hint"] = (
            "No KB articles yet. Create one via POST /api/v1/incident-kb/articles "
            "or search via GET /api/v1/incident-kb/search?query=..."
        )
    return envelope


@router.post("/articles", dependencies=[Depends(api_key_auth)], status_code=201)
def create_article(body: ArticleCreate, org_id: str = Query(default="default")):
    """Create a new KB article."""
    try:
        return _get_engine().create_article(
            org_id,
            body.title,
            body.article_type,
            body.incident_type,
            body.severity,
            body.content,
            body.tags,
            body.author,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/articles/{article_id}", dependencies=[Depends(api_key_auth)])
def update_article(article_id: str, body: ArticleUpdate, org_id: str = Query(default="default")):
    """Update a KB article's content and tags."""
    try:
        return _get_engine().update_article(article_id, org_id, body.content, body.tags)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/articles/{article_id}/view", dependencies=[Depends(api_key_auth)])
def view_article(article_id: str, org_id: str = Query(default="default")):
    """Increment view count and return article."""
    try:
        return _get_engine().view_article(article_id, org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/articles/{article_id}/helpful", dependencies=[Depends(api_key_auth)])
def mark_helpful(article_id: str, org_id: str = Query(default="default")):
    """Mark an article as helpful."""
    try:
        return _get_engine().mark_helpful(article_id, org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/search", dependencies=[Depends(api_key_auth)])
def search_articles(
     org_id: str = Query(default="default"),
    query: str = Query(...),
    incident_type: Optional[str] = Query(None),
):
    """Search KB articles by keyword."""
    return _get_engine().search_articles(org_id, query, incident_type=incident_type)


# ---------------------------------------------------------------------------
# Runbooks
# ---------------------------------------------------------------------------


@router.post("/runbooks", dependencies=[Depends(api_key_auth)], status_code=201)
def create_runbook(body: RunbookCreate, org_id: str = Query(default="default")):
    """Create a new incident runbook."""
    try:
        return _get_engine().create_runbook(
            org_id,
            body.runbook_name,
            body.incident_type,
            body.steps,
            body.estimated_minutes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/runbooks/{runbook_id}/execute", dependencies=[Depends(api_key_auth)])
def execute_runbook(
    runbook_id: str, body: RunbookExecute, org_id: str = Query(default="default")
):
    """Record a runbook execution result."""
    try:
        return _get_engine().execute_runbook(runbook_id, org_id, body.success)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/runbooks/recommended", dependencies=[Depends(api_key_auth)])
def get_recommended_runbooks(
     org_id: str = Query(default="default"),
    incident_type: str = Query(...),
):
    """Return runbooks for a given incident type sorted by success rate."""
    return _get_engine().get_recommended_runbooks(org_id, incident_type)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_kb_stats(org_id: str = Query(default="default")):
    """Return KB-wide statistics."""
    return _get_engine().get_kb_stats(org_id)
