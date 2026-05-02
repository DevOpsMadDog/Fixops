"""
Security Knowledge Base API router.

Endpoints for managing and searching the security wiki — articles on
vulnerabilities, remediation guides, compliance checklists, and more.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.security_kb import (
    Article,
    ArticleCategory,
    SearchResult,
    SecurityKnowledgeBase,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/api/v1/kb",
    tags=["security-kb"],
    dependencies=[Depends(api_key_auth)],
)

_kb = SecurityKnowledgeBase()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ArticleCreate(BaseModel):
    title: str = Field(..., min_length=1)
    content: str = Field(..., min_length=1)
    category: ArticleCategory
    tags: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    owasp_ids: List[str] = Field(default_factory=list)
    language: Optional[str] = None
    framework: Optional[str] = None
    severity_context: Optional[str] = None
    author: str = "api"
    org_id: str = "default"


class ArticleUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    category: Optional[ArticleCategory] = None
    tags: Optional[List[str]] = None
    cwe_ids: Optional[List[str]] = None
    owasp_ids: Optional[List[str]] = None
    language: Optional[str] = None
    framework: Optional[str] = None
    severity_context: Optional[str] = None
    author: Optional[str] = None


class FindingQuery(BaseModel):
    cwe_ids: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    severity: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/articles", response_model=Article, status_code=201)
def create_article(body: ArticleCreate) -> Article:
    """Add a new article to the knowledge base."""
    article = Article(
        title=body.title,
        content=body.content,
        category=body.category,
        tags=body.tags,
        cwe_ids=body.cwe_ids,
        owasp_ids=body.owasp_ids,
        language=body.language,
        framework=body.framework,
        severity_context=body.severity_context,
        author=body.author,
        org_id=body.org_id,
    )
    return _kb.add_article(article)


@router.get("/articles", response_model=List[Article])
def list_articles(
    category: Optional[ArticleCategory] = Query(None),
    tags: Optional[str] = Query(None, description="Comma-separated tag list"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[Article]:
    """List articles with optional category and tag filters."""
    tag_list = [t.strip() for t in tags.split(",")] if tags else None
    return _kb.list_articles(category=category, tags=tag_list, limit=limit, offset=offset)


@router.get("/articles/{article_id}", response_model=Article)
def get_article(article_id: str) -> Article:
    """Retrieve a single article by ID."""
    try:
        return _kb.get_article(article_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Article not found: {article_id}")


@router.put("/articles/{article_id}", response_model=Article)
def update_article(article_id: str, body: ArticleUpdate) -> Article:
    """Update article fields (version is automatically incremented)."""
    try:
        _kb.get_article(article_id)  # confirm exists
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Article not found: {article_id}")

    updates: Dict[str, Any] = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    return _kb.update_article(article_id, updates)


@router.delete("/articles/{article_id}", status_code=204)
def delete_article(article_id: str) -> None:
    """Delete an article and its version history."""
    try:
        _kb.get_article(article_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Article not found: {article_id}")
    _kb.delete_article(article_id)


@router.get("/search", response_model=List[SearchResult])
def search_articles(
    q: str = Query(..., min_length=1, description="Full-text search query"),
    category: Optional[ArticleCategory] = Query(None),
    tags: Optional[str] = Query(None, description="Comma-separated tag filter"),
    limit: int = Query(20, ge=1, le=100),
) -> List[SearchResult]:
    """Full-text search across article titles, content, and metadata."""
    tag_list = [t.strip() for t in tags.split(",")] if tags else None
    return _kb.search(query=q, category=category, tags=tag_list, limit=limit)


@router.get("/cwe/{cwe_id}", response_model=List[Article])
def get_by_cwe(cwe_id: str) -> List[Article]:
    """Return all articles that reference a given CWE ID (e.g. CWE-89)."""
    return _kb.get_by_cwe(cwe_id)


@router.get("/owasp/{owasp_id}", response_model=List[Article])
def get_by_owasp(owasp_id: str) -> List[Article]:
    """Return all articles that reference a given OWASP category (e.g. A03:2021)."""
    return _kb.get_by_owasp(owasp_id)


@router.get("/for-finding", response_model=List[Article])
def get_for_finding(
    cwe_ids: Optional[str] = Query(None, description="Comma-separated CWE IDs"),
    tags: Optional[str] = Query(None, description="Comma-separated tags"),
    severity: Optional[str] = Query(None),
) -> List[Article]:
    """Return articles relevant to a security finding (matched by CWE, tags, severity)."""
    finding: Dict[str, Any] = {}
    if cwe_ids:
        finding["cwe_ids"] = [c.strip() for c in cwe_ids.split(",")]
    if tags:
        finding["tags"] = [t.strip() for t in tags.split(",")]
    if severity:
        finding["severity"] = severity
    return _kb.get_for_finding(finding)


@router.get("/tags", response_model=List[str])
def get_tags() -> List[str]:
    """Return all unique tags in the knowledge base, sorted by frequency."""
    return _kb.get_tags()


@router.get("/stats", response_model=Dict[str, Any])
def get_stats() -> Dict[str, Any]:
    """Return summary statistics about the knowledge base."""
    return _kb.get_kb_stats()


@router.get("/articles/{article_id}/versions", response_model=List[Dict[str, Any]])
def get_article_versions(article_id: str) -> List[Dict[str, Any]]:
    """Return the version history for an article."""
    try:
        _kb.get_article(article_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Article not found: {article_id}")
    return _kb.get_article_versions(article_id)
