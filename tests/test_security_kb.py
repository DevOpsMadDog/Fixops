"""
Tests for the SecurityKnowledgeBase module and API router.

Covers:
- Article CRUD (create, read, update, delete)
- Version history
- FTS5 full-text search (title + content)
- CWE and OWASP lookup
- Finding matching
- Tag listing
- Seed articles exist on fresh DB
- Stats endpoint
- API router (FastAPI TestClient)
"""
from __future__ import annotations

import os
import tempfile
import uuid

import pytest

# ---------------------------------------------------------------------------
# Environment setup — must happen before any app imports
# ---------------------------------------------------------------------------
os.environ["FIXOPS_MODE"] = "dev"
os.environ["FIXOPS_API_TOKEN"] = "test-token"
os.environ["FIXOPS_JWT_SECRET"] = "test-secret-that-is-at-least-32-chars-long"
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.security_kb import (
    Article,
    ArticleCategory,
    SearchResult,
    SecurityKnowledgeBase,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def kb(tmp_path):
    """Return a fresh SecurityKnowledgeBase backed by a temp SQLite file."""
    db_file = tmp_path / "test_kb.db"
    return SecurityKnowledgeBase(db_path=str(db_file))


@pytest.fixture()
def sample_article():
    return Article(
        title="Buffer Overflow in C (CWE-121)",
        content="## Buffer Overflow\n\nStack-based buffer overflow allows arbitrary code execution.",
        category=ArticleCategory.VULNERABILITY,
        tags=["c", "memory-safety", "buffer-overflow"],
        cwe_ids=["CWE-121", "CWE-787"],
        owasp_ids=["A03:2021"],
        severity_context="critical",
        author="tester",
    )


# ---------------------------------------------------------------------------
# CRUD Tests
# ---------------------------------------------------------------------------


class TestArticleCRUD:
    def test_add_and_get_article(self, kb, sample_article):
        added = kb.add_article(sample_article)
        assert added.id == sample_article.id

        fetched = kb.get_article(sample_article.id)
        assert fetched.title == sample_article.title
        assert fetched.category == ArticleCategory.VULNERABILITY
        assert "CWE-121" in fetched.cwe_ids
        assert "memory-safety" in fetched.tags

    def test_get_article_not_found_raises(self, kb):
        with pytest.raises(KeyError):
            kb.get_article("nonexistent-id")

    def test_update_article_increments_version(self, kb, sample_article):
        kb.add_article(sample_article)
        updated = kb.update_article(sample_article.id, {"title": "Updated Title"})
        assert updated.version == 2
        assert updated.title == "Updated Title"

    def test_update_article_preserves_unchanged_fields(self, kb, sample_article):
        kb.add_article(sample_article)
        updated = kb.update_article(sample_article.id, {"title": "New Title"})
        assert "CWE-121" in updated.cwe_ids
        assert updated.author == "tester"

    def test_update_tags(self, kb, sample_article):
        kb.add_article(sample_article)
        updated = kb.update_article(sample_article.id, {"tags": ["new-tag", "security"]})
        assert "new-tag" in updated.tags
        assert "buffer-overflow" not in updated.tags

    def test_delete_article(self, kb, sample_article):
        kb.add_article(sample_article)
        kb.delete_article(sample_article.id)
        with pytest.raises(KeyError):
            kb.get_article(sample_article.id)

    def test_delete_nonexistent_does_not_raise(self, kb):
        # Should silently succeed
        kb.delete_article("nonexistent-id")


# ---------------------------------------------------------------------------
# Versioning Tests
# ---------------------------------------------------------------------------


class TestVersioning:
    def test_version_history_empty_initially(self, kb, sample_article):
        kb.add_article(sample_article)
        versions = kb.get_article_versions(sample_article.id)
        assert versions == []

    def test_version_history_grows_on_update(self, kb, sample_article):
        kb.add_article(sample_article)
        kb.update_article(sample_article.id, {"title": "v2 Title"})
        kb.update_article(sample_article.id, {"title": "v3 Title"})

        versions = kb.get_article_versions(sample_article.id)
        assert len(versions) == 2
        assert versions[0]["version"] == 1
        assert versions[1]["version"] == 2

    def test_version_history_stores_old_title(self, kb, sample_article):
        kb.add_article(sample_article)
        original_title = sample_article.title
        kb.update_article(sample_article.id, {"title": "Changed"})

        versions = kb.get_article_versions(sample_article.id)
        assert versions[0]["title"] == original_title

    def test_multiple_updates_increment_version_correctly(self, kb, sample_article):
        kb.add_article(sample_article)
        for i in range(5):
            kb.update_article(sample_article.id, {"content": f"Content revision {i}"})
        article = kb.get_article(sample_article.id)
        assert article.version == 6


# ---------------------------------------------------------------------------
# FTS5 Search Tests
# ---------------------------------------------------------------------------


class TestSearch:
    def test_search_finds_by_title(self, kb, sample_article):
        kb.add_article(sample_article)
        results = kb.search("Buffer Overflow")
        assert any(r.article_id == sample_article.id for r in results)

    def test_search_finds_by_content(self, kb, sample_article):
        kb.add_article(sample_article)
        results = kb.search("arbitrary code execution")
        assert any(r.article_id == sample_article.id for r in results)

    def test_search_result_has_snippet(self, kb, sample_article):
        kb.add_article(sample_article)
        results = kb.search("buffer overflow")
        assert len(results) > 0
        assert len(results[0].snippet) > 0

    def test_search_result_has_relevance_score(self, kb, sample_article):
        kb.add_article(sample_article)
        results = kb.search("buffer overflow")
        assert len(results) > 0
        assert results[0].relevance_score > 0

    def test_search_returns_empty_for_unknown_term(self, kb):
        results = kb.search("xyzzy_nonexistent_term_99999")
        assert results == []

    def test_search_category_filter(self, kb):
        art1 = Article(
            title="SQL Injection Vuln",
            content="SQL injection allows database attacks",
            category=ArticleCategory.VULNERABILITY,
            tags=[],
        )
        art2 = Article(
            title="SQL Injection Fix",
            content="Use parameterized queries to fix SQL injection",
            category=ArticleCategory.REMEDIATION,
            tags=[],
        )
        kb.add_article(art1)
        kb.add_article(art2)
        results = kb.search("SQL injection", category=ArticleCategory.REMEDIATION)
        ids = [r.article_id for r in results]
        assert art2.id in ids
        assert art1.id not in ids

    def test_search_tag_filter(self, kb, sample_article):
        kb.add_article(sample_article)
        results = kb.search("buffer overflow", tags=["c"])
        assert any(r.article_id == sample_article.id for r in results)

        results_no_match = kb.search("buffer overflow", tags=["java"])
        assert not any(r.article_id == sample_article.id for r in results_no_match)


# ---------------------------------------------------------------------------
# CWE / OWASP Lookup Tests
# ---------------------------------------------------------------------------


class TestCweOwaspLookup:
    def test_get_by_cwe(self, kb, sample_article):
        kb.add_article(sample_article)
        results = kb.get_by_cwe("CWE-121")
        assert any(a.id == sample_article.id for a in results)

    def test_get_by_cwe_no_match(self, kb, sample_article):
        kb.add_article(sample_article)
        results = kb.get_by_cwe("CWE-999")
        assert all(a.id != sample_article.id for a in results)

    def test_get_by_owasp(self, kb, sample_article):
        kb.add_article(sample_article)
        results = kb.get_by_owasp("A03:2021")
        assert any(a.id == sample_article.id for a in results)

    def test_get_by_owasp_no_match(self, kb):
        results = kb.get_by_owasp("A99:2099")
        assert results == []

    def test_cwe_returns_multiple_articles(self, kb):
        shared_cwe = "CWE-89"
        for i in range(3):
            kb.add_article(Article(
                title=f"SQL Article {i}",
                content=f"Content {i} about SQL injection",
                category=ArticleCategory.VULNERABILITY,
                cwe_ids=[shared_cwe],
                tags=[],
            ))
        results = kb.get_by_cwe(shared_cwe)
        assert len(results) >= 3


# ---------------------------------------------------------------------------
# Finding Matching Tests
# ---------------------------------------------------------------------------


class TestFindingMatching:
    def test_get_for_finding_by_cwe(self, kb, sample_article):
        kb.add_article(sample_article)
        finding = {"cwe_ids": ["CWE-121"], "severity": "critical"}
        results = kb.get_for_finding(finding)
        assert any(a.id == sample_article.id for a in results)

    def test_get_for_finding_by_tags(self, kb, sample_article):
        kb.add_article(sample_article)
        finding = {"tags": ["buffer-overflow"], "severity": "high"}
        results = kb.get_for_finding(finding)
        assert any(a.id == sample_article.id for a in results)

    def test_get_for_finding_empty_finding_returns_list(self, kb):
        results = kb.get_for_finding({})
        # With seeded articles this may return best-practice articles for empty finding
        assert isinstance(results, list)

    def test_get_for_finding_multiple_cwes(self, kb, sample_article):
        kb.add_article(sample_article)
        finding = {"cwe_ids": ["CWE-121", "CWE-787"]}
        results = kb.get_for_finding(finding)
        # sample_article matches both CWEs — should appear only once
        ids = [a.id for a in results]
        assert ids.count(sample_article.id) == 1


# ---------------------------------------------------------------------------
# Tag Listing Tests
# ---------------------------------------------------------------------------


class TestTagListing:
    def test_get_tags_returns_list(self, kb):
        tags = kb.get_tags()
        assert isinstance(tags, list)

    def test_get_tags_includes_added_tags(self, kb, sample_article):
        kb.add_article(sample_article)
        tags = kb.get_tags()
        assert "buffer-overflow" in tags
        assert "memory-safety" in tags

    def test_tags_sorted_by_frequency(self, kb):
        # Add articles with overlapping tags
        for _ in range(3):
            kb.add_article(Article(
                title=f"Article {uuid.uuid4()}",
                content="content",
                category=ArticleCategory.BEST_PRACTICE,
                tags=["common-tag"],
            ))
        kb.add_article(Article(
            title="Rare article",
            content="content",
            category=ArticleCategory.BEST_PRACTICE,
            tags=["rare-tag"],
        ))
        tags = kb.get_tags()
        common_idx = tags.index("common-tag")
        rare_idx = tags.index("rare-tag")
        assert common_idx < rare_idx  # common-tag appears first


# ---------------------------------------------------------------------------
# Seed Articles Tests
# ---------------------------------------------------------------------------


class TestSeedArticles:
    def test_seed_articles_exist(self, kb):
        stats = kb.get_kb_stats()
        assert stats["total_articles"] >= 15

    def test_seed_articles_cover_owasp_top_10(self, kb):
        # At least one article per major OWASP 2021 category
        for owasp_id in ["A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021"]:
            results = kb.get_by_owasp(owasp_id)
            assert len(results) >= 1, f"No article for {owasp_id}"

    def test_seed_articles_cover_multiple_categories(self, kb):
        stats = kb.get_kb_stats()
        categories = stats["by_category"]
        assert len(categories) >= 4

    def test_seed_articles_have_tags(self, kb):
        tags = kb.get_tags()
        assert len(tags) >= 5


# ---------------------------------------------------------------------------
# Stats Tests
# ---------------------------------------------------------------------------


class TestStats:
    def test_get_kb_stats_structure(self, kb):
        stats = kb.get_kb_stats()
        assert "total_articles" in stats
        assert "by_category" in stats
        assert "top_tags" in stats
        assert "tag_count" in stats

    def test_stats_total_count_accurate(self, kb, sample_article):
        before = kb.get_kb_stats()["total_articles"]
        kb.add_article(sample_article)
        after = kb.get_kb_stats()["total_articles"]
        assert after == before + 1

    def test_stats_by_category(self, kb):
        stats = kb.get_kb_stats()
        by_cat = stats["by_category"]
        assert isinstance(by_cat, dict)
        # Seeded articles include vulnerability category
        assert "vulnerability" in by_cat

    def test_stats_top_tags_is_list(self, kb):
        stats = kb.get_kb_stats()
        assert isinstance(stats["top_tags"], list)


# ---------------------------------------------------------------------------
# List Articles Tests
# ---------------------------------------------------------------------------


class TestListArticles:
    def test_list_all_articles(self, kb):
        articles = kb.list_articles()
        assert len(articles) >= 15  # seed articles

    def test_list_with_category_filter(self, kb):
        articles = kb.list_articles(category=ArticleCategory.VULNERABILITY)
        assert all(a.category == ArticleCategory.VULNERABILITY for a in articles)

    def test_list_with_limit(self, kb):
        articles = kb.list_articles(limit=3)
        assert len(articles) <= 3

    def test_list_with_offset(self, kb):
        all_articles = kb.list_articles(limit=100)
        offset_articles = kb.list_articles(limit=100, offset=1)
        if len(all_articles) > 1:
            assert offset_articles[0].id != all_articles[0].id


# ---------------------------------------------------------------------------
# API Router Tests
# ---------------------------------------------------------------------------


class TestAPIRouter:
    @pytest.fixture(autouse=True)
    def setup_client(self, tmp_path):
        """Build a test FastAPI app with the KB router mounted, auth bypassed."""
        from unittest.mock import AsyncMock, patch

        import apps.api.security_kb_router as kb_module

        db_file = tmp_path / "api_test_kb.db"
        # Inject a fresh KB into the router module
        fresh_kb = SecurityKnowledgeBase(db_path=str(db_file))
        kb_module._kb = fresh_kb

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api.security_kb_router import router
        from apps.api import auth_deps

        app = FastAPI()
        app.include_router(router)

        # Bypass auth for tests by overriding the dependency
        async def _no_auth():
            return None

        app.dependency_overrides[auth_deps.api_key_auth] = _no_auth
        self.client = TestClient(app)

    def test_list_articles_returns_seed(self):
        resp = self.client.get("/api/v1/kb/articles")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 15

    def test_create_article(self):
        payload = {
            "title": "Test Article",
            "content": "Test content for the article",
            "category": "vulnerability",
            "tags": ["test"],
            "cwe_ids": ["CWE-999"],
            "owasp_ids": [],
            "author": "tester",
            "org_id": "default",
        }
        resp = self.client.post("/api/v1/kb/articles", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "Test Article"
        assert data["version"] == 1

    def test_get_article(self):
        # First create one
        payload = {
            "title": "Get Test",
            "content": "Content here",
            "category": "best_practice",
            "tags": [],
            "cwe_ids": [],
            "owasp_ids": [],
            "author": "tester",
            "org_id": "default",
        }
        create_resp = self.client.post("/api/v1/kb/articles", json=payload)
        article_id = create_resp.json()["id"]

        get_resp = self.client.get(f"/api/v1/kb/articles/{article_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == article_id

    def test_get_article_not_found(self):
        resp = self.client.get("/api/v1/kb/articles/no-such-id")
        assert resp.status_code == 404

    def test_update_article(self):
        payload = {
            "title": "Original",
            "content": "Original content",
            "category": "vulnerability",
            "tags": [],
            "cwe_ids": [],
            "owasp_ids": [],
            "author": "tester",
            "org_id": "default",
        }
        article_id = self.client.post("/api/v1/kb/articles", json=payload).json()["id"]
        update_resp = self.client.put(
            f"/api/v1/kb/articles/{article_id}", json={"title": "Updated Title"}
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["title"] == "Updated Title"
        assert update_resp.json()["version"] == 2

    def test_delete_article(self):
        payload = {
            "title": "To Delete",
            "content": "Will be deleted",
            "category": "compliance",
            "tags": [],
            "cwe_ids": [],
            "owasp_ids": [],
            "author": "tester",
            "org_id": "default",
        }
        article_id = self.client.post("/api/v1/kb/articles", json=payload).json()["id"]
        del_resp = self.client.delete(f"/api/v1/kb/articles/{article_id}")
        assert del_resp.status_code == 204
        get_resp = self.client.get(f"/api/v1/kb/articles/{article_id}")
        assert get_resp.status_code == 404

    def test_search_endpoint(self):
        resp = self.client.get("/api/v1/kb/search", params={"q": "injection"})
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_cwe_endpoint(self):
        resp = self.client.get("/api/v1/kb/cwe/CWE-89")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1

    def test_owasp_endpoint(self):
        resp = self.client.get("/api/v1/kb/owasp/A03:2021")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1

    def test_tags_endpoint(self):
        resp = self.client.get("/api/v1/kb/tags")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
        assert len(resp.json()) >= 5

    def test_stats_endpoint(self):
        resp = self.client.get("/api/v1/kb/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_articles"] >= 15

    def test_for_finding_endpoint(self):
        resp = self.client.get("/api/v1/kb/for-finding", params={"cwe_ids": "CWE-89"})
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_article_versions_endpoint(self):
        payload = {
            "title": "Versioned",
            "content": "v1 content",
            "category": "architecture",
            "tags": [],
            "cwe_ids": [],
            "owasp_ids": [],
            "author": "tester",
            "org_id": "default",
        }
        article_id = self.client.post("/api/v1/kb/articles", json=payload).json()["id"]
        self.client.put(f"/api/v1/kb/articles/{article_id}", json={"content": "v2 content"})

        resp = self.client.get(f"/api/v1/kb/articles/{article_id}/versions")
        assert resp.status_code == 200
        assert len(resp.json()) == 1  # one archived version

    def test_list_with_category_filter(self):
        resp = self.client.get("/api/v1/kb/articles", params={"category": "vulnerability"})
        assert resp.status_code == 200
        data = resp.json()
        assert all(a["category"] == "vulnerability" for a in data)

    def test_search_with_category_filter(self):
        resp = self.client.get(
            "/api/v1/kb/search",
            params={"q": "injection", "category": "vulnerability"},
        )
        assert resp.status_code == 200
