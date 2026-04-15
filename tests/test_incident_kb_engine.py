"""Tests for IncidentKBEngine.

Tests cover: article CRUD, view/helpful counters, search LIKE matching
(including tags), runbook creation, rolling success_rate, recommended
runbooks ordering, and KB stats.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.incident_kb_engine import IncidentKBEngine


@pytest.fixture
def engine(tmp_path):
    return IncidentKBEngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# Article creation
# ---------------------------------------------------------------------------


def test_create_article_basic(engine):
    a = engine.create_article(
        "org1", "How to handle ransomware", "howto", "ransomware",
        "critical", "Step by step guide...", ["ransomware", "recovery"], "alice"
    )
    assert a["id"]
    assert a["org_id"] == "org1"
    assert a["title"] == "How to handle ransomware"
    assert a["article_type"] == "howto"
    assert a["incident_type"] == "ransomware"
    assert a["severity"] == "critical"
    assert "ransomware" in a["tags"]
    assert a["author"] == "alice"
    assert a["view_count"] == 0
    assert a["helpful_count"] == 0


def test_create_article_tags_as_string(engine):
    a = engine.create_article(
        "org1", "T", "reference", "phishing", "high",
        "Content", "tag1,tag2", "bob"
    )
    assert "tag1" in a["tags"]
    assert "tag2" in a["tags"]


def test_create_article_tags_as_list(engine):
    a = engine.create_article(
        "org1", "T", "postmortem", "data-breach", "critical",
        "Content", ["alpha", "beta", "gamma"], "carol"
    )
    assert "alpha" in a["tags"]
    assert "beta" in a["tags"]


def test_create_article_empty_tags(engine):
    a = engine.create_article(
        "org1", "T", "howto", "ddos", "medium", "Content", "", "dave"
    )
    assert a["tags"] == ""


# ---------------------------------------------------------------------------
# Article update
# ---------------------------------------------------------------------------


def test_update_article(engine):
    a = engine.create_article(
        "org1", "Old title", "howto", "ransomware", "high", "Old content", "old", "eve"
    )
    updated = engine.update_article(a["id"], "org1", "New content", ["new-tag"])
    assert updated["content"] == "New content"
    assert "new-tag" in updated["tags"]


def test_update_article_not_found(engine):
    with pytest.raises(KeyError):
        engine.update_article("nonexistent", "org1", "content", [])


def test_update_article_wrong_org(engine):
    a = engine.create_article(
        "org1", "T", "howto", "ransomware", "high", "Content", "", "frank"
    )
    with pytest.raises(KeyError):
        engine.update_article(a["id"], "org2", "new content", [])


# ---------------------------------------------------------------------------
# View / helpful counters
# ---------------------------------------------------------------------------


def test_view_article_increments(engine):
    a = engine.create_article(
        "org1", "T", "howto", "phishing", "medium", "C", "", "grace"
    )
    v1 = engine.view_article(a["id"], "org1")
    assert v1["view_count"] == 1
    v2 = engine.view_article(a["id"], "org1")
    assert v2["view_count"] == 2


def test_view_article_not_found(engine):
    with pytest.raises(KeyError):
        engine.view_article("nonexistent", "org1")


def test_mark_helpful_increments(engine):
    a = engine.create_article(
        "org1", "T", "reference", "ddos", "low", "C", "", "henry"
    )
    h1 = engine.mark_helpful(a["id"], "org1")
    assert h1["helpful_count"] == 1
    h2 = engine.mark_helpful(a["id"], "org1")
    assert h2["helpful_count"] == 2


def test_mark_helpful_not_found(engine):
    with pytest.raises(KeyError):
        engine.mark_helpful("nonexistent", "org1")


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


def test_search_by_title(engine):
    engine.create_article(
        "org1", "Ransomware Recovery Guide", "howto", "ransomware",
        "critical", "Detailed recovery steps", [], "alice"
    )
    engine.create_article(
        "org1", "Phishing Detection", "howto", "phishing",
        "high", "How to spot phishing", [], "bob"
    )
    results = engine.search_articles("org1", "Ransomware")
    assert len(results) == 1
    assert results[0]["title"] == "Ransomware Recovery Guide"


def test_search_by_content(engine):
    engine.create_article(
        "org1", "Title", "howto", "ddos", "medium",
        "This article covers lateral movement techniques", [], "alice"
    )
    results = engine.search_articles("org1", "lateral movement")
    assert len(results) == 1


def test_search_by_tags(engine):
    engine.create_article(
        "org1", "Article One", "reference", "supply-chain", "high",
        "Content about supply chain", "solarwinds,log4j", "alice"
    )
    engine.create_article(
        "org1", "Article Two", "howto", "zero-day", "critical",
        "Zero-day content", "cve,patch", "bob"
    )
    results = engine.search_articles("org1", "log4j")
    assert len(results) == 1
    assert results[0]["title"] == "Article One"


def test_search_case_insensitive(engine):
    engine.create_article(
        "org1", "RANSOMWARE GUIDE", "howto", "ransomware",
        "critical", "Guide content", [], "alice"
    )
    results = engine.search_articles("org1", "ransomware")
    assert len(results) == 1


def test_search_with_incident_type_filter(engine):
    engine.create_article(
        "org1", "Article A", "howto", "ransomware", "high", "content", [], "alice"
    )
    engine.create_article(
        "org1", "Article B", "howto", "phishing", "high", "content", [], "bob"
    )
    results = engine.search_articles("org1", "Article", incident_type="ransomware")
    assert len(results) == 1
    assert results[0]["incident_type"] == "ransomware"


def test_search_records_search_entry(engine):
    engine.create_article(
        "org1", "T", "howto", "ransomware", "high", "C", [], "alice"
    )
    engine.search_articles("org1", "ransomware")
    # Stats should show the query
    stats = engine.get_kb_stats("org1")
    assert any(t["query"] == "ransomware" for t in stats["top_searched_terms"])


def test_search_no_results(engine):
    results = engine.search_articles("org1", "xyznotfound")
    assert results == []


def test_search_org_isolation(engine):
    engine.create_article(
        "org1", "Secret Article", "howto", "ransomware", "high", "content", [], "alice"
    )
    results = engine.search_articles("org2", "Secret")
    assert results == []


# ---------------------------------------------------------------------------
# Runbooks
# ---------------------------------------------------------------------------


def test_create_runbook_basic(engine):
    rb = engine.create_runbook(
        "org1", "Ransomware Response", "ransomware",
        ["Isolate host", "Notify SOC", "Backup analysis"], 60
    )
    assert rb["id"]
    assert rb["runbook_name"] == "Ransomware Response"
    assert rb["incident_type"] == "ransomware"
    assert rb["estimated_minutes"] == 60
    assert rb["success_rate"] == pytest.approx(0.0)
    assert rb["execution_count"] == 0


def test_create_runbook_steps_as_list(engine):
    rb = engine.create_runbook(
        "org1", "R", "phishing", ["step1", "step2"], 30
    )
    import json
    steps = json.loads(rb["steps"])
    assert steps == ["step1", "step2"]


def test_execute_runbook_success(engine):
    rb = engine.create_runbook("org1", "R", "ddos", [], 20)
    result = engine.execute_runbook(rb["id"], "org1", success=True)
    assert result["execution_count"] == 1
    assert result["success_rate"] == pytest.approx(1.0)
    assert result["last_executed"] != ""


def test_execute_runbook_failure(engine):
    rb = engine.create_runbook("org1", "R", "ddos", [], 20)
    result = engine.execute_runbook(rb["id"], "org1", success=False)
    assert result["execution_count"] == 1
    assert result["success_rate"] == pytest.approx(0.0)


def test_execute_runbook_rolling_average(engine):
    """Rolling average: 1 success + 1 failure = 0.5."""
    rb = engine.create_runbook("org1", "R", "ransomware", [], 30)
    engine.execute_runbook(rb["id"], "org1", success=True)
    r2 = engine.execute_runbook(rb["id"], "org1", success=False)
    assert r2["execution_count"] == 2
    assert r2["success_rate"] == pytest.approx(0.5)


def test_execute_runbook_rolling_3_executions(engine):
    """2 success + 1 failure = 2/3 ≈ 0.6667."""
    rb = engine.create_runbook("org1", "R", "phishing", [], 15)
    engine.execute_runbook(rb["id"], "org1", success=True)
    engine.execute_runbook(rb["id"], "org1", success=True)
    r3 = engine.execute_runbook(rb["id"], "org1", success=False)
    assert r3["success_rate"] == pytest.approx(2 / 3, rel=1e-3)


def test_execute_runbook_not_found(engine):
    with pytest.raises(KeyError):
        engine.execute_runbook("nonexistent", "org1", success=True)


def test_execute_runbook_wrong_org(engine):
    rb = engine.create_runbook("org1", "R", "ddos", [], 30)
    with pytest.raises(KeyError):
        engine.execute_runbook(rb["id"], "org2", success=True)


def test_get_recommended_runbooks_sorted_by_success(engine):
    rb1 = engine.create_runbook("org1", "Low Success", "phishing", [], 30)
    rb2 = engine.create_runbook("org1", "High Success", "phishing", [], 30)

    engine.execute_runbook(rb1["id"], "org1", success=False)
    engine.execute_runbook(rb2["id"], "org1", success=True)

    recs = engine.get_recommended_runbooks("org1", "phishing")
    assert len(recs) == 2
    assert recs[0]["runbook_name"] == "High Success"
    assert recs[1]["runbook_name"] == "Low Success"


def test_get_recommended_runbooks_filters_by_type(engine):
    engine.create_runbook("org1", "Ransomware RB", "ransomware", [], 60)
    engine.create_runbook("org1", "Phishing RB", "phishing", [], 15)
    recs = engine.get_recommended_runbooks("org1", "ransomware")
    assert len(recs) == 1
    assert recs[0]["runbook_name"] == "Ransomware RB"


def test_get_recommended_runbooks_empty(engine):
    recs = engine.get_recommended_runbooks("org1", "zero-day")
    assert recs == []


def test_get_recommended_runbooks_org_isolation(engine):
    engine.create_runbook("org1", "R", "ddos", [], 20)
    recs = engine.get_recommended_runbooks("org2", "ddos")
    assert recs == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_get_kb_stats_empty(engine):
    stats = engine.get_kb_stats("org1")
    assert stats["total_articles"] == 0
    assert stats["total_runbooks"] == 0
    assert stats["avg_success_rate"] == pytest.approx(0.0)
    assert stats["most_viewed_article"] is None
    assert stats["top_searched_terms"] == []


def test_get_kb_stats_counts(engine):
    engine.create_article("org1", "A1", "howto", "ransomware", "high", "C", [], "alice")
    engine.create_article("org1", "A2", "postmortem", "phishing", "medium", "C", [], "bob")
    engine.create_runbook("org1", "R1", "ddos", [], 30)

    stats = engine.get_kb_stats("org1")
    assert stats["total_articles"] == 2
    assert stats["total_runbooks"] == 1


def test_get_kb_stats_avg_success_rate(engine):
    rb = engine.create_runbook("org1", "R", "ransomware", [], 60)
    engine.execute_runbook(rb["id"], "org1", success=True)
    engine.execute_runbook(rb["id"], "org1", success=True)
    engine.execute_runbook(rb["id"], "org1", success=False)

    stats = engine.get_kb_stats("org1")
    assert stats["avg_success_rate"] == pytest.approx(2 / 3, rel=1e-3)


def test_get_kb_stats_most_viewed_article(engine):
    a1 = engine.create_article("org1", "Popular", "howto", "phishing", "high", "C", [], "alice")
    a2 = engine.create_article("org1", "Unpopular", "reference", "ddos", "low", "C", [], "bob")

    engine.view_article(a1["id"], "org1")
    engine.view_article(a1["id"], "org1")
    engine.view_article(a1["id"], "org1")
    engine.view_article(a2["id"], "org1")

    stats = engine.get_kb_stats("org1")
    assert stats["most_viewed_article"]["title"] == "Popular"
    assert stats["most_viewed_article"]["view_count"] == 3


def test_get_kb_stats_top_searched_terms(engine):
    for _ in range(3):
        engine.search_articles("org1", "ransomware")
    for _ in range(5):
        engine.search_articles("org1", "phishing")
    engine.search_articles("org1", "ddos")

    stats = engine.get_kb_stats("org1")
    terms = [t["query"] for t in stats["top_searched_terms"]]
    assert terms[0] == "phishing"
    assert "ransomware" in terms


def test_get_kb_stats_org_isolation(engine):
    engine.create_article("org1", "A", "howto", "ransomware", "high", "C", [], "alice")
    engine.create_runbook("org1", "R", "ransomware", [], 30)
    stats = engine.get_kb_stats("org2")
    assert stats["total_articles"] == 0
    assert stats["total_runbooks"] == 0
