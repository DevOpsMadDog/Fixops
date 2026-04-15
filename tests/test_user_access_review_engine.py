"""Tests for UserAccessReviewEngine — 35+ tests covering all methods."""
from __future__ import annotations

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.user_access_review_engine import UserAccessReviewEngine

ORG = "test-org"
ORG2 = "other-org"


@pytest.fixture
def engine(tmp_path):
    return UserAccessReviewEngine(db_path=str(tmp_path / "test_uar.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_review(engine, org=ORG, **kwargs):
    defaults = dict(
        review_name="Q1 Review",
        review_type="quarterly",
        reviewer_id="reviewer-1",
        due_date="2099-12-31T00:00:00+00:00",
    )
    defaults.update(kwargs)
    return engine.create_review(org_id=org, **defaults)


def _add_item(engine, review_id, org=ORG, **kwargs):
    defaults = dict(
        user_id="user-1",
        resource_id="res-1",
        resource_type="database",
        access_level="read",
    )
    defaults.update(kwargs)
    return engine.add_review_item(review_id=review_id, org_id=org, **defaults)


# ---------------------------------------------------------------------------
# create_review
# ---------------------------------------------------------------------------

def test_create_review_returns_dict(engine):
    r = _make_review(engine)
    assert isinstance(r, dict)
    assert r["id"]
    assert r["org_id"] == ORG
    assert r["review_name"] == "Q1 Review"


def test_create_review_status_pending(engine):
    r = _make_review(engine)
    assert r["status"] == "pending"


def test_create_review_type_stored(engine):
    r = _make_review(engine, review_type="annual")
    assert r["review_type"] == "annual"


def test_create_review_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="review_type"):
        engine.create_review(ORG, "bad", review_type="bad-type")


def test_create_review_all_valid_types(engine):
    for t in ["quarterly", "annual", "triggered", "ad-hoc", "role-based", "system-based"]:
        r = engine.create_review(ORG, f"Review {t}", review_type=t)
        assert r["review_type"] == t


def test_create_review_due_date_stored(engine):
    r = _make_review(engine, due_date="2099-06-01T00:00:00+00:00")
    assert r["due_date"] == "2099-06-01T00:00:00+00:00"


def test_create_review_reviewer_id_stored(engine):
    r = _make_review(engine, reviewer_id="alice")
    assert r["reviewer_id"] == "alice"


# ---------------------------------------------------------------------------
# add_review_item
# ---------------------------------------------------------------------------

def test_add_review_item_returns_dict(engine):
    r = _make_review(engine)
    item = _add_item(engine, r["id"])
    assert isinstance(item, dict)
    assert item["review_id"] == r["id"]
    assert item["user_id"] == "user-1"


def test_add_review_item_no_decision_initially(engine):
    r = _make_review(engine)
    item = _add_item(engine, r["id"])
    assert item["decision"] is None
    assert item["decided_at"] is None


def test_add_review_item_moves_review_to_in_progress(engine):
    r = _make_review(engine)
    assert r["status"] == "pending"
    _add_item(engine, r["id"])
    review = engine.get_review(r["id"], ORG)
    assert review["status"] == "in-progress"


def test_add_multiple_items(engine):
    r = _make_review(engine)
    for i in range(3):
        _add_item(engine, r["id"], user_id=f"user-{i}", resource_id=f"res-{i}")
    review = engine.get_review(r["id"], ORG)
    assert len(review["items"]) == 3


# ---------------------------------------------------------------------------
# make_decision
# ---------------------------------------------------------------------------

def test_make_decision_certify(engine):
    r = _make_review(engine)
    item = _add_item(engine, r["id"])
    updated = engine.make_decision(r["id"], item["id"], ORG, "certify", "looks good", "alice")
    assert updated["decision"] == "certify"
    assert updated["decision_reason"] == "looks good"
    assert updated["decided_by"] == "alice"
    assert updated["decided_at"] is not None


def test_make_decision_revoke(engine):
    r = _make_review(engine)
    item = _add_item(engine, r["id"])
    updated = engine.make_decision(r["id"], item["id"], ORG, "revoke")
    assert updated["decision"] == "revoke"


def test_make_decision_modify(engine):
    r = _make_review(engine)
    item = _add_item(engine, r["id"])
    updated = engine.make_decision(r["id"], item["id"], ORG, "modify")
    assert updated["decision"] == "modify"


def test_make_decision_defer(engine):
    r = _make_review(engine)
    item = _add_item(engine, r["id"])
    updated = engine.make_decision(r["id"], item["id"], ORG, "defer")
    assert updated["decision"] == "defer"


def test_make_decision_invalid_raises(engine):
    r = _make_review(engine)
    item = _add_item(engine, r["id"])
    with pytest.raises(ValueError, match="decision"):
        engine.make_decision(r["id"], item["id"], ORG, "invalid-decision")


def test_make_decision_auto_completes_review(engine):
    r = _make_review(engine)
    item = _add_item(engine, r["id"])
    engine.make_decision(r["id"], item["id"], ORG, "certify")
    review = engine.get_review(r["id"], ORG)
    assert review["status"] == "completed"
    assert review["completed_at"] is not None


def test_make_decision_not_complete_until_all_decided(engine):
    r = _make_review(engine)
    item1 = _add_item(engine, r["id"], user_id="u1", resource_id="r1")
    item2 = _add_item(engine, r["id"], user_id="u2", resource_id="r2")
    engine.make_decision(r["id"], item1["id"], ORG, "certify")
    review = engine.get_review(r["id"], ORG)
    assert review["status"] == "in-progress"
    engine.make_decision(r["id"], item2["id"], ORG, "revoke")
    review = engine.get_review(r["id"], ORG)
    assert review["status"] == "completed"


# ---------------------------------------------------------------------------
# get_review
# ---------------------------------------------------------------------------

def test_get_review_includes_items(engine):
    r = _make_review(engine)
    _add_item(engine, r["id"])
    review = engine.get_review(r["id"], ORG)
    assert "items" in review
    assert len(review["items"]) == 1


def test_get_review_not_found_returns_none(engine):
    result = engine.get_review("nonexistent-id", ORG)
    assert result is None


def test_get_review_org_isolation(engine):
    r = _make_review(engine, org=ORG)
    result = engine.get_review(r["id"], ORG2)
    assert result is None


# ---------------------------------------------------------------------------
# list_reviews
# ---------------------------------------------------------------------------

def test_list_reviews_returns_list(engine):
    _make_review(engine)
    _make_review(engine, review_name="Q2 Review")
    reviews = engine.list_reviews(ORG)
    assert len(reviews) == 2


def test_list_reviews_filter_by_status(engine):
    _make_review(engine)
    reviews = engine.list_reviews(ORG, status="pending")
    assert all(r["status"] == "pending" for r in reviews)


def test_list_reviews_org_isolation(engine):
    _make_review(engine, org=ORG)
    _make_review(engine, org=ORG2)
    assert len(engine.list_reviews(ORG)) == 1
    assert len(engine.list_reviews(ORG2)) == 1


# ---------------------------------------------------------------------------
# get_overdue_reviews
# ---------------------------------------------------------------------------

def test_get_overdue_reviews_past_due(engine):
    r = engine.create_review(ORG, "Overdue", due_date="2000-01-01T00:00:00+00:00")
    overdue = engine.get_overdue_reviews(ORG)
    assert any(o["id"] == r["id"] for o in overdue)


def test_get_overdue_reviews_future_not_overdue(engine):
    _make_review(engine, due_date="2099-12-31T00:00:00+00:00")
    overdue = engine.get_overdue_reviews(ORG)
    assert len(overdue) == 0


def test_get_overdue_reviews_completed_excluded(engine):
    r = engine.create_review(ORG, "Done", due_date="2000-01-01T00:00:00+00:00")
    item = _add_item(engine, r["id"])
    engine.make_decision(r["id"], item["id"], ORG, "certify")
    overdue = engine.get_overdue_reviews(ORG)
    assert not any(o["id"] == r["id"] for o in overdue)


# ---------------------------------------------------------------------------
# create_campaign & get_campaign_stats
# ---------------------------------------------------------------------------

def test_create_campaign_returns_dict(engine):
    c = engine.create_campaign(ORG, "Annual IAM Review", "annual", "all-users")
    assert isinstance(c, dict)
    assert c["campaign_name"] == "Annual IAM Review"
    assert c["frequency"] == "annual"


def test_create_campaign_invalid_frequency_raises(engine):
    with pytest.raises(ValueError, match="frequency"):
        engine.create_campaign(ORG, "bad", "daily")


def test_create_campaign_all_valid_frequencies(engine):
    for freq in ["monthly", "quarterly", "semi-annual", "annual"]:
        c = engine.create_campaign(ORG, f"Campaign {freq}", freq)
        assert c["frequency"] == freq


def test_get_campaign_stats_empty(engine):
    stats = engine.get_campaign_stats(ORG)
    assert stats["total_campaigns"] == 0
    assert stats["avg_completion_rate"] == 0.0


def test_get_campaign_stats_counts(engine):
    engine.create_campaign(ORG, "C1", "quarterly")
    engine.create_campaign(ORG, "C2", "annual")
    stats = engine.get_campaign_stats(ORG)
    assert stats["total_campaigns"] == 2


def test_get_campaign_stats_org_isolation(engine):
    engine.create_campaign(ORG, "C1", "quarterly")
    engine.create_campaign(ORG2, "C2", "quarterly")
    assert engine.get_campaign_stats(ORG)["total_campaigns"] == 1
    assert engine.get_campaign_stats(ORG2)["total_campaigns"] == 1


# ---------------------------------------------------------------------------
# get_review_summary
# ---------------------------------------------------------------------------

def test_get_review_summary_empty(engine):
    s = engine.get_review_summary(ORG)
    assert s["total"] == 0
    assert s["pending"] == 0
    assert s["completed"] == 0
    assert s["overdue"] == 0


def test_get_review_summary_counts(engine):
    _make_review(engine)
    _make_review(engine)
    s = engine.get_review_summary(ORG)
    assert s["total"] == 2
    assert s["pending"] == 2


def test_get_review_summary_completed_counted(engine):
    r = _make_review(engine)
    item = _add_item(engine, r["id"])
    engine.make_decision(r["id"], item["id"], ORG, "certify")
    s = engine.get_review_summary(ORG)
    assert s["completed"] == 1


def test_get_review_summary_overdue_counted(engine):
    engine.create_review(ORG, "Overdue", due_date="2000-01-01T00:00:00+00:00")
    s = engine.get_review_summary(ORG)
    assert s["overdue"] == 1


def test_get_review_summary_org_isolation(engine):
    _make_review(engine, org=ORG)
    _make_review(engine, org=ORG2)
    assert engine.get_review_summary(ORG)["total"] == 1
    assert engine.get_review_summary(ORG2)["total"] == 1
