"""Tests for IncidentLessonsEngine — Beast Mode wave 31."""

from __future__ import annotations

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.incident_lessons_engine import IncidentLessonsEngine


@pytest.fixture
def engine(tmp_path):
    return IncidentLessonsEngine(db_path=str(tmp_path / "test_lessons.db"))


ORG = "test-org"
OTHER_ORG = "other-org"


def _lesson(engine, org_id=ORG, **kwargs):
    params = dict(
        incident_id="INC-001",
        title="Test Lesson",
        description="Description",
        lesson_type="process",
        severity="high",
        identified_by="alice",
    )
    params.update(kwargs)
    return engine.create_lesson(org_id, **params)


def _action(engine, lesson_id, org_id=ORG, **kwargs):
    params = dict(
        action="Fix the process",
        owner="bob",
        due_date="2026-12-31",
        priority="high",
    )
    params.update(kwargs)
    return engine.add_action_item(lesson_id, org_id, **params)


# ---------------------------------------------------------------------------
# create_lesson
# ---------------------------------------------------------------------------

def test_create_lesson_basic(engine):
    lesson = _lesson(engine)
    assert lesson["id"]
    assert lesson["org_id"] == ORG
    assert lesson["status"] == "open"
    assert lesson["incident_id"] == "INC-001"
    assert lesson["lesson_type"] == "process"
    assert lesson["severity"] == "high"
    assert lesson["created_at"]
    assert lesson["reviewed_at"] is None


def test_create_lesson_all_types(engine):
    types = ["process", "technology", "communication", "training",
             "detection", "response", "recovery", "prevention"]
    for i, lt in enumerate(types):
        lesson = _lesson(engine, incident_id=f"INC-{i}", lesson_type=lt)
        assert lesson["lesson_type"] == lt


def test_create_lesson_all_severities(engine):
    for i, sev in enumerate(["critical", "high", "medium", "low"]):
        lesson = _lesson(engine, incident_id=f"INC-SEV-{i}", severity=sev)
        assert lesson["severity"] == sev


def test_create_lesson_invalid_type(engine):
    with pytest.raises(ValueError, match="lesson_type"):
        _lesson(engine, lesson_type="invalid")


def test_create_lesson_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        _lesson(engine, severity="unknown")


def test_create_lesson_missing_title(engine):
    with pytest.raises(ValueError, match="title"):
        engine.create_lesson(ORG, "INC-001", "", "desc", "process", "high")


def test_create_lesson_missing_incident_id(engine):
    with pytest.raises(ValueError, match="incident_id"):
        engine.create_lesson(ORG, "", "Title", "desc", "process", "high")


def test_create_lesson_org_isolation(engine):
    l1 = _lesson(engine, org_id=ORG)
    l2 = _lesson(engine, org_id=OTHER_ORG, incident_id="INC-002")
    assert l1["org_id"] == ORG
    assert l2["org_id"] == OTHER_ORG


# ---------------------------------------------------------------------------
# add_action_item
# ---------------------------------------------------------------------------

def test_add_action_item_basic(engine):
    lesson = _lesson(engine)
    action = _action(engine, lesson["id"])
    assert action["id"]
    assert action["lesson_id"] == lesson["id"]
    assert action["status"] == "open"
    assert action["priority"] == "high"
    assert action["completed_at"] is None


def test_add_action_item_advances_lesson_to_in_progress(engine):
    lesson = _lesson(engine)
    assert lesson["status"] == "open"
    _action(engine, lesson["id"])
    updated = engine.get_lesson(lesson["id"], ORG)
    assert updated["status"] == "in-progress"


def test_add_action_item_all_priorities(engine):
    lesson = _lesson(engine)
    for i, prio in enumerate(["critical", "high", "medium", "low"]):
        action = engine.add_action_item(
            lesson["id"], ORG, f"Action {i}", "owner", "2026-12-31", prio
        )
        assert action["priority"] == prio


def test_add_action_item_invalid_priority(engine):
    lesson = _lesson(engine)
    with pytest.raises(ValueError, match="priority"):
        engine.add_action_item(lesson["id"], ORG, "Action", "owner", "2026-12-31", "urgent")


def test_add_action_item_not_found_lesson(engine):
    with pytest.raises(KeyError):
        engine.add_action_item("nonexistent-id", ORG, "Action", "owner", "2026-12-31")


def test_add_action_item_missing_action(engine):
    lesson = _lesson(engine)
    with pytest.raises(ValueError, match="action"):
        engine.add_action_item(lesson["id"], ORG, "", "owner", "2026-12-31")


def test_add_action_item_missing_due_date(engine):
    lesson = _lesson(engine)
    with pytest.raises(ValueError, match="due_date"):
        engine.add_action_item(lesson["id"], ORG, "Do it", "owner", "")


# ---------------------------------------------------------------------------
# complete_action
# ---------------------------------------------------------------------------

def test_complete_action_basic(engine):
    lesson = _lesson(engine)
    action = _action(engine, lesson["id"])
    completed = engine.complete_action(lesson["id"], action["id"], ORG)
    assert completed["status"] == "completed"
    assert completed["completed_at"]


def test_complete_all_actions_implements_lesson(engine):
    lesson = _lesson(engine)
    a1 = _action(engine, lesson["id"])
    a2 = engine.add_action_item(lesson["id"], ORG, "Second action", "bob", "2026-12-31")
    engine.complete_action(lesson["id"], a1["id"], ORG)
    # Still in-progress after first
    mid = engine.get_lesson(lesson["id"], ORG)
    assert mid["status"] == "in-progress"
    engine.complete_action(lesson["id"], a2["id"], ORG)
    final = engine.get_lesson(lesson["id"], ORG)
    assert final["status"] == "implemented"


def test_complete_action_not_found(engine):
    lesson = _lesson(engine)
    with pytest.raises(KeyError):
        engine.complete_action(lesson["id"], "nonexistent-action", ORG)


def test_complete_single_action_implements_lesson(engine):
    lesson = _lesson(engine)
    action = _action(engine, lesson["id"])
    engine.complete_action(lesson["id"], action["id"], ORG)
    final = engine.get_lesson(lesson["id"], ORG)
    assert final["status"] == "implemented"


# ---------------------------------------------------------------------------
# review_lesson
# ---------------------------------------------------------------------------

def test_review_lesson_basic(engine):
    lesson = _lesson(engine)
    review = engine.review_lesson(lesson["id"], ORG, "charlie", "accepted", "LGTM")
    assert review["id"]
    assert review["reviewer"] == "charlie"
    assert review["outcome"] == "accepted"
    assert review["reviewed_at"]


def test_review_lesson_updates_status(engine):
    lesson = _lesson(engine)
    engine.review_lesson(lesson["id"], ORG, "reviewer", "accepted")
    updated = engine.get_lesson(lesson["id"], ORG)
    assert updated["status"] == "reviewed"
    assert updated["reviewed_at"]


def test_review_lesson_all_outcomes(engine):
    for i, outcome in enumerate(["accepted", "rejected", "modified"]):
        lesson = _lesson(engine, incident_id=f"INC-REV-{i}")
        review = engine.review_lesson(lesson["id"], ORG, "reviewer", outcome)
        assert review["outcome"] == outcome


def test_review_lesson_invalid_outcome(engine):
    lesson = _lesson(engine)
    with pytest.raises(ValueError, match="outcome"):
        engine.review_lesson(lesson["id"], ORG, "reviewer", "approved")


def test_review_lesson_missing_reviewer(engine):
    lesson = _lesson(engine)
    with pytest.raises(ValueError, match="reviewer"):
        engine.review_lesson(lesson["id"], ORG, "", "accepted")


def test_review_lesson_not_found(engine):
    with pytest.raises(KeyError):
        engine.review_lesson("nonexistent", ORG, "reviewer", "accepted")


def test_review_does_not_override_implemented(engine):
    lesson = _lesson(engine)
    action = _action(engine, lesson["id"])
    engine.complete_action(lesson["id"], action["id"], ORG)
    engine.review_lesson(lesson["id"], ORG, "reviewer", "accepted")
    final = engine.get_lesson(lesson["id"], ORG)
    # implemented takes precedence — review should not downgrade
    assert final["status"] == "implemented"


# ---------------------------------------------------------------------------
# get_lesson
# ---------------------------------------------------------------------------

def test_get_lesson_with_actions_and_reviews(engine):
    lesson = _lesson(engine)
    _action(engine, lesson["id"])
    engine.review_lesson(lesson["id"], ORG, "reviewer", "accepted")
    full = engine.get_lesson(lesson["id"], ORG)
    assert len(full["action_items"]) == 1
    assert len(full["reviews"]) == 1


def test_get_lesson_not_found(engine):
    assert engine.get_lesson("nonexistent", ORG) is None


def test_get_lesson_org_isolation(engine):
    lesson = _lesson(engine, org_id=ORG)
    # Other org cannot access
    assert engine.get_lesson(lesson["id"], OTHER_ORG) is None


# ---------------------------------------------------------------------------
# list_lessons
# ---------------------------------------------------------------------------

def test_list_lessons_basic(engine):
    _lesson(engine, incident_id="INC-A")
    _lesson(engine, incident_id="INC-B")
    lessons = engine.list_lessons(ORG)
    assert len(lessons) == 2


def test_list_lessons_filter_status(engine):
    l1 = _lesson(engine, incident_id="INC-A")
    _lesson(engine, incident_id="INC-B")
    action = _action(engine, l1["id"])
    engine.complete_action(l1["id"], action["id"], ORG)
    implemented = engine.list_lessons(ORG, status="implemented")
    assert len(implemented) == 1
    assert implemented[0]["id"] == l1["id"]


def test_list_lessons_filter_type(engine):
    _lesson(engine, incident_id="INC-A", lesson_type="process")
    _lesson(engine, incident_id="INC-B", lesson_type="technology")
    result = engine.list_lessons(ORG, lesson_type="process")
    assert len(result) == 1
    assert result[0]["lesson_type"] == "process"


def test_list_lessons_org_isolation(engine):
    _lesson(engine, org_id=ORG, incident_id="INC-A")
    _lesson(engine, org_id=OTHER_ORG, incident_id="INC-B")
    assert len(engine.list_lessons(ORG)) == 1
    assert len(engine.list_lessons(OTHER_ORG)) == 1


# ---------------------------------------------------------------------------
# get_overdue_actions
# ---------------------------------------------------------------------------

def test_get_overdue_actions(engine):
    lesson = _lesson(engine)
    # Past due date
    engine.add_action_item(lesson["id"], ORG, "Overdue action", "bob", "2020-01-01")
    # Future due date
    engine.add_action_item(lesson["id"], ORG, "Future action", "bob", "2099-12-31")
    overdue = engine.get_overdue_actions(ORG)
    assert len(overdue) == 1
    assert overdue[0]["action"] == "Overdue action"


def test_get_overdue_actions_excludes_completed(engine):
    lesson = _lesson(engine)
    action = engine.add_action_item(lesson["id"], ORG, "Done action", "bob", "2020-01-01")
    engine.complete_action(lesson["id"], action["id"], ORG)
    overdue = engine.get_overdue_actions(ORG)
    assert len(overdue) == 0


def test_get_overdue_actions_org_isolation(engine):
    l1 = _lesson(engine, org_id=ORG)
    l2 = _lesson(engine, org_id=OTHER_ORG, incident_id="INC-002")
    engine.add_action_item(l1["id"], ORG, "Overdue", "bob", "2020-01-01")
    engine.add_action_item(l2["id"], OTHER_ORG, "Overdue2", "bob", "2020-01-01")
    assert len(engine.get_overdue_actions(ORG)) == 1
    assert len(engine.get_overdue_actions(OTHER_ORG)) == 1


# ---------------------------------------------------------------------------
# get_implementation_rate
# ---------------------------------------------------------------------------

def test_get_implementation_rate_empty(engine):
    result = engine.get_implementation_rate(ORG)
    assert result["total_lessons"] == 0
    assert result["implementation_rate_pct"] == 0.0


def test_get_implementation_rate_partial(engine):
    l1 = _lesson(engine, incident_id="INC-A")
    l2 = _lesson(engine, incident_id="INC-B")
    a1 = _action(engine, l1["id"])
    engine.complete_action(l1["id"], a1["id"], ORG)
    result = engine.get_implementation_rate(ORG)
    assert result["total_lessons"] == 2
    assert result["implemented_lessons"] == 1
    assert result["implementation_rate_pct"] == 50.0


def test_get_implementation_rate_full(engine):
    for i in range(3):
        lesson = _lesson(engine, incident_id=f"INC-{i}")
        action = _action(engine, lesson["id"])
        engine.complete_action(lesson["id"], action["id"], ORG)
    result = engine.get_implementation_rate(ORG)
    assert result["implementation_rate_pct"] == 100.0


# ---------------------------------------------------------------------------
# get_lessons_summary
# ---------------------------------------------------------------------------

def test_get_lessons_summary_basic(engine):
    _lesson(engine, incident_id="INC-A", lesson_type="process")
    _lesson(engine, incident_id="INC-B", lesson_type="technology")
    summary = engine.get_lessons_summary(ORG)
    assert "by_status" in summary
    assert "by_lesson_type" in summary
    assert "total_action_items" in summary
    assert "open_action_items" in summary
    assert summary["by_status"].get("open", 0) == 2
    assert summary["by_lesson_type"].get("process", 0) == 1
    assert summary["by_lesson_type"].get("technology", 0) == 1


def test_get_lessons_summary_counts_actions(engine):
    lesson = _lesson(engine)
    _action(engine, lesson["id"])
    _action(engine, lesson["id"])
    summary = engine.get_lessons_summary(ORG)
    assert summary["total_action_items"] == 2
    assert summary["open_action_items"] == 2
