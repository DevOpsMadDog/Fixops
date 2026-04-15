"""Tests for RiskTreatmentEngine — 35+ tests covering all methods."""
from __future__ import annotations

import pytest

from core.risk_treatment_engine import RiskTreatmentEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_risk_treatment_engine.db")


@pytest.fixture
def engine(db_path):
    return RiskTreatmentEngine(db_path=db_path)


ORG = "org-rt-test"
ORG2 = "org-rt-other"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_treatment(engine, org=ORG, **kwargs):
    defaults = {
        "title": "Patch critical vuln",
        "treatment_type": "mitigate",
        "treatment_status": "planned",
        "risk_level": "high",
        "owner": "security-team",
        "due_date": "2030-12-31T00:00:00+00:00",
    }
    defaults.update(kwargs)
    return engine.create_treatment(org, defaults)


def _make_note(engine, treatment_id, org=ORG, **kwargs):
    defaults = {
        "note": "Made progress on patching.",
        "author": "alice",
        "progress_pct_at_note": 25,
    }
    defaults.update(kwargs)
    return engine.add_progress_note(org, treatment_id, defaults)


# ---------------------------------------------------------------------------
# create_treatment
# ---------------------------------------------------------------------------

class TestCreateTreatment:
    def test_create_basic(self, engine):
        t = _make_treatment(engine)
        assert t["id"]
        assert t["title"] == "Patch critical vuln"
        assert t["treatment_type"] == "mitigate"
        assert t["treatment_status"] == "planned"
        assert t["risk_level"] == "high"
        assert t["progress_pct"] == 0
        assert t["completed_at"] == ""

    def test_create_sets_org_id(self, engine):
        t = _make_treatment(engine, org=ORG)
        assert t["org_id"] == ORG

    def test_create_all_treatment_types(self, engine):
        for tt in ("mitigate", "accept", "transfer", "avoid"):
            t = _make_treatment(engine, treatment_type=tt)
            assert t["treatment_type"] == tt

    def test_create_all_statuses(self, engine):
        for st in ("planned", "in_progress", "completed", "cancelled", "deferred"):
            t = _make_treatment(engine, treatment_status=st)
            assert t["treatment_status"] == st

    def test_create_all_risk_levels(self, engine):
        for rl in ("critical", "high", "medium", "low"):
            t = _make_treatment(engine, risk_level=rl)
            assert t["risk_level"] == rl

    def test_create_missing_title_raises(self, engine):
        with pytest.raises(ValueError, match="title is required"):
            engine.create_treatment(ORG, {"treatment_type": "mitigate"})

    def test_create_invalid_treatment_type_raises(self, engine):
        with pytest.raises(ValueError, match="treatment_type"):
            _make_treatment(engine, treatment_type="ignore")

    def test_create_invalid_status_raises(self, engine):
        with pytest.raises(ValueError, match="treatment_status"):
            _make_treatment(engine, treatment_status="unknown")

    def test_create_invalid_risk_level_raises(self, engine):
        with pytest.raises(ValueError, match="risk_level"):
            _make_treatment(engine, risk_level="extreme")

    def test_create_progress_pct_clamped(self, engine):
        t = engine.create_treatment(ORG, {"title": "T", "progress_pct": 150})
        assert t["progress_pct"] == 100

    def test_create_with_cost_fields(self, engine):
        t = engine.create_treatment(ORG, {
            "title": "Costly fix",
            "treatment_type": "mitigate",
            "cost_estimate": 5000.0,
            "actual_cost": 1200.0,
        })
        assert t["cost_estimate"] == 5000.0
        assert t["actual_cost"] == 1200.0


# ---------------------------------------------------------------------------
# list_treatments
# ---------------------------------------------------------------------------

class TestListTreatments:
    def test_list_empty(self, engine):
        assert engine.list_treatments(ORG) == []

    def test_list_returns_own_org(self, engine):
        _make_treatment(engine, org=ORG)
        _make_treatment(engine, org=ORG2)
        results = engine.list_treatments(ORG)
        assert len(results) == 1
        assert results[0]["org_id"] == ORG

    def test_filter_by_treatment_type(self, engine):
        _make_treatment(engine, treatment_type="mitigate")
        _make_treatment(engine, treatment_type="accept")
        results = engine.list_treatments(ORG, treatment_type="accept")
        assert len(results) == 1
        assert results[0]["treatment_type"] == "accept"

    def test_filter_by_treatment_status(self, engine):
        _make_treatment(engine, treatment_status="planned")
        _make_treatment(engine, treatment_status="in_progress")
        results = engine.list_treatments(ORG, treatment_status="in_progress")
        assert len(results) == 1

    def test_filter_by_risk_level(self, engine):
        _make_treatment(engine, risk_level="high")
        _make_treatment(engine, risk_level="low")
        results = engine.list_treatments(ORG, risk_level="high")
        assert len(results) == 1
        assert results[0]["risk_level"] == "high"

    def test_list_multiple(self, engine):
        for _ in range(3):
            _make_treatment(engine)
        assert len(engine.list_treatments(ORG)) == 3


# ---------------------------------------------------------------------------
# get_treatment
# ---------------------------------------------------------------------------

class TestGetTreatment:
    def test_get_existing(self, engine):
        t = _make_treatment(engine)
        fetched = engine.get_treatment(ORG, t["id"])
        assert fetched is not None
        assert fetched["id"] == t["id"]

    def test_get_nonexistent_returns_none(self, engine):
        assert engine.get_treatment(ORG, "no-such-id") is None

    def test_get_wrong_org_returns_none(self, engine):
        t = _make_treatment(engine, org=ORG)
        assert engine.get_treatment(ORG2, t["id"]) is None


# ---------------------------------------------------------------------------
# update_treatment_status
# ---------------------------------------------------------------------------

class TestUpdateTreatmentStatus:
    def test_update_status_basic(self, engine):
        t = _make_treatment(engine)
        updated = engine.update_treatment_status(ORG, t["id"], "in_progress")
        assert updated["treatment_status"] == "in_progress"

    def test_update_status_completed_sets_completed_at(self, engine):
        t = _make_treatment(engine)
        updated = engine.update_treatment_status(ORG, t["id"], "completed")
        assert updated["treatment_status"] == "completed"
        assert updated["completed_at"] != ""

    def test_update_status_with_progress_pct(self, engine):
        t = _make_treatment(engine)
        updated = engine.update_treatment_status(ORG, t["id"], "in_progress", progress_pct=50)
        assert updated["progress_pct"] == 50

    def test_update_status_progress_pct_clamped(self, engine):
        t = _make_treatment(engine)
        updated = engine.update_treatment_status(ORG, t["id"], "in_progress", progress_pct=200)
        assert updated["progress_pct"] == 100

    def test_update_invalid_status_raises(self, engine):
        t = _make_treatment(engine)
        with pytest.raises(ValueError, match="treatment_status"):
            engine.update_treatment_status(ORG, t["id"], "unknown")

    def test_update_nonexistent_raises_key_error(self, engine):
        with pytest.raises(KeyError):
            engine.update_treatment_status(ORG, "no-such-id", "in_progress")

    def test_update_preserves_progress_if_none(self, engine):
        t = _make_treatment(engine)
        engine.update_treatment_status(ORG, t["id"], "in_progress", progress_pct=30)
        updated = engine.update_treatment_status(ORG, t["id"], "deferred")
        assert updated["progress_pct"] == 30


# ---------------------------------------------------------------------------
# add_progress_note / list_progress_notes
# ---------------------------------------------------------------------------

class TestProgressNotes:
    def test_add_note_basic(self, engine):
        t = _make_treatment(engine)
        note = _make_note(engine, t["id"])
        assert note["id"]
        assert note["treatment_id"] == t["id"]
        assert note["note"] == "Made progress on patching."
        assert note["author"] == "alice"
        assert note["progress_pct_at_note"] == 25

    def test_add_note_missing_note_raises(self, engine):
        t = _make_treatment(engine)
        with pytest.raises(ValueError, match="note is required"):
            engine.add_progress_note(ORG, t["id"], {"author": "alice"})

    def test_add_note_missing_author_raises(self, engine):
        t = _make_treatment(engine)
        with pytest.raises(ValueError, match="author is required"):
            engine.add_progress_note(ORG, t["id"], {"note": "Some note"})

    def test_list_notes_ordered_desc(self, engine):
        t = _make_treatment(engine)
        _make_note(engine, t["id"], note="First note", progress_pct_at_note=10)
        _make_note(engine, t["id"], note="Second note", progress_pct_at_note=20)
        notes = engine.list_progress_notes(ORG, t["id"])
        assert len(notes) == 2
        # DESC order — second note should be first
        assert notes[0]["progress_pct_at_note"] == 20

    def test_list_notes_empty(self, engine):
        t = _make_treatment(engine)
        assert engine.list_progress_notes(ORG, t["id"]) == []

    def test_notes_org_isolation(self, engine):
        t1 = _make_treatment(engine, org=ORG)
        t2 = _make_treatment(engine, org=ORG2)
        _make_note(engine, t1["id"], org=ORG)
        _make_note(engine, t2["id"], org=ORG2)
        assert len(engine.list_progress_notes(ORG, t1["id"])) == 1
        assert len(engine.list_progress_notes(ORG2, t2["id"])) == 1
        # Wrong org returns nothing
        assert engine.list_progress_notes(ORG2, t1["id"]) == []


# ---------------------------------------------------------------------------
# get_treatment_stats
# ---------------------------------------------------------------------------

class TestTreatmentStats:
    def test_stats_empty(self, engine):
        stats = engine.get_treatment_stats(ORG)
        assert stats["total_treatments"] == 0
        assert stats["by_status"] == {}
        assert stats["by_type"] == {}
        assert stats["by_risk_level"] == {}
        assert stats["completed_on_time"] == 0
        assert stats["avg_progress_pct"] == 0.0
        assert stats["overdue_count"] == 0

    def test_stats_total_treatments(self, engine):
        _make_treatment(engine)
        _make_treatment(engine)
        stats = engine.get_treatment_stats(ORG)
        assert stats["total_treatments"] == 2

    def test_stats_by_status(self, engine):
        _make_treatment(engine, treatment_status="planned")
        _make_treatment(engine, treatment_status="in_progress")
        stats = engine.get_treatment_stats(ORG)
        assert stats["by_status"]["planned"] == 1
        assert stats["by_status"]["in_progress"] == 1

    def test_stats_by_type(self, engine):
        _make_treatment(engine, treatment_type="mitigate")
        _make_treatment(engine, treatment_type="accept")
        stats = engine.get_treatment_stats(ORG)
        assert stats["by_type"]["mitigate"] == 1
        assert stats["by_type"]["accept"] == 1

    def test_stats_by_risk_level(self, engine):
        _make_treatment(engine, risk_level="high")
        _make_treatment(engine, risk_level="critical")
        stats = engine.get_treatment_stats(ORG)
        assert stats["by_risk_level"]["high"] == 1
        assert stats["by_risk_level"]["critical"] == 1

    def test_stats_org_isolation(self, engine):
        _make_treatment(engine, org=ORG)
        _make_treatment(engine, org=ORG2)
        stats = engine.get_treatment_stats(ORG)
        assert stats["total_treatments"] == 1

    def test_stats_avg_progress_pct(self, engine):
        t = _make_treatment(engine)
        engine.update_treatment_status(ORG, t["id"], "in_progress", progress_pct=60)
        stats = engine.get_treatment_stats(ORG)
        assert stats["avg_progress_pct"] == 60.0

    def test_stats_completed_on_time(self, engine):
        # due_date in the future, complete it => on_time
        t = _make_treatment(engine, due_date="2099-12-31T23:59:59+00:00")
        engine.update_treatment_status(ORG, t["id"], "completed")
        stats = engine.get_treatment_stats(ORG)
        assert stats["completed_on_time"] == 1

    def test_stats_overdue_count(self, engine):
        # due_date in the past, still planned => overdue
        _make_treatment(engine, due_date="2000-01-01T00:00:00+00:00", treatment_status="planned")
        stats = engine.get_treatment_stats(ORG)
        assert stats["overdue_count"] == 1

    def test_stats_no_due_date_not_overdue(self, engine):
        engine.create_treatment(ORG, {"title": "No deadline", "treatment_type": "accept"})
        stats = engine.get_treatment_stats(ORG)
        assert stats["overdue_count"] == 0
