"""Tests for SecurityRoadmapEngine — 25+ tests covering all methods and org isolation."""

from __future__ import annotations

import tempfile
from datetime import date, timedelta

import pytest

from core.security_roadmap_engine import SecurityRoadmapEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_roadmap.db")
    return SecurityRoadmapEngine(db_path=db)


ORG_A = "org-alpha"
ORG_B = "org-beta"


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def _make_initiative(title="MFA Rollout", **kwargs):
    return {
        "title": title,
        "description": "Deploy MFA across all services",
        "category": "technology",
        "priority": "high",
        "status": "planned",
        "owner": "ciso@example.com",
        "budget_usd": 50000.0,
        "start_date": "2026-05-01",
        "target_date": "2026-12-31",
        **kwargs,
    }


def _make_milestone(title="Phase 1 complete", **kwargs):
    return {
        "title": title,
        "description": "First phase done",
        "due_date": "2026-07-01",
        **kwargs,
    }


def _make_gap(title="No MFA on VPN", **kwargs):
    return {
        "title": title,
        "description": "VPN lacks MFA enforcement",
        "gap_type": "technology",
        "severity": "high",
        **kwargs,
    }


def _make_metric(**kwargs):
    return {
        "metric_name": "MFA adoption rate",
        "target_value": 100.0,
        "current_value": 42.0,
        "unit": "percent",
        **kwargs,
    }


# ---------------------------------------------------------------------------
# Initiative tests
# ---------------------------------------------------------------------------

class TestCreateInitiative:
    def test_create_returns_dict_with_id(self, engine):
        result = engine.create_initiative(ORG_A, _make_initiative())
        assert "initiative_id" in result
        assert result["title"] == "MFA Rollout"
        assert result["org_id"] == ORG_A

    def test_create_defaults_category_on_invalid(self, engine):
        result = engine.create_initiative(ORG_A, _make_initiative(category="invalid"))
        assert result["category"] == "technology"

    def test_create_defaults_priority_on_invalid(self, engine):
        result = engine.create_initiative(ORG_A, _make_initiative(priority="bogus"))
        assert result["priority"] == "medium"

    def test_create_defaults_status_on_invalid(self, engine):
        result = engine.create_initiative(ORG_A, _make_initiative(status="unknown"))
        assert result["status"] == "planned"

    def test_create_sets_budget(self, engine):
        result = engine.create_initiative(ORG_A, _make_initiative(budget_usd=99999.99))
        assert result["budget_usd"] == pytest.approx(99999.99)


class TestListInitiatives:
    def test_list_returns_all_for_org(self, engine):
        engine.create_initiative(ORG_A, _make_initiative("A1"))
        engine.create_initiative(ORG_A, _make_initiative("A2"))
        assert len(engine.list_initiatives(ORG_A)) == 2

    def test_list_filter_by_status(self, engine):
        engine.create_initiative(ORG_A, _make_initiative("P1", status="planned"))
        engine.create_initiative(ORG_A, _make_initiative("IP1", status="in_progress"))
        planned = engine.list_initiatives(ORG_A, status="planned")
        assert all(i["status"] == "planned" for i in planned)

    def test_list_filter_by_category(self, engine):
        engine.create_initiative(ORG_A, _make_initiative("T1", category="technology"))
        engine.create_initiative(ORG_A, _make_initiative("P1", category="people"))
        tech = engine.list_initiatives(ORG_A, category="technology")
        assert all(i["category"] == "technology" for i in tech)

    def test_list_empty_for_new_org(self, engine):
        assert engine.list_initiatives("org-new") == []


class TestGetInitiative:
    def test_get_returns_correct_record(self, engine):
        created = engine.create_initiative(ORG_A, _make_initiative())
        fetched = engine.get_initiative(ORG_A, created["initiative_id"])
        assert fetched is not None
        assert fetched["initiative_id"] == created["initiative_id"]

    def test_get_returns_none_for_missing(self, engine):
        assert engine.get_initiative(ORG_A, "non-existent-id") is None

    def test_get_org_isolation(self, engine):
        created = engine.create_initiative(ORG_A, _make_initiative())
        # ORG_B cannot see ORG_A's initiative
        assert engine.get_initiative(ORG_B, created["initiative_id"]) is None


class TestUpdateInitiative:
    def test_update_status(self, engine):
        created = engine.create_initiative(ORG_A, _make_initiative())
        ok = engine.update_initiative(ORG_A, created["initiative_id"], {"status": "in_progress"})
        assert ok is True
        updated = engine.get_initiative(ORG_A, created["initiative_id"])
        assert updated["status"] == "in_progress"

    def test_update_rejects_invalid_status(self, engine):
        created = engine.create_initiative(ORG_A, _make_initiative())
        ok = engine.update_initiative(ORG_A, created["initiative_id"], {"status": "bad_status"})
        assert ok is False

    def test_update_no_valid_fields_returns_false(self, engine):
        created = engine.create_initiative(ORG_A, _make_initiative())
        ok = engine.update_initiative(ORG_A, created["initiative_id"], {"title": "New Title"})
        assert ok is False  # 'title' is not an allowed update field

    def test_update_budget(self, engine):
        created = engine.create_initiative(ORG_A, _make_initiative())
        engine.update_initiative(ORG_A, created["initiative_id"], {"budget_usd": 75000.0})
        updated = engine.get_initiative(ORG_A, created["initiative_id"])
        assert updated["budget_usd"] == pytest.approx(75000.0)


# ---------------------------------------------------------------------------
# Milestone tests
# ---------------------------------------------------------------------------

class TestMilestones:
    def test_add_milestone_returns_dict(self, engine):
        init = engine.create_initiative(ORG_A, _make_initiative())
        ms = engine.add_milestone(ORG_A, init["initiative_id"], _make_milestone())
        assert "milestone_id" in ms
        assert ms["initiative_id"] == init["initiative_id"]

    def test_list_milestones(self, engine):
        init = engine.create_initiative(ORG_A, _make_initiative())
        engine.add_milestone(ORG_A, init["initiative_id"], _make_milestone("M1"))
        engine.add_milestone(ORG_A, init["initiative_id"], _make_milestone("M2"))
        milestones = engine.list_milestones(ORG_A, init["initiative_id"])
        assert len(milestones) == 2

    def test_complete_milestone(self, engine):
        init = engine.create_initiative(ORG_A, _make_initiative())
        ms = engine.add_milestone(ORG_A, init["initiative_id"], _make_milestone())
        ok = engine.complete_milestone(ORG_A, ms["milestone_id"])
        assert ok is True
        milestones = engine.list_milestones(ORG_A, init["initiative_id"])
        assert milestones[0]["status"] == "completed"
        assert milestones[0]["completion_date"] != ""

    def test_complete_milestone_wrong_org_returns_false(self, engine):
        init = engine.create_initiative(ORG_A, _make_initiative())
        ms = engine.add_milestone(ORG_A, init["initiative_id"], _make_milestone())
        ok = engine.complete_milestone(ORG_B, ms["milestone_id"])
        assert ok is False

    def test_list_milestones_org_isolation(self, engine):
        init_a = engine.create_initiative(ORG_A, _make_initiative())
        engine.add_milestone(ORG_A, init_a["initiative_id"], _make_milestone())
        # ORG_B has no milestones for this initiative_id
        assert engine.list_milestones(ORG_B, init_a["initiative_id"]) == []


# ---------------------------------------------------------------------------
# Gap tests
# ---------------------------------------------------------------------------

class TestGaps:
    def test_add_gap_returns_dict(self, engine):
        gap = engine.add_gap(ORG_A, _make_gap())
        assert "gap_id" in gap
        assert gap["org_id"] == ORG_A

    def test_list_gaps_unresolved_by_default(self, engine):
        engine.add_gap(ORG_A, _make_gap("G1"))
        engine.add_gap(ORG_A, _make_gap("G2"))
        gaps = engine.list_gaps(ORG_A)
        assert len(gaps) == 2

    def test_list_gaps_filter_by_severity(self, engine):
        engine.add_gap(ORG_A, _make_gap("Critical gap", severity="critical"))
        engine.add_gap(ORG_A, _make_gap("Low gap", severity="low"))
        critical = engine.list_gaps(ORG_A, severity="critical")
        assert all(g["severity"] == "critical" for g in critical)

    def test_link_gap_to_initiative(self, engine):
        init = engine.create_initiative(ORG_A, _make_initiative())
        gap = engine.add_gap(ORG_A, _make_gap())
        ok = engine.link_gap_to_initiative(ORG_A, gap["gap_id"], init["initiative_id"])
        assert ok is True
        gaps = engine.list_gaps(ORG_A)
        assert gaps[0]["linked_initiative_id"] == init["initiative_id"]

    def test_link_gap_wrong_org_returns_false(self, engine):
        init = engine.create_initiative(ORG_A, _make_initiative())
        gap = engine.add_gap(ORG_A, _make_gap())
        ok = engine.link_gap_to_initiative(ORG_B, gap["gap_id"], init["initiative_id"])
        assert ok is False

    def test_gaps_org_isolation(self, engine):
        engine.add_gap(ORG_A, _make_gap())
        assert engine.list_gaps(ORG_B) == []


# ---------------------------------------------------------------------------
# Metrics tests
# ---------------------------------------------------------------------------

class TestMetrics:
    def test_add_metric_returns_dict(self, engine):
        init = engine.create_initiative(ORG_A, _make_initiative())
        metric = engine.add_metric(ORG_A, init["initiative_id"], _make_metric())
        assert "metric_id" in metric
        assert metric["metric_name"] == "MFA adoption rate"

    def test_add_metric_values(self, engine):
        init = engine.create_initiative(ORG_A, _make_initiative())
        metric = engine.add_metric(ORG_A, init["initiative_id"], _make_metric(
            target_value=100.0, current_value=75.0, unit="percent"
        ))
        assert metric["target_value"] == pytest.approx(100.0)
        assert metric["current_value"] == pytest.approx(75.0)
        assert metric["unit"] == "percent"


# ---------------------------------------------------------------------------
# Stats tests
# ---------------------------------------------------------------------------

class TestRoadmapStats:
    def test_stats_empty_org(self, engine):
        stats = engine.get_roadmap_stats("org-empty")
        assert stats["total_initiatives"] == 0
        assert stats["total_gaps"] == 0
        assert stats["total_budget"] == pytest.approx(0.0)
        assert stats["overdue_milestones"] == 0

    def test_stats_counts(self, engine):
        engine.create_initiative(ORG_A, _make_initiative("I1", budget_usd=10000.0))
        engine.create_initiative(ORG_A, _make_initiative("I2", budget_usd=20000.0))
        engine.add_gap(ORG_A, _make_gap())
        stats = engine.get_roadmap_stats(ORG_A)
        assert stats["total_initiatives"] == 2
        assert stats["total_gaps"] == 1
        assert stats["unresolved_gaps"] == 1
        assert stats["total_budget"] == pytest.approx(30000.0)

    def test_stats_by_status(self, engine):
        engine.create_initiative(ORG_A, _make_initiative("P", status="planned"))
        engine.create_initiative(ORG_A, _make_initiative("IP", status="in_progress"))
        engine.create_initiative(ORG_A, _make_initiative("C", status="completed"))
        stats = engine.get_roadmap_stats(ORG_A)
        assert stats["by_status"].get("planned", 0) == 1
        assert stats["by_status"].get("in_progress", 0) == 1
        assert stats["by_status"].get("completed", 0) == 1

    def test_stats_by_category(self, engine):
        engine.create_initiative(ORG_A, _make_initiative("T", category="technology"))
        engine.create_initiative(ORG_A, _make_initiative("P", category="people"))
        stats = engine.get_roadmap_stats(ORG_A)
        assert stats["by_category"].get("technology", 0) == 1
        assert stats["by_category"].get("people", 0) == 1

    def test_stats_overdue_milestones(self, engine):
        init = engine.create_initiative(ORG_A, _make_initiative())
        past_date = (date.today() - timedelta(days=5)).isoformat()
        engine.add_milestone(ORG_A, init["initiative_id"], _make_milestone(due_date=past_date))
        stats = engine.get_roadmap_stats(ORG_A)
        assert stats["overdue_milestones"] >= 1

    def test_stats_on_track_initiatives(self, engine):
        future_date = (date.today() + timedelta(days=90)).isoformat()
        engine.create_initiative(
            ORG_A,
            _make_initiative(status="in_progress", target_date=future_date)
        )
        stats = engine.get_roadmap_stats(ORG_A)
        assert stats["initiatives_on_track"] == 1

    def test_stats_org_isolation(self, engine):
        engine.create_initiative(ORG_A, _make_initiative())
        stats_b = engine.get_roadmap_stats(ORG_B)
        assert stats_b["total_initiatives"] == 0
