"""Tests for SecurityPostureMaturityEngine.

Covers:
- record_assessment: valid, clamping, invalid domain, missing capability
- update_level: updates fields, clamping, org isolation, not found
- create_roadmap_item: valid, invalid domain/priority/effort
- advance_roadmap_item: planned→in_progress→completed, can't advance completed
- get_roadmap: all + filtered by status, org isolation
- take_snapshot: overall_level avg, domain_scores grouping
- get_maturity_overview: snapshot + assessments + roadmap
- get_domain_breakdown: grouping per domain
- get_overdue_reviews: returns only past next_review, org isolation
- Multi-tenant isolation throughout
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.security_posture_maturity_engine import SecurityPostureMaturityEngine

ORG = "org-maturity-test"
ORG2 = "org-maturity-other"


@pytest.fixture
def engine(tmp_path):
    return SecurityPostureMaturityEngine(db_path=str(tmp_path / "maturity.db"))


def _assessment(overrides=None):
    base = {
        "domain": "identity",
        "capability": "IAM lifecycle",
        "maturity_level": 3,
        "max_level": 5,
        "evidence": "policy docs",
        "assessor": "alice",
        "next_review": "",
    }
    if overrides:
        base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# record_assessment
# ---------------------------------------------------------------------------

class TestRecordAssessment:
    def test_returns_dict_with_id(self, engine):
        result = engine.record_assessment(ORG, **_assessment())
        assert "id" in result and len(result["id"]) == 36

    def test_stores_correct_domain_and_capability(self, engine):
        result = engine.record_assessment(ORG, **_assessment())
        assert result["domain"] == "identity"
        assert result["capability"] == "IAM lifecycle"

    def test_maturity_level_stored(self, engine):
        result = engine.record_assessment(ORG, **_assessment({"maturity_level": 4}))
        assert result["maturity_level"] == 4

    def test_clamp_above_max_level(self, engine):
        result = engine.record_assessment(ORG, **_assessment({"maturity_level": 99, "max_level": 5}))
        assert result["maturity_level"] == 5

    def test_clamp_below_one(self, engine):
        result = engine.record_assessment(ORG, **_assessment({"maturity_level": 0}))
        assert result["maturity_level"] == 1

    def test_clamp_respects_custom_max_level(self, engine):
        result = engine.record_assessment(ORG, **_assessment({"maturity_level": 4, "max_level": 3}))
        assert result["maturity_level"] == 3

    def test_invalid_domain_raises(self, engine):
        with pytest.raises(ValueError, match="domain"):
            engine.record_assessment(ORG, **_assessment({"domain": "invalid-domain"}))

    def test_empty_capability_raises(self, engine):
        with pytest.raises(ValueError, match="capability"):
            engine.record_assessment(ORG, **_assessment({"capability": ""}))

    def test_all_valid_domains(self, engine):
        domains = ["identity", "network", "endpoint", "data", "application",
                   "cloud", "physical", "governance", "risk", "compliance"]
        for d in domains:
            r = engine.record_assessment(ORG, **_assessment({"domain": d, "capability": f"cap-{d}"}))
            assert r["domain"] == d

    def test_assessed_at_set(self, engine):
        result = engine.record_assessment(ORG, **_assessment())
        assert result["assessed_at"] != ""

    def test_org_id_stored(self, engine):
        result = engine.record_assessment(ORG, **_assessment())
        assert result["org_id"] == ORG


# ---------------------------------------------------------------------------
# update_level
# ---------------------------------------------------------------------------

class TestUpdateLevel:
    def test_updates_maturity_level(self, engine):
        rec = engine.record_assessment(ORG, **_assessment({"maturity_level": 2}))
        updated = engine.update_level(rec["id"], ORG, 4)
        assert updated["maturity_level"] == 4

    def test_updates_evidence(self, engine):
        rec = engine.record_assessment(ORG, **_assessment())
        updated = engine.update_level(rec["id"], ORG, 3, evidence="new evidence")
        assert updated["evidence"] == "new evidence"

    def test_clamps_level_to_max(self, engine):
        rec = engine.record_assessment(ORG, **_assessment({"max_level": 4}))
        updated = engine.update_level(rec["id"], ORG, 10)
        assert updated["maturity_level"] == 4

    def test_clamps_level_to_one(self, engine):
        rec = engine.record_assessment(ORG, **_assessment())
        updated = engine.update_level(rec["id"], ORG, -5)
        assert updated["maturity_level"] == 1

    def test_not_found_raises_key_error(self, engine):
        with pytest.raises(KeyError):
            engine.update_level("no-such-id", ORG, 3)

    def test_org_isolation(self, engine):
        rec = engine.record_assessment(ORG, **_assessment())
        with pytest.raises(KeyError):
            engine.update_level(rec["id"], ORG2, 3)


# ---------------------------------------------------------------------------
# create_roadmap_item
# ---------------------------------------------------------------------------

class TestCreateRoadmapItem:
    def test_returns_dict_with_id(self, engine):
        r = engine.create_roadmap_item(ORG, "network", "Segmentation", 2, 4)
        assert "id" in r and len(r["id"]) == 36

    def test_default_status_planned(self, engine):
        r = engine.create_roadmap_item(ORG, "network", "Segmentation", 2, 4)
        assert r["status"] == "planned"

    def test_invalid_domain_raises(self, engine):
        with pytest.raises(ValueError):
            engine.create_roadmap_item(ORG, "bogus", "cap", 1, 3)

    def test_invalid_priority_raises(self, engine):
        with pytest.raises(ValueError):
            engine.create_roadmap_item(ORG, "cloud", "cap", 1, 3, priority="urgent")

    def test_invalid_effort_raises(self, engine):
        with pytest.raises(ValueError):
            engine.create_roadmap_item(ORG, "cloud", "cap", 1, 3, effort="massive")

    def test_all_valid_priorities(self, engine):
        for p in ["critical", "high", "medium", "low"]:
            r = engine.create_roadmap_item(ORG, "cloud", f"cap-{p}", 1, 3, priority=p)
            assert r["priority"] == p

    def test_all_valid_efforts(self, engine):
        for e in ["low", "medium", "high", "very-high"]:
            r = engine.create_roadmap_item(ORG, "data", f"cap-{e}", 1, 3, effort=e)
            assert r["effort"] == e


# ---------------------------------------------------------------------------
# advance_roadmap_item
# ---------------------------------------------------------------------------

class TestAdvanceRoadmapItem:
    def test_planned_to_in_progress(self, engine):
        r = engine.create_roadmap_item(ORG, "network", "cap", 1, 3)
        adv = engine.advance_roadmap_item(r["id"], ORG)
        assert adv["status"] == "in_progress"

    def test_in_progress_to_completed(self, engine):
        r = engine.create_roadmap_item(ORG, "network", "cap", 1, 3)
        engine.advance_roadmap_item(r["id"], ORG)
        adv = engine.advance_roadmap_item(r["id"], ORG)
        assert adv["status"] == "completed"

    def test_completed_cannot_advance(self, engine):
        r = engine.create_roadmap_item(ORG, "network", "cap", 1, 3)
        engine.advance_roadmap_item(r["id"], ORG)
        engine.advance_roadmap_item(r["id"], ORG)
        with pytest.raises(ValueError):
            engine.advance_roadmap_item(r["id"], ORG)

    def test_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.advance_roadmap_item("no-such-id", ORG)

    def test_org_isolation(self, engine):
        r = engine.create_roadmap_item(ORG, "network", "cap", 1, 3)
        with pytest.raises(KeyError):
            engine.advance_roadmap_item(r["id"], ORG2)


# ---------------------------------------------------------------------------
# get_roadmap
# ---------------------------------------------------------------------------

class TestGetRoadmap:
    def test_returns_all_items(self, engine):
        engine.create_roadmap_item(ORG, "network", "A", 1, 3)
        engine.create_roadmap_item(ORG, "cloud", "B", 2, 4, priority="high")
        items = engine.get_roadmap(ORG)
        assert len(items) == 2

    def test_filter_by_status(self, engine):
        r = engine.create_roadmap_item(ORG, "network", "A", 1, 3)
        engine.create_roadmap_item(ORG, "cloud", "B", 1, 3)
        engine.advance_roadmap_item(r["id"], ORG)
        planned = engine.get_roadmap(ORG, status="planned")
        in_prog = engine.get_roadmap(ORG, status="in_progress")
        assert len(planned) == 1
        assert len(in_prog) == 1

    def test_org_isolation(self, engine):
        engine.create_roadmap_item(ORG, "network", "A", 1, 3)
        items = engine.get_roadmap(ORG2)
        assert items == []


# ---------------------------------------------------------------------------
# take_snapshot
# ---------------------------------------------------------------------------

class TestTakeSnapshot:
    def test_snapshot_overall_level_average(self, engine):
        engine.record_assessment(ORG, **_assessment({"maturity_level": 2, "capability": "A"}))
        engine.record_assessment(ORG, **_assessment({"maturity_level": 4, "capability": "B"}))
        snap = engine.take_snapshot(ORG)
        assert snap["overall_level"] == pytest.approx(3.0, abs=0.01)

    def test_snapshot_domain_scores(self, engine):
        engine.record_assessment(ORG, **_assessment({"domain": "network", "capability": "A", "maturity_level": 2}))
        engine.record_assessment(ORG, **_assessment({"domain": "network", "capability": "B", "maturity_level": 4}))
        engine.record_assessment(ORG, **_assessment({"domain": "cloud", "capability": "C", "maturity_level": 5}))
        snap = engine.take_snapshot(ORG)
        ds = snap["domain_scores"]
        assert ds["network"] == pytest.approx(3.0, abs=0.01)
        assert ds["cloud"] == pytest.approx(5.0, abs=0.01)

    def test_snapshot_date_is_today(self, engine):
        engine.record_assessment(ORG, **_assessment())
        snap = engine.take_snapshot(ORG)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        assert snap["snapshot_date"] == today

    def test_empty_org_snapshot(self, engine):
        snap = engine.take_snapshot(ORG)
        assert snap["overall_level"] == 0.0

    def test_org_isolation_snapshot(self, engine):
        engine.record_assessment(ORG, **_assessment({"maturity_level": 5}))
        snap2 = engine.take_snapshot(ORG2)
        assert snap2["overall_level"] == 0.0


# ---------------------------------------------------------------------------
# get_maturity_overview
# ---------------------------------------------------------------------------

class TestGetMaturityOverview:
    def test_returns_all_keys(self, engine):
        ov = engine.get_maturity_overview(ORG)
        assert "latest_snapshot" in ov
        assert "assessments" in ov
        assert "roadmap" in ov

    def test_with_data(self, engine):
        engine.record_assessment(ORG, **_assessment())
        engine.create_roadmap_item(ORG, "network", "cap", 1, 3)
        engine.take_snapshot(ORG)
        ov = engine.get_maturity_overview(ORG)
        assert len(ov["assessments"]) == 1
        assert len(ov["roadmap"]) == 1
        assert ov["latest_snapshot"] is not None

    def test_no_snapshot_returns_none(self, engine):
        ov = engine.get_maturity_overview(ORG)
        assert ov["latest_snapshot"] is None


# ---------------------------------------------------------------------------
# get_domain_breakdown
# ---------------------------------------------------------------------------

class TestGetDomainBreakdown:
    def test_groups_by_domain(self, engine):
        engine.record_assessment(ORG, **_assessment({"domain": "network", "capability": "A", "maturity_level": 2}))
        engine.record_assessment(ORG, **_assessment({"domain": "network", "capability": "B", "maturity_level": 4}))
        engine.record_assessment(ORG, **_assessment({"domain": "cloud", "capability": "C", "maturity_level": 3}))
        breakdown = engine.get_domain_breakdown(ORG)
        domains = {d["domain"]: d for d in breakdown}
        assert "network" in domains
        assert "cloud" in domains
        assert domains["network"]["capability_count"] == 2
        assert domains["network"]["avg_level"] == pytest.approx(3.0, abs=0.01)

    def test_assessments_listed_per_domain(self, engine):
        engine.record_assessment(ORG, **_assessment({"domain": "endpoint", "capability": "EDR"}))
        breakdown = engine.get_domain_breakdown(ORG)
        ep = next(d for d in breakdown if d["domain"] == "endpoint")
        assert len(ep["assessments"]) == 1

    def test_org_isolation(self, engine):
        engine.record_assessment(ORG, **_assessment())
        breakdown = engine.get_domain_breakdown(ORG2)
        assert breakdown == []


# ---------------------------------------------------------------------------
# get_overdue_reviews
# ---------------------------------------------------------------------------

class TestGetOverdueReviews:
    def _past(self, days=1):
        return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    def _future(self, days=7):
        return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

    def test_overdue_returned(self, engine):
        engine.record_assessment(ORG, **_assessment({"next_review": self._past()}))
        overdue = engine.get_overdue_reviews(ORG)
        assert len(overdue) == 1

    def test_future_review_not_returned(self, engine):
        engine.record_assessment(ORG, **_assessment({"next_review": self._future()}))
        overdue = engine.get_overdue_reviews(ORG)
        assert len(overdue) == 0

    def test_no_next_review_not_returned(self, engine):
        engine.record_assessment(ORG, **_assessment({"next_review": ""}))
        overdue = engine.get_overdue_reviews(ORG)
        assert len(overdue) == 0

    def test_org_isolation(self, engine):
        engine.record_assessment(ORG, **_assessment({"next_review": self._past()}))
        overdue = engine.get_overdue_reviews(ORG2)
        assert len(overdue) == 0

    def test_multiple_overdue(self, engine):
        engine.record_assessment(ORG, **_assessment({"capability": "A", "next_review": self._past(1)}))
        engine.record_assessment(ORG, **_assessment({"capability": "B", "next_review": self._past(2)}))
        engine.record_assessment(ORG, **_assessment({"capability": "C", "next_review": self._future()}))
        overdue = engine.get_overdue_reviews(ORG)
        assert len(overdue) == 2
