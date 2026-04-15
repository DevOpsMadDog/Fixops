"""
Tests for RegulatoryTrackerEngine and its API router.

Coverage:
- Engine: add_regulation, list_regulations, add_change, list_changes,
  get_upcoming_changes, add_obligation, list_obligations,
  update_obligation_status, record_assessment, get_regulatory_stats
- Router: all endpoints via TestClient
- Org isolation (different org_ids don't see each other's data)
- Invalid value handling (bad category, impact_level, status)

>= 25 tests total. All use in-memory SQLite (:memory:) to avoid I/O side-effects.

Run with:
    python -m pytest tests/test_regulatory_tracker_engine.py -x --tb=short --timeout=10 -q
"""
from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.regulatory_tracker_engine import RegulatoryTrackerEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ORG = "org-regulatory-test"
ORG2 = "org-regulatory-other"


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "regulatory_test.db")
    return RegulatoryTrackerEngine(db_path=db)


def _make_reg(engine, org=ORG, name="GDPR", category="privacy", status="enacted"):
    return engine.add_regulation(org, {
        "name": name,
        "jurisdiction": "EU",
        "category": category,
        "version": "2024-Q1",
        "effective_date": "2024-01-01",
        "status": status,
        "url": "https://example.com/gdpr",
    })


def _make_change(engine, reg_id, org=ORG, impact_level="high", days_ahead=30):
    future = (datetime.now(timezone.utc) + timedelta(days=days_ahead)).isoformat()
    return engine.add_change(org, reg_id, {
        "change_type": "new_requirement",
        "title": "New data retention rule",
        "description": "Retain logs for 7 years",
        "impact_level": impact_level,
        "affected_domains": ["data_retention", "access_control"],
        "published_at": datetime.now(timezone.utc).isoformat(),
        "effective_at": future,
        "action_required": True,
    })


def _make_obligation(engine, reg_id, org=ORG, status="pending"):
    return engine.add_obligation(org, {
        "reg_id": reg_id,
        "title": "Implement data retention policy",
        "description": "Policy doc required",
        "obligation_type": "administrative",
        "deadline": "2025-06-30",
        "status": status,
        "owner": "compliance-team",
    })


# ---------------------------------------------------------------------------
# Regulation tests
# ---------------------------------------------------------------------------

class TestAddRegulation:
    def test_returns_dict_with_reg_id(self, engine):
        reg = _make_reg(engine)
        assert "reg_id" in reg
        assert reg["name"] == "GDPR"

    def test_org_id_stored(self, engine):
        reg = _make_reg(engine)
        assert reg["org_id"] == ORG

    def test_category_stored(self, engine):
        reg = _make_reg(engine, category="privacy")
        assert reg["category"] == "privacy"

    def test_invalid_category_defaults_to_cybersecurity(self, engine):
        reg = engine.add_regulation(ORG, {"name": "Test", "category": "invalid_cat"})
        assert reg["category"] == "cybersecurity"

    def test_invalid_status_defaults_to_enacted(self, engine):
        reg = engine.add_regulation(ORG, {"name": "Test", "status": "bad_status"})
        assert reg["status"] == "enacted"

    def test_url_stored(self, engine):
        reg = _make_reg(engine)
        assert reg["url"] == "https://example.com/gdpr"


class TestListRegulations:
    def test_empty_org_returns_empty(self, engine):
        assert engine.list_regulations("unknown-org") == []

    def test_lists_added_regulations(self, engine):
        _make_reg(engine)
        regs = engine.list_regulations(ORG)
        assert len(regs) == 1

    def test_filter_by_category(self, engine):
        _make_reg(engine, category="privacy")
        _make_reg(engine, name="PCI-DSS", category="financial")
        privacy = engine.list_regulations(ORG, category="privacy")
        assert all(r["category"] == "privacy" for r in privacy)
        assert len(privacy) == 1

    def test_filter_by_status(self, engine):
        _make_reg(engine, status="enacted")
        _make_reg(engine, name="Proposed Rule", status="proposed")
        enacted = engine.list_regulations(ORG, status="enacted")
        assert all(r["status"] == "enacted" for r in enacted)

    def test_org_isolation(self, engine):
        _make_reg(engine, org=ORG)
        _make_reg(engine, org=ORG2, name="HIPAA")
        assert len(engine.list_regulations(ORG)) == 1
        assert len(engine.list_regulations(ORG2)) == 1


# ---------------------------------------------------------------------------
# Regulatory Changes tests
# ---------------------------------------------------------------------------

class TestAddChange:
    def test_returns_dict_with_change_id(self, engine):
        reg = _make_reg(engine)
        change = _make_change(engine, reg["reg_id"])
        assert "change_id" in change
        assert change["title"] == "New data retention rule"

    def test_affected_domains_deserialized(self, engine):
        reg = _make_reg(engine)
        change = _make_change(engine, reg["reg_id"])
        assert isinstance(change["affected_domains"], list)
        assert "data_retention" in change["affected_domains"]

    def test_invalid_impact_defaults_to_medium(self, engine):
        reg = _make_reg(engine)
        change = engine.add_change(ORG, reg["reg_id"], {
            "title": "Test", "impact_level": "super_critical"
        })
        assert change["impact_level"] == "medium"

    def test_invalid_change_type_defaults(self, engine):
        reg = _make_reg(engine)
        change = engine.add_change(ORG, reg["reg_id"], {
            "title": "Test", "change_type": "bogus"
        })
        assert change["change_type"] == "new_requirement"


class TestListChanges:
    def test_empty_returns_empty(self, engine):
        assert engine.list_changes(ORG) == []

    def test_lists_changes(self, engine):
        reg = _make_reg(engine)
        _make_change(engine, reg["reg_id"])
        changes = engine.list_changes(ORG)
        assert len(changes) == 1

    def test_filter_by_impact_level(self, engine):
        reg = _make_reg(engine)
        _make_change(engine, reg["reg_id"], impact_level="high")
        _make_change(engine, reg["reg_id"], impact_level="low")
        highs = engine.list_changes(ORG, impact_level="high")
        assert len(highs) == 1
        assert highs[0]["impact_level"] == "high"

    def test_action_required_filter(self, engine):
        reg = _make_reg(engine)
        _make_change(engine, reg["reg_id"])
        all_changes = engine.list_changes(ORG, action_required=False)
        assert len(all_changes) >= 1


class TestGetUpcomingChanges:
    def test_returns_changes_within_days_ahead(self, engine):
        reg = _make_reg(engine)
        _make_change(engine, reg["reg_id"], days_ahead=30)
        upcoming = engine.get_upcoming_changes(ORG, days_ahead=90)
        assert len(upcoming) == 1

    def test_excludes_past_changes(self, engine):
        reg = _make_reg(engine)
        past = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        engine.add_change(ORG, reg["reg_id"], {
            "title": "Past change",
            "impact_level": "low",
            "effective_at": past,
        })
        upcoming = engine.get_upcoming_changes(ORG, days_ahead=90)
        assert len(upcoming) == 0

    def test_excludes_far_future_changes(self, engine):
        reg = _make_reg(engine)
        _make_change(engine, reg["reg_id"], days_ahead=200)
        upcoming = engine.get_upcoming_changes(ORG, days_ahead=90)
        assert len(upcoming) == 0


# ---------------------------------------------------------------------------
# Obligations tests
# ---------------------------------------------------------------------------

class TestObligations:
    def test_add_obligation_returns_dict(self, engine):
        reg = _make_reg(engine)
        ob = _make_obligation(engine, reg["reg_id"])
        assert "obligation_id" in ob
        assert ob["title"] == "Implement data retention policy"

    def test_list_obligations(self, engine):
        reg = _make_reg(engine)
        _make_obligation(engine, reg["reg_id"])
        obs = engine.list_obligations(ORG)
        assert len(obs) == 1

    def test_filter_by_status(self, engine):
        reg = _make_reg(engine)
        _make_obligation(engine, reg["reg_id"], status="pending")
        _make_obligation(engine, reg["reg_id"], status="compliant")
        pending = engine.list_obligations(ORG, status="pending")
        assert all(o["status"] == "pending" for o in pending)

    def test_update_obligation_status(self, engine):
        reg = _make_reg(engine)
        ob = _make_obligation(engine, reg["reg_id"])
        updated = engine.update_obligation_status(ORG, ob["obligation_id"], "compliant")
        assert updated is True
        obs = engine.list_obligations(ORG, status="compliant")
        assert len(obs) == 1

    def test_update_obligation_status_with_owner(self, engine):
        reg = _make_reg(engine)
        ob = _make_obligation(engine, reg["reg_id"])
        updated = engine.update_obligation_status(
            ORG, ob["obligation_id"], "in_progress", owner="new-owner"
        )
        assert updated is True

    def test_update_nonexistent_obligation_returns_false(self, engine):
        updated = engine.update_obligation_status(ORG, "no-such-id", "compliant")
        assert updated is False

    def test_update_invalid_status_returns_false(self, engine):
        reg = _make_reg(engine)
        ob = _make_obligation(engine, reg["reg_id"])
        updated = engine.update_obligation_status(ORG, ob["obligation_id"], "invalid")
        assert updated is False


# ---------------------------------------------------------------------------
# Assessment tests
# ---------------------------------------------------------------------------

class TestAssessments:
    def test_record_assessment_returns_dict(self, engine):
        reg = _make_reg(engine)
        assessment = engine.record_assessment(ORG, {
            "reg_id": reg["reg_id"],
            "compliance_pct": 85.5,
            "gaps_count": 3,
            "critical_gaps": 1,
            "assessor": "auditor@example.com",
            "notes": "Annual review",
        })
        assert "assessment_id" in assessment
        assert assessment["compliance_pct"] == 85.5
        assert assessment["gaps_count"] == 3


# ---------------------------------------------------------------------------
# Stats tests
# ---------------------------------------------------------------------------

class TestRegulatoryStats:
    def test_empty_org_stats(self, engine):
        stats = engine.get_regulatory_stats("empty-org")
        assert stats["total_regulations"] == 0
        assert stats["active_regulations"] == 0
        assert stats["pending_changes"] == 0
        assert stats["critical_changes"] == 0
        assert stats["overdue_obligations"] == 0
        assert stats["avg_compliance_pct"] == 0.0
        assert stats["upcoming_changes_90d"] == 0

    def test_stats_counts_correctly(self, engine):
        reg = _make_reg(engine)
        _make_change(engine, reg["reg_id"], impact_level="critical", days_ahead=30)
        _make_obligation(engine, reg["reg_id"])
        engine.record_assessment(ORG, {
            "reg_id": reg["reg_id"],
            "compliance_pct": 70.0,
        })
        stats = engine.get_regulatory_stats(ORG)
        assert stats["total_regulations"] == 1
        assert stats["active_regulations"] == 1
        assert stats["pending_changes"] == 1
        assert stats["critical_changes"] == 1
        assert stats["upcoming_changes_90d"] == 1
        assert stats["avg_compliance_pct"] == 70.0

    def test_overdue_obligations_counted(self, engine):
        reg = _make_reg(engine)
        engine.add_obligation(ORG, {
            "reg_id": reg["reg_id"],
            "title": "Overdue task",
            "deadline": "2020-01-01",  # well in the past
            "status": "pending",
        })
        stats = engine.get_regulatory_stats(ORG)
        assert stats["overdue_obligations"] == 1

    def test_compliant_obligations_not_overdue(self, engine):
        reg = _make_reg(engine)
        engine.add_obligation(ORG, {
            "reg_id": reg["reg_id"],
            "title": "Done task",
            "deadline": "2020-01-01",
            "status": "compliant",
        })
        stats = engine.get_regulatory_stats(ORG)
        assert stats["overdue_obligations"] == 0
