"""Tests for SecurityProgramMaturityEngine.

Covers:
- register_domain: valid, invalid domain_type, clamping target_level, missing name
- assess_domain: level/score clamping, last_assessed set, org isolation, not found
- create_assessment: valid, missing name
- complete_assessment: AVG aggregation of current_level + score, domains_assessed COUNT
- list_assessments: org isolation
- add_improvement: valid, invalid priority, target_level clamping
- complete_improvement: status=completed, completed_at set, org isolation, not found
- get_roadmap: ordered by priority (critical→low) then effort_days ASC, excludes completed
- get_maturity_profile: gap computed, improvements attached per domain
- get_summary: avg_current_level, avg_score, domains_at_target, pending_improvements, by_domain_type
- Multi-tenant isolation throughout
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.security_program_maturity_engine import SecurityProgramMaturityEngine

ORG = "org-spm-test"
ORG2 = "org-spm-other"


@pytest.fixture
def engine(tmp_path):
    return SecurityProgramMaturityEngine(db_path=str(tmp_path / "spm.db"))


# ---------------------------------------------------------------------------
# register_domain
# ---------------------------------------------------------------------------

class TestRegisterDomain:
    def test_returns_dict_with_id(self, engine):
        d = engine.register_domain(ORG, "Policy Management", "governance")
        assert "id" in d and len(d["id"]) == 36

    def test_current_level_starts_at_1(self, engine):
        d = engine.register_domain(ORG, "Risk Framework", "risk")
        assert d["current_level"] == 1

    def test_score_starts_at_zero(self, engine):
        d = engine.register_domain(ORG, "IAM Governance", "access-control")
        assert d["score"] == 0.0

    def test_target_level_stored(self, engine):
        d = engine.register_domain(ORG, "Compliance Controls", "compliance", target_level=4)
        assert d["target_level"] == 4

    def test_target_level_clamped_min(self, engine):
        d = engine.register_domain(ORG, "Awareness", "security-awareness", target_level=0)
        assert d["target_level"] == 1

    def test_target_level_clamped_max(self, engine):
        d = engine.register_domain(ORG, "Threat Intel", "threat-intel", target_level=99)
        assert d["target_level"] == 5

    def test_invalid_domain_type_raises(self, engine):
        with pytest.raises(ValueError, match="domain_type"):
            engine.register_domain(ORG, "Test", "invalid-type")

    def test_empty_name_raises(self, engine):
        with pytest.raises(ValueError, match="domain_name"):
            engine.register_domain(ORG, "", "governance")

    def test_org_id_stored(self, engine):
        d = engine.register_domain(ORG, "Asset Mgmt", "asset-management")
        assert d["org_id"] == ORG

    def test_multiple_domains_same_org(self, engine):
        engine.register_domain(ORG, "Dom A", "governance")
        engine.register_domain(ORG, "Dom B", "risk")
        domains = engine.list_domains(ORG)
        assert len(domains) == 2


# ---------------------------------------------------------------------------
# assess_domain
# ---------------------------------------------------------------------------

class TestAssessDomain:
    def test_updates_current_level(self, engine):
        d = engine.register_domain(ORG, "Policy", "governance")
        updated = engine.assess_domain(d["id"], ORG, current_level=3, score=70.0)
        assert updated["current_level"] == 3

    def test_updates_score(self, engine):
        d = engine.register_domain(ORG, "Risk", "risk")
        updated = engine.assess_domain(d["id"], ORG, current_level=2, score=55.5)
        assert updated["score"] == 55.5

    def test_level_clamped_min(self, engine):
        d = engine.register_domain(ORG, "IAM", "access-control")
        updated = engine.assess_domain(d["id"], ORG, current_level=0, score=10.0)
        assert updated["current_level"] == 1

    def test_level_clamped_max(self, engine):
        d = engine.register_domain(ORG, "Vuln", "vulnerability-management")
        updated = engine.assess_domain(d["id"], ORG, current_level=99, score=90.0)
        assert updated["current_level"] == 5

    def test_score_clamped_min(self, engine):
        d = engine.register_domain(ORG, "Awareness", "security-awareness")
        updated = engine.assess_domain(d["id"], ORG, current_level=1, score=-10.0)
        assert updated["score"] == 0.0

    def test_score_clamped_max(self, engine):
        d = engine.register_domain(ORG, "Compliance", "compliance")
        updated = engine.assess_domain(d["id"], ORG, current_level=5, score=200.0)
        assert updated["score"] == 100.0

    def test_last_assessed_set(self, engine):
        d = engine.register_domain(ORG, "Third Party", "third-party")
        updated = engine.assess_domain(d["id"], ORG, current_level=2, score=40.0)
        assert updated["last_assessed"] != ""

    def test_evidence_stored(self, engine):
        d = engine.register_domain(ORG, "IR", "incident-response")
        updated = engine.assess_domain(d["id"], ORG, current_level=3, score=60.0, evidence="policy docs")
        assert updated["evidence"] == "policy docs"

    def test_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.assess_domain("nonexistent", ORG, current_level=3, score=50.0)

    def test_org_isolation(self, engine):
        d = engine.register_domain(ORG, "Domain X", "governance")
        with pytest.raises(KeyError):
            engine.assess_domain(d["id"], ORG2, current_level=3, score=50.0)


# ---------------------------------------------------------------------------
# create_assessment + complete_assessment
# ---------------------------------------------------------------------------

class TestAssessments:
    def test_create_returns_in_progress(self, engine):
        a = engine.create_assessment(ORG, "Q1 Assessment", "alice")
        assert a["status"] == "in_progress"
        assert a["overall_level"] == 0.0

    def test_create_missing_name_raises(self, engine):
        with pytest.raises(ValueError, match="assessment_name"):
            engine.create_assessment(ORG, "", "alice")

    def test_complete_aggregates_avg_level(self, engine):
        d1 = engine.register_domain(ORG, "D1", "governance")
        d2 = engine.register_domain(ORG, "D2", "risk")
        engine.assess_domain(d1["id"], ORG, current_level=2, score=40.0)
        engine.assess_domain(d2["id"], ORG, current_level=4, score=80.0)
        a = engine.create_assessment(ORG, "Full Review")
        completed = engine.complete_assessment(a["id"], ORG)
        assert completed["status"] == "completed"
        # AVG(2,4) = 3.0
        assert completed["overall_level"] == pytest.approx(3.0, abs=0.01)

    def test_complete_aggregates_avg_score(self, engine):
        d1 = engine.register_domain(ORG, "D1", "compliance")
        d2 = engine.register_domain(ORG, "D2", "access-control")
        engine.assess_domain(d1["id"], ORG, current_level=3, score=60.0)
        engine.assess_domain(d2["id"], ORG, current_level=3, score=80.0)
        a = engine.create_assessment(ORG, "Score Review")
        completed = engine.complete_assessment(a["id"], ORG)
        assert completed["overall_score"] == pytest.approx(70.0, abs=0.01)

    def test_complete_counts_domains(self, engine):
        for i in range(3):
            d = engine.register_domain(ORG, f"Domain {i}", "governance")
            engine.assess_domain(d["id"], ORG, current_level=2, score=50.0)
        a = engine.create_assessment(ORG, "Count Test")
        completed = engine.complete_assessment(a["id"], ORG)
        assert completed["domains_assessed"] == 3

    def test_complete_sets_completed_at(self, engine):
        a = engine.create_assessment(ORG, "Timing Test")
        completed = engine.complete_assessment(a["id"], ORG)
        assert completed["completed_at"] != ""

    def test_complete_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.complete_assessment("nonexistent", ORG)

    def test_complete_org_isolation(self, engine):
        a = engine.create_assessment(ORG, "Org Isolation Test")
        with pytest.raises(KeyError):
            engine.complete_assessment(a["id"], ORG2)

    def test_list_assessments_org_isolation(self, engine):
        engine.create_assessment(ORG, "Org A Assessment")
        engine.create_assessment(ORG2, "Org B Assessment")
        results_a = engine.list_assessments(ORG)
        results_b = engine.list_assessments(ORG2)
        assert len(results_a) == 1
        assert len(results_b) == 1
        assert results_a[0]["assessment_name"] == "Org A Assessment"


# ---------------------------------------------------------------------------
# add_improvement + complete_improvement
# ---------------------------------------------------------------------------

class TestImprovements:
    def test_add_returns_planned(self, engine):
        d = engine.register_domain(ORG, "Governance", "governance")
        imp = engine.add_improvement(d["id"], ORG, "Implement policy framework", priority="high")
        assert imp["status"] == "planned"

    def test_invalid_priority_raises(self, engine):
        d = engine.register_domain(ORG, "Risk", "risk")
        with pytest.raises(ValueError, match="priority"):
            engine.add_improvement(d["id"], ORG, "Test", priority="urgent")

    def test_target_level_clamped(self, engine):
        d = engine.register_domain(ORG, "Compliance", "compliance")
        imp = engine.add_improvement(d["id"], ORG, "Uplift", priority="medium", target_level=10)
        assert imp["target_level"] == 5

    def test_effort_days_stored(self, engine):
        d = engine.register_domain(ORG, "IAM", "access-control")
        imp = engine.add_improvement(d["id"], ORG, "MFA rollout", effort_days=30)
        assert imp["effort_days"] == 30

    def test_complete_improvement_sets_status(self, engine):
        d = engine.register_domain(ORG, "Awareness", "security-awareness")
        imp = engine.add_improvement(d["id"], ORG, "Training program")
        completed = engine.complete_improvement(imp["id"], ORG)
        assert completed["status"] == "completed"
        assert completed["completed_at"] != ""

    def test_complete_improvement_not_found(self, engine):
        with pytest.raises(KeyError):
            engine.complete_improvement("nonexistent", ORG)

    def test_complete_improvement_org_isolation(self, engine):
        d = engine.register_domain(ORG, "IR", "incident-response")
        imp = engine.add_improvement(d["id"], ORG, "Playbooks")
        with pytest.raises(KeyError):
            engine.complete_improvement(imp["id"], ORG2)


# ---------------------------------------------------------------------------
# get_roadmap
# ---------------------------------------------------------------------------

class TestGetRoadmap:
    def test_roadmap_excludes_completed(self, engine):
        d = engine.register_domain(ORG, "Gov", "governance")
        imp1 = engine.add_improvement(d["id"], ORG, "Active", priority="high", effort_days=10)
        imp2 = engine.add_improvement(d["id"], ORG, "Done", priority="low", effort_days=5)
        engine.complete_improvement(imp2["id"], ORG)
        roadmap = engine.get_roadmap(ORG)
        ids = [r["id"] for r in roadmap]
        assert imp1["id"] in ids
        assert imp2["id"] not in ids

    def test_roadmap_priority_ordering(self, engine):
        d = engine.register_domain(ORG, "Risk", "risk")
        low = engine.add_improvement(d["id"], ORG, "Low task", priority="low", effort_days=5)
        critical = engine.add_improvement(d["id"], ORG, "Critical task", priority="critical", effort_days=20)
        high = engine.add_improvement(d["id"], ORG, "High task", priority="high", effort_days=10)
        medium = engine.add_improvement(d["id"], ORG, "Medium task", priority="medium", effort_days=15)
        roadmap = engine.get_roadmap(ORG)
        priorities = [r["priority"] for r in roadmap]
        assert priorities[0] == "critical"
        assert priorities[-1] == "low"

    def test_roadmap_effort_days_secondary_sort(self, engine):
        d = engine.register_domain(ORG, "Compliance", "compliance")
        imp_high = engine.add_improvement(d["id"], ORG, "High 10d", priority="high", effort_days=10)
        imp_high2 = engine.add_improvement(d["id"], ORG, "High 5d", priority="high", effort_days=5)
        roadmap = engine.get_roadmap(ORG)
        high_items = [r for r in roadmap if r["priority"] == "high"]
        assert high_items[0]["effort_days"] == 5

    def test_roadmap_org_isolation(self, engine):
        d1 = engine.register_domain(ORG, "D1", "governance")
        d2 = engine.register_domain(ORG2, "D2", "risk")
        engine.add_improvement(d1["id"], ORG, "Org1 task")
        engine.add_improvement(d2["id"], ORG2, "Org2 task")
        roadmap = engine.get_roadmap(ORG)
        assert all(r["org_id"] == ORG for r in roadmap)


# ---------------------------------------------------------------------------
# get_maturity_profile
# ---------------------------------------------------------------------------

class TestMaturityProfile:
    def test_gap_computed(self, engine):
        d = engine.register_domain(ORG, "Gov", "governance", target_level=4)
        engine.assess_domain(d["id"], ORG, current_level=2, score=40.0)
        profile = engine.get_maturity_profile(ORG)
        assert profile[0]["gap"] == 2  # target=4 - current=2

    def test_improvements_attached(self, engine):
        d = engine.register_domain(ORG, "IAM", "access-control")
        engine.add_improvement(d["id"], ORG, "MFA rollout")
        engine.add_improvement(d["id"], ORG, "PAM implementation")
        profile = engine.get_maturity_profile(ORG)
        assert len(profile[0]["improvements"]) == 2

    def test_org_isolation(self, engine):
        engine.register_domain(ORG, "D1", "governance")
        engine.register_domain(ORG2, "D2", "risk")
        profile = engine.get_maturity_profile(ORG)
        assert len(profile) == 1


# ---------------------------------------------------------------------------
# get_summary
# ---------------------------------------------------------------------------

class TestGetSummary:
    def test_empty_org_returns_zeros(self, engine):
        summary = engine.get_summary("org-empty")
        assert summary["total_domains"] == 0
        assert summary["avg_current_level"] == 0.0

    def test_avg_current_level(self, engine):
        d1 = engine.register_domain(ORG, "D1", "governance")
        d2 = engine.register_domain(ORG, "D2", "risk")
        engine.assess_domain(d1["id"], ORG, current_level=2, score=40.0)
        engine.assess_domain(d2["id"], ORG, current_level=4, score=80.0)
        summary = engine.get_summary(ORG)
        assert summary["avg_current_level"] == pytest.approx(3.0, abs=0.01)

    def test_domains_at_target(self, engine):
        d1 = engine.register_domain(ORG, "D1", "compliance", target_level=3)
        d2 = engine.register_domain(ORG, "D2", "risk", target_level=3)
        engine.assess_domain(d1["id"], ORG, current_level=3, score=70.0)
        engine.assess_domain(d2["id"], ORG, current_level=2, score=50.0)
        summary = engine.get_summary(ORG)
        assert summary["domains_at_target"] == 1

    def test_pending_improvements(self, engine):
        d = engine.register_domain(ORG, "IAM", "access-control")
        imp1 = engine.add_improvement(d["id"], ORG, "Task 1")
        imp2 = engine.add_improvement(d["id"], ORG, "Task 2")
        engine.complete_improvement(imp1["id"], ORG)
        summary = engine.get_summary(ORG)
        assert summary["pending_improvements"] == 1

    def test_by_domain_type(self, engine):
        engine.register_domain(ORG, "Gov 1", "governance")
        engine.register_domain(ORG, "Gov 2", "governance")
        engine.register_domain(ORG, "Risk 1", "risk")
        summary = engine.get_summary(ORG)
        assert summary["by_domain_type"]["governance"] == 2
        assert summary["by_domain_type"]["risk"] == 1

    def test_total_domains(self, engine):
        for i in range(4):
            engine.register_domain(ORG, f"D{i}", "compliance")
        summary = engine.get_summary(ORG)
        assert summary["total_domains"] == 4
