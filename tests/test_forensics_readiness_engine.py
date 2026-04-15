"""
Comprehensive tests for ForensicsReadinessEngine.

Covers:
- register_evidence_source: valid/invalid source_type and collection_method, defaults
- list_evidence_sources: filtering by source_type, org isolation
- assess_readiness: 5-check scoring (each check = 20 pts), level derivation
- create_collection_plan: valid/invalid priority, target_sources/steps stored
- execute_collection_plan: status=executing, executed_by, started_at
- complete_collection_plan: status=completed, items_collected, notes
- get_readiness_stats: ready/partial/not_ready counts, avg_coverage_score, overall_readiness_score
- Multi-tenant isolation throughout
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.forensics_readiness_engine import ForensicsReadinessEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "forensics_readiness.db")
    return ForensicsReadinessEngine(db_path=db)


ORG = "org-forensics-test"
ORG2 = "org-forensics-other"


def _source(overrides=None):
    base = {
        "name": "Test Source",
        "source_type": "endpoint_logs",
        "retention_days": 365,
        "collection_method": "api",
    }
    if overrides:
        base.update(overrides)
    return base


def _plan(overrides=None):
    base = {
        "name": "Test Plan",
        "incident_type": "ransomware",
        "priority": "high",
        "target_sources": [],
        "collection_steps": ["Step 1", "Step 2"],
    }
    if overrides:
        base.update(overrides)
    return base


def _full_assessment():
    return {
        "encryption": True,
        "integrity_check": True,
        "chain_of_custody": True,
        "offsite_backup": True,
        "access_logging": True,
    }


# ---------------------------------------------------------------------------
# register_evidence_source
# ---------------------------------------------------------------------------

class TestRegisterEvidenceSource:
    def test_returns_dict_with_id(self, engine):
        result = engine.register_evidence_source(ORG, _source())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_stores_name_and_source_type(self, engine):
        result = engine.register_evidence_source(ORG, _source({"name": "PCAP", "source_type": "network_pcap"}))
        assert result["name"] == "PCAP"
        assert result["source_type"] == "network_pcap"

    def test_default_retention_days(self, engine):
        data = {"name": "S", "source_type": "cloud_trail"}
        result = engine.register_evidence_source(ORG, data)
        assert result["retention_days"] == 365

    def test_default_collection_method_is_api(self, engine):
        data = {"name": "S", "source_type": "cloud_trail"}
        result = engine.register_evidence_source(ORG, data)
        assert result["collection_method"] == "api"

    def test_default_status_is_active(self, engine):
        result = engine.register_evidence_source(ORG, _source())
        assert result["status"] == "active"

    def test_coverage_score_starts_at_zero(self, engine):
        result = engine.register_evidence_source(ORG, _source())
        assert result["coverage_score"] == 0

    def test_readiness_level_starts_not_ready(self, engine):
        result = engine.register_evidence_source(ORG, _source())
        assert result["readiness_level"] == "not_ready"

    def test_all_valid_source_types(self, engine):
        types = [
            "endpoint_logs", "network_pcap", "cloud_trail", "email_archive",
            "database_audit", "identity_logs", "application_logs",
        ]
        for st in types:
            result = engine.register_evidence_source(ORG, _source({"source_type": st, "name": st}))
            assert result["source_type"] == st

    def test_all_valid_collection_methods(self, engine):
        for method in ("agent", "api", "syslog", "manual"):
            result = engine.register_evidence_source(ORG, _source({"collection_method": method, "name": method}))
            assert result["collection_method"] == method

    def test_invalid_source_type_raises(self, engine):
        with pytest.raises(ValueError, match="source_type"):
            engine.register_evidence_source(ORG, _source({"source_type": "invalid"}))

    def test_invalid_collection_method_raises(self, engine):
        with pytest.raises(ValueError, match="collection_method"):
            engine.register_evidence_source(ORG, _source({"collection_method": "ftp"}))

    def test_missing_name_raises(self, engine):
        with pytest.raises(ValueError, match="name"):
            engine.register_evidence_source(ORG, {"source_type": "endpoint_logs"})


# ---------------------------------------------------------------------------
# list_evidence_sources
# ---------------------------------------------------------------------------

class TestListEvidenceSources:
    def test_returns_created_sources(self, engine):
        engine.register_evidence_source(ORG, _source())
        sources = engine.list_evidence_sources(ORG)
        assert len(sources) >= 1

    def test_filter_by_source_type(self, engine):
        engine.register_evidence_source(ORG, _source({"source_type": "cloud_trail", "name": "C"}))
        engine.register_evidence_source(ORG, _source({"source_type": "email_archive", "name": "E"}))
        sources = engine.list_evidence_sources(ORG, source_type="cloud_trail")
        assert all(s["source_type"] == "cloud_trail" for s in sources)

    def test_org_isolation(self, engine):
        engine.register_evidence_source(ORG, _source({"name": "Org1 Source"}))
        sources2 = engine.list_evidence_sources(ORG2)
        assert all(s["org_id"] == ORG2 for s in sources2)


# ---------------------------------------------------------------------------
# assess_readiness
# ---------------------------------------------------------------------------

class TestAssessReadiness:
    def test_all_true_gives_score_100(self, engine):
        src = engine.register_evidence_source(ORG, _source())
        result = engine.assess_readiness(ORG, src["id"], _full_assessment())
        assert result["coverage_score"] == 100

    def test_all_false_gives_score_0(self, engine):
        src = engine.register_evidence_source(ORG, _source())
        result = engine.assess_readiness(ORG, src["id"], {
            "encryption": False, "integrity_check": False,
            "chain_of_custody": False, "offsite_backup": False, "access_logging": False,
        })
        assert result["coverage_score"] == 0

    def test_three_true_gives_score_60(self, engine):
        src = engine.register_evidence_source(ORG, _source())
        result = engine.assess_readiness(ORG, src["id"], {
            "encryption": True, "integrity_check": True,
            "chain_of_custody": True, "offsite_backup": False, "access_logging": False,
        })
        assert result["coverage_score"] == 60

    def test_score_100_gives_level_ready(self, engine):
        src = engine.register_evidence_source(ORG, _source())
        result = engine.assess_readiness(ORG, src["id"], _full_assessment())
        assert result["readiness_level"] == "ready"

    def test_score_80_gives_level_ready(self, engine):
        src = engine.register_evidence_source(ORG, _source())
        result = engine.assess_readiness(ORG, src["id"], {
            "encryption": True, "integrity_check": True,
            "chain_of_custody": True, "offsite_backup": True, "access_logging": False,
        })
        assert result["coverage_score"] == 80
        assert result["readiness_level"] == "ready"

    def test_score_60_gives_level_partial(self, engine):
        src = engine.register_evidence_source(ORG, _source())
        result = engine.assess_readiness(ORG, src["id"], {
            "encryption": True, "integrity_check": True,
            "chain_of_custody": True, "offsite_backup": False, "access_logging": False,
        })
        assert result["readiness_level"] == "partial"

    def test_score_40_gives_level_partial(self, engine):
        src = engine.register_evidence_source(ORG, _source())
        result = engine.assess_readiness(ORG, src["id"], {
            "encryption": True, "integrity_check": True,
            "chain_of_custody": False, "offsite_backup": False, "access_logging": False,
        })
        assert result["coverage_score"] == 40
        assert result["readiness_level"] == "partial"

    def test_score_0_gives_level_not_ready(self, engine):
        src = engine.register_evidence_source(ORG, _source())
        result = engine.assess_readiness(ORG, src["id"], {})
        assert result["readiness_level"] == "not_ready"

    def test_sets_assessed_at(self, engine):
        src = engine.register_evidence_source(ORG, _source())
        result = engine.assess_readiness(ORG, src["id"], _full_assessment())
        assert result["assessed_at"] is not None

    def test_invalid_source_id_raises(self, engine):
        with pytest.raises(ValueError):
            engine.assess_readiness(ORG, "nonexistent-id", _full_assessment())

    def test_org_isolation(self, engine):
        src = engine.register_evidence_source(ORG, _source())
        with pytest.raises(ValueError):
            engine.assess_readiness(ORG2, src["id"], _full_assessment())


# ---------------------------------------------------------------------------
# create_collection_plan
# ---------------------------------------------------------------------------

class TestCreateCollectionPlan:
    def test_returns_dict_with_id(self, engine):
        result = engine.create_collection_plan(ORG, _plan())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_status_defaults_to_draft(self, engine):
        result = engine.create_collection_plan(ORG, _plan())
        assert result["status"] == "draft"

    def test_stores_incident_type(self, engine):
        result = engine.create_collection_plan(ORG, _plan({"incident_type": "data_breach"}))
        assert result["incident_type"] == "data_breach"

    def test_stores_priority(self, engine):
        result = engine.create_collection_plan(ORG, _plan({"priority": "critical"}))
        assert result["priority"] == "critical"

    def test_stores_target_sources_as_list(self, engine):
        src = engine.register_evidence_source(ORG, _source())
        result = engine.create_collection_plan(ORG, _plan({"target_sources": [src["id"]]}))
        assert isinstance(result["target_sources"], list)
        assert src["id"] in result["target_sources"]

    def test_stores_collection_steps_as_list(self, engine):
        result = engine.create_collection_plan(ORG, _plan({"collection_steps": ["A", "B", "C"]}))
        assert result["collection_steps"] == ["A", "B", "C"]

    def test_all_valid_priorities(self, engine):
        for p in ("low", "medium", "high", "critical"):
            result = engine.create_collection_plan(ORG, _plan({"priority": p, "name": p}))
            assert result["priority"] == p

    def test_invalid_priority_raises(self, engine):
        with pytest.raises(ValueError, match="priority"):
            engine.create_collection_plan(ORG, _plan({"priority": "urgent"}))

    def test_missing_name_raises(self, engine):
        with pytest.raises(ValueError, match="name"):
            engine.create_collection_plan(ORG, {"incident_type": "breach", "priority": "high"})

    def test_missing_incident_type_raises(self, engine):
        with pytest.raises(ValueError, match="incident_type"):
            engine.create_collection_plan(ORG, {"name": "Plan", "priority": "high"})


# ---------------------------------------------------------------------------
# execute_collection_plan
# ---------------------------------------------------------------------------

class TestExecuteCollectionPlan:
    def test_sets_status_executing(self, engine):
        plan = engine.create_collection_plan(ORG, _plan())
        result = engine.execute_collection_plan(ORG, plan["id"], "analyst-1")
        assert result["status"] == "executing"

    def test_sets_executed_by(self, engine):
        plan = engine.create_collection_plan(ORG, _plan())
        result = engine.execute_collection_plan(ORG, plan["id"], "responder-007")
        assert result["executed_by"] == "responder-007"

    def test_sets_started_at(self, engine):
        plan = engine.create_collection_plan(ORG, _plan())
        result = engine.execute_collection_plan(ORG, plan["id"], "analyst")
        assert result["started_at"] is not None

    def test_invalid_plan_id_raises(self, engine):
        with pytest.raises(ValueError):
            engine.execute_collection_plan(ORG, "nonexistent-id", "analyst")

    def test_org_isolation(self, engine):
        plan = engine.create_collection_plan(ORG, _plan())
        with pytest.raises(ValueError):
            engine.execute_collection_plan(ORG2, plan["id"], "analyst")


# ---------------------------------------------------------------------------
# complete_collection_plan
# ---------------------------------------------------------------------------

class TestCompleteCollectionPlan:
    def test_sets_status_completed(self, engine):
        plan = engine.create_collection_plan(ORG, _plan())
        engine.execute_collection_plan(ORG, plan["id"], "analyst")
        result = engine.complete_collection_plan(ORG, plan["id"], 42, "Done")
        assert result["status"] == "completed"

    def test_sets_items_collected(self, engine):
        plan = engine.create_collection_plan(ORG, _plan())
        result = engine.complete_collection_plan(ORG, plan["id"], 99, "")
        assert result["items_collected"] == 99

    def test_sets_notes(self, engine):
        plan = engine.create_collection_plan(ORG, _plan())
        result = engine.complete_collection_plan(ORG, plan["id"], 10, "All artifacts secured")
        assert result["notes"] == "All artifacts secured"

    def test_sets_completed_at(self, engine):
        plan = engine.create_collection_plan(ORG, _plan())
        result = engine.complete_collection_plan(ORG, plan["id"], 5, "")
        assert result["completed_at"] is not None

    def test_invalid_plan_id_raises(self, engine):
        with pytest.raises(ValueError):
            engine.complete_collection_plan(ORG, "nonexistent-id", 0, "")


# ---------------------------------------------------------------------------
# get_readiness_stats
# ---------------------------------------------------------------------------

class TestGetReadinessStats:
    def test_total_sources(self, engine):
        engine.register_evidence_source(ORG, _source({"name": "S1"}))
        engine.register_evidence_source(ORG, _source({"name": "S2"}))
        stats = engine.get_readiness_stats(ORG)
        assert stats["total_sources"] == 2

    def test_by_type_dict(self, engine):
        engine.register_evidence_source(ORG, _source({"source_type": "cloud_trail", "name": "C1"}))
        engine.register_evidence_source(ORG, _source({"source_type": "cloud_trail", "name": "C2"}))
        engine.register_evidence_source(ORG, _source({"source_type": "email_archive", "name": "E1"}))
        stats = engine.get_readiness_stats(ORG)
        assert stats["by_type"]["cloud_trail"] == 2
        assert stats["by_type"]["email_archive"] == 1

    def test_avg_coverage_score(self, engine):
        src1 = engine.register_evidence_source(ORG, _source({"name": "A"}))
        src2 = engine.register_evidence_source(ORG, _source({"name": "B"}))
        engine.assess_readiness(ORG, src1["id"], _full_assessment())  # 100
        engine.assess_readiness(ORG, src2["id"], {
            "encryption": False, "integrity_check": False,
            "chain_of_custody": False, "offsite_backup": False, "access_logging": False,
        })  # 0
        stats = engine.get_readiness_stats(ORG)
        assert abs(stats["avg_coverage_score"] - 50.0) < 1.0

    def test_ready_sources_count(self, engine):
        src = engine.register_evidence_source(ORG, _source({"name": "R"}))
        engine.assess_readiness(ORG, src["id"], _full_assessment())  # score=100 → ready
        stats = engine.get_readiness_stats(ORG)
        assert stats["ready_sources"] >= 1

    def test_partial_sources_count(self, engine):
        src = engine.register_evidence_source(ORG, _source({"name": "P"}))
        engine.assess_readiness(ORG, src["id"], {
            "encryption": True, "integrity_check": True,
            "chain_of_custody": True, "offsite_backup": False, "access_logging": False,
        })  # score=60 → partial
        stats = engine.get_readiness_stats(ORG)
        assert stats["partial_sources"] >= 1

    def test_not_ready_sources_count(self, engine):
        engine.register_evidence_source(ORG, _source({"name": "NR"}))
        # Not assessed = score 0 → not_ready
        stats = engine.get_readiness_stats(ORG)
        assert stats["not_ready_sources"] >= 1

    def test_overall_readiness_score_is_rounded_avg(self, engine):
        src1 = engine.register_evidence_source(ORG, _source({"name": "X"}))
        src2 = engine.register_evidence_source(ORG, _source({"name": "Y"}))
        engine.assess_readiness(ORG, src1["id"], _full_assessment())  # 100
        engine.assess_readiness(ORG, src2["id"], _full_assessment())  # 100
        stats = engine.get_readiness_stats(ORG)
        assert stats["overall_readiness_score"] == 100

    def test_total_plans(self, engine):
        engine.create_collection_plan(ORG, _plan({"name": "P1"}))
        engine.create_collection_plan(ORG, _plan({"name": "P2"}))
        stats = engine.get_readiness_stats(ORG)
        assert stats["total_plans"] == 2

    def test_active_plans_count(self, engine):
        plan = engine.create_collection_plan(ORG, _plan())
        engine.execute_collection_plan(ORG, plan["id"], "analyst")
        stats = engine.get_readiness_stats(ORG)
        assert stats["active_plans"] >= 1

    def test_empty_org_stats(self, engine):
        stats = engine.get_readiness_stats("empty-org")
        assert stats["total_sources"] == 0
        assert stats["avg_coverage_score"] == 0.0
        assert stats["overall_readiness_score"] == 0
        assert stats["total_plans"] == 0

    def test_org_isolation(self, engine):
        engine.register_evidence_source(ORG, _source({"name": "O1"}))
        engine.register_evidence_source(ORG, _source({"name": "O2"}))
        engine.register_evidence_source(ORG2, _source({"name": "X1"}))
        stats1 = engine.get_readiness_stats(ORG)
        stats2 = engine.get_readiness_stats(ORG2)
        assert stats1["total_sources"] == 2
        assert stats2["total_sources"] == 1
