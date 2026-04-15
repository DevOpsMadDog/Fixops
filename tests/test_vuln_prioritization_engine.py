"""Tests for VulnerabilityPrioritizationEngine — 30+ tests covering priority
formula correctness, batch scoring, SLA assignment, tier distribution, and stats.
"""
from __future__ import annotations

import pytest
from core.vuln_prioritization_engine import (
    VulnerabilityPrioritizationEngine,
    _compute_priority_score,
    _priority_tier,
)


@pytest.fixture
def engine(tmp_path):
    eng = VulnerabilityPrioritizationEngine.__new__(VulnerabilityPrioritizationEngine)
    eng.org_id = "org-test"
    import threading
    eng.db_path = str(tmp_path / "vuln_prio_test.db")
    eng._lock = threading.RLock()
    eng._init_db()
    return eng


@pytest.fixture
def org():
    return "org-test"


@pytest.fixture
def org2():
    return "org-test-beta"


def _vuln(cve_id="CVE-2024-0001", asset_id="asset-01", **kwargs):
    defaults = {
        "cve_id": cve_id,
        "asset_id": asset_id,
        "asset_criticality": "high",
        "cvss_score": 7.5,
        "epss_score": 0.3,
        "kev_listed": False,
        "exploitability": "poc_available",
        "exposure": "internal",
    }
    defaults.update(kwargs)
    return defaults


# ---------------------------------------------------------------------------
# Formula unit tests (_compute_priority_score, _priority_tier)
# ---------------------------------------------------------------------------

class TestPriorityFormula:
    def test_max_score_capped_at_1(self):
        score = _compute_priority_score(10.0, 1.0, True, 1.0, 1.0, 1.0)
        assert score <= 1.0

    def test_zero_inputs_gives_low_score(self):
        score = _compute_priority_score(0.0, 0.0, False, 0.0, 0.0, 0.0)
        assert score == 0.0

    def test_kev_bonus_increases_score(self):
        without_kev = _compute_priority_score(7.0, 0.2, False, 0.6, 0.5, 0.7)
        with_kev = _compute_priority_score(7.0, 0.2, True, 0.6, 0.5, 0.7)
        assert with_kev > without_kev

    def test_asset_criticality_amplifies_score(self):
        low = _compute_priority_score(7.0, 0.3, False, 0.6, 0.5, 0.2)
        high = _compute_priority_score(7.0, 0.3, False, 0.6, 0.5, 1.0)
        assert high > low

    def test_priority_tier_immediate(self):
        assert _priority_tier(0.75) == "immediate"
        assert _priority_tier(1.0) == "immediate"

    def test_priority_tier_urgent(self):
        assert _priority_tier(0.5) == "urgent"
        assert _priority_tier(0.74) == "urgent"

    def test_priority_tier_planned(self):
        assert _priority_tier(0.25) == "planned"
        assert _priority_tier(0.49) == "planned"

    def test_priority_tier_backlog(self):
        assert _priority_tier(0.0) == "backlog"
        assert _priority_tier(0.24) == "backlog"


# ---------------------------------------------------------------------------
# score_vulnerability
# ---------------------------------------------------------------------------

class TestScoreVulnerability:
    def test_score_returns_record(self, engine, org):
        result = engine.score_vulnerability(org, _vuln())
        assert result["id"] is not None
        assert result["cve_id"] == "CVE-2024-0001"
        assert result["org_id"] == org
        assert 0.0 <= result["priority_score"] <= 1.0
        assert result["priority_tier"] in ("immediate", "urgent", "planned", "backlog")
        assert result["risk_explanation"]

    def test_score_kev_explanation_mentions_kev(self, engine, org):
        result = engine.score_vulnerability(org, _vuln(kev_listed=True))
        assert "KEV" in result["risk_explanation"]

    def test_score_non_kev_explanation_mentions_epss(self, engine, org):
        result = engine.score_vulnerability(org, _vuln(kev_listed=False, epss_score=0.45))
        assert "EPSS" in result["risk_explanation"]

    def test_score_invalid_asset_criticality_raises(self, engine, org):
        with pytest.raises(ValueError, match="asset_criticality"):
            engine.score_vulnerability(org, _vuln(asset_criticality="ultra"))

    def test_score_invalid_exploitability_raises(self, engine, org):
        with pytest.raises(ValueError, match="exploitability"):
            engine.score_vulnerability(org, _vuln(exploitability="unknown"))

    def test_score_invalid_exposure_raises(self, engine, org):
        with pytest.raises(ValueError, match="exposure"):
            engine.score_vulnerability(org, _vuln(exposure="cloud"))

    def test_score_high_cvss_kev_internet_facing_is_immediate(self, engine, org):
        result = engine.score_vulnerability(org, _vuln(
            cvss_score=9.8,
            epss_score=0.9,
            kev_listed=True,
            asset_criticality="critical",
            exploitability="weaponized",
            exposure="internet_facing",
        ))
        assert result["priority_tier"] == "immediate"
        assert result["priority_score"] >= 0.75

    def test_score_low_cvss_isolated_is_backlog(self, engine, org):
        result = engine.score_vulnerability(org, _vuln(
            cvss_score=1.0,
            epss_score=0.01,
            kev_listed=False,
            asset_criticality="low",
            exploitability="theoretical",
            exposure="isolated",
        ))
        assert result["priority_tier"] == "backlog"

    def test_score_persisted_in_db(self, engine, org):
        engine.score_vulnerability(org, _vuln())
        scored = engine.list_scored(org)
        assert len(scored) == 1

    def test_score_org_isolation(self, engine, org, org2):
        # Use a second engine pointing at different db for org2
        import threading, tempfile, os
        eng2 = VulnerabilityPrioritizationEngine.__new__(VulnerabilityPrioritizationEngine)
        eng2.org_id = org2
        db2 = engine.db_path.replace("vuln_prio_test.db", "vuln_prio_test2.db")
        eng2.db_path = db2
        eng2._lock = threading.RLock()
        eng2._init_db()

        engine.score_vulnerability(org, _vuln(cve_id="CVE-A"))
        eng2.score_vulnerability(org2, _vuln(cve_id="CVE-B"))

        assert len(engine.list_scored(org)) == 1
        assert engine.list_scored(org)[0]["cve_id"] == "CVE-A"


# ---------------------------------------------------------------------------
# batch_score
# ---------------------------------------------------------------------------

class TestBatchScore:
    def test_batch_score_returns_summary(self, engine, org):
        vulns = [_vuln(cve_id=f"CVE-2024-{i:04d}", asset_id=f"asset-{i}") for i in range(5)]
        result = engine.batch_score(org, vulns)
        assert result["run_id"] is not None
        assert result["scored_count"] == 5
        assert isinstance(result["by_tier"], dict)
        assert sum(result["by_tier"].values()) == 5

    def test_batch_score_creates_run_record(self, engine, org):
        vulns = [_vuln(cve_id=f"CVE-B-{i}") for i in range(3)]
        result = engine.batch_score(org, vulns)
        run = engine.get_run(org, result["run_id"])
        assert run is not None
        assert run["total_vulns"] == 3
        assert run["status"] == "completed"

    def test_batch_score_empty_list(self, engine, org):
        result = engine.batch_score(org, [])
        assert result["scored_count"] == 0
        assert result["run_id"] is not None

    def test_batch_score_skips_invalid(self, engine, org):
        vulns = [
            _vuln(cve_id="CVE-VALID"),
            {"cve_id": "CVE-BAD", "asset_id": "x", "asset_criticality": "INVALID"},
        ]
        result = engine.batch_score(org, vulns)
        assert result["scored_count"] == 1  # only valid one scored

    def test_batch_score_tier_distribution(self, engine, org):
        # Force one immediate, one backlog
        vulns = [
            _vuln(cve_id="CVE-HIGH", cvss_score=9.8, epss_score=0.9, kev_listed=True,
                  asset_criticality="critical", exploitability="weaponized",
                  exposure="internet_facing"),
            _vuln(cve_id="CVE-LOW", cvss_score=1.0, epss_score=0.01, kev_listed=False,
                  asset_criticality="low", exploitability="theoretical", exposure="isolated"),
        ]
        result = engine.batch_score(org, vulns)
        assert result["by_tier"]["immediate"] >= 1
        assert result["by_tier"]["backlog"] >= 1


# ---------------------------------------------------------------------------
# list_scored / get_score
# ---------------------------------------------------------------------------

class TestListAndGetScored:
    def test_list_scored_empty(self, engine, org):
        assert engine.list_scored(org) == []

    def test_list_scored_filter_tier(self, engine, org):
        engine.score_vulnerability(org, _vuln(cve_id="CVE-IMM", cvss_score=9.8,
                                              epss_score=0.9, kev_listed=True,
                                              asset_criticality="critical",
                                              exploitability="weaponized",
                                              exposure="internet_facing"))
        engine.score_vulnerability(org, _vuln(cve_id="CVE-BCK", cvss_score=1.0,
                                              epss_score=0.01, kev_listed=False,
                                              asset_criticality="low",
                                              exploitability="theoretical",
                                              exposure="isolated"))
        immediate = engine.list_scored(org, priority_tier="immediate")
        assert all(v["priority_tier"] == "immediate" for v in immediate)

    def test_list_scored_kev_only(self, engine, org):
        engine.score_vulnerability(org, _vuln(cve_id="CVE-KEV", kev_listed=True))
        engine.score_vulnerability(org, _vuln(cve_id="CVE-NOKEV", kev_listed=False))
        kev = engine.list_scored(org, kev_only=True)
        assert len(kev) == 1
        assert kev[0]["cve_id"] == "CVE-KEV"

    def test_list_scored_limit(self, engine, org):
        for i in range(10):
            engine.score_vulnerability(org, _vuln(cve_id=f"CVE-{i}", asset_id=f"a-{i}"))
        result = engine.list_scored(org, limit=3)
        assert len(result) == 3

    def test_get_score_found(self, engine, org):
        rec = engine.score_vulnerability(org, _vuln())
        fetched = engine.get_score(org, rec["id"])
        assert fetched is not None
        assert fetched["id"] == rec["id"]

    def test_get_score_not_found(self, engine, org):
        assert engine.get_score(org, "nonexistent-id") is None

    def test_get_score_org_isolation(self, engine, org, org2):
        rec = engine.score_vulnerability(org, _vuln())
        # Different org cannot access org's vuln
        assert engine.get_score(org2, rec["id"]) is None


# ---------------------------------------------------------------------------
# SLA assignment
# ---------------------------------------------------------------------------

class TestSLAAssignment:
    def test_assign_sla_returns_record(self, engine, org):
        rec = engine.score_vulnerability(org, _vuln(cvss_score=9.8, kev_listed=True,
                                                    asset_criticality="critical",
                                                    exploitability="weaponized",
                                                    exposure="internet_facing",
                                                    epss_score=0.9))
        sla = engine.assign_sla(org, rec["id"], "soc-team")
        assert sla["id"] is not None
        assert sla["assigned_team"] == "soc-team"
        assert sla["vuln_score_id"] == rec["id"]
        assert sla["status"] == "pending"

    def test_assign_sla_immediate_tier_has_7_days(self, engine, org):
        rec = engine.score_vulnerability(org, _vuln(cvss_score=9.8, kev_listed=True,
                                                    asset_criticality="critical",
                                                    exploitability="weaponized",
                                                    exposure="internet_facing",
                                                    epss_score=0.9))
        assert rec["priority_tier"] == "immediate"
        sla = engine.assign_sla(org, rec["id"], "soc-team")
        assert sla["sla_days"] == 7

    def test_assign_sla_backlog_tier_has_180_days(self, engine, org):
        rec = engine.score_vulnerability(org, _vuln(cvss_score=1.0, epss_score=0.01,
                                                    kev_listed=False,
                                                    asset_criticality="low",
                                                    exploitability="theoretical",
                                                    exposure="isolated"))
        assert rec["priority_tier"] == "backlog"
        sla = engine.assign_sla(org, rec["id"], "patch-team")
        assert sla["sla_days"] == 180

    def test_assign_sla_not_found_raises(self, engine, org):
        with pytest.raises(ValueError, match="not found"):
            engine.assign_sla(org, "ghost-id", "team-x")

    def test_list_sla_assignments_empty(self, engine, org):
        assert engine.list_sla_assignments(org) == []

    def test_list_sla_assignments_filter_status(self, engine, org):
        rec = engine.score_vulnerability(org, _vuln())
        engine.assign_sla(org, rec["id"], "red-team")
        pending = engine.list_sla_assignments(org, status="pending")
        assert len(pending) == 1
        completed = engine.list_sla_assignments(org, status="completed")
        assert len(completed) == 0

    def test_list_sla_assignments_filter_team(self, engine, org):
        rec1 = engine.score_vulnerability(org, _vuln(cve_id="CVE-1", asset_id="a1"))
        rec2 = engine.score_vulnerability(org, _vuln(cve_id="CVE-2", asset_id="a2"))
        engine.assign_sla(org, rec1["id"], "team-alpha")
        engine.assign_sla(org, rec2["id"], "team-beta")
        alpha = engine.list_sla_assignments(org, team="team-alpha")
        assert len(alpha) == 1
        assert alpha[0]["assigned_team"] == "team-alpha"


# ---------------------------------------------------------------------------
# Runs
# ---------------------------------------------------------------------------

class TestRuns:
    def test_get_run_found(self, engine, org):
        vulns = [_vuln(cve_id=f"CVE-R-{i}", asset_id=f"a-{i}") for i in range(2)]
        result = engine.batch_score(org, vulns)
        run = engine.get_run(org, result["run_id"])
        assert run is not None
        assert run["total_vulns"] == 2

    def test_get_run_not_found(self, engine, org):
        assert engine.get_run(org, "ghost-run") is None

    def test_list_runs_empty(self, engine, org):
        assert engine.list_runs(org) == []

    def test_list_runs_multiple(self, engine, org):
        for _ in range(3):
            engine.batch_score(org, [_vuln()])
        runs = engine.list_runs(org)
        assert len(runs) == 3


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats_empty(self, engine, org):
        stats = engine.get_stats(org)
        assert stats["total_scored"] == 0
        assert stats["kev_count"] == 0
        assert stats["avg_priority_score"] == 0.0
        assert stats["sla_breached_count"] == 0
        assert stats["upcoming_due"] == []

    def test_stats_populated(self, engine, org):
        engine.score_vulnerability(org, _vuln(cve_id="CVE-1", kev_listed=True))
        engine.score_vulnerability(org, _vuln(cve_id="CVE-2", kev_listed=False))
        stats = engine.get_stats(org)
        assert stats["total_scored"] == 2
        assert stats["kev_count"] == 1
        assert stats["avg_priority_score"] > 0.0

    def test_stats_by_tier(self, engine, org):
        engine.score_vulnerability(org, _vuln(cve_id="CVE-H", cvss_score=9.8, kev_listed=True,
                                              asset_criticality="critical",
                                              exploitability="weaponized",
                                              exposure="internet_facing", epss_score=0.9))
        engine.score_vulnerability(org, _vuln(cve_id="CVE-L", cvss_score=1.0, kev_listed=False,
                                              asset_criticality="low",
                                              exploitability="theoretical",
                                              exposure="isolated", epss_score=0.01))
        stats = engine.get_stats(org)
        assert "immediate" in stats["by_tier"]
        assert "backlog" in stats["by_tier"]

    def test_stats_upcoming_due(self, engine, org):
        rec = engine.score_vulnerability(org, _vuln())
        engine.assign_sla(org, rec["id"], "sec-team")
        stats = engine.get_stats(org)
        assert len(stats["upcoming_due"]) == 1

    def test_stats_org_isolation(self, engine, org, org2):
        engine.score_vulnerability(org, _vuln(cve_id="CVE-ORG1"))
        # org2 has its own engine - check org stats show only org data
        stats = engine.get_stats(org)
        assert stats["total_scored"] == 1
        stats2 = engine.get_stats(org2)
        assert stats2["total_scored"] == 0
