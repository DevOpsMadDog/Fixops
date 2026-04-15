"""Tests for scripts/seed_demo_data.py — Demo Data Seeder.

Verifies that every seed function runs without errors, returns the expected
keys, and writes data with the correct org_id.

All tests that assert exact counts use reset=True so they are idempotent
across repeated pytest runs (the shared .fixops_data/ SQLite databases
persist on disk between runs).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup — mirror what the seeder does
# ---------------------------------------------------------------------------

REPO_ROOT  = Path(__file__).resolve().parents[1]
SUITE_CORE = REPO_ROOT / "suite-core"
SCRIPTS    = REPO_ROOT / "scripts"

if str(SUITE_CORE) not in sys.path:
    sys.path.insert(0, str(SUITE_CORE))
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

# Import the seeder module by path (avoids naming conflicts with other seed scripts)
_SEEDER_PATH = SCRIPTS / "seed_demo_data.py"
_spec = importlib.util.spec_from_file_location("seed_demo_data", _SEEDER_PATH)
_mod  = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

seed_posture         = _mod.seed_posture
seed_threat_feeds    = _mod.seed_threat_feeds
seed_forensics       = _mod.seed_forensics
seed_roadmap         = _mod.seed_roadmap
seed_data_governance = _mod.seed_data_governance
seed_compliance      = _mod.seed_compliance
seed_asset_risk      = _mod.seed_asset_risk
seed_health          = _mod.seed_health
seed_timelines       = _mod.seed_timelines
seed_vuln_trends     = _mod.seed_vuln_trends
ORG_ID               = _mod.ORG_ID

# Each test class gets its own org prefix so DB rows are isolated.
# Tests always use reset=True when asserting exact counts so re-runs are safe.
_P = "t-dseeder"   # short prefix keeps org IDs within any length limits


# ---------------------------------------------------------------------------
# 1. Module-level smoke: seeder is importable
# ---------------------------------------------------------------------------

class TestModuleImport:
    def test_module_importable(self):
        assert _mod is not None

    def test_org_id_default(self):
        assert ORG_ID == "aldeci-demo"

    def test_all_seed_functions_callable(self):
        fns = [seed_posture, seed_threat_feeds, seed_forensics, seed_roadmap,
               seed_data_governance, seed_compliance, seed_asset_risk,
               seed_health, seed_timelines, seed_vuln_trends]
        for fn in fns:
            assert callable(fn), f"{fn} is not callable"

    def test_helper_ts_returns_iso_string(self):
        ts = _mod._ts()
        assert isinstance(ts, str)
        assert "T" in ts

    def test_helper_date_returns_yyyy_mm_dd(self):
        d = _mod._date()
        assert isinstance(d, str)
        assert len(d) == 10  # YYYY-MM-DD


# ---------------------------------------------------------------------------
# 2. PostureScoreEngine seeder
# ---------------------------------------------------------------------------

class TestSeedPosture:
    ORG = f"{_P}-posture"

    def test_returns_dict_with_required_keys(self):
        result = seed_posture(self.ORG, reset=True)
        assert isinstance(result, dict)
        for key in ("current_score", "grade", "history_snapshots"):
            assert key in result

    def test_score_is_positive(self):
        result = seed_posture(self.ORG, reset=True)
        assert result["current_score"] > 0

    def test_history_snapshots_count(self):
        result = seed_posture(self.ORG, reset=True)
        assert result["history_snapshots"] == 12

    def test_reset_then_reseed_is_idempotent(self):
        seed_posture(self.ORG, reset=False)
        result = seed_posture(self.ORG, reset=True)
        assert result["current_score"] > 0


# ---------------------------------------------------------------------------
# 3. ThreatFeedAggregator seeder
# ---------------------------------------------------------------------------

class TestSeedThreatFeeds:
    ORG = f"{_P}-feeds"

    def test_returns_dict_with_required_keys(self):
        result = seed_threat_feeds(self.ORG, reset=True)
        assert isinstance(result, dict)
        for key in ("sources", "items"):
            assert key in result

    def test_source_count(self):
        result = seed_threat_feeds(self.ORG, reset=True)
        assert result["sources"] == 8

    def test_item_count(self):
        result = seed_threat_feeds(self.ORG, reset=True)
        assert result["items"] == 20

    def test_reset_clears_then_reseeds(self):
        # Seed twice without reset to accumulate
        seed_threat_feeds(self.ORG, reset=False)
        seed_threat_feeds(self.ORG, reset=False)
        # reset=True must restore to exactly 8 sources
        result = seed_threat_feeds(self.ORG, reset=True)
        assert result["sources"] == 8


# ---------------------------------------------------------------------------
# 4. DigitalForensicsEngine seeder
# ---------------------------------------------------------------------------

class TestSeedForensics:
    ORG = f"{_P}-forensics"

    def test_returns_dict_with_required_keys(self):
        result = seed_forensics(self.ORG, reset=True)
        assert isinstance(result, dict)
        for key in ("cases", "evidence_items", "analyses", "open_cases"):
            assert key in result

    def test_case_count(self):
        result = seed_forensics(self.ORG, reset=True)
        assert result["cases"] == 5

    def test_evidence_count(self):
        result = seed_forensics(self.ORG, reset=True)
        # 4 + 3 + 4 + 3 + 3 = 17 evidence items
        assert result["evidence_items"] == 17

    def test_analyses_count(self):
        result = seed_forensics(self.ORG, reset=True)
        # 1 + 1 + 2 + 1 + 1 = 6 analysis results
        assert result["analyses"] == 6

    def test_open_cases_positive(self):
        result = seed_forensics(self.ORG, reset=True)
        assert result["open_cases"] > 0


# ---------------------------------------------------------------------------
# 5. SecurityRoadmapEngine seeder
# ---------------------------------------------------------------------------

class TestSeedRoadmap:
    ORG = f"{_P}-roadmap"

    def test_returns_dict_with_required_keys(self):
        result = seed_roadmap(self.ORG, reset=True)
        assert isinstance(result, dict)
        for key in ("initiatives", "milestones", "gaps", "total_budget"):
            assert key in result

    def test_initiative_count(self):
        result = seed_roadmap(self.ORG, reset=True)
        assert result["initiatives"] == 8

    def test_gap_count(self):
        result = seed_roadmap(self.ORG, reset=True)
        assert result["gaps"] == 4

    def test_total_budget_positive(self):
        result = seed_roadmap(self.ORG, reset=True)
        assert result["total_budget"] > 0

    def test_milestones_created(self):
        result = seed_roadmap(self.ORG, reset=True)
        # 5+4+3+4+4+3+3+3 = 29 milestones
        assert result["milestones"] == 29


# ---------------------------------------------------------------------------
# 6. DataGovernanceEngine seeder
# ---------------------------------------------------------------------------

class TestSeedDataGovernance:
    ORG = f"{_P}-dg"

    def test_returns_dict_with_required_keys(self):
        result = seed_data_governance(self.ORG, reset=True)
        assert isinstance(result, dict)
        for key in ("assets", "policies", "open_violations"):
            assert key in result

    def test_asset_count(self):
        result = seed_data_governance(self.ORG, reset=True)
        assert result["assets"] == 12

    def test_policy_count(self):
        result = seed_data_governance(self.ORG, reset=True)
        assert result["policies"] == 6

    def test_open_violations_count(self):
        result = seed_data_governance(self.ORG, reset=True)
        assert result["open_violations"] == 3


# ---------------------------------------------------------------------------
# 7. ComplianceScannerEngine seeder
# ---------------------------------------------------------------------------

class TestSeedCompliance:
    ORG = f"{_P}-comp"

    def test_returns_dict_with_required_keys(self):
        result = seed_compliance(self.ORG, reset=True)
        assert isinstance(result, dict)
        for key in ("profiles", "scans_run", "avg_score", "remediation_tasks"):
            assert key in result

    def test_profiles_count(self):
        result = seed_compliance(self.ORG, reset=True)
        assert result["profiles"] == 3

    def test_scans_run(self):
        result = seed_compliance(self.ORG, reset=True)
        assert result["scans_run"] == 3

    def test_avg_score_in_range(self):
        result = seed_compliance(self.ORG, reset=True)
        assert 0.0 <= result["avg_score"] <= 100.0

    def test_remediation_tasks_count(self):
        result = seed_compliance(self.ORG, reset=True)
        assert result["remediation_tasks"] == 8


# ---------------------------------------------------------------------------
# 8. AssetRiskCalculator seeder
# ---------------------------------------------------------------------------

class TestSeedAssetRisk:
    ORG = f"{_P}-risk"

    def test_returns_dict_with_required_keys(self):
        result = seed_asset_risk(self.ORG, reset=True)
        assert isinstance(result, dict)
        for key in ("assets", "by_risk_level", "avg_composite_score"):
            assert key in result

    def test_asset_count(self):
        result = seed_asset_risk(self.ORG, reset=True)
        assert result["assets"] == 15

    def test_avg_composite_score_positive(self):
        result = seed_asset_risk(self.ORG, reset=True)
        assert result["avg_composite_score"] > 0

    def test_by_risk_level_has_all_keys(self):
        result = seed_asset_risk(self.ORG, reset=True)
        levels = result["by_risk_level"]
        for level in ("critical", "high", "medium", "low", "minimal"):
            assert level in levels

    def test_has_critical_and_high_risk_assets(self):
        result = seed_asset_risk(self.ORG, reset=True)
        levels = result["by_risk_level"]
        assert levels.get("critical", 0) + levels.get("high", 0) > 0


# ---------------------------------------------------------------------------
# 9. SecurityHealthEngine seeder
# ---------------------------------------------------------------------------

class TestSeedHealth:
    ORG = f"{_P}-health"

    def test_returns_dict_with_required_keys(self):
        result = seed_health(self.ORG, reset=True)
        assert isinstance(result, dict)
        for key in ("checks", "overall_score", "open_incidents"):
            assert key in result

    def test_check_count(self):
        result = seed_health(self.ORG, reset=True)
        assert result["checks"] == 14

    def test_overall_score_in_range(self):
        result = seed_health(self.ORG, reset=True)
        assert 0 <= result["overall_score"] <= 100

    def test_incidents_logged(self):
        result = seed_health(self.ORG, reset=True)
        assert result["open_incidents"] >= 2


# ---------------------------------------------------------------------------
# 10. IncidentTimelineEngine seeder
# ---------------------------------------------------------------------------

class TestSeedTimelines:
    ORG = f"{_P}-tl"

    def test_returns_dict_with_required_keys(self):
        result = seed_timelines(self.ORG, reset=True)
        assert isinstance(result, dict)
        for key in ("timelines", "active", "resolved"):
            assert key in result

    def test_timeline_count(self):
        result = seed_timelines(self.ORG, reset=True)
        assert result["timelines"] == 3

    def test_has_active_timeline(self):
        result = seed_timelines(self.ORG, reset=True)
        assert result["active"] >= 1

    def test_has_resolved_timelines(self):
        result = seed_timelines(self.ORG, reset=True)
        # phishing (resolved) + insider (closed) = 2
        assert result["resolved"] >= 2


# ---------------------------------------------------------------------------
# 11. VulnTrendEngine seeder
# ---------------------------------------------------------------------------

class TestSeedVulnTrends:
    ORG = f"{_P}-vt"

    def test_returns_dict_with_required_keys(self):
        result = seed_vuln_trends(self.ORG, reset=True)
        assert isinstance(result, dict)
        for key in ("snapshots", "active_slas", "overall_trend", "avg_critical"):
            assert key in result

    def test_snapshot_count(self):
        result = seed_vuln_trends(self.ORG, reset=True)
        assert result["snapshots"] == 6

    def test_sla_count(self):
        result = seed_vuln_trends(self.ORG, reset=True)
        assert result["active_slas"] == 8

    def test_overall_trend_valid_value(self):
        result = seed_vuln_trends(self.ORG, reset=True)
        assert result["overall_trend"] in ("increasing", "decreasing", "stable")

    def test_avg_critical_positive(self):
        result = seed_vuln_trends(self.ORG, reset=True)
        assert result["avg_critical"] > 0


# ---------------------------------------------------------------------------
# 12. Org ID isolation — data is scoped to the org_id supplied
# ---------------------------------------------------------------------------

class TestOrgIdIsolation:
    def test_posture_org_id_stored(self):
        from core.posture_score_engine import PostureScoreEngine
        org = f"{_P}-orgcheck-posture"
        seed_posture(org, reset=True)
        engine = PostureScoreEngine()
        score = engine.get_current_score(org)
        assert score.get("org_id") == org

    def test_feeds_org_id_stored(self):
        from core.threat_feed_aggregator import ThreatFeedAggregator
        org = f"{_P}-orgcheck-feeds"
        seed_threat_feeds(org, reset=True)
        engine = ThreatFeedAggregator()
        sources = engine.list_feed_sources(org)
        assert len(sources) > 0
        assert all(s["org_id"] == org for s in sources)

    def test_forensics_org_id_stored(self):
        from core.digital_forensics_engine import DigitalForensicsEngine
        org = f"{_P}-orgcheck-forensics"
        seed_forensics(org, reset=True)
        engine = DigitalForensicsEngine()
        cases = engine.list_cases(org)
        assert len(cases) > 0
        assert all(c["org_id"] == org for c in cases)

    def test_roadmap_org_id_stored(self):
        from core.security_roadmap_engine import SecurityRoadmapEngine
        org = f"{_P}-orgcheck-roadmap"
        seed_roadmap(org, reset=True)
        engine = SecurityRoadmapEngine()
        initiatives = engine.list_initiatives(org)
        assert len(initiatives) > 0
        assert all(i["org_id"] == org for i in initiatives)

    def test_assets_org_id_stored(self):
        from core.asset_risk_calculator import AssetRiskCalculator
        org = f"{_P}-orgcheck-assets"
        seed_asset_risk(org, reset=True)
        engine = AssetRiskCalculator()
        assets = engine.list_assets(org)
        assert len(assets) > 0
        assert all(a["org_id"] == org for a in assets)


# ---------------------------------------------------------------------------
# 13. Reset flag behaviour
# ---------------------------------------------------------------------------

class TestResetFlag:
    def test_reset_clears_accumulated_sources(self):
        """reset=True must restore source count to exactly 8 even after accumulation."""
        from core.threat_feed_aggregator import ThreatFeedAggregator
        org = f"{_P}-reset-accum"
        # Accumulate 16 sources across two unseeded calls
        seed_threat_feeds(org, reset=False)
        seed_threat_feeds(org, reset=False)
        engine = ThreatFeedAggregator()
        assert len(engine.list_feed_sources(org)) == 16
        # Reset brings it back to 8
        result = seed_threat_feeds(org, reset=True)
        assert result["sources"] == 8
        assert len(engine.list_feed_sources(org)) == 8

    def test_forensics_reset_restores_case_count(self):
        from core.digital_forensics_engine import DigitalForensicsEngine
        org = f"{_P}-reset-forensics"
        seed_forensics(org, reset=False)
        seed_forensics(org, reset=True)   # clears and reseeds
        engine = DigitalForensicsEngine()
        assert len(engine.list_cases(org)) == 5

    def test_health_reset_restores_check_count(self):
        from core.security_health_engine import SecurityHealthEngine
        org = f"{_P}-reset-health"
        seed_health(org, reset=False)
        seed_health(org, reset=True)
        engine = SecurityHealthEngine()
        assert len(engine.list_checks(org)) == 14


# ---------------------------------------------------------------------------
# 14. Script CLI (--help must exit cleanly and mention org-id)
# ---------------------------------------------------------------------------

class TestCLI:
    def test_help_exits_zero(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, str(_SEEDER_PATH), "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0

    def test_help_mentions_org_id(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, str(_SEEDER_PATH), "--help"],
            capture_output=True, text=True, timeout=10,
        )
        combined = result.stdout + result.stderr
        assert "org-id" in combined.lower()

    def test_help_mentions_default_org(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, str(_SEEDER_PATH), "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert "aldeci-demo" in result.stdout + result.stderr
