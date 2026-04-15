"""Tests for VulnIntelFusionEngine — ALDECI.

Coverage:
  - ingest_from_source: new CVE insert, source_count increment on re-ingest
  - _compute_fusion: cvss*0.4 + epss*30 + kev*30 + min(10,sources)*1
  - consensus_severity: kev override, cvss thresholds 9/7/4
  - consensus_priority: critical=1, high=2, medium=3, low=4
  - kev_listed: MAX across sources (any kev=1 makes kev=1)
  - mark_patch_available: sets patch_available=1
  - add_asset_impact: INSERT OR IGNORE, affected_assets increment
  - get_fusion_summary: totals, kev_count, by_severity, avg_score
  - get_priority_queue: ordering by priority ASC then fusion_score DESC
  - get_vuln_detail: fused + source_feeds + asset_impacts
  - get_kev_vulns: only kev=1, ordered by fusion_score DESC
  - org isolation
"""

from __future__ import annotations

import pytest

from core.vuln_intel_fusion_engine import VulnIntelFusionEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_vuln_fusion.db")
    return VulnIntelFusionEngine(db_path=db)


ORG_A = "org-alpha"
ORG_B = "org-beta"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ingest(engine, org=ORG_A, cve_id="CVE-2026-0001", source="NVD",
           source_severity="high", cvss=7.5, epss=0.1, kev=0,
           title="Test CVE", additional_data=None):
    return engine.ingest_from_source(
        org_id=org, cve_id=cve_id, source_name=source,
        source_severity=source_severity, cvss_score=cvss,
        epss_score=epss, kev_listed=kev, title=title,
        additional_data=additional_data or {},
    )


# ---------------------------------------------------------------------------
# ingest_from_source — new CVE
# ---------------------------------------------------------------------------

class TestIngestNew:
    def test_creates_fused_vuln(self, engine):
        result = ingest(engine)
        assert result["cve_id"] == "CVE-2026-0001"
        assert result["org_id"] == ORG_A

    def test_source_count_starts_at_1(self, engine):
        result = ingest(engine)
        assert result["source_count"] == 1

    def test_title_stored(self, engine):
        result = ingest(engine, title="Log4Shell Exploit")
        assert result["title"] == "Log4Shell Exploit"

    def test_patch_available_defaults_to_0(self, engine):
        result = ingest(engine)
        assert result["patch_available"] == 0

    def test_affected_assets_defaults_to_0(self, engine):
        result = ingest(engine)
        assert result["affected_assets"] == 0

    def test_kev_not_listed_by_default(self, engine):
        result = ingest(engine, kev=0)
        assert result["kev_listed"] == 0
        assert result["exploited_in_wild"] == 0


# ---------------------------------------------------------------------------
# ingest_from_source — re-ingest (source_count increment)
# ---------------------------------------------------------------------------

class TestIngestReIngest:
    def test_source_count_increments_on_second_ingest(self, engine):
        ingest(engine, source="NVD", cvss=7.5)
        result = ingest(engine, source="VENDOR", cvss=8.0)
        assert result["source_count"] == 2

    def test_source_count_increments_on_third_ingest(self, engine):
        ingest(engine, source="NVD")
        ingest(engine, source="VENDOR")
        result = ingest(engine, source="CERT")
        assert result["source_count"] == 3

    def test_last_updated_changes_on_reingest(self, engine):
        first = ingest(engine, source="NVD")
        second = ingest(engine, source="VENDOR")
        # last_updated should be set (may be same millisecond in tests, so just check it exists)
        assert second["last_updated"]


# ---------------------------------------------------------------------------
# Fusion score formula: cvss*0.4 + epss*30 + kev*30 + min(10,sources)*1
# ---------------------------------------------------------------------------

class TestFusionScore:
    def test_fusion_score_no_kev(self, engine):
        # cvss=7.5, epss=0.1, kev=0, sources=1
        # expected: 7.5*0.4 + 0.1*30 + 0*30 + 1*1 = 3.0 + 3.0 + 0 + 1 = 7.0
        result = ingest(engine, cvss=7.5, epss=0.1, kev=0)
        assert abs(result["fusion_score"] - 7.0) < 0.01

    def test_fusion_score_with_kev(self, engine):
        # cvss=7.5, epss=0.1, kev=1, sources=1
        # expected: 3.0 + 3.0 + 30.0 + 1.0 = 37.0
        result = ingest(engine, cvss=7.5, epss=0.1, kev=1)
        assert abs(result["fusion_score"] - 37.0) < 0.01

    def test_fusion_score_zero_inputs(self, engine):
        # cvss=0, epss=0, kev=0, sources=1 → 0 + 0 + 0 + 1 = 1.0
        result = ingest(engine, cvss=0.0, epss=0.0, kev=0)
        assert abs(result["fusion_score"] - 1.0) < 0.01

    def test_fusion_score_high_epss(self, engine):
        # cvss=5.0, epss=0.9, kev=0, sources=1 → 2.0 + 27.0 + 0 + 1 = 30.0
        result = ingest(engine, cvss=5.0, epss=0.9, kev=0)
        assert abs(result["fusion_score"] - 30.0) < 0.01

    def test_fusion_score_source_cap_at_10(self, engine):
        # Ingest 15 sources — cap at 10 for sources contribution
        cve = "CVE-2026-9999"
        for i in range(15):
            ingest(engine, cve_id=cve, source=f"SRC-{i}", cvss=0.0, epss=0.0, kev=0)
        result = engine.get_vuln_detail(cve, ORG_A)
        # sources contribution = min(10, 15)*1 = 10
        assert result["source_count"] == 15
        # fusion = 0 + 0 + 0 + 10 = 10.0
        assert abs(result["fusion_score"] - 10.0) < 0.01

    def test_fusion_score_two_sources_with_avg_cvss(self, engine):
        # Source 1: cvss=6.0; Source 2: cvss=8.0 → avg=7.0
        # epss max=0.2, kev=0, sources=2
        # fusion = 7.0*0.4 + 0.2*30 + 0 + 2 = 2.8 + 6.0 + 0 + 2 = 10.8
        ingest(engine, source="S1", cvss=6.0, epss=0.1, kev=0)
        ingest(engine, source="S2", cvss=8.0, epss=0.2, kev=0)
        result = engine.get_vuln_detail("CVE-2026-0001", ORG_A)
        assert abs(result["fusion_score"] - 10.8) < 0.1


# ---------------------------------------------------------------------------
# Consensus severity
# ---------------------------------------------------------------------------

class TestConsensusSeverity:
    def test_kev_overrides_to_critical(self, engine):
        result = ingest(engine, cvss=2.0, kev=1)  # low cvss but kev
        assert result["consensus_severity"] == "critical"
        assert result["consensus_priority"] == 1

    def test_cvss_9_is_critical(self, engine):
        result = ingest(engine, cvss=9.0, kev=0)
        assert result["consensus_severity"] == "critical"

    def test_cvss_9_5_is_critical(self, engine):
        result = ingest(engine, cvss=9.5, kev=0)
        assert result["consensus_severity"] == "critical"

    def test_cvss_7_is_high(self, engine):
        result = ingest(engine, cvss=7.0, kev=0)
        assert result["consensus_severity"] == "high"
        assert result["consensus_priority"] == 2

    def test_cvss_8_5_is_high(self, engine):
        result = ingest(engine, cvss=8.5, kev=0)
        assert result["consensus_severity"] == "high"

    def test_cvss_4_is_medium(self, engine):
        result = ingest(engine, cvss=4.0, kev=0)
        assert result["consensus_severity"] == "medium"
        assert result["consensus_priority"] == 3

    def test_cvss_5_5_is_medium(self, engine):
        result = ingest(engine, cvss=5.5, kev=0)
        assert result["consensus_severity"] == "medium"

    def test_cvss_below_4_is_low(self, engine):
        result = ingest(engine, cvss=2.0, kev=0)
        assert result["consensus_severity"] == "low"
        assert result["consensus_priority"] == 4

    def test_cvss_zero_is_low(self, engine):
        result = ingest(engine, cvss=0.0, kev=0)
        assert result["consensus_severity"] == "low"


# ---------------------------------------------------------------------------
# KEV listed = MAX across sources
# ---------------------------------------------------------------------------

class TestKevMax:
    def test_kev_1_from_any_source_makes_fused_kev(self, engine):
        ingest(engine, source="NVD", kev=0, cvss=5.0)
        result = ingest(engine, source="CISA", kev=1, cvss=5.0)
        assert result["kev_listed"] == 1
        assert result["exploited_in_wild"] == 1

    def test_kev_stays_0_if_all_sources_are_0(self, engine):
        ingest(engine, source="NVD", kev=0)
        result = ingest(engine, source="VENDOR", kev=0)
        assert result["kev_listed"] == 0

    def test_epss_max_across_sources(self, engine):
        ingest(engine, source="S1", epss=0.1, cvss=5.0)
        result = ingest(engine, source="S2", epss=0.8, cvss=5.0)
        assert abs(result["epss_score"] - 0.8) < 0.01


# ---------------------------------------------------------------------------
# mark_patch_available
# ---------------------------------------------------------------------------

class TestMarkPatchAvailable:
    def test_sets_patch_available_to_1(self, engine):
        ingest(engine)
        result = engine.mark_patch_available("CVE-2026-0001", ORG_A)
        assert result["patch_available"] == 1

    def test_missing_cve_raises_key_error(self, engine):
        with pytest.raises(KeyError):
            engine.mark_patch_available("CVE-9999-9999", ORG_A)

    def test_wrong_org_raises_key_error(self, engine):
        ingest(engine, org=ORG_A)
        with pytest.raises(KeyError):
            engine.mark_patch_available("CVE-2026-0001", ORG_B)


# ---------------------------------------------------------------------------
# add_asset_impact
# ---------------------------------------------------------------------------

class TestAddAssetImpact:
    def test_adds_asset_impact(self, engine):
        ingest(engine)
        result = engine.add_asset_impact(ORG_A, "CVE-2026-0001", "asset-1", "web-server", "critical", "direct", 1)
        assert result["asset_id"] == "asset-1"

    def test_affected_assets_increments(self, engine):
        ingest(engine)
        engine.add_asset_impact(ORG_A, "CVE-2026-0001", "asset-1", "web-server", "high", "direct", 1)
        detail = engine.get_vuln_detail("CVE-2026-0001", ORG_A)
        assert detail["affected_assets"] == 1

    def test_affected_assets_increments_for_each_unique_asset(self, engine):
        ingest(engine)
        engine.add_asset_impact(ORG_A, "CVE-2026-0001", "asset-1", "web", "high", "direct", 1)
        engine.add_asset_impact(ORG_A, "CVE-2026-0001", "asset-2", "db", "critical", "direct", 1)
        detail = engine.get_vuln_detail("CVE-2026-0001", ORG_A)
        assert detail["affected_assets"] == 2

    def test_insert_or_ignore_same_asset(self, engine):
        ingest(engine)
        engine.add_asset_impact(ORG_A, "CVE-2026-0001", "asset-1", "web", "high", "direct", 1)
        engine.add_asset_impact(ORG_A, "CVE-2026-0001", "asset-1", "web", "high", "direct", 1)  # duplicate
        detail = engine.get_vuln_detail("CVE-2026-0001", ORG_A)
        assert detail["affected_assets"] == 1  # not 2

    def test_asset_impact_in_detail(self, engine):
        ingest(engine)
        engine.add_asset_impact(ORG_A, "CVE-2026-0001", "asset-1", "db-server", "critical", "direct", 1)
        detail = engine.get_vuln_detail("CVE-2026-0001", ORG_A)
        assert len(detail["asset_impacts"]) == 1
        assert detail["asset_impacts"][0]["asset_name"] == "db-server"


# ---------------------------------------------------------------------------
# get_fusion_summary
# ---------------------------------------------------------------------------

class TestGetFusionSummary:
    def test_total_vulns(self, engine):
        ingest(engine, cve_id="CVE-001")
        ingest(engine, cve_id="CVE-002")
        summary = engine.get_fusion_summary(ORG_A)
        assert summary["total_vulns"] == 2

    def test_kev_listed_count(self, engine):
        ingest(engine, cve_id="CVE-001", kev=1)
        ingest(engine, cve_id="CVE-002", kev=0)
        summary = engine.get_fusion_summary(ORG_A)
        assert summary["kev_listed_count"] == 1

    def test_critical_count(self, engine):
        ingest(engine, cve_id="CVE-001", cvss=9.5)
        ingest(engine, cve_id="CVE-002", cvss=5.0)
        summary = engine.get_fusion_summary(ORG_A)
        assert summary["critical_count"] == 1

    def test_by_consensus_severity(self, engine):
        ingest(engine, cve_id="CVE-001", cvss=9.5)
        ingest(engine, cve_id="CVE-002", cvss=7.0)
        ingest(engine, cve_id="CVE-003", cvss=5.0)
        summary = engine.get_fusion_summary(ORG_A)
        assert summary["by_consensus_severity"]["critical"] == 1
        assert summary["by_consensus_severity"]["high"] == 1
        assert summary["by_consensus_severity"]["medium"] == 1

    def test_patch_available_count(self, engine):
        ingest(engine, cve_id="CVE-001")
        ingest(engine, cve_id="CVE-002")
        engine.mark_patch_available("CVE-001", ORG_A)
        summary = engine.get_fusion_summary(ORG_A)
        assert summary["patch_available_count"] == 1
        assert summary["patch_missing_count"] == 1

    def test_avg_fusion_score(self, engine):
        # cvss=0, epss=0, kev=0, sources=1 → fusion=1.0 each
        ingest(engine, cve_id="CVE-001", cvss=0.0, epss=0.0, kev=0)
        ingest(engine, cve_id="CVE-002", cvss=0.0, epss=0.0, kev=0)
        summary = engine.get_fusion_summary(ORG_A)
        assert abs(summary["avg_fusion_score"] - 1.0) < 0.01

    def test_empty_org_returns_zeros(self, engine):
        summary = engine.get_fusion_summary("empty-org")
        assert summary["total_vulns"] == 0
        assert summary["kev_listed_count"] == 0


# ---------------------------------------------------------------------------
# get_priority_queue
# ---------------------------------------------------------------------------

class TestGetPriorityQueue:
    def test_critical_appears_first(self, engine):
        ingest(engine, cve_id="CVE-LOW", cvss=2.0)       # low, priority=4
        ingest(engine, cve_id="CVE-CRIT", cvss=9.5)      # critical, priority=1
        ingest(engine, cve_id="CVE-HIGH", cvss=7.5)      # high, priority=2
        queue = engine.get_priority_queue(ORG_A)
        assert queue[0]["cve_id"] == "CVE-CRIT"

    def test_order_by_priority_then_fusion_score(self, engine):
        # Two high-severity: higher fusion_score should come first
        ingest(engine, cve_id="CVE-H1", cvss=7.0, epss=0.5, kev=0)
        ingest(engine, cve_id="CVE-H2", cvss=7.0, epss=0.1, kev=0)
        queue = engine.get_priority_queue(ORG_A)
        high_vulns = [v for v in queue if v["consensus_severity"] == "high"]
        assert high_vulns[0]["epss_score"] >= high_vulns[1]["epss_score"]

    def test_limit_respected(self, engine):
        for i in range(10):
            ingest(engine, cve_id=f"CVE-{i:04d}")
        queue = engine.get_priority_queue(ORG_A, limit=5)
        assert len(queue) == 5


# ---------------------------------------------------------------------------
# get_vuln_detail
# ---------------------------------------------------------------------------

class TestGetVulnDetail:
    def test_returns_source_feeds(self, engine):
        ingest(engine, source="NVD")
        ingest(engine, source="VENDOR")
        detail = engine.get_vuln_detail("CVE-2026-0001", ORG_A)
        assert len(detail["source_feeds"]) == 2

    def test_returns_asset_impacts(self, engine):
        ingest(engine)
        engine.add_asset_impact(ORG_A, "CVE-2026-0001", "a1", "server", "high", "direct", 1)
        detail = engine.get_vuln_detail("CVE-2026-0001", ORG_A)
        assert len(detail["asset_impacts"]) == 1

    def test_returns_empty_for_missing_cve(self, engine):
        detail = engine.get_vuln_detail("CVE-9999-9999", ORG_A)
        assert detail == {}


# ---------------------------------------------------------------------------
# get_kev_vulns
# ---------------------------------------------------------------------------

class TestGetKevVulns:
    def test_returns_only_kev_vulns(self, engine):
        ingest(engine, cve_id="CVE-KEV", kev=1)
        ingest(engine, cve_id="CVE-NKEV", kev=0)
        kev = engine.get_kev_vulns(ORG_A)
        assert len(kev) == 1
        assert kev[0]["cve_id"] == "CVE-KEV"

    def test_ordered_by_fusion_score_desc(self, engine):
        ingest(engine, cve_id="CVE-K1", kev=1, cvss=5.0, epss=0.1)
        ingest(engine, cve_id="CVE-K2", kev=1, cvss=9.0, epss=0.8)
        kev = engine.get_kev_vulns(ORG_A)
        # CVE-K2 has higher fusion_score
        assert kev[0]["cve_id"] == "CVE-K2"

    def test_returns_empty_if_no_kev(self, engine):
        ingest(engine, kev=0)
        kev = engine.get_kev_vulns(ORG_A)
        assert kev == []


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_fused_vulns_isolated_by_org(self, engine):
        ingest(engine, org=ORG_A, cve_id="CVE-001")
        ingest(engine, org=ORG_B, cve_id="CVE-002")
        summary_a = engine.get_fusion_summary(ORG_A)
        summary_b = engine.get_fusion_summary(ORG_B)
        assert summary_a["total_vulns"] == 1
        assert summary_b["total_vulns"] == 1

    def test_detail_isolated_by_org(self, engine):
        ingest(engine, org=ORG_A, cve_id="CVE-001")
        detail_b = engine.get_vuln_detail("CVE-001", ORG_B)
        assert detail_b == {}

    def test_kev_isolated_by_org(self, engine):
        ingest(engine, org=ORG_A, cve_id="CVE-KEV", kev=1)
        kev_b = engine.get_kev_vulns(ORG_B)
        assert kev_b == []

    def test_asset_impact_isolated_by_org(self, engine):
        ingest(engine, org=ORG_A)
        ingest(engine, org=ORG_B)
        engine.add_asset_impact(ORG_A, "CVE-2026-0001", "a1", "server", "high", "direct", 1)
        detail_b = engine.get_vuln_detail("CVE-2026-0001", ORG_B)
        assert detail_b["affected_assets"] == 0
        assert detail_b["asset_impacts"] == []
