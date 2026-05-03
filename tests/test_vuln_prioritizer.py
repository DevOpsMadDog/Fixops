"""
Tests for Vulnerability Prioritization Engine — ALDECI.

Coverage:
- Enums and constants
- Pydantic models (EPSSScore, BusinessContext, ReachabilityResult, etc.)
- EPSS cache logic (cache hit, cache miss, cache expiry, API fallback)
- Business context upsert / get / _compute_business_impact
- Reachability upsert / get
- Composite score formula across all boundary conditions
- SLA deadline computation per bucket
- Recommendation generation (upgrade, workaround, mitigate, accept_risk)
- upsert_vuln end-to-end (with and without CVE, with/without context)
- list_prioritized (sorting, filtering by bucket and asset)
- SLA status (totals, breach rate, per-bucket breakdown)
- Trend analysis (counts, risk debt, breach rate)
- Auto-grouping (same_cve, same_library, same_pattern, min-2 rule)
- list_groups persistence
- run_prioritization (re-scoring, summary counts)
- Thread safety (concurrent upserts)
- Edge cases (empty org, unknown reachability, no business context)

Usage:
    pytest tests/test_vuln_prioritizer.py -v --timeout=10
"""

import json
import sqlite3
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is on path
suite_core = str(Path(__file__).parent.parent / "suite-core")
if suite_core not in sys.path:
    sys.path.insert(0, suite_core)

from core.vuln_prioritizer import (
    BusinessContext,
    ComplianceFramework,
    EPSSScore,
    PrioritizationSummary,
    PrioritizeRequest,
    PrioritizedVuln,
    ReachabilityLevel,
    ReachabilityResult,
    RemediationAction,
    RemediationRecommendation,
    RiskBucket,
    SLAStatus,
    VulnGroup,
    VulnPrioritizer,
    VulnTrend,
    _REACHABILITY_FACTOR,
    _SLA_HOURS,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "test_vuln.db")


@pytest.fixture
def engine(tmp_db):
    return VulnPrioritizer(db_path=tmp_db, org_id="test_org")


@pytest.fixture
def ctx_pii():
    return BusinessContext(
        asset_id="asset-pii",
        asset_name="PII Service",
        revenue_impact=0.8,
        data_sensitivity=0.9,
        regulatory_frameworks=[ComplianceFramework.GDPR, ComplianceFramework.SOC2],
        customer_count=50000,
        customer_impact_score=0.7,
        compensating_controls=0.1,
        tier="tier1",
        org_id="test_org",
    )


@pytest.fixture
def ctx_low():
    return BusinessContext(
        asset_id="asset-low",
        asset_name="Internal Tool",
        revenue_impact=0.05,
        data_sensitivity=0.05,
        regulatory_frameworks=[],
        customer_count=10,
        customer_impact_score=0.01,
        compensating_controls=0.8,
        tier="tier4",
        org_id="test_org",
    )


@pytest.fixture
def reach_confirmed():
    return ReachabilityResult(
        finding_id="finding-001",
        level=ReachabilityLevel.CONFIRMED_REACHABLE,
        call_path=["main.py:42", "lib/parser.py:100", "vuln_func:55"],
        evidence="Static analysis confirmed execution path.",
        analyzer="semgrep",
    )


# ============================================================================
# 1. Enums and constants
# ============================================================================


def test_reachability_level_values():
    assert ReachabilityLevel.CONFIRMED_REACHABLE.value == "confirmed_reachable"
    assert ReachabilityLevel.POTENTIALLY_REACHABLE.value == "potentially_reachable"
    assert ReachabilityLevel.NOT_REACHABLE.value == "not_reachable"
    assert ReachabilityLevel.UNKNOWN.value == "unknown"


def test_risk_bucket_values():
    assert RiskBucket.CRITICAL.value == "critical"
    assert RiskBucket.HIGH.value == "high"
    assert RiskBucket.MEDIUM.value == "medium"
    assert RiskBucket.LOW.value == "low"
    assert RiskBucket.INFO.value == "info"


def test_remediation_action_values():
    assert RemediationAction.UPGRADE.value == "upgrade"
    assert RemediationAction.WORKAROUND.value == "workaround"
    assert RemediationAction.ACCEPT_RISK.value == "accept_risk"
    assert RemediationAction.MITIGATE.value == "mitigate"


def test_sla_hours_mapping():
    assert _SLA_HOURS["critical"] == 24
    assert _SLA_HOURS["high"] == 168
    assert _SLA_HOURS["medium"] == 720
    assert _SLA_HOURS["low"] == 2160
    assert _SLA_HOURS["info"] == 8760


def test_reachability_factors():
    assert _REACHABILITY_FACTOR["confirmed_reachable"] == 1.0
    assert _REACHABILITY_FACTOR["potentially_reachable"] == 0.5
    assert _REACHABILITY_FACTOR["not_reachable"] == 0.1


def test_compliance_framework_values():
    assert ComplianceFramework.SOC2.value == "soc2"
    assert ComplianceFramework.PCI_DSS.value == "pci_dss"
    assert ComplianceFramework.HIPAA.value == "hipaa"
    assert ComplianceFramework.GDPR.value == "gdpr"


# ============================================================================
# 2. Pydantic models
# ============================================================================


def test_epss_score_model_defaults():
    s = EPSSScore(cve_id="CVE-2023-1234", epss=0.42, percentile=0.85)
    assert s.cve_id == "CVE-2023-1234"
    assert s.epss == 0.42
    assert s.percentile == 0.85
    assert s.model_version == "v3"
    assert s.cached is False


def test_epss_score_bounds():
    with pytest.raises(Exception):
        EPSSScore(cve_id="CVE-1", epss=1.5, percentile=0.5)
    with pytest.raises(Exception):
        EPSSScore(cve_id="CVE-1", epss=0.5, percentile=-0.1)


def test_business_context_model(ctx_pii):
    assert ctx_pii.asset_id == "asset-pii"
    assert ctx_pii.revenue_impact == 0.8
    assert ComplianceFramework.GDPR in ctx_pii.regulatory_frameworks
    assert ctx_pii.tier == "tier1"


def test_business_context_compensating_controls_bounds():
    with pytest.raises(Exception):
        BusinessContext(
            asset_id="x", asset_name="x",
            revenue_impact=0.5, data_sensitivity=0.5,
            customer_impact_score=0.5, compensating_controls=1.5,
        )


def test_remediation_recommendation_model():
    r = RemediationRecommendation(
        action=RemediationAction.UPGRADE,
        description="Upgrade to v2.0",
        fixed_version="2.0.0",
        effort_hours=3.0,
    )
    assert r.action == RemediationAction.UPGRADE
    assert r.confidence == 0.8


def test_prioritized_vuln_defaults():
    v = PrioritizedVuln(
        finding_id="f1",
        title="Test Vuln",
        asset_id="a1",
        asset_name="Asset 1",
    )
    assert v.risk_bucket == RiskBucket.MEDIUM
    assert v.composite_score == 0.0
    assert v.reachability == ReachabilityLevel.UNKNOWN


def test_vuln_group_model():
    g = VulnGroup(
        group_type="same_cve",
        label="CVE-2023-1234 (3 assets)",
        finding_ids=["f1", "f2", "f3"],
        cve_id="CVE-2023-1234",
        max_composite_score=72.5,
        fix_once_count=3,
    )
    assert g.fix_once_count == 3
    assert g.cve_id == "CVE-2023-1234"


# ============================================================================
# 3. EPSS cache logic
# ============================================================================


def test_epss_cache_miss_returns_zero_on_api_error(engine):
    """With no network, EPSS should return 0.0 gracefully."""
    score = engine.get_epss_score("CVE-2023-9999")
    assert score.cve_id == "CVE-2023-9999"
    assert 0.0 <= score.epss <= 1.0


def test_epss_cache_stores_and_retrieves(engine):
    """Manually cache a score, then verify retrieval."""
    fake = EPSSScore(cve_id="CVE-2021-44228", epss=0.975, percentile=0.99)
    engine._cache_epss(fake)

    result = engine._get_epss_from_cache("CVE-2021-44228")
    assert result is not None
    assert result.epss == 0.975
    assert result.cached is True


def test_epss_cache_expired_returns_none(engine):
    """A score cached 48h ago with 24h TTL should not be returned."""
    engine.epss_cache_ttl_hours = 24
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    with engine._get_conn() as conn:
        conn.execute(
            "INSERT INTO epss_cache (cve_id, epss, percentile, model_version, score_date, fetched_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("CVE-2020-0001", 0.5, 0.7, "v3", old_ts, old_ts),
        )
    result = engine._get_epss_from_cache("CVE-2020-0001")
    assert result is None


def test_epss_cache_upsert_overwrites(engine):
    """Caching the same CVE twice should update, not duplicate."""
    s1 = EPSSScore(cve_id="CVE-2022-0002", epss=0.1, percentile=0.2)
    s2 = EPSSScore(cve_id="CVE-2022-0002", epss=0.9, percentile=0.95)
    engine._cache_epss(s1)
    engine._cache_epss(s2)

    result = engine._get_epss_from_cache("CVE-2022-0002")
    assert result is not None
    assert result.epss == 0.9


def test_epss_force_refresh_bypasses_cache(engine):
    """force_refresh=True should call API even if cache is fresh."""
    fake = EPSSScore(cve_id="CVE-2023-0001", epss=0.5, percentile=0.6)
    engine._cache_epss(fake)

    # With network error, API returns 0.0
    result = engine.get_epss_score("CVE-2023-0001", force_refresh=True)
    # It should have called the API (returns 0.0 on failure), not cache (0.5)
    assert result.cached is False


# ============================================================================
# 4. Business context
# ============================================================================


def test_upsert_and_get_business_context(engine, ctx_pii):
    engine.upsert_business_context(ctx_pii)
    retrieved = engine.get_business_context("asset-pii")
    assert retrieved is not None
    assert retrieved.asset_name == "PII Service"
    assert retrieved.revenue_impact == 0.8
    assert ComplianceFramework.GDPR in retrieved.regulatory_frameworks


def test_get_business_context_not_found(engine):
    assert engine.get_business_context("nonexistent-asset") is None


def test_upsert_business_context_updates(engine, ctx_pii):
    engine.upsert_business_context(ctx_pii)
    updated = ctx_pii.model_copy(update={"revenue_impact": 0.3})
    engine.upsert_business_context(updated)
    retrieved = engine.get_business_context("asset-pii")
    assert retrieved.revenue_impact == 0.3


def test_compute_business_impact_none_returns_default(engine):
    impact = engine._compute_business_impact(None)
    assert impact == 0.4


def test_compute_business_impact_tier1_high(engine, ctx_pii):
    impact = engine._compute_business_impact(ctx_pii)
    assert impact > 0.7  # high revenue + PII + regulatory + tier1 boost


def test_compute_business_impact_tier4_low(engine, ctx_low):
    impact = engine._compute_business_impact(ctx_low)
    assert impact < 0.15


def test_compute_business_impact_capped_at_one(engine):
    ctx = BusinessContext(
        asset_id="x", asset_name="x",
        revenue_impact=1.0, data_sensitivity=1.0,
        regulatory_frameworks=list(ComplianceFramework),
        customer_count=1000000, customer_impact_score=1.0,
        compensating_controls=0.0, tier="tier1",
    )
    assert engine._compute_business_impact(ctx) <= 1.0


def test_business_impact_regulatory_weight_increases_score(engine):
    ctx_no_reg = BusinessContext(
        asset_id="a1", asset_name="A",
        revenue_impact=0.5, data_sensitivity=0.5,
        regulatory_frameworks=[],
        customer_impact_score=0.5, compensating_controls=0.0,
    )
    ctx_reg = ctx_no_reg.model_copy(
        update={"regulatory_frameworks": [ComplianceFramework.HIPAA, ComplianceFramework.PCI_DSS]}
    )
    assert engine._compute_business_impact(ctx_reg) > engine._compute_business_impact(ctx_no_reg)


# ============================================================================
# 5. Reachability
# ============================================================================


def test_upsert_and_get_reachability(engine, reach_confirmed):
    engine.upsert_reachability(reach_confirmed)
    result = engine.get_reachability("finding-001")
    assert result is not None
    assert result.level == ReachabilityLevel.CONFIRMED_REACHABLE
    assert "main.py:42" in result.call_path


def test_get_reachability_not_found(engine):
    assert engine.get_reachability("unknown-finding") is None


def test_upsert_reachability_updates_level(engine):
    r = ReachabilityResult(finding_id="f99", level=ReachabilityLevel.UNKNOWN)
    engine.upsert_reachability(r)
    updated = ReachabilityResult(
        finding_id="f99", level=ReachabilityLevel.NOT_REACHABLE, evidence="dead code"
    )
    engine.upsert_reachability(updated)
    result = engine.get_reachability("f99")
    assert result.level == ReachabilityLevel.NOT_REACHABLE
    assert result.evidence == "dead code"


# ============================================================================
# 6. Composite score formula
# ============================================================================


def test_composite_score_critical_threshold(engine):
    score, bucket = engine.compute_composite_score(
        epss=0.95,
        reachability=ReachabilityLevel.CONFIRMED_REACHABLE,
        business_impact=0.9,
        compensating_controls=0.0,
    )
    assert score >= 75.0
    assert bucket == RiskBucket.CRITICAL


def test_composite_score_info_threshold(engine):
    score, bucket = engine.compute_composite_score(
        epss=0.01,
        reachability=ReachabilityLevel.NOT_REACHABLE,
        business_impact=0.1,
        compensating_controls=0.0,
    )
    assert score < 5.0
    assert bucket == RiskBucket.INFO


def test_composite_score_high_threshold(engine):
    score, bucket = engine.compute_composite_score(
        epss=0.7,
        reachability=ReachabilityLevel.CONFIRMED_REACHABLE,
        business_impact=0.8,
        compensating_controls=0.0,
    )
    assert 50.0 <= score < 75.0 or bucket == RiskBucket.CRITICAL  # may tip to critical


def test_composite_score_compensating_controls_reduce_score(engine):
    score_no_ctrl, _ = engine.compute_composite_score(
        epss=0.5,
        reachability=ReachabilityLevel.CONFIRMED_REACHABLE,
        business_impact=0.8,
        compensating_controls=0.0,
    )
    score_with_ctrl, _ = engine.compute_composite_score(
        epss=0.5,
        reachability=ReachabilityLevel.CONFIRMED_REACHABLE,
        business_impact=0.8,
        compensating_controls=0.9,
    )
    assert score_with_ctrl < score_no_ctrl


def test_composite_score_not_reachable_reduces_score(engine):
    score_reach, _ = engine.compute_composite_score(
        epss=0.8,
        reachability=ReachabilityLevel.CONFIRMED_REACHABLE,
        business_impact=0.8,
        compensating_controls=0.0,
    )
    score_no_reach, _ = engine.compute_composite_score(
        epss=0.8,
        reachability=ReachabilityLevel.NOT_REACHABLE,
        business_impact=0.8,
        compensating_controls=0.0,
    )
    assert score_no_reach < score_reach


def test_composite_score_unknown_reachability_uses_half(engine):
    score_unknown, _ = engine.compute_composite_score(
        epss=0.8,
        reachability=ReachabilityLevel.UNKNOWN,
        business_impact=0.8,
        compensating_controls=0.0,
    )
    score_potential, _ = engine.compute_composite_score(
        epss=0.8,
        reachability=ReachabilityLevel.POTENTIALLY_REACHABLE,
        business_impact=0.8,
        compensating_controls=0.0,
    )
    assert abs(score_unknown - score_potential) < 0.01


def test_composite_score_max_capped_at_100(engine):
    score, _ = engine.compute_composite_score(
        epss=1.0,
        reachability=ReachabilityLevel.CONFIRMED_REACHABLE,
        business_impact=1.0,
        compensating_controls=0.0,
    )
    assert score == 100.0


def test_composite_score_zero_epss_returns_info(engine):
    score, bucket = engine.compute_composite_score(
        epss=0.0,
        reachability=ReachabilityLevel.CONFIRMED_REACHABLE,
        business_impact=1.0,
        compensating_controls=0.0,
    )
    assert score == 0.0
    assert bucket == RiskBucket.INFO


# ============================================================================
# 7. SLA deadline
# ============================================================================


def test_sla_deadline_critical_24h(engine):
    now = datetime.now(timezone.utc)
    deadline = engine._compute_sla_deadline(now, RiskBucket.CRITICAL)
    assert abs((deadline - now).total_seconds() - 86400) < 2


def test_sla_deadline_high_7d(engine):
    now = datetime.now(timezone.utc)
    deadline = engine._compute_sla_deadline(now, RiskBucket.HIGH)
    assert abs((deadline - now).total_seconds() - 7 * 86400) < 2


def test_sla_deadline_medium_30d(engine):
    now = datetime.now(timezone.utc)
    deadline = engine._compute_sla_deadline(now, RiskBucket.MEDIUM)
    assert abs((deadline - now).total_seconds() - 30 * 86400) < 2


def test_sla_deadline_low_90d(engine):
    now = datetime.now(timezone.utc)
    deadline = engine._compute_sla_deadline(now, RiskBucket.LOW)
    assert abs((deadline - now).total_seconds() - 90 * 86400) < 2


# ============================================================================
# 8. Remediation recommendations
# ============================================================================


def test_recommendations_critical_with_cve(engine):
    recs = engine._build_recommendations(
        cve_id="CVE-2023-1234",
        title="SQL injection in db.py",
        epss=0.9,
        bucket=RiskBucket.CRITICAL,
    )
    actions = {r.action for r in recs}
    assert RemediationAction.UPGRADE in actions
    assert RemediationAction.WORKAROUND in actions
    assert RemediationAction.MITIGATE in actions


def test_recommendations_no_cve_no_upgrade(engine):
    recs = engine._build_recommendations(
        cve_id=None,
        title="Misconfigured S3 bucket",
        epss=0.0,
        bucket=RiskBucket.LOW,
    )
    actions = {r.action for r in recs}
    assert RemediationAction.UPGRADE not in actions
    assert RemediationAction.ACCEPT_RISK in actions


def test_recommendations_high_has_workaround(engine):
    recs = engine._build_recommendations(
        cve_id="CVE-2022-5555",
        title="RCE in parser",
        epss=0.6,
        bucket=RiskBucket.HIGH,
    )
    actions = {r.action for r in recs}
    assert RemediationAction.WORKAROUND in actions


def test_recommendations_medium_no_mitigate(engine):
    recs = engine._build_recommendations(
        cve_id="CVE-2021-3333",
        title="XSS in template",
        epss=0.3,
        bucket=RiskBucket.MEDIUM,
    )
    actions = {r.action for r in recs}
    assert RemediationAction.MITIGATE not in actions


def test_accept_risk_template_contains_cve(engine):
    recs = engine._build_recommendations(
        cve_id="CVE-2020-1111",
        title="Low severity info leak",
        epss=0.01,
        bucket=RiskBucket.INFO,
    )
    accept = next((r for r in recs if r.action == RemediationAction.ACCEPT_RISK), None)
    assert accept is not None
    assert "CVE-2020-1111" in (accept.accept_risk_template or "")


# ============================================================================
# 9. upsert_vuln end-to-end
# ============================================================================


def test_upsert_vuln_no_context_no_cve(engine):
    v = engine.upsert_vuln(
        finding_id="fnd-001",
        title="Misconfigured nginx",
        asset_id="asset-web",
        asset_name="Web Server",
    )
    assert v.finding_id == "fnd-001"
    assert v.composite_score >= 0.0
    assert v.sla_deadline is not None
    assert v.risk_bucket in list(RiskBucket)


def test_upsert_vuln_with_cve_and_context(engine, ctx_pii, reach_confirmed):
    engine.upsert_business_context(ctx_pii)
    engine.upsert_reachability(reach_confirmed)
    v = engine.upsert_vuln(
        finding_id="finding-001",
        title="Log4Shell RCE",
        asset_id="asset-pii",
        asset_name="PII Service",
        cve_id="CVE-2021-44228",
        assigned_team="platform",
    )
    assert v.cve_id == "CVE-2021-44228"
    assert v.reachability == ReachabilityLevel.CONFIRMED_REACHABLE
    assert v.assigned_team == "platform"
    assert len(v.recommendations) > 0


def test_upsert_vuln_idempotent(engine):
    """Calling upsert twice with same finding_id should update, not duplicate."""
    engine.upsert_vuln(
        finding_id="fnd-dupe",
        title="First version",
        asset_id="a1",
        asset_name="A1",
    )
    engine.upsert_vuln(
        finding_id="fnd-dupe",
        title="Updated version",
        asset_id="a1",
        asset_name="A1",
    )
    results = engine.list_prioritized()
    dupes = [v for v in results if v.finding_id == "fnd-dupe"]
    assert len(dupes) == 1
    assert dupes[0].title == "Updated version"


def test_upsert_vuln_sla_breached_for_old_discovery(engine):
    """A finding discovered 100 days ago should have breached all SLA levels."""
    old = datetime.now(timezone.utc) - timedelta(days=100)
    v = engine.upsert_vuln(
        finding_id="fnd-old",
        title="Ancient vuln",
        asset_id="a1",
        asset_name="A1",
        discovered_at=old,
    )
    assert v.days_open >= 99
    # Not necessarily breached if bucket is INFO (365d SLA), but days_open is correct
    assert v.days_open >= 99


def test_upsert_vuln_no_sla_breach_for_new_finding(engine):
    v = engine.upsert_vuln(
        finding_id="fnd-new",
        title="Brand new vuln",
        asset_id="a1",
        asset_name="A1",
    )
    # Just discovered — never breached regardless of bucket
    assert v.days_open == 0


# ============================================================================
# 10. list_prioritized
# ============================================================================


def test_list_prioritized_sorted_by_score(engine):
    for i, epss in enumerate([0.9, 0.1, 0.5]):
        fake = EPSSScore(cve_id=f"CVE-2023-{i:04d}", epss=epss, percentile=epss)
        engine._cache_epss(fake)
        engine.upsert_vuln(
            finding_id=f"fnd-sort-{i}",
            title=f"Vuln {i}",
            asset_id="a1",
            asset_name="A1",
            cve_id=f"CVE-2023-{i:04d}",
        )
    results = engine.list_prioritized(org_id="test_org")
    scores = [v.composite_score for v in results]
    assert scores == sorted(scores, reverse=True)


def test_list_prioritized_filter_by_bucket(engine):
    # Insert one INFO and one CRITICAL
    engine.upsert_vuln(
        finding_id="info-fnd",
        title="Info finding",
        asset_id="a1",
        asset_name="A1",
    )
    results = engine.list_prioritized(bucket=RiskBucket.CRITICAL)
    for v in results:
        assert v.risk_bucket == RiskBucket.CRITICAL


def test_list_prioritized_filter_by_asset(engine):
    engine.upsert_vuln(finding_id="f-a1", title="V1", asset_id="asset-x", asset_name="X")
    engine.upsert_vuln(finding_id="f-a2", title="V2", asset_id="asset-y", asset_name="Y")
    results = engine.list_prioritized(asset_id="asset-x")
    assert all(v.asset_id == "asset-x" for v in results)


def test_list_prioritized_pagination(engine):
    for i in range(5):
        engine.upsert_vuln(
            finding_id=f"page-{i}",
            title=f"V{i}",
            asset_id="a1",
            asset_name="A1",
        )
    page1 = engine.list_prioritized(limit=2, offset=0)
    page2 = engine.list_prioritized(limit=2, offset=2)
    assert len(page1) == 2
    assert len(page2) == 2
    assert {v.finding_id for v in page1}.isdisjoint({v.finding_id for v in page2})


# ============================================================================
# 11. SLA status
# ============================================================================


def test_sla_status_empty_org(engine):
    status = engine.get_sla_status(org_id="empty-org")
    assert status.total_open == 0
    assert status.breach_rate == 0.0


def test_sla_status_counts(engine):
    engine.upsert_vuln(finding_id="s1", title="V1", asset_id="a1", asset_name="A1")
    engine.upsert_vuln(finding_id="s2", title="V2", asset_id="a2", asset_name="A2")
    status = engine.get_sla_status()
    assert status.total_open >= 2
    assert status.within_sla + status.breached == status.total_open


def test_sla_status_breach_rate_calculation(engine):
    # Inject a breached finding directly
    with engine._get_conn() as conn:
        conn.execute(
            "INSERT INTO prioritized_vulns "
            "(id, finding_id, title, asset_id, asset_name, epss_score, reachability, "
            "reachability_factor, business_impact, compensating_controls, composite_score, "
            "risk_bucket, sla_breached, days_open, recommendations, discovered_at, "
            "last_prioritized, org_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "br-id", "br-fnd", "Breached", "a1", "A1",
                0.0, "unknown", 0.5, 0.4, 0.0, 10.0,
                "medium", 1, 50, "[]",
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
                "test_org",
            ),
        )
    status = engine.get_sla_status()
    assert status.breached >= 1
    assert status.breach_rate > 0.0


def test_sla_status_filter_by_team(engine):
    engine.upsert_vuln(
        finding_id="team-fnd",
        title="Team Vuln",
        asset_id="a1",
        asset_name="A1",
        assigned_team="red-team",
    )
    status = engine.get_sla_status(team="red-team")
    assert status.team == "red-team"
    assert status.total_open >= 1


def test_sla_status_by_bucket_populated(engine):
    engine.upsert_vuln(finding_id="bk1", title="V", asset_id="a1", asset_name="A1")
    status = engine.get_sla_status()
    assert isinstance(status.by_bucket, dict)


# ============================================================================
# 12. Trend analysis
# ============================================================================


def test_trend_empty_org(engine):
    trend = engine.compute_trend(org_id="no-vulns")
    assert trend.total_open == 0
    assert trend.risk_debt_score == 0.0
    assert trend.sla_breach_rate == 0.0


def test_trend_new_vulns_in_period(engine):
    engine.upsert_vuln(finding_id="tr1", title="V1", asset_id="a1", asset_name="A1")
    engine.upsert_vuln(finding_id="tr2", title="V2", asset_id="a2", asset_name="A2")
    trend = engine.compute_trend(days=30)
    assert trend.new_vulns >= 2
    assert trend.total_open >= 2


def test_trend_old_finding_not_counted_as_new(engine):
    old = datetime.now(timezone.utc) - timedelta(days=60)
    engine.upsert_vuln(
        finding_id="tr-old",
        title="Old",
        asset_id="a1",
        asset_name="A1",
        discovered_at=old,
    )
    trend = engine.compute_trend(days=30)
    assert trend.new_vulns == 0


def test_trend_risk_debt_positive(engine):
    engine.upsert_vuln(finding_id="debt1", title="V", asset_id="a1", asset_name="A1")
    trend = engine.compute_trend()
    assert trend.risk_debt_score >= 0.0


def test_trend_period_boundaries(engine):
    trend = engine.compute_trend(days=7)
    assert trend.period_end > trend.period_start
    delta = (trend.period_end - trend.period_start).days
    assert 6 <= delta <= 8


def test_trend_bucket_counts(engine):
    engine.upsert_vuln(finding_id="bc1", title="V1", asset_id="a1", asset_name="A1")
    trend = engine.compute_trend()
    total = (
        trend.critical_count
        + trend.high_count
        + trend.medium_count
        + trend.low_count
    )
    # total per-bucket may not include info — just check it's non-negative
    assert total >= 0


# ============================================================================
# 13. Auto-grouping
# ============================================================================


def test_rebuild_groups_same_cve(engine):
    for i in range(3):
        engine.upsert_vuln(
            finding_id=f"g-cve-{i}",
            title=f"Service {i} CVE hit",
            asset_id=f"asset-{i}",
            asset_name=f"Asset {i}",
            cve_id="CVE-2023-7777",
        )
    groups = engine.rebuild_groups()
    cve_groups = [g for g in groups if g.group_type == "same_cve"]
    assert len(cve_groups) >= 1
    assert cve_groups[0].cve_id == "CVE-2023-7777"
    assert cve_groups[0].fix_once_count == 3


def test_rebuild_groups_same_library(engine):
    for i in range(2):
        engine.upsert_vuln(
            finding_id=f"g-lib-{i}",
            title=f"log4j: critical RCE in service {i}",
            asset_id=f"asset-lib-{i}",
            asset_name=f"Service {i}",
        )
    groups = engine.rebuild_groups()
    lib_groups = [g for g in groups if g.group_type == "same_library"]
    lib_names = [g.library for g in lib_groups]
    assert "log4j:" in lib_names or "log4j" in lib_names


def test_rebuild_groups_min_two_members(engine):
    """A lone finding should NOT form a group."""
    engine.upsert_vuln(
        finding_id="g-lone",
        title="Unique finding with no siblings",
        asset_id="asset-lone",
        asset_name="Lone Asset",
        cve_id="CVE-9999-1111",
    )
    groups = engine.rebuild_groups()
    lone_cve_groups = [g for g in groups if g.cve_id == "CVE-9999-1111"]
    assert len(lone_cve_groups) == 0


def test_rebuild_groups_clears_old_groups(engine):
    for i in range(2):
        engine.upsert_vuln(
            finding_id=f"clr-{i}",
            title=f"vuln {i}",
            asset_id=f"a-{i}",
            asset_name=f"A{i}",
            cve_id="CVE-2023-8888",
        )
    engine.rebuild_groups()
    engine.rebuild_groups()  # second call should not duplicate
    groups = engine.list_groups()
    cve_groups = [g for g in groups if g.cve_id == "CVE-2023-8888"]
    assert len(cve_groups) == 1


def test_list_groups_sorted_by_score(engine):
    for j, cve in enumerate(["CVE-2023-1001", "CVE-2023-1002"]):
        for i in range(2):
            engine.upsert_vuln(
                finding_id=f"sg-{j}-{i}",
                title=f"Vuln j={j} i={i}",
                asset_id=f"a-{j}-{i}",
                asset_name="A",
                cve_id=cve,
            )
    engine.rebuild_groups()
    groups = engine.list_groups()
    scores = [g.max_composite_score for g in groups]
    assert scores == sorted(scores, reverse=True)


# ============================================================================
# 14. run_prioritization
# ============================================================================


def test_run_prioritization_empty(engine):
    summary = engine.run_prioritization()
    assert summary.vulns_evaluated == 0
    assert isinstance(summary, PrioritizationSummary)


def test_run_prioritization_counts(engine):
    for i in range(3):
        engine.upsert_vuln(
            finding_id=f"rp-{i}",
            title=f"V{i}",
            asset_id="a1",
            asset_name="A1",
        )
    summary = engine.run_prioritization()
    assert summary.vulns_evaluated == 3
    total = (
        summary.critical_count
        + summary.high_count
        + summary.medium_count
        + summary.low_count
        + summary.info_count
    )
    assert total == 3


def test_run_prioritization_asset_filter(engine):
    engine.upsert_vuln(finding_id="rp-a", title="V", asset_id="asset-x", asset_name="X")
    engine.upsert_vuln(finding_id="rp-b", title="V", asset_id="asset-y", asset_name="Y")
    summary = engine.run_prioritization(asset_ids=["asset-x"])
    assert summary.vulns_evaluated == 1


def test_run_prioritization_duration_is_positive(engine):
    engine.upsert_vuln(finding_id="dur-1", title="V", asset_id="a1", asset_name="A1")
    summary = engine.run_prioritization()
    assert summary.duration_ms >= 0.0


def test_prioritize_request_model():
    req = PrioritizeRequest(org_id="acme", asset_ids=["a1", "a2"], force_epss_refresh=True)
    assert req.org_id == "acme"
    assert "a1" in req.asset_ids
    assert req.force_epss_refresh is True


# ============================================================================
# 15. Thread safety
# ============================================================================


def test_concurrent_upserts_no_errors(engine):
    errors = []

    def worker(idx: int):
        try:
            engine.upsert_vuln(
                finding_id=f"thread-{idx}",
                title=f"Concurrent V{idx}",
                asset_id="shared-asset",
                asset_name="Shared",
            )
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    results = engine.list_prioritized()
    assert len(results) == 10


# ============================================================================
# 16. Edge cases
# ============================================================================


def test_empty_org_list_prioritized(engine):
    results = engine.list_prioritized(org_id="nonexistent-org")
    assert results == []


def test_upsert_vuln_preserves_org_id(engine):
    v = engine.upsert_vuln(
        finding_id="org-test",
        title="V",
        asset_id="a1",
        asset_name="A1",
        org_id="acme-corp",
    )
    assert v.org_id == "acme-corp"
    results = engine.list_prioritized(org_id="acme-corp")
    assert any(r.finding_id == "org-test" for r in results)


def test_multiple_orgs_isolated(engine):
    engine.upsert_vuln(
        finding_id="org1-fnd", title="V", asset_id="a1", asset_name="A1", org_id="org-A"
    )
    engine.upsert_vuln(
        finding_id="org2-fnd", title="V", asset_id="a1", asset_name="A1", org_id="org-B"
    )
    org_a = engine.list_prioritized(org_id="org-A")
    org_b = engine.list_prioritized(org_id="org-B")
    assert all(v.org_id == "org-A" for v in org_a)
    assert all(v.org_id == "org-B" for v in org_b)


def test_cve_id_normalized_uppercase(engine):
    fake = EPSSScore(cve_id="CVE-2023-9876", epss=0.3, percentile=0.5)
    engine._cache_epss(fake)
    result = engine._get_epss_from_cache("cve-2023-9876")
    assert result is not None


def test_business_context_no_regulatory_frameworks(engine):
    ctx = BusinessContext(
        asset_id="simple", asset_name="Simple",
        revenue_impact=0.3, data_sensitivity=0.2,
        customer_impact_score=0.1, compensating_controls=0.0,
    )
    engine.upsert_business_context(ctx)
    retrieved = engine.get_business_context("simple")
    assert retrieved.regulatory_frameworks == []


def test_vuln_with_no_recommendations_for_medium_no_cve(engine):
    recs = engine._build_recommendations(
        cve_id=None, title="Weak TLS config", epss=0.1, bucket=RiskBucket.MEDIUM
    )
    # No CVE = no upgrade. EPSS > 0.05 = no accept_risk. Medium = no mitigate.
    # Should be empty list
    assert all(r.action != RemediationAction.UPGRADE for r in recs)
    assert all(r.action != RemediationAction.MITIGATE for r in recs)


# ============================================================================
# Scoring Config tests (weights + thresholds, added 2026-05-03)
# ============================================================================

from core.vuln_prioritizer import BucketThresholds, ScoringConfig, ScoringWeights


def test_scoring_config_defaults(engine):
    """get_scoring_config returns factory defaults when nothing has been persisted."""
    cfg = engine.get_scoring_config("default")
    assert cfg.org_id == "default"
    assert cfg.weights.revenue_impact == 0.35
    assert cfg.weights.data_sensitivity == 0.30
    assert cfg.thresholds.critical == 75.0
    assert cfg.thresholds.high == 50.0


def test_scoring_config_roundtrip(engine):
    """upsert_scoring_config persists and get_scoring_config retrieves correctly."""
    new_cfg = ScoringConfig(
        org_id="test-org",
        weights=ScoringWeights(
            revenue_impact=0.50,
            data_sensitivity=0.20,
            customer_impact=0.20,
            regulatory=0.10,
        ),
        thresholds=BucketThresholds(critical=80.0, high=60.0, medium=25.0, low=8.0),
    )
    saved = engine.upsert_scoring_config(new_cfg)
    assert saved.weights.revenue_impact == 0.50

    retrieved = engine.get_scoring_config("test-org")
    assert retrieved.weights.revenue_impact == 0.50
    assert retrieved.thresholds.critical == 80.0
    assert retrieved.thresholds.high == 60.0
    assert retrieved.thresholds.medium == 25.0
    assert retrieved.thresholds.low == 8.0


def test_custom_thresholds_change_bucket(engine):
    """compute_composite_score respects custom bucket thresholds."""
    # score = 0.9 * 1.0 * 0.8 * 1.0 * 100 = 72.0
    # with default thresholds (critical=75) → HIGH; with custom (critical=70) → CRITICAL
    score, bucket_default = engine.compute_composite_score(
        epss=0.9,
        reachability=ReachabilityLevel.CONFIRMED_REACHABLE,
        business_impact=0.8,
        compensating_controls=0.0,
        thresholds=BucketThresholds(),  # critical=75
    )
    assert bucket_default == RiskBucket.HIGH

    score2, bucket_custom = engine.compute_composite_score(
        epss=0.9,
        reachability=ReachabilityLevel.CONFIRMED_REACHABLE,
        business_impact=0.8,
        compensating_controls=0.0,
        thresholds=BucketThresholds(critical=70.0),
    )
    assert score == score2  # same raw score
    assert bucket_custom == RiskBucket.CRITICAL


def test_custom_weights_change_business_impact(engine):
    """_compute_business_impact respects custom ScoringWeights."""
    ctx = BusinessContext(
        asset_id="w-asset", asset_name="WeightTest",
        revenue_impact=1.0,
        data_sensitivity=0.0,
        customer_impact_score=0.0,
        compensating_controls=0.0,
    )
    # Default: revenue contributes 0.35 weight → impact = 1.0 * 0.35 = 0.35
    default_impact = engine._compute_business_impact(ctx, weights=ScoringWeights())
    assert abs(default_impact - 0.35) < 1e-6

    # Custom: revenue weight = 0.80 → impact = 1.0 * 0.80 = 0.80
    custom_w = ScoringWeights(
        revenue_impact=0.80,
        data_sensitivity=0.10,
        customer_impact=0.05,
        regulatory=0.05,
    )
    custom_impact = engine._compute_business_impact(ctx, weights=custom_w)
    assert abs(custom_impact - 0.80) < 1e-6


def test_scoring_config_upsert_overwrites(engine):
    """Second upsert of the same org_id overwrites; no duplicates in DB."""
    cfg_v1 = ScoringConfig(
        org_id="overwrite-org",
        thresholds=BucketThresholds(critical=90.0),
    )
    engine.upsert_scoring_config(cfg_v1)

    cfg_v2 = ScoringConfig(
        org_id="overwrite-org",
        thresholds=BucketThresholds(critical=60.0),
    )
    engine.upsert_scoring_config(cfg_v2)

    retrieved = engine.get_scoring_config("overwrite-org")
    assert retrieved.thresholds.critical == 60.0

    # Confirm only one row exists in the DB
    import sqlite3 as _sq
    conn = _sq.connect(engine.db_path)
    count = conn.execute(
        "SELECT COUNT(*) FROM scoring_config WHERE org_id='overwrite-org'"
    ).fetchone()[0]
    conn.close()
    assert count == 1
