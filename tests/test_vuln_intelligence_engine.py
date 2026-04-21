"""Tests for VulnIntelligenceEngine (suite-core/core/vuln_intelligence_engine.py).

Covers: CVE add/update/filter, advisory lifecycle, subscriptions, stats,
org isolation, validation errors.
All tests use an in-memory temp SQLite DB — no real I/O side effects.
"""

from __future__ import annotations

import pytest

from core.vuln_intelligence_engine import VulnIntelligenceEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_vuln_intel.db")
    return VulnIntelligenceEngine(db_path=db)


ORG = "org-alpha"
ORG2 = "org-beta"


def _cve_data(**kwargs):
    base = {
        "cve_id": "CVE-2024-12345",
        "title": "Test Vuln",
        "description": "A critical test vulnerability",
        "cvss_score": 9.8,
        "severity": "critical",
        "kev_listed": True,
        "exploit_available": True,
        "exploit_type": "in_the_wild",
        "patch_available": False,
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# CVE add tests
# ---------------------------------------------------------------------------

def test_add_cve_basic(engine):
    cve = engine.add_cve(ORG, _cve_data())
    assert cve["id"]
    assert cve["cve_id"] == "CVE-2024-12345"
    assert cve["severity"] == "critical"
    assert cve["kev_listed"] is True
    assert cve["exploit_available"] is True
    assert cve["org_id"] == ORG


def test_add_cve_missing_id(engine):
    with pytest.raises(ValueError, match="cve_id"):
        engine.add_cve(ORG, {"title": "no id"})


def test_add_cve_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.add_cve(ORG, {"cve_id": "CVE-2024-1", "severity": "extreme"})


def test_add_cve_normalizes_id_uppercase(engine):
    cve = engine.add_cve(ORG, {"cve_id": "cve-2024-99999"})
    assert cve["cve_id"] == "CVE-2024-99999"


def test_add_cve_upsert_updates_existing(engine):
    engine.add_cve(ORG, _cve_data(title="Original"))
    updated = engine.add_cve(ORG, _cve_data(title="Updated", cvss_score=7.5))
    assert updated["title"] == "Updated"
    assert updated["cvss_score"] == 7.5
    # Should still be 1 record
    cves = engine.list_cves(ORG)
    assert len(cves) == 1


def test_add_cve_with_affected_products(engine):
    products = [{"vendor": "acme", "product": "widget", "version_range": "< 2.0"}]
    cve = engine.add_cve(ORG, _cve_data(affected_products=products))
    assert isinstance(cve["affected_products"], list)
    assert cve["affected_products"][0]["vendor"] == "acme"


def test_add_cve_with_references(engine):
    refs = ["https://nvd.nist.gov/vuln/detail/CVE-2024-12345", "https://example.com/advisory"]
    cve = engine.add_cve(ORG, _cve_data(references=refs))
    assert len(cve["ref_urls"]) == 2


def test_add_cve_status_new(engine):
    cve = engine.add_cve(ORG, _cve_data())
    assert cve["status"] == "new"


# ---------------------------------------------------------------------------
# CVE list / get tests
# ---------------------------------------------------------------------------

def test_list_cves_empty(engine):
    assert engine.list_cves(ORG) == []


def test_list_cves_multiple(engine):
    engine.add_cve(ORG, _cve_data(cve_id="CVE-2024-1"))
    engine.add_cve(ORG, _cve_data(cve_id="CVE-2024-2", severity="high"))
    engine.add_cve(ORG, _cve_data(cve_id="CVE-2024-3", severity="medium"))
    assert len(engine.list_cves(ORG)) == 3


def test_list_cves_filter_severity(engine):
    engine.add_cve(ORG, _cve_data(cve_id="CVE-A", severity="critical"))
    engine.add_cve(ORG, _cve_data(cve_id="CVE-B", severity="high"))
    crits = engine.list_cves(ORG, severity="critical")
    assert len(crits) == 1 and crits[0]["severity"] == "critical"


def test_list_cves_filter_kev(engine):
    engine.add_cve(ORG, _cve_data(cve_id="CVE-K", kev_listed=True))
    engine.add_cve(ORG, _cve_data(cve_id="CVE-NK", kev_listed=False))
    kev = engine.list_cves(ORG, kev_listed=True)
    assert len(kev) == 1


def test_list_cves_filter_exploit(engine):
    engine.add_cve(ORG, _cve_data(cve_id="CVE-E", exploit_available=True))
    engine.add_cve(ORG, _cve_data(cve_id="CVE-NE", exploit_available=False))
    exploitable = engine.list_cves(ORG, exploit_available=True)
    assert len(exploitable) == 1


def test_list_cves_filter_status(engine):
    engine.add_cve(ORG, _cve_data(cve_id="CVE-NEW", status="new"))
    engine.add_cve(ORG, _cve_data(cve_id="CVE-PAT", status="patched"))
    patched = engine.list_cves(ORG, status="patched")
    assert len(patched) == 1


def test_list_cves_limit(engine):
    for i in range(10):
        engine.add_cve(ORG, _cve_data(cve_id=f"CVE-2024-{i:04d}"))
    result = engine.list_cves(ORG, limit=3)
    assert len(result) == 3


def test_get_cve_found(engine):
    engine.add_cve(ORG, _cve_data())
    cve = engine.get_cve(ORG, "CVE-2024-12345")
    assert cve is not None
    assert cve["cve_id"] == "CVE-2024-12345"


def test_get_cve_not_found(engine):
    assert engine.get_cve(ORG, "CVE-9999-9999") is None


def test_get_cve_case_insensitive(engine):
    engine.add_cve(ORG, _cve_data())
    cve = engine.get_cve(ORG, "cve-2024-12345")
    assert cve is not None


# ---------------------------------------------------------------------------
# CVE status update tests
# ---------------------------------------------------------------------------

def test_update_cve_status(engine):
    engine.add_cve(ORG, _cve_data())
    result = engine.update_cve_status(ORG, "CVE-2024-12345", "patched")
    assert result is True
    cve = engine.get_cve(ORG, "CVE-2024-12345")
    assert cve["status"] == "patched"


def test_update_cve_status_invalid(engine):
    engine.add_cve(ORG, _cve_data())
    with pytest.raises(ValueError, match="status"):
        engine.update_cve_status(ORG, "CVE-2024-12345", "hacked")


def test_update_cve_status_not_found(engine):
    result = engine.update_cve_status(ORG, "CVE-9999-9999", "patched")
    assert result is False


# ---------------------------------------------------------------------------
# Advisory tests
# ---------------------------------------------------------------------------

def test_add_advisory_basic(engine):
    adv = engine.add_advisory(ORG, {
        "vendor": "Microsoft",
        "product": "Windows",
        "severity": "critical",
        "advisory_id": "MS-2024-001",
        "cves_covered": ["CVE-2024-12345"],
        "patch_version": "KB5000001",
    })
    assert adv["id"]
    assert adv["vendor"] == "Microsoft"
    assert adv["status"] == "new"
    assert "CVE-2024-12345" in adv["cves_covered"]


def test_add_advisory_missing_vendor(engine):
    with pytest.raises(ValueError, match="vendor"):
        engine.add_advisory(ORG, {"product": "Windows"})


def test_list_advisories_empty(engine):
    assert engine.list_advisories(ORG) == []


def test_list_advisories_filter_vendor(engine):
    engine.add_advisory(ORG, {"vendor": "Microsoft", "product": "Office"})
    engine.add_advisory(ORG, {"vendor": "Adobe", "product": "Acrobat"})
    result = engine.list_advisories(ORG, vendor="Microsoft")
    assert len(result) == 1 and result[0]["vendor"] == "Microsoft"


def test_list_advisories_filter_status(engine):
    engine.add_advisory(ORG, {"vendor": "Apple"})
    result = engine.list_advisories(ORG, status="new")
    assert len(result) == 1


def test_apply_advisory(engine):
    adv = engine.add_advisory(ORG, {"vendor": "Oracle"})
    result = engine.apply_advisory(ORG, adv["id"])
    assert result is True
    applied = engine.list_advisories(ORG, status="applied")
    assert len(applied) == 1


def test_apply_advisory_not_found(engine):
    assert engine.apply_advisory(ORG, "bad-id") is False


# ---------------------------------------------------------------------------
# Subscription tests
# ---------------------------------------------------------------------------

def test_add_subscription_vendor(engine):
    sub = engine.add_subscription(ORG, {
        "subscription_type": "vendor",
        "subscription_value": "Microsoft",
        "notify_severity_min": "high",
    })
    assert sub["id"]
    assert sub["subscription_type"] == "vendor"
    assert sub["active"] is True


def test_add_subscription_missing_value(engine):
    with pytest.raises(ValueError, match="subscription_value"):
        engine.add_subscription(ORG, {"subscription_type": "vendor"})


def test_add_subscription_invalid_type(engine):
    with pytest.raises(ValueError, match="subscription_type"):
        engine.add_subscription(ORG, {"subscription_type": "bad_type", "subscription_value": "x"})


def test_list_subscriptions(engine):
    engine.add_subscription(ORG, {"subscription_type": "vendor", "subscription_value": "MSFT"})
    engine.add_subscription(ORG, {"subscription_type": "product", "subscription_value": "OpenSSL"})
    subs = engine.list_subscriptions(ORG)
    assert len(subs) == 2


# ---------------------------------------------------------------------------
# Stats tests
# ---------------------------------------------------------------------------

def test_get_intel_stats_empty(engine):
    stats = engine.get_intel_stats(ORG)
    assert stats["total_cves"] == 0
    assert stats["kev_count"] == 0
    assert stats["exploit_available"] == 0
    assert stats["patch_available"] == 0
    assert stats["avg_epss"] == 0.0
    assert stats["advisories_pending"] == 0


def test_get_intel_stats_populated(engine):
    engine.add_cve(ORG, _cve_data(
        cve_id="CVE-A", kev_listed=True, exploit_available=True,
        patch_available=False, epss_score=0.9,
        affected_products=[{"vendor": "acme", "product": "widget"}]
    ))
    engine.add_cve(ORG, _cve_data(
        cve_id="CVE-B", severity="high", kev_listed=False, exploit_available=False,
        patch_available=True, epss_score=0.5
    ))
    engine.add_advisory(ORG, {"vendor": "Acme"})  # status=new = pending

    stats = engine.get_intel_stats(ORG)
    assert stats["total_cves"] == 2
    assert stats["kev_count"] == 1
    assert stats["exploit_available"] == 1
    assert stats["patch_available"] == 1
    assert stats["avg_epss"] == pytest.approx(0.7, abs=0.01)
    assert stats["advisories_pending"] == 1
    assert "critical" in stats["by_severity"]
    assert len(stats["top_affected_products"]) >= 1


# ---------------------------------------------------------------------------
# Org isolation tests
# ---------------------------------------------------------------------------

def test_org_isolation_cves(engine):
    engine.add_cve(ORG, _cve_data())
    assert engine.list_cves(ORG2) == []
    assert engine.get_cve(ORG2, "CVE-2024-12345") is None


def test_org_isolation_advisories(engine):
    engine.add_advisory(ORG, {"vendor": "Microsoft"})
    assert engine.list_advisories(ORG2) == []


def test_org_isolation_subscriptions(engine):
    engine.add_subscription(ORG, {"subscription_type": "vendor", "subscription_value": "MSFT"})
    assert engine.list_subscriptions(ORG2) == []


def test_org_isolation_stats(engine):
    engine.add_cve(ORG, _cve_data())
    stats2 = engine.get_intel_stats(ORG2)
    assert stats2["total_cves"] == 0


# ---------------------------------------------------------------------------
# get_cve_context tests
# ---------------------------------------------------------------------------

def test_get_cve_context_returns_none_for_unknown(engine):
    """Context returns None when the CVE does not exist for the org."""
    result = engine.get_cve_context(ORG, "CVE-9999-99999")
    assert result is None


def test_get_cve_context_basic_structure(engine):
    """Context endpoint returns all required top-level keys with correct CVE data."""
    engine.add_cve(ORG, _cve_data(
        cve_id="CVE-2024-12345",
        title="Log4Shell",
        cvss_score=9.8,
        severity="critical",
    ))
    ctx = engine.get_cve_context(ORG, "CVE-2024-12345")

    assert ctx is not None
    # Required top-level keys
    assert "cve" in ctx
    assert "affected_components" in ctx
    assert "related_cves" in ctx
    assert "risk_score" in ctx
    # CVE details are correct
    assert ctx["cve"]["cve_id"] == "CVE-2024-12345"
    assert ctx["cve"]["cvss_score"] == 9.8
    assert ctx["cve"]["severity"] == "critical"
    # Lists are always present even when empty (no supply chain data in unit test)
    assert isinstance(ctx["affected_components"], list)
    assert isinstance(ctx["related_cves"], list)


def test_get_cve_context_related_cves_by_product(engine):
    """Related CVEs sharing an affected product are surfaced (up to 5)."""
    shared_product = [{"vendor": "apache", "product": "log4j"}]

    engine.add_cve(ORG, _cve_data(
        cve_id="CVE-2024-12345",
        affected_products=shared_product,
    ))
    engine.add_cve(ORG, _cve_data(
        cve_id="CVE-2024-11111",
        title="Related vuln in log4j",
        severity="high",
        cvss_score=7.5,
        affected_products=shared_product,
    ))
    # This one has a different product — should NOT appear as related
    engine.add_cve(ORG, _cve_data(
        cve_id="CVE-2024-22222",
        title="Unrelated vuln",
        severity="medium",
        cvss_score=4.0,
        affected_products=[{"vendor": "nginx", "product": "nginx"}],
    ))

    ctx = engine.get_cve_context(ORG, "CVE-2024-12345")
    related_ids = [r["cve_id"] for r in ctx["related_cves"]]

    assert "CVE-2024-11111" in related_ids
    assert "CVE-2024-22222" not in related_ids
    assert "CVE-2024-12345" not in related_ids  # self must not appear
