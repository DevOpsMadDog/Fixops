"""Tests for DarkWebMonitoringEngine — ALDECI."""

from __future__ import annotations

import pytest

from core.dark_web_monitoring_engine import DarkWebMonitoringEngine


@pytest.fixture
def engine(tmp_path):
    return DarkWebMonitoringEngine(db_path=str(tmp_path / "darkweb.db"))


# ---------------------------------------------------------------------------
# add_mention — valid types
# ---------------------------------------------------------------------------

VALID_MENTION_TYPES = [
    "credential_leak",
    "data_dump",
    "phishing_kit",
    "malware_sale",
    "exploit_sale",
    "brand_mention",
    "executive_mention",
]


@pytest.mark.parametrize("mention_type", VALID_MENTION_TYPES)
def test_add_mention_all_valid_types(engine, mention_type):
    m = engine.add_mention("org1", {
        "mention_type": mention_type,
        "source_category": "forum",
        "keyword_matched": "acme.com",
        "severity": "high",
    })
    assert m["mention_type"] == mention_type
    assert m["status"] == "new"
    assert m["org_id"] == "org1"
    assert "id" in m
    assert "discovered_at" in m
    assert "updated_at" in m


def test_add_mention_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="mention_type"):
        engine.add_mention("org1", {
            "mention_type": "bad_type",
            "source_category": "forum",
            "keyword_matched": "acme.com",
        })


def test_add_mention_invalid_source_category_raises(engine):
    with pytest.raises(ValueError, match="source_category"):
        engine.add_mention("org1", {
            "mention_type": "credential_leak",
            "source_category": "invalid_src",
            "keyword_matched": "acme.com",
        })


def test_add_mention_invalid_severity_raises(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.add_mention("org1", {
            "mention_type": "brand_mention",
            "source_category": "paste_site",
            "keyword_matched": "acme.com",
            "severity": "extreme",
        })


def test_add_mention_missing_keyword_raises(engine):
    with pytest.raises(ValueError, match="keyword_matched"):
        engine.add_mention("org1", {
            "mention_type": "data_dump",
            "source_category": "paste_site",
            "keyword_matched": "",
        })


# ---------------------------------------------------------------------------
# Source categories
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("source_cat", [
    "paste_site", "forum", "marketplace", "telegram", "ransomware_site"
])
def test_add_mention_all_source_categories(engine, source_cat):
    m = engine.add_mention("org1", {
        "mention_type": "brand_mention",
        "source_category": source_cat,
        "keyword_matched": "acme",
    })
    assert m["source_category"] == source_cat


# ---------------------------------------------------------------------------
# Content preview truncation
# ---------------------------------------------------------------------------

def test_content_preview_truncated_at_500(engine):
    long_content = "x" * 600
    m = engine.add_mention("org1", {
        "mention_type": "data_dump",
        "source_category": "paste_site",
        "keyword_matched": "acme.com",
        "content_preview": long_content,
    })
    assert len(m["content_preview"]) <= 500


# ---------------------------------------------------------------------------
# list_mentions
# ---------------------------------------------------------------------------

def test_list_mentions_empty(engine):
    assert engine.list_mentions("org1") == []


def test_list_mentions_returns_all(engine):
    for mt in ["credential_leak", "brand_mention"]:
        engine.add_mention("org1", {
            "mention_type": mt,
            "source_category": "forum",
            "keyword_matched": "kw",
        })
    result = engine.list_mentions("org1")
    assert len(result) == 2


def test_list_mentions_filter_by_type(engine):
    engine.add_mention("org1", {
        "mention_type": "credential_leak",
        "source_category": "paste_site",
        "keyword_matched": "kw",
    })
    engine.add_mention("org1", {
        "mention_type": "data_dump",
        "source_category": "forum",
        "keyword_matched": "kw",
    })
    result = engine.list_mentions("org1", mention_type="credential_leak")
    assert all(r["mention_type"] == "credential_leak" for r in result)
    assert len(result) == 1


def test_list_mentions_filter_by_severity(engine):
    engine.add_mention("org1", {"mention_type": "brand_mention", "source_category": "forum",
                                "keyword_matched": "kw", "severity": "critical"})
    engine.add_mention("org1", {"mention_type": "brand_mention", "source_category": "forum",
                                "keyword_matched": "kw", "severity": "low"})
    result = engine.list_mentions("org1", severity="critical")
    assert len(result) == 1
    assert result[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# get_mention
# ---------------------------------------------------------------------------

def test_get_mention_found(engine):
    m = engine.add_mention("org1", {
        "mention_type": "phishing_kit",
        "source_category": "marketplace",
        "keyword_matched": "acme",
    })
    fetched = engine.get_mention("org1", m["id"])
    assert fetched["id"] == m["id"]


def test_get_mention_not_found(engine):
    assert engine.get_mention("org1", "nonexistent") is None


def test_get_mention_wrong_org(engine):
    m = engine.add_mention("org1", {
        "mention_type": "brand_mention",
        "source_category": "forum",
        "keyword_matched": "kw",
    })
    assert engine.get_mention("org2", m["id"]) is None


# ---------------------------------------------------------------------------
# update_mention_status
# ---------------------------------------------------------------------------

VALID_STATUSES = ["new", "investigating", "confirmed", "false_positive", "mitigated"]


@pytest.mark.parametrize("new_status", VALID_STATUSES)
def test_update_mention_status_valid(engine, new_status):
    m = engine.add_mention("org1", {
        "mention_type": "credential_leak",
        "source_category": "paste_site",
        "keyword_matched": "kw",
    })
    updated = engine.update_mention_status("org1", m["id"], new_status)
    assert updated["status"] == new_status


def test_update_mention_status_invalid_raises(engine):
    m = engine.add_mention("org1", {
        "mention_type": "brand_mention",
        "source_category": "forum",
        "keyword_matched": "kw",
    })
    with pytest.raises(ValueError):
        engine.update_mention_status("org1", m["id"], "bad_status")


def test_update_mention_status_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.update_mention_status("org1", "nonexistent", "confirmed")


def test_update_mention_status_lifecycle(engine):
    m = engine.add_mention("org1", {
        "mention_type": "exploit_sale",
        "source_category": "marketplace",
        "keyword_matched": "acme",
    })
    assert m["status"] == "new"
    u1 = engine.update_mention_status("org1", m["id"], "investigating")
    assert u1["status"] == "investigating"
    u2 = engine.update_mention_status("org1", m["id"], "confirmed")
    assert u2["status"] == "confirmed"
    u3 = engine.update_mention_status("org1", m["id"], "mitigated")
    assert u3["status"] == "mitigated"


# ---------------------------------------------------------------------------
# add_keyword / list_keywords
# ---------------------------------------------------------------------------

VALID_KEYWORD_TYPES = ["domain", "email_domain", "brand", "executive_name", "product", "ip_range"]


@pytest.mark.parametrize("ktype", VALID_KEYWORD_TYPES)
def test_add_keyword_all_types(engine, ktype):
    kw = engine.add_keyword("org1", {"keyword": "acme.com", "keyword_type": ktype})
    assert kw["keyword_type"] == ktype
    assert kw["is_active"] is True


def test_add_keyword_missing_keyword_raises(engine):
    with pytest.raises(ValueError, match="keyword"):
        engine.add_keyword("org1", {"keyword": "", "keyword_type": "domain"})


def test_add_keyword_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="keyword_type"):
        engine.add_keyword("org1", {"keyword": "test", "keyword_type": "bad"})


def test_list_keywords_filter_by_type(engine):
    engine.add_keyword("org1", {"keyword": "acme.com", "keyword_type": "domain"})
    engine.add_keyword("org1", {"keyword": "ceo@acme.com", "keyword_type": "executive_name"})
    domains = engine.list_keywords("org1", keyword_type="domain")
    assert len(domains) == 1
    assert domains[0]["keyword_type"] == "domain"


def test_list_keywords_filter_by_is_active(engine):
    engine.add_keyword("org1", {"keyword": "kw1", "keyword_type": "brand"})
    result = engine.list_keywords("org1", is_active=True)
    assert len(result) >= 1
    for r in result:
        assert r["is_active"] == 1


# ---------------------------------------------------------------------------
# record_credential_exposure / list_credential_exposures
# ---------------------------------------------------------------------------

def test_record_credential_exposure_valid(engine):
    exp = engine.record_credential_exposure("org1", {
        "email_domain": "acme.com",
        "exposure_count": 150,
        "source": "breach_db",
    })
    assert exp["email_domain"] == "acme.com"
    assert exp["exposure_count"] == 150
    assert exp["verified"] == 0


def test_record_credential_exposure_missing_domain_raises(engine):
    with pytest.raises(ValueError, match="email_domain"):
        engine.record_credential_exposure("org1", {
            "email_domain": "",
            "exposure_count": 1,
            "source": "breach_db",
        })


def test_record_credential_exposure_invalid_source_raises(engine):
    with pytest.raises(ValueError, match="source"):
        engine.record_credential_exposure("org1", {
            "email_domain": "acme.com",
            "exposure_count": 1,
            "source": "unknown_source",
        })


def test_record_credential_exposure_count_zero_raises(engine):
    with pytest.raises(ValueError, match="exposure_count"):
        engine.record_credential_exposure("org1", {
            "email_domain": "acme.com",
            "exposure_count": 0,
            "source": "paste_site",
        })


@pytest.mark.parametrize("source", ["breach_db", "paste_site", "dark_forum"])
def test_record_credential_exposure_all_sources(engine, source):
    exp = engine.record_credential_exposure("org1", {
        "email_domain": "test.com",
        "exposure_count": 10,
        "source": source,
    })
    assert exp["source"] == source


def test_list_credential_exposures_filter_verified(engine):
    engine.record_credential_exposure("org1", {
        "email_domain": "acme.com", "exposure_count": 5, "source": "breach_db", "verified": True
    })
    engine.record_credential_exposure("org1", {
        "email_domain": "beta.com", "exposure_count": 3, "source": "paste_site", "verified": False
    })
    verified = engine.list_credential_exposures("org1", verified=True)
    assert all(r["verified"] == 1 for r in verified)
    unverified = engine.list_credential_exposures("org1", verified=False)
    assert all(r["verified"] == 0 for r in unverified)


# ---------------------------------------------------------------------------
# get_dark_web_stats
# ---------------------------------------------------------------------------

def test_get_dark_web_stats_empty(engine):
    stats = engine.get_dark_web_stats("org1")
    assert stats["total_mentions"] == 0
    assert stats["new_mentions"] == 0
    assert stats["active_keywords"] == 0
    assert stats["total_exposures"] == 0
    assert stats["unverified_exposures"] == 0
    assert stats["by_type"] == {}
    assert stats["by_severity"] == {}


def test_get_dark_web_stats_counting(engine):
    engine.add_mention("org1", {
        "mention_type": "credential_leak", "source_category": "paste_site",
        "keyword_matched": "kw", "severity": "critical"
    })
    engine.add_mention("org1", {
        "mention_type": "brand_mention", "source_category": "forum",
        "keyword_matched": "kw", "severity": "low"
    })
    engine.add_keyword("org1", {"keyword": "acme.com", "keyword_type": "domain"})
    engine.record_credential_exposure("org1", {
        "email_domain": "acme.com", "exposure_count": 10, "source": "breach_db"
    })

    stats = engine.get_dark_web_stats("org1")
    assert stats["total_mentions"] == 2
    assert stats["new_mentions"] == 2
    assert stats["active_keywords"] == 1
    assert stats["total_exposures"] == 1
    assert stats["unverified_exposures"] == 1
    assert stats["by_type"]["credential_leak"] == 1
    assert stats["by_type"]["brand_mention"] == 1
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["low"] == 1


def test_get_dark_web_stats_new_vs_mitigated(engine):
    m = engine.add_mention("org1", {
        "mention_type": "data_dump", "source_category": "forum",
        "keyword_matched": "kw",
    })
    engine.update_mention_status("org1", m["id"], "mitigated")
    stats = engine.get_dark_web_stats("org1")
    assert stats["total_mentions"] == 1
    assert stats["new_mentions"] == 0


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_mentions(engine):
    engine.add_mention("org1", {
        "mention_type": "brand_mention", "source_category": "forum", "keyword_matched": "kw"
    })
    assert engine.list_mentions("org2") == []


def test_org_isolation_keywords(engine):
    engine.add_keyword("org1", {"keyword": "acme.com", "keyword_type": "domain"})
    assert engine.list_keywords("org2") == []


def test_org_isolation_exposures(engine):
    engine.record_credential_exposure("org1", {
        "email_domain": "acme.com", "exposure_count": 5, "source": "breach_db"
    })
    assert engine.list_credential_exposures("org2") == []


def test_org_isolation_stats(engine):
    engine.add_mention("org1", {
        "mention_type": "malware_sale", "source_category": "marketplace", "keyword_matched": "kw"
    })
    stats_org2 = engine.get_dark_web_stats("org2")
    assert stats_org2["total_mentions"] == 0
