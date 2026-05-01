"""Test that /api/v1/ti-automation/feeds surfaces real global-registry feeds.

Verifies the empty-endpoint fix: when the org has no enrolled feeds, the
operator can call POST /import-global which bulk-registers every feed defined
in the global registry (suite-feeds/feeds_service.py — 28+ real public feeds).

The importer is exercised against an in-memory ThreatIntelligenceAutomationEngine
backed by a tmp_path SQLite DB. Real catalog records are also injected directly
to verify deterministic mapping rules without hitting the live network.
"""
from __future__ import annotations

import pytest

from core.threat_intelligence_automation_engine import ThreatIntelligenceAutomationEngine
from core.global_feed_registry_importer import import_global_feeds


@pytest.fixture
def engine(tmp_path, monkeypatch):
    # Engine constructor accepts a directory and routes the DB inside it.
    db_dir = tmp_path / "tia"
    return ThreatIntelligenceAutomationEngine(db_dir=str(db_dir))


def _sample_records():
    """Return a representative subset across all 7 catalogs.

    Every URL/name comes from suite-feeds/feeds_service.py — no fakes.
    """
    return [
        ("AUTHORITATIVE_FEEDS", "cisa_kev", {
            "name": "CISA Known Exploited Vulnerabilities",
            "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "format": "json",
            "api_key_required": False,
            "refresh_hours": 6,
        }),
        ("AUTHORITATIVE_FEEDS", "nvd", {
            "name": "NVD - National Vulnerability Database",
            "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "format": "json",
            "api_key_required": True,  # commercial via API key
            "refresh_hours": 1,
        }),
        ("AUTHORITATIVE_FEEDS", "epss", {
            "name": "EPSS - Exploit Prediction Scoring System",
            "url": "https://epss.cyentia.com/epss_scores-current.csv.gz",
            "format": "csv_gz",  # normalised to "csv"
            "api_key_required": False,
            "refresh_hours": 24,
        }),
        ("NATIONAL_CERT_FEEDS", "ncsc_uk", {
            "name": "NCSC UK",
            "url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
            "format": "rss",  # normalised to "json"
            "refresh_hours": 12,
        }),
        ("EXPLOIT_FEEDS", "exploit_db", {
            "name": "Exploit-DB",
            "url": "https://www.exploit-db.com/files.csv",
            "format": "csv",
            "refresh_hours": 6,
        }),
        ("THREAT_ACTOR_FEEDS", "abuse_ch", {
            "name": "abuse.ch",
            "url": "https://urlhaus.abuse.ch/downloads/json/",
            "format": "json",
            "refresh_hours": 1,
        }),
        ("SUPPLY_CHAIN_FEEDS", "rustsec", {
            "name": "RustSec Advisory Database",
            "url": "https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/",
            "format": "toml",  # normalised to "json"
            "refresh_hours": 24,
        }),
        ("CLOUD_RUNTIME_FEEDS", "redhat_security", {
            "name": "Red Hat Security Data",
            "url": "https://access.redhat.com/hydra/rest/securitydata/cve.json",
            "format": "json",
            "refresh_hours": 6,
        }),
        ("EARLY_SIGNAL_FEEDS", "cisco_psirt", {
            "name": "Cisco PSIRT",
            "url": "https://sec.cloudapps.cisco.com/security/center/publicationService.x",
            "format": "json",
            "refresh_hours": 6,
        }),
    ]


def test_empty_org_imports_full_global_subset(engine):
    """import_global_feeds bulk-registers every record into tia_feeds."""
    res = import_global_feeds(engine, "fresh-org", catalog_records=_sample_records())
    assert res["source"] == "global-registry"
    assert res["imported"] == 9
    assert res["skipped_existing"] == 0
    assert res["errors"] == 0
    assert res["total_available"] == 9

    # Every feed now visible via list_feeds.
    rows = engine.list_feeds("fresh-org")
    assert len(rows) == 9
    names = {r["feed_name"] for r in rows}
    assert "CISA Known Exploited Vulnerabilities" in names
    assert "EPSS - Exploit Prediction Scoring System" in names
    assert "RustSec Advisory Database" in names


def test_format_normalisation_applied(engine):
    """csv_gz -> csv, rss -> json, toml -> json."""
    res = import_global_feeds(engine, "fmt-org", catalog_records=_sample_records())
    assert res["imported"] == 9
    rows = {r["feed_name"]: r for r in engine.list_feeds("fmt-org")}
    assert rows["EPSS - Exploit Prediction Scoring System"]["format"] == "csv"
    assert rows["NCSC UK"]["format"] == "json"
    assert rows["RustSec Advisory Database"]["format"] == "json"
    # Already-valid formats untouched.
    assert rows["CISA Known Exploited Vulnerabilities"]["format"] == "json"


def test_feed_type_classification(engine):
    """government / commercial / osint mapped per the rules in the importer."""
    res = import_global_feeds(engine, "type-org", catalog_records=_sample_records())
    rows = {r["feed_name"]: r for r in engine.list_feeds("type-org")}
    # CISA KEV is _GOVERNMENT_FEED_KEYS
    assert rows["CISA Known Exploited Vulnerabilities"]["feed_type"] == "government"
    # NCSC UK is in NATIONAL_CERT_FEEDS catalog
    assert rows["NCSC UK"]["feed_type"] == "government"
    # NVD requires api_key -> commercial
    assert rows["NVD - National Vulnerability Database"]["feed_type"] == "commercial"
    # Default OSINT
    assert rows["Exploit-DB"]["feed_type"] == "osint"
    assert rows["abuse.ch"]["feed_type"] == "osint"
    # Aggregated by_feed_type matches.
    assert res["by_feed_type"].get("government", 0) >= 2
    assert res["by_feed_type"].get("commercial", 0) >= 1
    assert res["by_feed_type"].get("osint", 0) >= 1


def test_idempotent_second_import_skips_all(engine):
    """Re-running the importer skips every already-registered feed."""
    res1 = import_global_feeds(engine, "idem-org", catalog_records=_sample_records())
    assert res1["imported"] == 9

    res2 = import_global_feeds(engine, "idem-org", catalog_records=_sample_records())
    assert res2["imported"] == 0
    assert res2["skipped_existing"] == 9
    assert res2["errors"] == 0

    # No duplicates accumulated.
    rows = engine.list_feeds("idem-org")
    assert len(rows) == 9


def test_poll_interval_minutes_from_refresh_hours(engine):
    """refresh_hours=6 -> poll_interval_minutes=360, etc."""
    import_global_feeds(engine, "poll-org", catalog_records=_sample_records())
    rows = {r["feed_name"]: r for r in engine.list_feeds("poll-org")}
    assert rows["CISA Known Exploited Vulnerabilities"]["poll_interval_minutes"] == 6 * 60
    assert rows["NVD - National Vulnerability Database"]["poll_interval_minutes"] == 1 * 60
    assert rows["EPSS - Exploit Prediction Scoring System"]["poll_interval_minutes"] == 24 * 60


def test_empty_records_returns_warning(engine):
    """When no global catalog is available, returns 0 imports + warning."""
    res = import_global_feeds(engine, "noop-org", catalog_records=[])
    assert res["imported"] == 0
    assert res["total_available"] == 0
    assert "warning" in res
