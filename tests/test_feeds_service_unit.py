"""Unit tests for suite-feeds/feeds_service.py — FeedsService + dataclasses.

Pillar: V3 (Decision Intelligence) — feeds enrich the FAIL engine and brain pipeline.
Coverage target: suite-feeds/feeds_service.py (3,042 LOC, ~0% baseline).
Created: 2026-03-01 by agent-doctor (health run v10).
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from feeds_service import (
    CloudSecurityBulletin,
    EarlySignal,
    EPSSScore,
    ExploitConfidenceScore,
    ExploitIntelligence,
    FeedCategory,
    FeedRefreshResult,
    FeedsService,
    GeoRegion,
    GeoWeightedRisk,
    KEVEntry,
    NationalCERTAdvisory,
    SupplyChainVuln,
    ThreatActorMapping,
    # Feed configs
    AUTHORITATIVE_FEEDS,
    CLOUD_RUNTIME_FEEDS,
    EARLY_SIGNAL_FEEDS,
    EXPLOIT_FEEDS,
    NATIONAL_CERT_FEEDS,
    SUPPLY_CHAIN_FEEDS,
    THREAT_ACTOR_FEEDS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def svc(tmp_path: Path) -> FeedsService:
    """Create a FeedsService with a temp database."""
    return FeedsService(db_path=tmp_path / "test_feeds.db", timeout=5.0)


@pytest.fixture
def populated_svc(svc: FeedsService) -> FeedsService:
    """FeedsService pre-populated with sample data across all tables."""
    conn = sqlite3.connect(svc.db_path)
    now = datetime.now(timezone.utc).isoformat()

    # EPSS
    conn.execute(
        "INSERT INTO epss_scores (cve_id, epss, percentile, date, updated_at) VALUES (?, ?, ?, ?, ?)",
        ("CVE-2021-44228", 0.975, 99.9, "2026-03-01", now),
    )
    conn.execute(
        "INSERT INTO epss_scores (cve_id, epss, percentile, date, updated_at) VALUES (?, ?, ?, ?, ?)",
        ("CVE-2023-0001", 0.12, 45.0, "2026-03-01", now),
    )

    # KEV
    conn.execute(
        "INSERT INTO kev_entries (cve_id, vendor_project, product, vulnerability_name, date_added, short_description, required_action, due_date, known_ransomware_campaign_use, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            "CVE-2021-44228",
            "Apache",
            "Log4j",
            "Apache Log4j2 RCE",
            "2021-12-10",
            "Remote code execution via JNDI",
            "Apply updates",
            "2022-01-01",
            "Known",
            now,
        ),
    )

    # NVD
    conn.execute(
        "INSERT INTO nvd_cves (cve_id, description, severity, cvss_score, cvss_vector, cwe_ids, affected_packages, references_json, published, modified, source_identifier, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "CVE-2021-44228",
            "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI RCE",
            "CRITICAL",
            10.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            json.dumps(["CWE-502", "CWE-400"]),
            json.dumps(["org.apache.logging.log4j:log4j-core"]),
            json.dumps(["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]),
            "2021-12-10",
            "2022-01-20",
            "nvd@nist.gov",
            now,
        ),
    )
    conn.execute(
        "INSERT INTO nvd_cves (cve_id, description, severity, cvss_score, cvss_vector, cwe_ids, affected_packages, references_json, published, modified, source_identifier, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "CVE-2023-0001",
            "Test medium vuln",
            "MEDIUM",
            5.5,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            json.dumps(["CWE-79"]),
            json.dumps(["test-package"]),
            json.dumps([]),
            "2023-01-15",
            "2023-02-01",
            "nvd@nist.gov",
            now,
        ),
    )

    # Exploit intelligence
    conn.execute(
        "INSERT INTO exploit_intelligence (cve_id, exploit_source, exploit_type, exploit_url, exploit_date, verified, reliability, metasploit_module, nuclei_template, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            "CVE-2021-44228",
            "exploit-db",
            "remote",
            "https://exploit-db.com/exploits/50592",
            "2021-12-12",
            1,
            "high",
            "exploits/multi/http/log4shell_header_injection",
            "cves/2021/CVE-2021-44228.yaml",
            now,
        ),
    )

    # Threat actor
    conn.execute(
        "INSERT INTO threat_actor_mappings (cve_id, threat_actor, campaign, first_seen, last_seen, target_sectors, target_countries, ttps, confidence, source, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            "CVE-2021-44228",
            "APT41",
            "Log4Shell Campaign",
            "2021-12-12",
            "2022-06-01",
            json.dumps(["technology", "finance"]),
            json.dumps(["US", "EU"]),
            json.dumps(["T1190", "T1059"]),
            "high",
            "mandiant",
            now,
        ),
    )

    conn.commit()
    conn.close()
    return svc


# ---------------------------------------------------------------------------
# 1. Enum Tests
# ---------------------------------------------------------------------------


class TestEnums:
    def test_feed_category_values(self):
        assert FeedCategory.AUTHORITATIVE == "authoritative"
        assert FeedCategory.EXPLOIT == "exploit"
        assert FeedCategory.THREAT_ACTOR == "threat_actor"
        assert FeedCategory.SUPPLY_CHAIN == "supply_chain"
        assert FeedCategory.CLOUD_RUNTIME == "cloud_runtime"
        assert FeedCategory.EARLY_SIGNAL == "early_signal"
        assert FeedCategory.ENTERPRISE == "enterprise"
        assert FeedCategory.NATIONAL_CERT == "national_cert"

    def test_geo_region_values(self):
        assert GeoRegion.GLOBAL == "global"
        assert GeoRegion.NORTH_AMERICA == "north_america"
        assert GeoRegion.EUROPE == "europe"
        assert GeoRegion.ASIA_PACIFIC == "asia_pacific"
        assert GeoRegion.MIDDLE_EAST == "middle_east"
        assert GeoRegion.LATIN_AMERICA == "latin_america"


# ---------------------------------------------------------------------------
# 2. Dataclass Tests
# ---------------------------------------------------------------------------


class TestEPSSScore:
    def test_create(self):
        s = EPSSScore(cve_id="CVE-2021-44228", epss=0.975, percentile=99.9, date="2026-01-01")
        assert s.cve_id == "CVE-2021-44228"
        assert s.epss == 0.975
        assert s.percentile == 99.9

    def test_to_dict(self):
        s = EPSSScore(cve_id="CVE-2021-44228", epss=0.5, percentile=50.0, date="2026-01-01")
        d = s.to_dict()
        assert d["cve_id"] == "CVE-2021-44228"
        assert d["epss"] == 0.5
        assert "percentile" in d


class TestKEVEntry:
    def test_create(self):
        k = KEVEntry(
            cve_id="CVE-2021-44228",
            vendor_project="Apache",
            product="Log4j",
            vulnerability_name="Log4Shell",
            date_added="2021-12-10",
            short_description="RCE",
            required_action="Patch",
            due_date="2022-01-01",
            known_ransomware_campaign_use="Known",
        )
        assert k.product == "Log4j"
        assert k.known_ransomware_campaign_use == "Known"

    def test_to_dict(self):
        k = KEVEntry(
            cve_id="CVE-2021-44228",
            vendor_project="Apache",
            product="Log4j",
            vulnerability_name="Log4Shell",
            date_added="2021-12-10",
            short_description="RCE",
            required_action="Patch",
            due_date="2022-01-01",
            known_ransomware_campaign_use="Known",
        )
        d = k.to_dict()
        assert d["cve_id"] == "CVE-2021-44228"
        assert "vendor_project" in d


class TestExploitIntelligence:
    def test_to_dict(self):
        e = ExploitIntelligence(
            cve_id="CVE-2021-44228",
            exploit_source="exploit-db",
            exploit_type="remote",
            exploit_url="https://example.com",
            exploit_date="2021-12-12",
            verified=True,
            reliability="high",
            metasploit_module="log4shell",
            nuclei_template="cve-2021-44228",
        )
        d = e.to_dict()
        assert d["verified"] is True
        assert d["exploit_source"] == "exploit-db"


class TestThreatActorMapping:
    def test_to_dict(self):
        t = ThreatActorMapping(
            cve_id="CVE-2021-44228",
            threat_actor="APT41",
            campaign="Log4Shell",
            first_seen="2021-12",
            last_seen="2022-06",
            target_sectors=["tech"],
            target_countries=["US"],
            ttps=["T1190"],
            confidence="high",
            source="mandiant",
        )
        d = t.to_dict()
        assert d["threat_actor"] == "APT41"
        assert "target_sectors" in d


class TestSupplyChainVuln:
    def test_to_dict(self):
        s = SupplyChainVuln(
            vuln_id="CVE-2023-0001",
            ecosystem="npm",
            package_name="lodash",
            affected_versions="<4.17.21",
            patched_versions="4.17.21",
            severity="high",
            source="osv",
        )
        d = s.to_dict()
        assert d["package_name"] == "lodash"
        assert d["ecosystem"] == "npm"
        assert d["vuln_id"] == "CVE-2023-0001"


class TestCloudSecurityBulletin:
    def test_to_dict(self):
        b = CloudSecurityBulletin(
            bulletin_id="AWS-2026-001",
            provider="aws",
            title="EKS CVE",
            severity="critical",
            cve_ids=["CVE-2026-0001"],
            affected_services=["EKS"],
            published_date="2026-01-01",
            remediation="Update EKS",
        )
        d = b.to_dict()
        assert d["provider"] == "aws"
        assert "CVE-2026-0001" in d["cve_ids"]
        assert d["remediation"] == "Update EKS"


class TestEarlySignal:
    def test_to_dict(self):
        e = EarlySignal(
            signal_id="SIG-001",
            signal_type="vendor_advisory",
            title="Possible 0-day",
            description="Unpatched RCE in Exchange",
            cve_id="CVE-2026-0001",
            severity_estimate="critical",
            confidence="high",
        )
        d = e.to_dict()
        assert d["signal_type"] == "vendor_advisory"
        assert d["confidence"] == "high"
        assert d["cve_id"] == "CVE-2026-0001"


class TestNationalCERTAdvisory:
    def test_to_dict(self):
        a = NationalCERTAdvisory(
            advisory_id="NCSC-2026-001",
            cert_name="NCSC-UK",
            country="GB",
            region="europe",
            title="Log4Shell advisory",
            severity="critical",
            cve_ids=["CVE-2021-44228"],
            published_date="2021-12-13",
            url="https://ncsc.gov.uk",
        )
        d = a.to_dict()
        assert d["cert_name"] == "NCSC-UK"
        assert d["region"] == "europe"
        assert d["country"] == "GB"


class TestGeoWeightedRisk:
    def test_to_dict(self):
        g = GeoWeightedRisk(
            cve_id="CVE-2021-44228",
            base_score=9.5,
            geo_scores={"north_america": 11.4, "europe": 10.2},
            cert_mentions={"europe": ["NCSC-001"]},
        )
        d = g.to_dict()
        assert d["base_score"] == 9.5
        assert "north_america" in d["geo_scores"]
        assert d["cve_id"] == "CVE-2021-44228"


class TestExploitConfidenceScore:
    def test_to_dict(self):
        e = ExploitConfidenceScore(
            cve_id="CVE-2021-44228",
            confidence_score=0.85,
            factors={"epss_score": 0.975, "in_kev": 1.0},
            calculated_at="2026-01-01",
        )
        d = e.to_dict()
        assert d["confidence_score"] == 0.85
        assert "factors" in d


# ---------------------------------------------------------------------------
# 3. Feed Config Tests
# ---------------------------------------------------------------------------


class TestFeedConfigs:
    def test_authoritative_feeds_populated(self):
        assert len(AUTHORITATIVE_FEEDS) >= 5
        assert "nvd" in AUTHORITATIVE_FEEDS
        assert "cisa_kev" in AUTHORITATIVE_FEEDS

    def test_exploit_feeds_populated(self):
        assert len(EXPLOIT_FEEDS) >= 5
        assert "exploit_db" in EXPLOIT_FEEDS

    def test_threat_actor_feeds_populated(self):
        assert len(THREAT_ACTOR_FEEDS) >= 3
        assert "mitre_attack" in THREAT_ACTOR_FEEDS

    def test_supply_chain_feeds_populated(self):
        assert len(SUPPLY_CHAIN_FEEDS) >= 4
        assert "osv" in SUPPLY_CHAIN_FEEDS

    def test_cloud_runtime_feeds_populated(self):
        assert len(CLOUD_RUNTIME_FEEDS) >= 5
        assert "aws_security" in CLOUD_RUNTIME_FEEDS

    def test_early_signal_feeds_populated(self):
        assert len(EARLY_SIGNAL_FEEDS) >= 2

    def test_national_cert_feeds_populated(self):
        assert len(NATIONAL_CERT_FEEDS) >= 5

    def test_feed_url_format(self):
        for feed_dict in [
            AUTHORITATIVE_FEEDS,
            EXPLOIT_FEEDS,
            SUPPLY_CHAIN_FEEDS,
            CLOUD_RUNTIME_FEEDS,
        ]:
            for key, feed in feed_dict.items():
                assert "url" in feed, f"{key} missing url"
                assert "name" in feed, f"{key} missing name"
                assert feed["url"].startswith("http"), f"{key} URL invalid"


# ---------------------------------------------------------------------------
# 4. FeedsService Initialization
# ---------------------------------------------------------------------------


class TestFeedsServiceInit:
    def test_creates_db_file(self, svc: FeedsService):
        assert svc.db_path.exists()

    def test_db_has_epss_table(self, svc: FeedsService):
        conn = sqlite3.connect(svc.db_path)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='epss_scores'")
        assert cursor.fetchone() is not None
        conn.close()

    def test_db_has_kev_table(self, svc: FeedsService):
        conn = sqlite3.connect(svc.db_path)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='kev_entries'")
        assert cursor.fetchone() is not None
        conn.close()

    def test_db_has_nvd_table(self, svc: FeedsService):
        conn = sqlite3.connect(svc.db_path)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nvd_cves'")
        assert cursor.fetchone() is not None
        conn.close()

    def test_db_has_exploit_intelligence_table(self, svc: FeedsService):
        conn = sqlite3.connect(svc.db_path)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='exploit_intelligence'")
        assert cursor.fetchone() is not None
        conn.close()

    def test_db_has_threat_actor_table(self, svc: FeedsService):
        conn = sqlite3.connect(svc.db_path)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='threat_actor_mappings'")
        assert cursor.fetchone() is not None
        conn.close()

    def test_db_has_feed_metadata_table(self, svc: FeedsService):
        conn = sqlite3.connect(svc.db_path)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='feed_metadata'")
        assert cursor.fetchone() is not None
        conn.close()

    def test_default_timeout(self, tmp_path: Path):
        svc = FeedsService(db_path=tmp_path / "t.db")
        assert svc.timeout == 60.0

    def test_custom_timeout(self, tmp_path: Path):
        svc = FeedsService(db_path=tmp_path / "t.db", timeout=120.0)
        assert svc.timeout == 120.0

    def test_creates_parent_dirs(self, tmp_path: Path):
        deep_path = tmp_path / "a" / "b" / "c" / "feeds.db"
        FeedsService(db_path=deep_path)
        assert deep_path.parent.exists()


# ---------------------------------------------------------------------------
# 5. NVD CVE Methods
# ---------------------------------------------------------------------------


class TestNVDMethods:
    def test_get_nvd_cve_found(self, populated_svc: FeedsService):
        result = populated_svc.get_nvd_cve("CVE-2021-44228")
        assert result is not None
        assert result["cve_id"] == "CVE-2021-44228"
        assert result["severity"] == "CRITICAL"
        assert result["cvss_score"] == 10.0
        assert "CWE-502" in result["cwe_ids"]

    def test_get_nvd_cve_not_found(self, populated_svc: FeedsService):
        assert populated_svc.get_nvd_cve("CVE-9999-9999") is None

    def test_get_nvd_cve_case_insensitive(self, populated_svc: FeedsService):
        result = populated_svc.get_nvd_cve("cve-2021-44228")
        assert result is not None

    def test_get_recent_nvd_cves(self, populated_svc: FeedsService):
        results = populated_svc.get_recent_nvd_cves()
        assert len(results) == 2
        # Most recent first
        assert results[0]["cve_id"] == "CVE-2023-0001"

    def test_get_recent_nvd_cves_filter_severity(self, populated_svc: FeedsService):
        results = populated_svc.get_recent_nvd_cves(severity="CRITICAL")
        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2021-44228"

    def test_get_recent_nvd_cves_pagination(self, populated_svc: FeedsService):
        results = populated_svc.get_recent_nvd_cves(limit=1, offset=0)
        assert len(results) == 1

    def test_get_recent_nvd_cves_empty(self, svc: FeedsService):
        results = svc.get_recent_nvd_cves()
        assert results == []


# ---------------------------------------------------------------------------
# 6. EPSS Methods
# ---------------------------------------------------------------------------


class TestEPSSMethods:
    def test_get_epss_score_found(self, populated_svc: FeedsService):
        result = populated_svc.get_epss_score("CVE-2021-44228")
        assert result is not None
        assert isinstance(result, EPSSScore)
        assert result.epss == 0.975
        assert result.percentile == 99.9

    def test_get_epss_score_not_found(self, populated_svc: FeedsService):
        assert populated_svc.get_epss_score("CVE-9999-9999") is None

    def test_get_epss_score_case_insensitive(self, populated_svc: FeedsService):
        result = populated_svc.get_epss_score("cve-2021-44228")
        assert result is not None


# ---------------------------------------------------------------------------
# 7. KEV Methods
# ---------------------------------------------------------------------------


class TestKEVMethods:
    def test_get_kev_entry_found(self, populated_svc: FeedsService):
        result = populated_svc.get_kev_entry("CVE-2021-44228")
        assert result is not None
        assert isinstance(result, KEVEntry)
        assert result.product == "Log4j"

    def test_get_kev_entry_not_found(self, populated_svc: FeedsService):
        assert populated_svc.get_kev_entry("CVE-9999-9999") is None

    def test_is_in_kev_true(self, populated_svc: FeedsService):
        assert populated_svc.is_in_kev("CVE-2021-44228") is True

    def test_is_in_kev_false(self, populated_svc: FeedsService):
        assert populated_svc.is_in_kev("CVE-2023-0001") is False


# ---------------------------------------------------------------------------
# 8. Enrichment
# ---------------------------------------------------------------------------


class TestEnrichFindings:
    def test_enrich_with_epss_and_kev(self, populated_svc: FeedsService):
        findings = [{"cve_id": "CVE-2021-44228", "title": "Log4Shell"}]
        enriched = populated_svc.enrich_findings(findings)
        assert len(enriched) == 1
        assert enriched[0]["epss_score"] == 0.975
        assert enriched[0]["in_kev"] is True
        assert enriched[0]["kev_due_date"] == "2022-01-01"

    def test_enrich_without_kev(self, populated_svc: FeedsService):
        findings = [{"cve_id": "CVE-2023-0001"}]
        enriched = populated_svc.enrich_findings(findings)
        assert enriched[0]["in_kev"] is False
        assert enriched[0]["epss_score"] == 0.12

    def test_enrich_non_cve_finding(self, populated_svc: FeedsService):
        findings = [{"vulnerability_id": "GHSA-0001", "title": "Not a CVE"}]
        enriched = populated_svc.enrich_findings(findings)
        assert enriched[0]["epss_score"] is None
        assert enriched[0]["in_kev"] is False

    def test_enrich_empty_list(self, svc: FeedsService):
        assert svc.enrich_findings([]) == []

    def test_enrich_preserves_original_fields(self, populated_svc: FeedsService):
        findings = [{"cve_id": "CVE-2021-44228", "custom": "value"}]
        enriched = populated_svc.enrich_findings(findings)
        assert enriched[0]["custom"] == "value"

    def test_enrich_with_vulnerability_id_key(self, populated_svc: FeedsService):
        findings = [{"vulnerability_id": "CVE-2021-44228"}]
        enriched = populated_svc.enrich_findings(findings)
        assert enriched[0]["epss_score"] == 0.975


# ---------------------------------------------------------------------------
# 9. High Risk CVEs
# ---------------------------------------------------------------------------


class TestHighRiskCVEs:
    def test_get_high_risk_default_threshold(self, populated_svc: FeedsService):
        results = populated_svc.get_high_risk_cves()
        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2021-44228"

    def test_get_high_risk_low_threshold(self, populated_svc: FeedsService):
        results = populated_svc.get_high_risk_cves(epss_threshold=0.01)
        assert len(results) == 1  # Only CVE-2021-44228 is in KEV

    def test_get_high_risk_high_threshold(self, populated_svc: FeedsService):
        results = populated_svc.get_high_risk_cves(epss_threshold=0.99)
        assert len(results) == 0

    def test_get_high_risk_empty_db(self, svc: FeedsService):
        assert svc.get_high_risk_cves() == []


# ---------------------------------------------------------------------------
# 10. Feed Stats
# ---------------------------------------------------------------------------


class TestFeedStats:
    def test_stats_populated(self, populated_svc: FeedsService):
        stats = populated_svc.get_feed_stats()
        assert stats["epss"]["total_cves"] == 2
        assert stats["kev"]["total_cves"] == 1
        assert stats["overlap"]["cves_in_both"] == 1

    def test_stats_empty(self, svc: FeedsService):
        stats = svc.get_feed_stats()
        assert stats["epss"]["total_cves"] == 0
        assert stats["kev"]["total_cves"] == 0
        assert stats["overlap"]["cves_in_both"] == 0

    def test_stats_epss_avg(self, populated_svc: FeedsService):
        stats = populated_svc.get_feed_stats()
        expected_avg = round((0.975 + 0.12) / 2, 4)
        assert stats["epss"]["average_score"] == expected_avg


# ---------------------------------------------------------------------------
# 11. Threat Actor Methods
# ---------------------------------------------------------------------------


class TestThreatActorMethods:
    def test_add_and_get_threat_actor(self, svc: FeedsService):
        mapping = ThreatActorMapping(
            cve_id="CVE-2024-0001",
            threat_actor="Lazarus",
            campaign="OpDream",
            first_seen="2024-01",
            last_seen="2024-06",
            target_sectors=["finance"],
            target_countries=["KR"],
            ttps=["T1566"],
            confidence="medium",
            source="crowdstrike",
        )
        svc.add_threat_actor_mapping(mapping)
        results = svc.get_threat_actors_for_cve("CVE-2024-0001")
        assert len(results) == 1
        assert results[0].threat_actor == "Lazarus"
        assert results[0].confidence == "medium"

    def test_get_cves_by_threat_actor(self, populated_svc: FeedsService):
        cves = populated_svc.get_cves_by_threat_actor("APT41")
        assert "CVE-2021-44228" in cves

    def test_get_cves_by_unknown_actor(self, populated_svc: FeedsService):
        assert populated_svc.get_cves_by_threat_actor("UnknownActor") == []

    def test_get_all_threat_actors(self, populated_svc: FeedsService):
        actors = populated_svc.get_all_threat_actors()
        assert len(actors) >= 1
        assert actors[0]["threat_actor"] == "APT41"

    def test_get_all_threat_actors_pagination(self, populated_svc: FeedsService):
        actors = populated_svc.get_all_threat_actors(limit=1, offset=0)
        assert len(actors) == 1

    def test_get_all_threat_actors_empty(self, svc: FeedsService):
        actors = svc.get_all_threat_actors()
        assert actors == []

    def test_threat_actor_case_insensitive_cve(self, svc: FeedsService):
        mapping = ThreatActorMapping(
            cve_id="cve-2024-0002",
            threat_actor="FIN7",
            campaign=None,
            first_seen="2024-01",
            last_seen="2024-06",
            target_sectors=[],
            target_countries=[],
            ttps=[],
            confidence="low",
            source="internal",
        )
        svc.add_threat_actor_mapping(mapping)
        results = svc.get_threat_actors_for_cve("CVE-2024-0002")
        assert len(results) == 1


# ---------------------------------------------------------------------------
# 12. Exploit Intelligence Methods
# ---------------------------------------------------------------------------


class TestExploitIntelligenceMethods:
    def test_add_and_get_exploit(self, svc: FeedsService):
        exploit = ExploitIntelligence(
            cve_id="CVE-2024-1000",
            exploit_source="metasploit",
            exploit_type="remote",
            exploit_url="https://metasploit.com/module",
            exploit_date="2024-06-01",
            verified=True,
            reliability="high",
            metasploit_module="exploit/multi/http/test",
            nuclei_template=None,
        )
        svc.add_exploit_intelligence(exploit)
        results = svc.get_exploits_for_cve("CVE-2024-1000")
        assert len(results) == 1
        assert results[0].exploit_source == "metasploit"
        assert results[0].verified is True

    def test_get_exploits_for_cve_populated(self, populated_svc: FeedsService):
        results = populated_svc.get_exploits_for_cve("CVE-2021-44228")
        assert len(results) == 1
        assert results[0].metasploit_module is not None

    def test_get_exploits_not_found(self, svc: FeedsService):
        assert svc.get_exploits_for_cve("CVE-9999-9999") == []


# ---------------------------------------------------------------------------
# 13. Exploit Confidence Scoring [V3]
# ---------------------------------------------------------------------------


class TestExploitConfidence:
    def test_calculate_confidence_full_data(self, populated_svc: FeedsService):
        score = populated_svc.calculate_exploit_confidence("CVE-2021-44228")
        assert isinstance(score, ExploitConfidenceScore)
        assert score.confidence_score > 0.5  # High-risk CVE
        assert "epss_score" in score.factors
        assert "in_kev" in score.factors

    def test_calculate_confidence_minimal_data(self, populated_svc: FeedsService):
        score = populated_svc.calculate_exploit_confidence("CVE-2023-0001")
        assert isinstance(score, ExploitConfidenceScore)
        assert score.confidence_score < 0.5  # Low-risk, not in KEV

    def test_calculate_confidence_unknown_cve(self, svc: FeedsService):
        score = svc.calculate_exploit_confidence("CVE-9999-9999")
        assert isinstance(score, ExploitConfidenceScore)
        assert score.confidence_score == 0.0


# ---------------------------------------------------------------------------
# 14. Supply Chain Vuln Methods
# ---------------------------------------------------------------------------


class TestSupplyChainMethods:
    def test_add_and_get_supply_chain_vuln(self, svc: FeedsService):
        vuln = SupplyChainVuln(
            vuln_id="CVE-2024-2000",
            ecosystem="pip",
            package_name="requests",
            affected_versions="<2.28.1",
            patched_versions="2.28.1",
            severity="high",
            source="osv",
        )
        svc.add_supply_chain_vuln(vuln)
        results = svc.get_vulns_for_package("requests", "pip")
        assert len(results) == 1
        assert results[0].patched_versions == "2.28.1"
        assert results[0].vuln_id == "CVE-2024-2000"

    def test_get_vulns_no_ecosystem_filter(self, svc: FeedsService):
        vuln = SupplyChainVuln(
            vuln_id="CVE-2024-3000",
            ecosystem="npm",
            package_name="express",
            affected_versions="<4.18.0",
            severity="medium",
            source="github",
        )
        svc.add_supply_chain_vuln(vuln)
        results = svc.get_vulns_for_package("express")
        assert len(results) == 1

    def test_get_vulns_empty(self, svc: FeedsService):
        results = svc.get_vulns_for_package("nonexistent")
        assert results == []


# ---------------------------------------------------------------------------
# 15. FeedRefreshResult
# ---------------------------------------------------------------------------


class TestFeedRefreshResult:
    def test_create(self):
        r = FeedRefreshResult(
            feed_name="nvd",
            success=True,
            records_updated=100,
        )
        assert r.success is True
        assert r.records_updated == 100
        assert r.error is None

    def test_create_failure(self):
        r = FeedRefreshResult(
            feed_name="kev",
            success=False,
            records_updated=0,
            error="Connection timeout",
        )
        assert r.success is False
        assert r.error == "Connection timeout"
