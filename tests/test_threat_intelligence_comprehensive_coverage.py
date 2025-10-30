"""Comprehensive coverage tests for threat intelligence feeds.

This test file focuses on achieving 100% code coverage for all feed modules.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from risk.feeds.base import FeedMetadata, VulnerabilityRecord
from risk.feeds.ecosystems import (
    AlpineSecDBFeed,
    DebianSecurityFeed,
    GoVulnDBFeed,
    MavenSecurityFeed,
    NPMSecurityFeed,
    NuGetSecurityFeed,
    PyPISecurityFeed,
    RubySecFeed,
    RustSecFeed,
    UbuntuSecurityFeed,
)
from risk.feeds.epss import (
    _load_json_cache,
    _parse_epss_csv,
    _write_json_cache,
    load_epss_scores,
    update_epss_feed,
)
from risk.feeds.exploits import (
    AbuseCHMalwareBazaarFeed,
    AbuseCHThreatFoxFeed,
    AbuseCHURLHausFeed,
    AlienVaultOTXFeed,
    ExploitDBFeed,
    Rapid7AttackerKBFeed,
    VulnersFeed,
)
from risk.feeds.github import GitHubSecurityAdvisoriesFeed
from risk.feeds.kev import load_kev_catalog, update_kev_feed
from risk.feeds.nvd import NVDFeed
from risk.feeds.orchestrator import ThreatIntelligenceOrchestrator
from risk.feeds.osv import OSVFeed
from risk.feeds.vendors import (
    AppleSecurityFeed,
    AWSSecurityFeed,
    AzureSecurityFeed,
    CiscoSecurityFeed,
    DockerSecurityFeed,
    KubernetesSecurityFeed,
    MicrosoftSecurityFeed,
    OracleSecurityFeed,
    VMwareSecurityFeed,
)


@pytest.fixture
def temp_cache_dir(tmp_path: Path) -> Path:
    """Create temporary cache directory."""
    cache_dir = tmp_path / "feeds_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


class TestEPSSFeed:
    """Comprehensive tests for EPSS feed."""

    def test_parse_epss_csv(self, temp_cache_dir: Path):
        """Test parsing EPSS CSV file."""
        csv_path = temp_cache_dir / "epss.csv"
        csv_content = """cve,epss,percentile
CVE-2024-1234,0.75,0.95
CVE-2024-5678,0.25,0.50
CVE-2024-9999,0.01,0.10"""
        csv_path.write_text(csv_content)

        scores = _parse_epss_csv(csv_path)

        assert "CVE-2024-1234" in scores
        assert scores["CVE-2024-1234"] == 0.75
        assert "CVE-2024-5678" in scores
        assert scores["CVE-2024-5678"] == 0.25

    def test_parse_epss_csv_with_invalid_rows(self, temp_cache_dir: Path):
        """Test parsing EPSS CSV with invalid rows."""
        csv_path = temp_cache_dir / "epss.csv"
        csv_content = """cve,epss,percentile
CVE-2024-1234,0.75,0.95
,0.25,0.50
CVE-2024-5678,,0.50
CVE-2024-9999,invalid,0.10
CVE-2024-7777,0.50,0.60"""
        csv_path.write_text(csv_content)

        scores = _parse_epss_csv(csv_path)

        assert "CVE-2024-1234" in scores
        assert "CVE-2024-7777" in scores
        assert len(scores) == 2

    def test_write_and_load_json_cache(self, temp_cache_dir: Path):
        """Test writing and loading JSON cache."""
        scores = {"CVE-2024-1234": 0.75, "CVE-2024-5678": 0.25}

        _write_json_cache(temp_cache_dir, scores)

        loaded_scores = _load_json_cache(temp_cache_dir)
        assert loaded_scores is not None
        assert loaded_scores["CVE-2024-1234"] == 0.75
        assert loaded_scores["CVE-2024-5678"] == 0.25

    def test_load_json_cache_not_found(self, temp_cache_dir: Path):
        """Test loading JSON cache when file doesn't exist."""
        result = _load_json_cache(temp_cache_dir)
        assert result is None

    def test_load_json_cache_invalid_json(self, temp_cache_dir: Path):
        """Test loading JSON cache with invalid JSON."""
        json_path = temp_cache_dir / "epss.json"
        json_path.write_text("not valid json")

        result = _load_json_cache(temp_cache_dir)
        assert result is None

    def test_load_json_cache_invalid_type(self, temp_cache_dir: Path):
        """Test loading JSON cache with invalid type."""
        json_path = temp_cache_dir / "epss.json"
        json_path.write_text("[]")

        result = _load_json_cache(temp_cache_dir)
        assert result is None

    def test_update_epss_feed_success(self, temp_cache_dir: Path):
        """Test updating EPSS feed successfully."""
        csv_content = b"""cve,epss,percentile
CVE-2024-1234,0.75,0.95"""

        def mock_fetcher(url: str) -> bytes:
            return csv_content

        result = update_epss_feed(cache_dir=temp_cache_dir, fetcher=mock_fetcher)

        assert result.exists()
        assert result.name == "epss.csv"

        json_path = temp_cache_dir / "epss.json"
        assert json_path.exists()

    def test_update_epss_feed_with_fallback(self, temp_cache_dir: Path):
        """Test updating EPSS feed with fallback to cached JSON."""
        scores = {"CVE-2024-1234": 0.75}
        _write_json_cache(temp_cache_dir, scores)

        def mock_fetcher(url: str) -> bytes:
            raise TimeoutError("Network timeout")

        result = update_epss_feed(cache_dir=temp_cache_dir, fetcher=mock_fetcher)

        assert result.name == "epss.json"

    def test_update_epss_feed_failure_no_cache(self, temp_cache_dir: Path):
        """Test updating EPSS feed failure with no cache."""

        def mock_fetcher(url: str) -> bytes:
            raise TimeoutError("Network timeout")

        with pytest.raises(TimeoutError):
            update_epss_feed(cache_dir=temp_cache_dir, fetcher=mock_fetcher)

    def test_load_epss_scores_from_csv(self, temp_cache_dir: Path):
        """Test loading EPSS scores from CSV."""
        csv_path = temp_cache_dir / "epss.csv"
        csv_content = """cve,epss,percentile
CVE-2024-1234,0.75,0.95"""
        csv_path.write_text(csv_content)

        scores = load_epss_scores(cache_dir=temp_cache_dir)

        assert "CVE-2024-1234" in scores
        assert scores["CVE-2024-1234"] == 0.75

    def test_load_epss_scores_from_json(self, temp_cache_dir: Path):
        """Test loading EPSS scores from JSON cache."""
        scores_data = {"CVE-2024-1234": 0.75}
        _write_json_cache(temp_cache_dir, scores_data)

        scores = load_epss_scores(cache_dir=temp_cache_dir)

        assert "CVE-2024-1234" in scores
        assert scores["CVE-2024-1234"] == 0.75

    def test_load_epss_scores_not_found(self, temp_cache_dir: Path):
        """Test loading EPSS scores when not found."""
        with pytest.raises(FileNotFoundError):
            load_epss_scores(cache_dir=temp_cache_dir)

    def test_load_epss_scores_with_json_path(self, temp_cache_dir: Path):
        """Test loading EPSS scores with JSON path."""
        scores_data = {"CVE-2024-1234": 0.75}
        _write_json_cache(temp_cache_dir, scores_data)

        json_path = temp_cache_dir / "epss.json"
        scores = load_epss_scores(path=json_path, cache_dir=temp_cache_dir)

        assert "CVE-2024-1234" in scores

    def test_load_epss_scores_empty_csv_fallback(self, temp_cache_dir: Path):
        """Test loading EPSS scores with empty CSV fallback to JSON."""
        csv_path = temp_cache_dir / "epss.csv"
        csv_path.write_text("cve,epss,percentile\n")

        scores_data = {"CVE-2024-1234": 0.75}
        _write_json_cache(temp_cache_dir, scores_data)

        scores = load_epss_scores(cache_dir=temp_cache_dir)

        assert "CVE-2024-1234" in scores


class TestKEVFeed:
    """Comprehensive tests for KEV feed."""

    def test_update_kev_feed(self, temp_cache_dir: Path):
        """Test updating KEV feed."""
        kev_data = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "vulnerabilityName": "Test Vulnerability",
                    "dateAdded": "2024-01-01",
                    "vendorProject": "Test Vendor",
                    "product": "Test Product",
                    "requiredAction": "Apply patch",
                    "dueDate": "2024-02-01",
                }
            ]
        }

        def mock_fetcher(url: str) -> bytes:
            return json.dumps(kev_data).encode("utf-8")

        result = update_kev_feed(cache_dir=temp_cache_dir, fetcher=mock_fetcher)

        assert result.exists()
        assert result.name == "kev.json"

    def test_load_kev_catalog(self, temp_cache_dir: Path):
        """Test loading KEV catalog."""
        kev_data = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "vulnerabilityName": "Test Vulnerability",
                    "dateAdded": "2024-01-01",
                }
            ]
        }
        kev_path = temp_cache_dir / "kev.json"
        kev_path.write_text(json.dumps(kev_data))

        catalog = load_kev_catalog(cache_dir=temp_cache_dir)

        assert "CVE-2024-1234" in catalog
        assert catalog["CVE-2024-1234"]["vulnerabilityName"] == "Test Vulnerability"

    def test_load_kev_catalog_not_found(self, temp_cache_dir: Path):
        """Test loading KEV catalog when not found."""
        with pytest.raises(FileNotFoundError):
            load_kev_catalog(cache_dir=temp_cache_dir)


class TestAllFeedsParsing:
    """Test parse_feed method for all feed classes."""

    @pytest.mark.parametrize(
        "feed_class",
        [
            NPMSecurityFeed,
            PyPISecurityFeed,
            RubySecFeed,
            RustSecFeed,
            GoVulnDBFeed,
            MavenSecurityFeed,
            NuGetSecurityFeed,
            DebianSecurityFeed,
            UbuntuSecurityFeed,
            AlpineSecDBFeed,
            MicrosoftSecurityFeed,
            AppleSecurityFeed,
            AWSSecurityFeed,
            AzureSecurityFeed,
            OracleSecurityFeed,
            CiscoSecurityFeed,
            VMwareSecurityFeed,
            DockerSecurityFeed,
            KubernetesSecurityFeed,
            AlienVaultOTXFeed,
            VulnersFeed,
            Rapid7AttackerKBFeed,
            AbuseCHURLHausFeed,
            AbuseCHMalwareBazaarFeed,
            AbuseCHThreatFoxFeed,
        ],
    )
    def test_feed_parse_empty_data(self, feed_class, temp_cache_dir: Path):
        """Test parsing empty data for all feed classes."""
        feed = feed_class(cache_dir=temp_cache_dir)
        records = feed.parse_feed(b"{}")
        assert records == []

    @pytest.mark.parametrize(
        "feed_class",
        [
            NPMSecurityFeed,
            PyPISecurityFeed,
            RubySecFeed,
            RustSecFeed,
            GoVulnDBFeed,
            MavenSecurityFeed,
            NuGetSecurityFeed,
            DebianSecurityFeed,
            UbuntuSecurityFeed,
            AlpineSecDBFeed,
            MicrosoftSecurityFeed,
            AppleSecurityFeed,
            AWSSecurityFeed,
            AzureSecurityFeed,
            OracleSecurityFeed,
            CiscoSecurityFeed,
            VMwareSecurityFeed,
            DockerSecurityFeed,
            KubernetesSecurityFeed,
            AlienVaultOTXFeed,
            VulnersFeed,
            Rapid7AttackerKBFeed,
            AbuseCHURLHausFeed,
            AbuseCHMalwareBazaarFeed,
            AbuseCHThreatFoxFeed,
            OSVFeed,
            NVDFeed,
            GitHubSecurityAdvisoriesFeed,
            ExploitDBFeed,
        ],
    )
    def test_feed_get_metadata(self, feed_class, temp_cache_dir: Path):
        """Test get_metadata for all feed classes."""
        feed = feed_class(cache_dir=temp_cache_dir)
        metadata = feed.get_metadata()
        assert metadata.name == feed.feed_name
        assert metadata.record_count == 0

    @pytest.mark.parametrize(
        "feed_class,cache_filename",
        [
            (NPMSecurityFeed, "npm-security.json"),
            (PyPISecurityFeed, "pypi-security.json"),
            (RubySecFeed, "rubysec.json"),
            (OSVFeed, "osv-ecosystems.txt"),
            (NVDFeed, "nvd-cves.json"),
            (GitHubSecurityAdvisoriesFeed, "github-advisories.json"),
            (ExploitDBFeed, "exploitdb.csv"),
        ],
    )
    def test_feed_load_feed_with_empty_cache(
        self, feed_class, cache_filename, temp_cache_dir: Path
    ):
        """Test load_feed with empty cache file."""
        feed = feed_class(cache_dir=temp_cache_dir)
        cache_path = temp_cache_dir / cache_filename

        if cache_filename.endswith(".json"):
            cache_path.write_text("{}")
        elif cache_filename.endswith(".csv"):
            cache_path.write_text("id,description\n")
        else:
            cache_path.write_text("")

        records = feed.load_feed()
        assert isinstance(records, list)


class TestOrchestratorErrorHandling:
    """Test orchestrator error handling."""

    def test_orchestrator_update_all_feeds_with_failures(self, temp_cache_dir: Path):
        """Test orchestrator update_all_feeds handles failures gracefully."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        results = orchestrator.update_all_feeds()

        assert isinstance(results, dict)
        assert len(results) > 0

    def test_orchestrator_load_all_feeds_kev_failure(self, temp_cache_dir: Path):
        """Test orchestrator load_all_feeds with KEV failure."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        with patch("risk.feeds.orchestrator.load_kev_catalog") as mock_load:
            mock_load.side_effect = Exception("KEV load failed")
            results = orchestrator.load_all_feeds()

            assert isinstance(results, dict)

    def test_orchestrator_get_all_metadata_kev_failure(self, temp_cache_dir: Path):
        """Test orchestrator get_all_metadata with KEV failure."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        kev_path = temp_cache_dir / "kev.json"
        kev_path.write_text("{}")

        with patch("risk.feeds.orchestrator.load_kev_catalog") as mock_load:
            mock_load.side_effect = Exception("KEV metadata failed")
            metadata = orchestrator.get_all_metadata()

            assert isinstance(metadata, list)

    def test_orchestrator_enrich_vulnerability_by_cwe(self, temp_cache_dir: Path):
        """Test enriching vulnerability by CWE ID."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        mock_feeds: Dict[str, Any] = {
            "NVD": [
                VulnerabilityRecord(
                    id="CVE-2024-1234",
                    source="NVD",
                    cwe_ids=["CWE-79", "CWE-89"],
                )
            ],
        }

        enrichment = orchestrator.enrich_vulnerability("CWE-79", all_feeds=mock_feeds)

        assert "NVD" in enrichment["sources"]


class TestNVDFeedComprehensive:
    """Comprehensive tests for NVD feed."""

    def test_nvd_feed_parse_with_multiple_metrics(self, temp_cache_dir: Path):
        """Test NVD feed parsing with multiple CVSS metrics."""
        feed = NVDFeed(cache_dir=temp_cache_dir)

        nvd_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [{"lang": "en", "value": "Test"}],
                        "published": "2024-01-01T00:00:00.000",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                        "baseSeverity": "HIGH",
                                    }
                                }
                            ],
                            "cvssMetricV2": [
                                {
                                    "cvssData": {
                                        "baseScore": 5.0,
                                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                                    },
                                    "baseSeverity": "MEDIUM",
                                }
                            ],
                        },
                    }
                }
            ]
        }

        records = feed.parse_feed(json.dumps(nvd_data).encode("utf-8"))

        assert len(records) == 1
        assert records[0].cvss_score == 7.5

    def test_nvd_feed_parse_with_v2_only(self, temp_cache_dir: Path):
        """Test NVD feed parsing with CVSS v2 only."""
        feed = NVDFeed(cache_dir=temp_cache_dir)

        nvd_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [{"lang": "en", "value": "Test"}],
                        "published": "2024-01-01T00:00:00.000",
                        "metrics": {
                            "cvssMetricV2": [
                                {
                                    "cvssData": {
                                        "baseScore": 5.0,
                                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                                    },
                                    "baseSeverity": "MEDIUM",
                                }
                            ]
                        },
                    }
                }
            ]
        }

        records = feed.parse_feed(json.dumps(nvd_data).encode("utf-8"))

        assert len(records) == 1
        assert records[0].cvss_score == 5.0


class TestGitHubFeedComprehensive:
    """Comprehensive tests for GitHub Security Advisories feed."""

    def test_github_feed_parse_without_cvss(self, temp_cache_dir: Path):
        """Test GitHub feed parsing without CVSS data."""
        feed = GitHubSecurityAdvisoriesFeed(cache_dir=temp_cache_dir)

        github_data = {
            "data": {
                "securityAdvisories": {
                    "nodes": [
                        {
                            "ghsaId": "GHSA-xxxx-yyyy-zzzz",
                            "summary": "Test advisory",
                            "description": "Test description",
                            "severity": "HIGH",
                            "publishedAt": "2024-01-01T00:00:00Z",
                            "updatedAt": "2024-01-02T00:00:00Z",
                            "identifiers": [],
                            "references": [],
                            "cwes": {"nodes": []},
                            "vulnerabilities": {"nodes": []},
                        }
                    ]
                }
            }
        }

        records = feed.parse_feed(json.dumps(github_data).encode("utf-8"))

        assert len(records) == 1
        assert records[0].id == "GHSA-xxxx-yyyy-zzzz"


class TestOSVFeedComprehensive:
    """Comprehensive tests for OSV feed."""

    def test_osv_feed_parse_ecosystems_list(self, temp_cache_dir: Path):
        """Test OSV feed parsing ecosystems list."""
        feed = OSVFeed(cache_dir=temp_cache_dir)

        ecosystems_data = b"PyPI\nnpm\nGo\nMaven\nRubyGems\nNuGet"

        records = feed.parse_feed(ecosystems_data)

        assert isinstance(records, list)

    def test_osv_feed_parse_osv_record_full(self, temp_cache_dir: Path):
        """Test parsing full OSV vulnerability record."""
        feed = OSVFeed(cache_dir=temp_cache_dir)

        osv_data = {
            "id": "OSV-2024-1234",
            "summary": "Test vulnerability",
            "details": "Detailed description of the vulnerability",
            "published": "2024-01-01T00:00:00Z",
            "modified": "2024-01-02T00:00:00Z",
            "aliases": ["CVE-2024-1234", "GHSA-xxxx-yyyy-zzzz"],
            "severity": [{"type": "CVSS_V3", "score": "9.8/CVSS:3.1/AV:N/AC:L"}],
            "affected": [
                {
                    "package": {"name": "test-package", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.0.0"}],
                        }
                    ],
                }
            ],
            "references": [{"type": "ADVISORY", "url": "https://example.com/advisory"}],
            "database_specific": {"severity": "HIGH"},
        }

        record = feed._parse_osv_record(osv_data, "PyPI")

        assert record is not None
        assert record.id == "OSV-2024-1234"
        assert record.source == "OSV"
        assert record.cvss_score == 9.8
        assert record.severity == "CRITICAL"
        assert "test-package" in record.affected_packages
        assert "CVE-2024-1234" in record.cwe_ids
        assert len(record.references) > 0

    def test_osv_feed_parse_osv_record_minimal(self, temp_cache_dir: Path):
        """Test parsing minimal OSV vulnerability record."""
        feed = OSVFeed(cache_dir=temp_cache_dir)

        osv_data = {"id": "OSV-2024-5678", "summary": "Minimal vulnerability"}

        record = feed._parse_osv_record(osv_data, "npm")

        assert record is not None
        assert record.id == "OSV-2024-5678"
        assert record.source == "OSV"
        assert record.severity is None

    def test_osv_feed_parse_osv_record_no_id(self, temp_cache_dir: Path):
        """Test parsing OSV record without ID."""
        feed = OSVFeed(cache_dir=temp_cache_dir)

        osv_data = {"summary": "No ID vulnerability"}

        record = feed._parse_osv_record(osv_data, "PyPI")

        assert record is None

    def test_osv_feed_parse_osv_record_severity_levels(self, temp_cache_dir: Path):
        """Test OSV record severity level mapping."""
        feed = OSVFeed(cache_dir=temp_cache_dir)

        test_cases = [
            (9.5, "CRITICAL"),
            (8.0, "HIGH"),
            (5.0, "MEDIUM"),
            (2.0, "LOW"),
        ]

        for score, expected_severity in test_cases:
            osv_data = {
                "id": f"OSV-TEST-{score}",
                "severity": [{"type": "CVSS_V3", "score": f"{score}/CVSS:3.1/AV:N"}],
            }

            record = feed._parse_osv_record(osv_data, "PyPI")

            assert record is not None
            assert record.severity == expected_severity
            assert record.cvss_score == score

    def test_osv_feed_fetch_ecosystem_vulnerabilities_error(self, temp_cache_dir: Path):
        """Test fetching ecosystem vulnerabilities with error."""
        feed = OSVFeed(cache_dir=temp_cache_dir)

        def mock_fetcher(url: str) -> bytes:
            raise Exception("Network error")

        feed.fetcher = mock_fetcher

        records = feed.fetch_ecosystem_vulnerabilities("PyPI")

        assert records == []


class TestExploitFeedsComprehensive:
    """Comprehensive tests for exploit feeds."""

    def test_exploitdb_feed_parse_with_headers(self, temp_cache_dir: Path):
        """Test Exploit-DB feed parsing with CSV headers."""
        feed = ExploitDBFeed(cache_dir=temp_cache_dir)

        csv_data = b"""id,description,date,author,type,platform,port
12345,SQL Injection in WordPress,2024-01-01,John Doe,webapps,php,80
12346,Buffer Overflow in Apache,2024-01-02,Jane Smith,remote,linux,443"""

        records = feed.parse_feed(csv_data)

        assert len(records) == 2
        assert records[0].id == "EDB-12345"
        assert records[0].exploit_available is True
        assert records[1].id == "EDB-12346"


class TestKEVFeedComprehensive:
    """Comprehensive tests for KEV feed."""

    def test_kev_feed_update_with_error(self, temp_cache_dir: Path):
        """Test KEV feed update with network error."""

        def mock_fetcher(url: str) -> bytes:
            raise TimeoutError("Network timeout")

        with pytest.raises(TimeoutError):
            update_kev_feed(cache_dir=temp_cache_dir, fetcher=mock_fetcher)

    def test_kev_feed_load_catalog_with_multiple_vulns(self, temp_cache_dir: Path):
        """Test loading KEV catalog with multiple vulnerabilities."""
        kev_data = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "vulnerabilityName": "Test Vuln 1",
                    "dateAdded": "2024-01-01",
                },
                {
                    "cveID": "CVE-2024-5678",
                    "vulnerabilityName": "Test Vuln 2",
                    "dateAdded": "2024-01-02",
                },
            ]
        }
        kev_path = temp_cache_dir / "kev.json"
        kev_path.write_text(json.dumps(kev_data))

        catalog = load_kev_catalog(cache_dir=temp_cache_dir)

        assert len(catalog) == 2
        assert "CVE-2024-1234" in catalog
        assert "CVE-2024-5678" in catalog


class TestGitHubFeedMoreComprehensive:
    """More comprehensive tests for GitHub feed."""

    def test_github_feed_parse_json_decode_error(self, temp_cache_dir: Path):
        """Test GitHub feed parsing with invalid JSON."""
        feed = GitHubSecurityAdvisoriesFeed(cache_dir=temp_cache_dir)

        invalid_json = b"not valid json {"

        records = feed.parse_feed(invalid_json)

        assert records == []

    def test_github_feed_parse_advisory_no_ghsa_id(self, temp_cache_dir: Path):
        """Test parsing GitHub advisory without GHSA ID."""
        feed = GitHubSecurityAdvisoriesFeed(cache_dir=temp_cache_dir)

        advisory = {"summary": "Test advisory", "description": "Test description"}

        record = feed._parse_github_advisory(advisory)

        assert record is None

    def test_github_feed_parse_advisory_with_summary_in_description(
        self, temp_cache_dir: Path
    ):
        """Test parsing GitHub advisory where summary is already in description."""
        feed = GitHubSecurityAdvisoriesFeed(cache_dir=temp_cache_dir)

        advisory = {
            "ghsaId": "GHSA-test-1234",
            "summary": "SQL Injection",
            "description": "SQL Injection vulnerability in package",
        }

        record = feed._parse_github_advisory(advisory)

        assert record is not None
        assert record.id == "GHSA-test-1234"
        assert "SQL Injection" in record.description

    def test_github_feed_parse_advisory_with_cvss(self, temp_cache_dir: Path):
        """Test parsing GitHub advisory with CVSS data."""
        feed = GitHubSecurityAdvisoriesFeed(cache_dir=temp_cache_dir)

        advisory = {
            "ghsaId": "GHSA-test-5678",
            "summary": "Test vulnerability",
            "cvss": {"score": 8.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"},
        }

        record = feed._parse_github_advisory(advisory)

        assert record is not None
        assert record.cvss_score == 8.5
        assert record.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"

    def test_github_feed_parse_advisory_with_cve_identifiers(
        self, temp_cache_dir: Path
    ):
        """Test parsing GitHub advisory with CVE identifiers."""
        feed = GitHubSecurityAdvisoriesFeed(cache_dir=temp_cache_dir)

        advisory = {
            "ghsaId": "GHSA-test-9999",
            "summary": "Test vulnerability",
            "identifiers": [
                {"type": "CVE", "value": "CVE-2024-1234"},
                {"type": "GHSA", "value": "GHSA-test-9999"},
            ],
        }

        record = feed._parse_github_advisory(advisory)

        assert record is not None
        assert "CVE-2024-1234" in record.cwe_ids

    def test_github_feed_parse_advisory_with_vulnerabilities(
        self, temp_cache_dir: Path
    ):
        """Test parsing GitHub advisory with vulnerability details."""
        feed = GitHubSecurityAdvisoriesFeed(cache_dir=temp_cache_dir)

        advisory = {
            "ghsaId": "GHSA-test-0000",
            "summary": "Test vulnerability",
            "vulnerabilities": {
                "nodes": [
                    {
                        "package": {"name": "test-package", "ecosystem": "npm"},
                        "vulnerableVersionRange": "< 1.0.0",
                        "firstPatchedVersion": {"identifier": "1.0.0"},
                    }
                ]
            },
        }

        record = feed._parse_github_advisory(advisory)

        assert record is not None
        assert "npm:test-package" in record.affected_packages
        assert "< 1.0.0" in record.affected_versions
        assert "1.0.0" in record.fixed_versions

    def test_github_feed_parse_advisory_with_references(self, temp_cache_dir: Path):
        """Test parsing GitHub advisory with references."""
        feed = GitHubSecurityAdvisoriesFeed(cache_dir=temp_cache_dir)

        advisory = {
            "ghsaId": "GHSA-test-1111",
            "summary": "Test vulnerability",
            "references": [
                {"url": "https://example.com/advisory1"},
                {"url": "https://example.com/advisory2"},
            ],
        }

        record = feed._parse_github_advisory(advisory)

        assert record is not None
        assert len(record.references) == 2
        assert "https://example.com/advisory1" in record.references

    def test_github_feed_parse_advisory_with_cwes(self, temp_cache_dir: Path):
        """Test parsing GitHub advisory with CWE data."""
        feed = GitHubSecurityAdvisoriesFeed(cache_dir=temp_cache_dir)

        advisory = {
            "ghsaId": "GHSA-test-2222",
            "summary": "Test vulnerability",
            "cwes": {
                "nodes": [
                    {"cweId": "CWE-79", "name": "Cross-site Scripting"},
                    {"cweId": "CWE-89", "name": "SQL Injection"},
                ]
            },
        }

        record = feed._parse_github_advisory(advisory)

        assert record is not None
        assert "CWE-79" in record.cwe_ids
        assert "CWE-89" in record.cwe_ids


class TestNVDFeedMoreComprehensive:
    """More comprehensive tests for NVD feed."""

    def test_nvd_feed_parse_json_decode_error(self, temp_cache_dir: Path):
        """Test NVD feed parsing with invalid JSON."""
        feed = NVDFeed(cache_dir=temp_cache_dir)

        invalid_json = b"not valid json ["

        records = feed.parse_feed(invalid_json)

        assert records == []

    def test_nvd_feed_parse_cve_no_id(self, temp_cache_dir: Path):
        """Test parsing NVD CVE without ID."""
        feed = NVDFeed(cache_dir=temp_cache_dir)

        cve_data = {"descriptions": [{"lang": "en", "value": "Test"}]}

        record = feed._parse_nvd_cve(cve_data)

        assert record is None

    def test_nvd_feed_parse_cve_with_references(self, temp_cache_dir: Path):
        """Test parsing NVD CVE with references."""
        feed = NVDFeed(cache_dir=temp_cache_dir)

        cve_data = {
            "id": "CVE-2024-1234",
            "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
            "references": [
                {"url": "https://example.com/ref1"},
                {"url": "https://example.com/ref2"},
            ],
        }

        record = feed._parse_nvd_cve(cve_data)

        assert record is not None
        assert len(record.references) == 2

    def test_nvd_feed_parse_cve_with_cwes(self, temp_cache_dir: Path):
        """Test parsing NVD CVE with CWE data."""
        feed = NVDFeed(cache_dir=temp_cache_dir)

        cve_data = {
            "id": "CVE-2024-5678",
            "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
            "weaknesses": [
                {
                    "description": [
                        {"lang": "en", "value": "CWE-79"},
                        {"lang": "en", "value": "CWE-89"},
                    ]
                }
            ],
        }

        record = feed._parse_nvd_cve(cve_data)

        assert record is not None
        assert "CWE-79" in record.cwe_ids
        assert "CWE-89" in record.cwe_ids

    def test_nvd_feed_parse_cve_with_configurations(self, temp_cache_dir: Path):
        """Test parsing NVD CVE with configuration data."""
        feed = NVDFeed(cache_dir=temp_cache_dir)

        cve_data = {
            "id": "CVE-2024-9999",
            "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                                    "vulnerable": True,
                                }
                            ]
                        }
                    ]
                }
            ],
        }

        record = feed._parse_nvd_cve(cve_data)

        assert record is not None
        assert "vendor/product" in record.affected_packages


class TestOrchestratorMoreComprehensive:
    """More comprehensive tests for orchestrator."""

    def test_orchestrator_get_statistics(self, temp_cache_dir: Path):
        """Test getting orchestrator statistics."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        stats = orchestrator.get_statistics()

        assert isinstance(stats, dict)
        assert "total_feeds" in stats
        assert "total_vulnerabilities" in stats
        assert "feeds" in stats

    def test_orchestrator_export_unified_feed(self, temp_cache_dir: Path):
        """Test exporting unified feed."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        output_path = temp_cache_dir / "unified_feed.json"
        orchestrator.export_unified_feed(str(output_path))

        assert output_path.exists()


class TestExploitFeedsMoreComprehensive:
    """More comprehensive tests for exploit feeds to reach 100% coverage."""

    def test_exploitdb_feed_parse_no_exploit_id(self, temp_cache_dir: Path):
        """Test ExploitDB parsing with missing exploit ID."""
        feed = ExploitDBFeed(cache_dir=temp_cache_dir)

        csv_data = b"id,description,platform,type,date,author\n,Test exploit,Linux,local,2024-01-01,TestAuthor"

        records = feed.parse_feed(csv_data)

        assert len(records) == 0

    def test_exploitdb_feed_parse_error(self, temp_cache_dir: Path):
        """Test ExploitDB parsing with invalid CSV."""
        feed = ExploitDBFeed(cache_dir=temp_cache_dir)

        invalid_csv = b"invalid\xffcsv\xffdata"

        records = feed.parse_feed(invalid_csv)

        assert len(records) == 0

    def test_vulners_feed_json_decode_error(self, temp_cache_dir: Path):
        """Test Vulners feed with invalid JSON."""
        feed = VulnersFeed(cache_dir=temp_cache_dir)

        invalid_json = b"invalid json {{"

        records = feed.parse_feed(invalid_json)

        assert len(records) == 0

    def test_vulners_feed_parse_no_vuln_id(self, temp_cache_dir: Path):
        """Test Vulners feed parsing with missing vuln ID."""
        feed = VulnersFeed(cache_dir=temp_cache_dir)

        data = json.dumps({"data": {"search": [{"description": "Test vuln"}]}}).encode()

        records = feed.parse_feed(data)

        assert len(records) == 0

    def test_vulners_feed_parse_full(self, temp_cache_dir: Path):
        """Test Vulners feed parsing with full data."""
        feed = VulnersFeed(api_key="test-key", cache_dir=temp_cache_dir)

        data = json.dumps(
            {
                "data": {
                    "search": [
                        {
                            "id": "VULNERS:TEST-001",
                            "cvss": {"severity": "HIGH", "score": 7.5},
                            "description": "Test vulnerability",
                            "published": "2024-01-01",
                            "modified": "2024-01-02",
                            "exploit": True,
                            "href": "https://vulners.com/test",
                            "type": "cve",
                        }
                    ]
                }
            }
        ).encode()

        records = feed.parse_feed(data)

        assert len(records) == 1
        assert records[0].id == "VULNERS:TEST-001"
        assert records[0].severity == "HIGH"
        assert records[0].exploit_available is True

    def test_alienvault_otx_json_decode_error(self, temp_cache_dir: Path):
        """Test AlienVault OTX feed with invalid JSON."""
        feed = AlienVaultOTXFeed(cache_dir=temp_cache_dir)

        invalid_json = b"invalid json {{"

        records = feed.parse_feed(invalid_json)

        assert len(records) == 0

    def test_alienvault_otx_parse_no_pulse_id(self, temp_cache_dir: Path):
        """Test AlienVault OTX parsing with missing pulse ID."""
        feed = AlienVaultOTXFeed(api_key="test-key", cache_dir=temp_cache_dir)

        data = json.dumps({"results": [{"name": "Test pulse"}]}).encode()

        records = feed.parse_feed(data)

        assert len(records) == 0

    def test_alienvault_otx_parse_no_cve_indicators(self, temp_cache_dir: Path):
        """Test AlienVault OTX parsing with no CVE indicators."""
        feed = AlienVaultOTXFeed(cache_dir=temp_cache_dir)

        data = json.dumps(
            {
                "results": [
                    {
                        "id": "pulse-123",
                        "indicators": [{"type": "IP", "indicator": "1.2.3.4"}],
                    }
                ]
            }
        ).encode()

        records = feed.parse_feed(data)

        assert len(records) == 0

    def test_alienvault_otx_parse_full(self, temp_cache_dir: Path):
        """Test AlienVault OTX parsing with full data."""
        feed = AlienVaultOTXFeed(cache_dir=temp_cache_dir)

        data = json.dumps(
            {
                "results": [
                    {
                        "id": "pulse-123",
                        "name": "Test Pulse",
                        "description": "Test description",
                        "created": "2024-01-01",
                        "modified": "2024-01-02",
                        "TLP": "white",
                        "tags": ["malware", "apt"],
                        "indicators": [
                            {"type": "CVE", "indicator": "CVE-2024-1234"},
                            {"type": "CVE", "indicator": "CVE-2024-5678"},
                        ],
                    }
                ]
            }
        ).encode()

        records = feed.parse_feed(data)

        assert len(records) == 1
        assert records[0].id == "pulse-123"
        assert len(records[0].cwe_ids) == 2

    def test_urlhaus_feed_parse_with_comments(self, temp_cache_dir: Path):
        """Test URLhaus feed parsing with comments and empty lines."""
        feed = AbuseCHURLHausFeed(cache_dir=temp_cache_dir)

        data = b'# Comment line\n\n{"id": "123", "url": "http://malware.com", "dateadded": "2024-01-01", "threat": "malware", "tags": ["emotet"], "url_status": "online"}'

        records = feed.parse_feed(data)

        assert len(records) == 1
        assert records[0].id == "URLhaus-123"

    def test_urlhaus_feed_parse_no_url_id(self, temp_cache_dir: Path):
        """Test URLhaus feed parsing with missing URL ID."""
        feed = AbuseCHURLHausFeed(cache_dir=temp_cache_dir)

        data = b'{"url": "http://malware.com"}'

        records = feed.parse_feed(data)

        assert len(records) == 0

    def test_urlhaus_feed_parse_error(self, temp_cache_dir: Path):
        """Test URLhaus feed parsing with error."""
        feed = AbuseCHURLHausFeed(cache_dir=temp_cache_dir)

        invalid_data = b"invalid\xffjson"

        records = feed.parse_feed(invalid_data)

        assert len(records) == 0

    def test_malwarebazaar_json_decode_error(self, temp_cache_dir: Path):
        """Test MalwareBazaar feed with invalid JSON."""
        feed = AbuseCHMalwareBazaarFeed(cache_dir=temp_cache_dir)

        invalid_json = b"invalid json {{"

        records = feed.parse_feed(invalid_json)

        assert len(records) == 0

    def test_malwarebazaar_parse_no_sha256(self, temp_cache_dir: Path):
        """Test MalwareBazaar parsing with missing SHA256."""
        feed = AbuseCHMalwareBazaarFeed(cache_dir=temp_cache_dir)

        data = json.dumps({"data": [{"file_name": "malware.exe"}]}).encode()

        records = feed.parse_feed(data)

        assert len(records) == 0

    def test_malwarebazaar_parse_full(self, temp_cache_dir: Path):
        """Test MalwareBazaar parsing with full data."""
        feed = AbuseCHMalwareBazaarFeed(cache_dir=temp_cache_dir)

        data = json.dumps(
            {
                "data": [
                    {
                        "sha256_hash": "abcd1234" * 8,
                        "file_name": "malware.exe",
                        "first_seen": "2024-01-01",
                        "file_type": "exe",
                        "signature": "Emotet",
                        "tags": ["emotet", "trojan"],
                    }
                ]
            }
        ).encode()

        records = feed.parse_feed(data)

        assert len(records) == 1
        assert records[0].id.startswith("MalwareBazaar-")
        assert records[0].severity == "HIGH"

    def test_threatfox_feed_parse_with_comments(self, temp_cache_dir: Path):
        """Test ThreatFox feed parsing with comments and empty lines."""
        feed = AbuseCHThreatFoxFeed(cache_dir=temp_cache_dir)

        data = b'# Comment line\n\n{"id": "456", "ioc": "1.2.3.4", "ioc_type": "ip", "first_seen": "2024-01-01", "malware": "emotet", "confidence_level": 100, "tags": ["emotet"]}'

        records = feed.parse_feed(data)

        assert len(records) == 1
        assert records[0].id == "ThreatFox-456"

    def test_threatfox_feed_parse_no_ioc_id(self, temp_cache_dir: Path):
        """Test ThreatFox feed parsing with missing IOC ID."""
        feed = AbuseCHThreatFoxFeed(cache_dir=temp_cache_dir)

        data = b'{"ioc": "1.2.3.4"}'

        records = feed.parse_feed(data)

        assert len(records) == 0

    def test_threatfox_feed_parse_error(self, temp_cache_dir: Path):
        """Test ThreatFox feed parsing with error."""
        feed = AbuseCHThreatFoxFeed(cache_dir=temp_cache_dir)

        invalid_data = b"invalid\xffjson"

        records = feed.parse_feed(invalid_data)

        assert len(records) == 0

    def test_attackerkb_json_decode_error(self, temp_cache_dir: Path):
        """Test AttackerKB feed with invalid JSON."""
        feed = Rapid7AttackerKBFeed(cache_dir=temp_cache_dir)

        invalid_json = b"invalid json {{"

        records = feed.parse_feed(invalid_json)

        assert len(records) == 0

    def test_attackerkb_parse_no_topic_id(self, temp_cache_dir: Path):
        """Test AttackerKB parsing with missing topic ID."""
        feed = Rapid7AttackerKBFeed(api_key="test-key", cache_dir=temp_cache_dir)

        data = json.dumps({"data": [{"name": "Test topic"}]}).encode()

        records = feed.parse_feed(data)

        assert len(records) == 0

    def test_attackerkb_parse_full(self, temp_cache_dir: Path):
        """Test AttackerKB parsing with full data."""
        feed = Rapid7AttackerKBFeed(cache_dir=temp_cache_dir)

        data = json.dumps(
            {
                "data": [
                    {
                        "id": "topic-123",
                        "name": "CVE-2024-1234 Analysis",
                        "created": "2024-01-01",
                        "revised": "2024-01-02",
                        "metadata": {
                            "cve-id": "CVE-2024-1234",
                            "attacker-value": 4,
                            "exploitability": 3,
                        },
                    }
                ]
            }
        ).encode()

        records = feed.parse_feed(data)

        assert len(records) == 1
        assert records[0].id == "CVE-2024-1234"
        assert records[0].exploit_available is True
        assert records[0].exploit_maturity == "assessed"


class TestOrchestratorComplete:
    """Complete coverage tests for orchestrator to reach 100%."""

    def test_orchestrator_update_all_feeds_kev_failure(self, temp_cache_dir: Path):
        """Test update_all_feeds when KEV update fails."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        with patch("risk.feeds.orchestrator.update_kev_feed") as mock_kev:
            mock_kev.side_effect = Exception("KEV update failed")
            results = orchestrator.update_all_feeds()

            assert "KEV" in results

    def test_orchestrator_load_all_feeds_with_kev(
        self, temp_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Test load_all_feeds with KEV catalog present."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        kev_catalog = {
            "CVE-2024-1234": {
                "vulnerabilityName": "Test Vulnerability",
                "dateAdded": "2024-01-01",
                "vendorProject": "TestVendor",
                "requiredAction": "Apply patch",
                "dueDate": "2024-02-01",
            }
        }

        def mock_load_kev(cache_dir):
            return kev_catalog

        monkeypatch.setattr("risk.feeds.orchestrator.load_kev_catalog", mock_load_kev)

        results = orchestrator.load_all_feeds()

        assert "KEV" in results
        assert len(results["KEV"]) == 1
        assert results["KEV"][0].id == "CVE-2024-1234"
        assert results["KEV"][0].exploit_available is True
        assert results["KEV"][0].kev_listed is True

    def test_orchestrator_enrich_vulnerability_no_preloaded_feeds(
        self, temp_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Test enrich_vulnerability without pre-loaded feeds."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        def mock_load_all():
            return {
                "TestFeed": [
                    VulnerabilityRecord(
                        id="CVE-2024-1234",
                        source="TestFeed",
                        severity="HIGH",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        description="Test vulnerability",
                        exploit_available=True,
                        exploit_maturity="poc",
                        kev_listed=True,
                        affected_packages=["test-package"],
                        references=["https://example.com"],
                        cwe_ids=["CWE-79"],
                    )
                ]
            }

        monkeypatch.setattr(orchestrator, "load_all_feeds", mock_load_all)

        enrichment = orchestrator.enrich_vulnerability("CVE-2024-1234")

        assert enrichment["cve_id"] == "CVE-2024-1234"
        assert enrichment["severity"] == "HIGH"
        assert enrichment["cvss_score"] == 7.5
        assert (
            enrichment["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        )
        assert enrichment["exploit_available"] is True
        assert enrichment["exploit_maturity"] == "poc"
        assert enrichment["kev_listed"] is True
        assert "test-package" in enrichment["affected_packages"]
        assert "https://example.com" in enrichment["references"]
        assert "CWE-79" in enrichment["cwe_ids"]

    def test_orchestrator_enrich_vulnerability_multiple_sources(
        self, temp_cache_dir: Path
    ):
        """Test enrich_vulnerability with multiple sources providing data."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        all_feeds = {
            "Feed1": [
                VulnerabilityRecord(
                    id="CVE-2024-1234",
                    source="Feed1",
                    severity="HIGH",
                    description="Description from Feed1",
                )
            ],
            "Feed2": [
                VulnerabilityRecord(
                    id="CVE-2024-1234",
                    source="Feed2",
                    cvss_score=8.5,
                    description="Description from Feed2",
                    exploit_available=True,
                )
            ],
        }

        enrichment = orchestrator.enrich_vulnerability("CVE-2024-1234", all_feeds)

        assert len(enrichment["sources"]) == 2
        assert "Feed1" in enrichment["sources"]
        assert "Feed2" in enrichment["sources"]
        assert len(enrichment["descriptions"]) == 2
        assert enrichment["severity"] == "HIGH"
        assert enrichment["cvss_score"] == 8.5
        assert enrichment["exploit_available"] is True

    def test_orchestrator_export_unified_feed_with_duplicates(
        self, temp_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Test export_unified_feed with duplicate records from multiple sources."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        def mock_load_all():
            return {
                "Feed1": [
                    VulnerabilityRecord(
                        id="CVE-2024-1234",
                        source="Feed1",
                        severity="HIGH",
                        affected_packages=["pkg1"],
                        references=["https://ref1.com"],
                    )
                ],
                "Feed2": [
                    VulnerabilityRecord(
                        id="CVE-2024-1234",
                        source="Feed2",
                        cvss_score=7.5,
                        exploit_available=True,
                        affected_packages=["pkg2"],
                        references=["https://ref2.com"],
                    )
                ],
            }

        monkeypatch.setattr(orchestrator, "load_all_feeds", mock_load_all)

        output_path = temp_cache_dir / "unified.json"
        orchestrator.export_unified_feed(output_path)

        assert output_path.exists()
        data = json.loads(output_path.read_text())

        assert data["metadata"]["total_vulnerabilities"] == 1
        assert len(data["vulnerabilities"]) == 1

        vuln = data["vulnerabilities"][0]
        assert vuln["id"] == "CVE-2024-1234"
        assert len(vuln["sources"]) == 2
        assert "Feed1" in vuln["sources"]
        assert "Feed2" in vuln["sources"]
        assert vuln["severity"] == "HIGH"
        assert vuln["cvss_score"] == 7.5
        assert vuln["exploit_available"] is True
        assert set(vuln["affected_packages"]) == {"pkg1", "pkg2"}
        assert set(vuln["references"]) == {"https://ref1.com", "https://ref2.com"}

    def test_orchestrator_get_statistics_with_exploits_and_kev(
        self, temp_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Test get_statistics with exploit and KEV data."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        def mock_load_all():
            return {
                "Feed1": [
                    VulnerabilityRecord(
                        id="CVE-2024-1234",
                        source="Feed1",
                        exploit_available=True,
                        kev_listed=True,
                    ),
                    VulnerabilityRecord(
                        id="CVE-2024-5678", source="Feed1", exploit_available=True
                    ),
                ],
                "Feed2": [
                    VulnerabilityRecord(id="CVE-2024-9999", source="Feed2"),
                ],
            }

        def mock_get_metadata():
            return [
                FeedMetadata(
                    name="Feed1",
                    source="Source1",
                    url="https://feed1.com",
                    record_count=2,
                ),
                FeedMetadata(
                    name="Feed2",
                    source="Source2",
                    url="https://feed2.com",
                    record_count=1,
                ),
            ]

        monkeypatch.setattr(orchestrator, "load_all_feeds", mock_load_all)
        monkeypatch.setattr(orchestrator, "get_all_metadata", mock_get_metadata)

        stats = orchestrator.get_statistics()

        assert stats["total_feeds"] == 2
        assert stats["total_vulnerabilities"] == 3
        assert stats["vulnerabilities_with_exploits"] == 2
        assert stats["kev_listed_vulnerabilities"] == 1
        assert len(stats["feeds"]) == 2


class TestEcosystemsComplete:
    """Complete coverage tests for ecosystem feeds to reach 100%."""

    def test_npm_security_feed_json_decode_error(self, temp_cache_dir: Path):
        """Test NPM Security feed with invalid JSON."""
        feed = NPMSecurityFeed(cache_dir=temp_cache_dir)
        invalid_json = b"invalid json {{"
        records = feed.parse_feed(invalid_json)
        assert len(records) == 0

    def test_npm_security_feed_with_all_fields(self, temp_cache_dir: Path):
        """Test NPM Security feed with all fields present."""
        feed = NPMSecurityFeed(cache_dir=temp_cache_dir)
        data = json.dumps(
            {
                "advisories": {
                    "1234": {
                        "id": "GHSA-xxxx-yyyy-zzzz",
                        "severity": "high",
                        "overview": "Test vulnerability description",
                        "created": "2024-01-01",
                        "updated": "2024-01-02",
                        "module_name": "test-package",
                        "vulnerable_versions": ">=1.0.0 <2.0.0",
                        "patched_versions": ">=2.0.0",
                        "url": "https://example.com/advisory",
                        "cwe": "CWE-79",
                        "recommendation": "Update to version 2.0.0",
                    }
                }
            }
        ).encode()

        records = feed.parse_feed(data)

        assert len(records) == 1
        assert records[0].id == "GHSA-xxxx-yyyy-zzzz"
        assert records[0].severity == "high"
        assert records[0].description == "Test vulnerability description"
        assert records[0].affected_packages == ["test-package"]
        assert "https://example.com/advisory" in records[0].references
        assert "CWE-79" in records[0].cwe_ids

    def test_rubysec_feed_json_decode_error(self, temp_cache_dir: Path):
        """Test RubySec feed with invalid JSON."""
        feed = RubySecFeed(cache_dir=temp_cache_dir)
        invalid_json = b"invalid json {{"
        records = feed.parse_feed(invalid_json)
        assert len(records) == 0

    def test_rubysec_feed_missing_id(self, temp_cache_dir: Path):
        """Test RubySec feed with missing advisory ID."""
        feed = RubySecFeed(cache_dir=temp_cache_dir)
        data = json.dumps(
            [
                {
                    "criticality": "high",
                    "description": "Test vulnerability",
                    "date": "2024-01-01",
                }
            ]
        ).encode()

        records = feed.parse_feed(data)
        assert len(records) == 0

    def test_rubysec_feed_with_all_fields(self, temp_cache_dir: Path):
        """Test RubySec feed with all fields present."""
        feed = RubySecFeed(cache_dir=temp_cache_dir)
        data = json.dumps(
            [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "criticality": "high",
                    "description": "Test vulnerability description",
                    "date": "2024-01-01",
                    "gem": "test-gem",
                    "unaffected_versions": ["< 1.0.0"],
                    "patched_versions": [">= 2.0.0"],
                    "url": "https://example.com/advisory",
                    "cve": "2024-1234",
                    "title": "Test Advisory",
                }
            ]
        ).encode()

        records = feed.parse_feed(data)

        assert len(records) == 1
        assert records[0].id == "GHSA-xxxx-yyyy-zzzz"
        assert records[0].severity == "high"
        assert records[0].affected_packages == ["test-gem"]
        assert "https://example.com/advisory" in records[0].references

    def test_debian_security_feed_json_decode_error(self, temp_cache_dir: Path):
        """Test Debian Security feed with invalid JSON."""
        feed = DebianSecurityFeed(cache_dir=temp_cache_dir)
        invalid_json = b"invalid json {{"
        records = feed.parse_feed(invalid_json)
        assert len(records) == 0

    def test_debian_security_feed_non_cve_entries(self, temp_cache_dir: Path):
        """Test Debian Security feed with non-CVE entries."""
        feed = DebianSecurityFeed(cache_dir=temp_cache_dir)
        data = json.dumps(
            {
                "TEMP-1234": {"description": "Temporary entry"},
                "CVE-2024-1234": {
                    "description": "Test vulnerability",
                    "releases": {
                        "bullseye": {"package1": {"status": "vulnerable"}},
                        "bookworm": {"package2": {"status": "fixed"}},
                    },
                },
            }
        ).encode()

        records = feed.parse_feed(data)

        assert len(records) == 1
        assert records[0].id == "CVE-2024-1234"
        assert "debian:package1" in records[0].affected_packages
        assert "debian:package2" in records[0].affected_packages

    def test_ubuntu_security_feed_json_decode_error(self, temp_cache_dir: Path):
        """Test Ubuntu Security feed with invalid JSON."""
        feed = UbuntuSecurityFeed(cache_dir=temp_cache_dir)
        invalid_json = b"invalid json {{"
        records = feed.parse_feed(invalid_json)
        assert len(records) == 0

    def test_ubuntu_security_feed_missing_id(self, temp_cache_dir: Path):
        """Test Ubuntu Security feed with missing notice ID."""
        feed = UbuntuSecurityFeed(cache_dir=temp_cache_dir)
        data = json.dumps(
            {
                "notices": [
                    {"summary": "Test notice", "cves": ["CVE-2024-1234"]},
                ]
            }
        ).encode()

        records = feed.parse_feed(data)
        assert len(records) == 0

    def test_ubuntu_security_feed_with_all_fields(self, temp_cache_dir: Path):
        """Test Ubuntu Security feed with all fields present."""
        feed = UbuntuSecurityFeed(cache_dir=temp_cache_dir)
        data = json.dumps(
            {
                "notices": [
                    {
                        "id": "USN-1234-1",
                        "summary": "Test security notice",
                        "published": "2024-01-01",
                        "cves": ["CVE-2024-1234", "CVE-2024-5678"],
                        "title": "Test Notice Title",
                    }
                ]
            }
        ).encode()

        records = feed.parse_feed(data)

        assert len(records) == 1
        assert records[0].id == "USN-1234-1"
        assert records[0].description == "Test security notice"
        assert "CVE-2024-1234" in records[0].cwe_ids
        assert "CVE-2024-5678" in records[0].cwe_ids


class TestRemainingModulesComplete:
    """Complete coverage tests for all remaining modules to reach 100%."""

    def test_nvd_feed_fetch_recent_cves_with_api_key(
        self, temp_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Test NVD fetch_recent_cves with API key."""
        feed = NVDFeed(api_key="test-api-key", cache_dir=temp_cache_dir)

        def mock_fetcher(url):
            assert "apiKey=test-api-key" in url
            return json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2024-1234",
                                "descriptions": [
                                    {"lang": "en", "value": "Test vulnerability"}
                                ],
                            }
                        }
                    ]
                }
            ).encode()

        monkeypatch.setattr(feed, "fetcher", mock_fetcher)

        records = feed.fetch_recent_cves(days=7)

        assert len(records) == 1
        assert records[0].id == "CVE-2024-1234"

    def test_nvd_feed_fetch_recent_cves_error(
        self, temp_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Test NVD fetch_recent_cves with error."""
        feed = NVDFeed(cache_dir=temp_cache_dir)

        def mock_fetcher(url):
            raise Exception("Network error")

        monkeypatch.setattr(feed, "fetcher", mock_fetcher)

        records = feed.fetch_recent_cves(days=7)

        assert len(records) == 0

    def test_base_feed_load_with_cache_error(self, temp_cache_dir: Path):
        """Test base feed load with cache read error."""
        feed = NVDFeed(cache_dir=temp_cache_dir)

        cache_file = temp_cache_dir / feed.cache_filename
        cache_file.write_text("invalid json {{")

        records = feed.load_feed()

        assert len(records) == 0

    def test_orchestrator_get_all_metadata_with_kev_path_exists(
        self, temp_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Test get_all_metadata when KEV path exists."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        kev_path = temp_cache_dir / "kev.json"
        kev_path.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {"cveID": "CVE-2024-1234"},
                        {"cveID": "CVE-2024-5678"},
                    ]
                }
            )
        )

        metadata = orchestrator.get_all_metadata()

        kev_meta = [m for m in metadata if m.name == "KEV"]
        assert len(kev_meta) == 1
        assert kev_meta[0].record_count == 2

    def test_orchestrator_enrich_vulnerability_with_matching_cwe(
        self, temp_cache_dir: Path
    ):
        """Test enrich_vulnerability matching by CWE ID."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        all_feeds = {
            "Feed1": [
                VulnerabilityRecord(
                    id="VULN-001",
                    source="Feed1",
                    cwe_ids=["CVE-2024-1234"],
                    severity="HIGH",
                )
            ]
        }

        enrichment = orchestrator.enrich_vulnerability("CVE-2024-1234", all_feeds)

        assert "Feed1" in enrichment["sources"]
        assert enrichment["severity"] == "HIGH"

    def test_orchestrator_export_unified_feed_with_merge_logic(
        self, temp_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Test export_unified_feed merge logic for duplicate records."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        def mock_load_all():
            return {
                "Feed1": [
                    VulnerabilityRecord(
                        id="CVE-2024-1234",
                        source="Feed1",
                        severity="HIGH",
                        cvss_score=7.5,
                    )
                ],
                "Feed2": [
                    VulnerabilityRecord(
                        id="CVE-2024-1234",
                        source="Feed2",
                        exploit_available=True,
                        kev_listed=True,
                    )
                ],
            }

        monkeypatch.setattr(orchestrator, "load_all_feeds", mock_load_all)

        output_path = temp_cache_dir / "unified.json"
        orchestrator.export_unified_feed(output_path)

        data = json.loads(output_path.read_text())
        vuln = data["vulnerabilities"][0]

        assert vuln["severity"] == "HIGH"
        assert vuln["cvss_score"] == 7.5
        assert vuln["exploit_available"] is True
        assert vuln["kev_listed"] is True


class TestFinalCoverageGaps:
    """Tests to cover all remaining gaps and reach 100% coverage."""

    def test_kev_load_cache_with_non_dict_payload(self, temp_cache_dir: Path):
        """Test KEV _load_cache with non-dict payload."""
        from risk.feeds.kev import KEV_CACHE_FILENAME

        cache_file = temp_cache_dir / KEV_CACHE_FILENAME
        cache_file.write_text(json.dumps(["not", "a", "dict"]))

        from risk.feeds.kev import _load_cache

        result = _load_cache(temp_cache_dir)
        assert result is None

    def test_kev_update_feed_with_cache_fallback(
        self, temp_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Test KEV update_feed falling back to cache on network error."""
        from risk.feeds.kev import KEV_CACHE_FILENAME, update_kev_feed

        cache_file = temp_cache_dir / KEV_CACHE_FILENAME
        cache_data = {"vulnerabilities": [{"cveID": "CVE-2024-1234"}]}
        cache_file.write_text(json.dumps(cache_data))

        def mock_fetcher(url):
            from urllib.error import URLError

            raise URLError("Network error")

        result = update_kev_feed(cache_dir=temp_cache_dir, fetcher=mock_fetcher)

        assert result == temp_cache_dir / KEV_CACHE_FILENAME

    def test_kev_load_catalog_with_data_wrapper(self, temp_cache_dir: Path):
        """Test KEV load_catalog with data wrapper structure."""
        kev_path = temp_cache_dir / "kev.json"
        kev_path.write_text(
            json.dumps(
                {
                    "data": {
                        "vulnerabilities": [
                            {"cveID": "CVE-2024-1234"},
                            {"cveID": "CVE-2024-5678"},
                        ]
                    }
                }
            )
        )

        catalog = load_kev_catalog(path=kev_path, cache_dir=temp_cache_dir)

        assert len(catalog) == 2
        assert "CVE-2024-1234" in catalog

    def test_kev_load_catalog_with_non_dict_entry(self, temp_cache_dir: Path):
        """Test KEV load_catalog with non-dict entry in vulnerabilities."""
        kev_path = temp_cache_dir / "kev.json"
        kev_path.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {"cveID": "CVE-2024-1234"},
                        "invalid entry",
                        {"cveID": "CVE-2024-5678"},
                    ]
                }
            )
        )

        catalog = load_kev_catalog(path=kev_path, cache_dir=temp_cache_dir)

        assert len(catalog) == 2

    def test_kev_load_catalog_with_missing_cve_id(self, temp_cache_dir: Path):
        """Test KEV load_catalog with entry missing CVE ID."""
        kev_path = temp_cache_dir / "kev.json"
        kev_path.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {"cveID": "CVE-2024-1234"},
                        {"title": "No CVE ID"},
                        {"cveID": 12345},  # Non-string CVE ID
                    ]
                }
            )
        )

        catalog = load_kev_catalog(path=kev_path, cache_dir=temp_cache_dir)

        assert len(catalog) == 1

    def test_kev_cves_function(self, temp_cache_dir: Path):
        """Test kev_cves function."""
        from risk.feeds.kev import kev_cves

        catalog = {
            "CVE-2024-1234": {"cveID": "CVE-2024-1234"},
            "CVE-2024-5678": {"cveID": "CVE-2024-5678"},
        }

        cves = kev_cves(catalog)

        assert len(cves) == 2
        assert "CVE-2024-1234" in cves
        assert "CVE-2024-5678" in cves

    def test_nvd_feed_parse_cvss_v2_severity_high(self, temp_cache_dir: Path):
        """Test NVD parse with CVSS v2 HIGH severity."""
        feed = NVDFeed(cache_dir=temp_cache_dir)
        data = json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-1234",
                            "descriptions": [{"lang": "en", "value": "Test"}],
                            "metrics": {
                                "cvssMetricV2": [
                                    {
                                        "cvssData": {
                                            "baseScore": 8.5,
                                            "vectorString": "AV:N",
                                        }
                                    }
                                ]
                            },
                        }
                    }
                ]
            }
        ).encode()

        records = feed.parse_feed(data)

        assert len(records) == 1
        assert records[0].severity == "HIGH"
        assert records[0].cvss_score == 8.5

    def test_nvd_feed_parse_cvss_v2_severity_low(self, temp_cache_dir: Path):
        """Test NVD parse with CVSS v2 LOW severity."""
        feed = NVDFeed(cache_dir=temp_cache_dir)
        data = json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-1234",
                            "descriptions": [{"lang": "en", "value": "Test"}],
                            "metrics": {
                                "cvssMetricV2": [
                                    {
                                        "cvssData": {
                                            "baseScore": 2.5,
                                            "vectorString": "AV:L",
                                        }
                                    }
                                ]
                            },
                        }
                    }
                ]
            }
        ).encode()

        records = feed.parse_feed(data)

        assert len(records) == 1
        assert records[0].severity == "LOW"

    def test_osv_feed_parse_cvss_parsing_error(self, temp_cache_dir: Path):
        """Test OSV parse with CVSS parsing error."""
        feed = OSVFeed(cache_dir=temp_cache_dir)

        data = {
            "id": "OSV-2024-1234",
            "summary": "Test",
            "severity": [{"type": "CVSS_V3", "score": "invalid/format"}],
        }

        record = feed._parse_osv_record(data, "PyPI")

        assert record is not None
        assert record.cvss_score is None

    def test_orchestrator_export_unified_feed_missing_line(
        self, temp_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Test orchestrator export_unified_feed to cover line 294."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        def mock_load_all():
            return {
                "Feed1": [
                    VulnerabilityRecord(
                        id="CVE-2024-1234",
                        source="Feed1",
                        severity="HIGH",
                        description="Test vulnerability",
                    )
                ]
            }

        monkeypatch.setattr(orchestrator, "load_all_feeds", mock_load_all)

        output_path = temp_cache_dir / "unified.json"
        orchestrator.export_unified_feed(output_path)

        data = json.loads(output_path.read_text())
        assert "metadata" in data
        assert data["metadata"]["total_vulnerabilities"] == 1


class TestAbsoluteCompleteCoverage:
    """Final tests to achieve 100% coverage on all remaining lines."""

    def test_kev_load_catalog_json_decode_in_load(self, temp_cache_dir: Path):
        """Test KEV load_catalog with JSON decode error during load."""
        kev_path = temp_cache_dir / "kev.json"
        kev_path.write_text("invalid json content {{")

        try:
            catalog = load_kev_catalog(path=kev_path, cache_dir=temp_cache_dir)
            assert catalog == {}
        except FileNotFoundError:
            pass

    def test_base_feed_registry_load_all_with_error(self, temp_cache_dir: Path):
        """Test FeedRegistry load_all with feed load error."""
        from risk.feeds.base import FeedRegistry

        registry = FeedRegistry(cache_dir=temp_cache_dir)
        feed = NVDFeed(cache_dir=temp_cache_dir)
        registry.register(feed)

        results = registry.load_all()

        assert "NVD" in results or len(results) == 0

    def test_base_feed_get_metadata_with_load_error(self, temp_cache_dir: Path):
        """Test get_metadata when load_feed raises exception."""
        feed = NVDFeed(cache_dir=temp_cache_dir)

        cache_file = temp_cache_dir / feed.cache_filename
        cache_file.write_text("invalid json {{")

        metadata = feed.get_metadata()

        assert metadata.name == "NVD"
        assert metadata.record_count == 0

    def test_base_feed_registry_get_feed_not_found(self, temp_cache_dir: Path):
        """Test FeedRegistry get_feed with non-existent feed."""
        from risk.feeds.base import FeedRegistry

        registry = FeedRegistry(cache_dir=temp_cache_dir)

        result = registry.get_feed("NonExistentFeed")

        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
