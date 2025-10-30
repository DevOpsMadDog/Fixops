"""Comprehensive coverage tests for threat intelligence feeds.

This test file focuses on achieving 100% code coverage for all feed modules.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from risk.feeds.base import VulnerabilityRecord
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
