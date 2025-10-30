"""Comprehensive tests for threat intelligence feeds."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from risk.feeds.base import FeedMetadata, FeedRegistry, VulnerabilityRecord
from risk.feeds.ecosystems import DebianSecurityFeed, NPMSecurityFeed, RubySecFeed
from risk.feeds.exploits import ExploitDBFeed
from risk.feeds.github import GitHubSecurityAdvisoriesFeed
from risk.feeds.nvd import NVDFeed
from risk.feeds.orchestrator import ThreatIntelligenceOrchestrator
from risk.feeds.osv import OSVFeed
from risk.feeds.vendors import KubernetesSecurityFeed, MicrosoftSecurityFeed


@pytest.fixture
def temp_cache_dir(tmp_path: Path) -> Path:
    """Create temporary cache directory."""
    cache_dir = tmp_path / "feeds_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


class TestVulnerabilityRecord:
    """Test VulnerabilityRecord dataclass."""

    def test_vulnerability_record_creation(self):
        """Test creating a vulnerability record."""
        record = VulnerabilityRecord(
            id="CVE-2024-1234",
            source="Test Source",
            severity="HIGH",
            cvss_score=7.5,
            description="Test vulnerability",
        )

        assert record.id == "CVE-2024-1234"
        assert record.source == "Test Source"
        assert record.severity == "HIGH"
        assert record.cvss_score == 7.5

    def test_vulnerability_record_to_dict(self):
        """Test converting vulnerability record to dictionary."""
        record = VulnerabilityRecord(
            id="CVE-2024-1234",
            source="Test Source",
            severity="HIGH",
            cvss_score=7.5,
            description="Test vulnerability",
            affected_packages=["package1", "package2"],
            exploit_available=True,
        )

        result = record.to_dict()

        assert result["id"] == "CVE-2024-1234"
        assert result["source"] == "Test Source"
        assert result["severity"] == "HIGH"
        assert result["cvss_score"] == 7.5
        assert result["affected_packages"] == ["package1", "package2"]
        assert result["exploit_available"] is True


class TestFeedRegistry:
    """Test FeedRegistry."""

    def test_feed_registry_creation(self, temp_cache_dir: Path):
        """Test creating a feed registry."""
        registry = FeedRegistry(cache_dir=temp_cache_dir)
        assert len(registry.list_feeds()) == 0

    def test_feed_registry_register(self, temp_cache_dir: Path):
        """Test registering feeds."""
        registry = FeedRegistry(cache_dir=temp_cache_dir)

        osv_feed = OSVFeed(cache_dir=temp_cache_dir)
        registry.register(osv_feed)

        assert len(registry.list_feeds()) == 1
        assert "OSV" in registry.list_feeds()

    def test_feed_registry_get_feed(self, temp_cache_dir: Path):
        """Test getting a registered feed."""
        registry = FeedRegistry(cache_dir=temp_cache_dir)

        osv_feed = OSVFeed(cache_dir=temp_cache_dir)
        registry.register(osv_feed)

        retrieved_feed = registry.get_feed("OSV")
        assert retrieved_feed is not None
        assert retrieved_feed.feed_name == "OSV"

    def test_feed_registry_get_all_metadata(self, temp_cache_dir: Path):
        """Test getting metadata for all feeds."""
        registry = FeedRegistry(cache_dir=temp_cache_dir)

        osv_feed = OSVFeed(cache_dir=temp_cache_dir)
        nvd_feed = NVDFeed(cache_dir=temp_cache_dir)
        registry.register(osv_feed)
        registry.register(nvd_feed)

        metadata = registry.get_all_metadata()
        assert len(metadata) == 2
        assert all(isinstance(m, FeedMetadata) for m in metadata)


class TestOSVFeed:
    """Test OSV feed integration."""

    def test_osv_feed_properties(self, temp_cache_dir: Path):
        """Test OSV feed properties."""
        feed = OSVFeed(cache_dir=temp_cache_dir)

        assert feed.feed_name == "OSV"
        assert "osv-vulnerabilities" in feed.feed_url
        assert feed.cache_filename == "osv-ecosystems.txt"

    def test_osv_feed_parse_ecosystems(self, temp_cache_dir: Path):
        """Test parsing OSV ecosystems list."""
        feed = OSVFeed(cache_dir=temp_cache_dir)

        ecosystems_data = b"PyPI\nnpm\nGo\nMaven\nRubyGems"
        records = feed.parse_feed(ecosystems_data)

        assert isinstance(records, list)


class TestNVDFeed:
    """Test NVD feed integration."""

    def test_nvd_feed_properties(self, temp_cache_dir: Path):
        """Test NVD feed properties."""
        feed = NVDFeed(cache_dir=temp_cache_dir)

        assert feed.feed_name == "NVD"
        assert "nvd.nist.gov" in feed.feed_url
        assert feed.cache_filename == "nvd-cves.json"

    def test_nvd_feed_parse(self, temp_cache_dir: Path):
        """Test parsing NVD feed."""
        feed = NVDFeed(cache_dir=temp_cache_dir)

        nvd_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-02T00:00:00.000",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                        "baseSeverity": "HIGH",
                                    }
                                }
                            ]
                        },
                        "references": [{"url": "https://example.com"}],
                        "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                    }
                }
            ]
        }

        records = feed.parse_feed(json.dumps(nvd_data).encode("utf-8"))

        assert len(records) == 1
        assert records[0].id == "CVE-2024-1234"
        assert records[0].source == "NVD"
        assert records[0].severity == "HIGH"
        assert records[0].cvss_score == 7.5


class TestGitHubSecurityAdvisoriesFeed:
    """Test GitHub Security Advisories feed."""

    def test_github_feed_properties(self, temp_cache_dir: Path):
        """Test GitHub feed properties."""
        feed = GitHubSecurityAdvisoriesFeed(cache_dir=temp_cache_dir)

        assert feed.feed_name == "GitHub Security Advisories"
        assert "api.github.com" in feed.feed_url
        assert feed.cache_filename == "github-advisories.json"

    def test_github_feed_parse(self, temp_cache_dir: Path):
        """Test parsing GitHub Security Advisories feed."""
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
                            "cvss": {
                                "score": 7.5,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            },
                            "identifiers": [{"type": "CVE", "value": "CVE-2024-1234"}],
                            "references": [{"url": "https://example.com"}],
                            "cwes": {"nodes": [{"cweId": "CWE-79"}]},
                            "vulnerabilities": {
                                "nodes": [
                                    {
                                        "package": {
                                            "name": "test-package",
                                            "ecosystem": "npm",
                                        },
                                        "vulnerableVersionRange": "< 1.0.0",
                                        "firstPatchedVersion": {"identifier": "1.0.0"},
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        }

        records = feed.parse_feed(json.dumps(github_data).encode("utf-8"))

        assert len(records) == 1
        assert records[0].id == "GHSA-xxxx-yyyy-zzzz"
        assert records[0].source == "GitHub Security Advisories"
        assert records[0].severity == "HIGH"
        assert records[0].cvss_score == 7.5


class TestVendorFeeds:
    """Test vendor-specific feeds."""

    def test_microsoft_feed_properties(self, temp_cache_dir: Path):
        """Test Microsoft Security feed properties."""
        feed = MicrosoftSecurityFeed(cache_dir=temp_cache_dir)

        assert feed.feed_name == "Microsoft Security"
        assert "msrc.microsoft.com" in feed.feed_url
        assert feed.cache_filename == "microsoft-security.json"

    def test_kubernetes_feed_properties(self, temp_cache_dir: Path):
        """Test Kubernetes Security feed properties."""
        feed = KubernetesSecurityFeed(cache_dir=temp_cache_dir)

        assert feed.feed_name == "Kubernetes Security"
        assert "kubernetes.io" in feed.feed_url
        assert feed.cache_filename == "kubernetes-security.json"


class TestEcosystemFeeds:
    """Test ecosystem-specific feeds."""

    def test_npm_feed_properties(self, temp_cache_dir: Path):
        """Test npm Security feed properties."""
        feed = NPMSecurityFeed(cache_dir=temp_cache_dir)

        assert feed.feed_name == "npm Security"
        assert "registry.npmjs.org" in feed.feed_url
        assert feed.cache_filename == "npm-security.json"

    def test_rubysec_feed_properties(self, temp_cache_dir: Path):
        """Test RubySec feed properties."""
        feed = RubySecFeed(cache_dir=temp_cache_dir)

        assert feed.feed_name == "RubySec"
        assert "rubysec.com" in feed.feed_url
        assert feed.cache_filename == "rubysec.json"

    def test_debian_feed_properties(self, temp_cache_dir: Path):
        """Test Debian Security feed properties."""
        feed = DebianSecurityFeed(cache_dir=temp_cache_dir)

        assert feed.feed_name == "Debian Security"
        assert "security-tracker.debian.org" in feed.feed_url
        assert feed.cache_filename == "debian-security.json"


class TestExploitFeeds:
    """Test exploit intelligence feeds."""

    def test_exploitdb_feed_properties(self, temp_cache_dir: Path):
        """Test Exploit-DB feed properties."""
        feed = ExploitDBFeed(cache_dir=temp_cache_dir)

        assert feed.feed_name == "Exploit-DB"
        assert "exploit-database" in feed.feed_url
        assert feed.cache_filename == "exploitdb.csv"

    def test_exploitdb_feed_parse(self, temp_cache_dir: Path):
        """Test parsing Exploit-DB CSV feed."""
        feed = ExploitDBFeed(cache_dir=temp_cache_dir)

        csv_data = b"""id,description,date,author,type,platform
12345,Test Exploit,2024-01-01,Test Author,remote,linux"""

        records = feed.parse_feed(csv_data)

        assert len(records) == 1
        assert records[0].id == "EDB-12345"
        assert records[0].source == "Exploit-DB"
        assert records[0].exploit_available is True
        assert records[0].exploit_maturity == "public"


class TestThreatIntelligenceOrchestrator:
    """Test threat intelligence orchestrator."""

    def test_orchestrator_creation(self, temp_cache_dir: Path):
        """Test creating orchestrator."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        assert orchestrator.cache_dir == temp_cache_dir
        assert len(orchestrator.registry.list_feeds()) > 0

    def test_orchestrator_get_metadata(self, temp_cache_dir: Path):
        """Test getting metadata from orchestrator."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        metadata = orchestrator.get_all_metadata()

        assert isinstance(metadata, list)
        assert len(metadata) > 0
        assert all(isinstance(m, FeedMetadata) for m in metadata)

    def test_orchestrator_enrich_vulnerability(self, temp_cache_dir: Path):
        """Test enriching vulnerability with orchestrator."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        mock_feeds: Dict[str, Any] = {
            "NVD": [
                VulnerabilityRecord(
                    id="CVE-2024-1234",
                    source="NVD",
                    severity="HIGH",
                    cvss_score=7.5,
                    description="Test vulnerability from NVD",
                )
            ],
            "GitHub Security Advisories": [
                VulnerabilityRecord(
                    id="CVE-2024-1234",
                    source="GitHub Security Advisories",
                    exploit_available=True,
                    description="Test vulnerability from GitHub",
                )
            ],
        }

        enrichment = orchestrator.enrich_vulnerability(
            "CVE-2024-1234", all_feeds=mock_feeds
        )

        assert enrichment["cve_id"] == "CVE-2024-1234"
        assert len(enrichment["sources"]) == 2
        assert "NVD" in enrichment["sources"]
        assert "GitHub Security Advisories" in enrichment["sources"]
        assert enrichment["severity"] == "HIGH"
        assert enrichment["cvss_score"] == 7.5
        assert enrichment["exploit_available"] is True

    def test_orchestrator_get_statistics(self, temp_cache_dir: Path):
        """Test getting statistics from orchestrator."""
        orchestrator = ThreatIntelligenceOrchestrator(cache_dir=temp_cache_dir)

        stats = orchestrator.get_statistics()

        assert "total_feeds" in stats
        assert "total_vulnerabilities" in stats
        assert "vulnerabilities_with_exploits" in stats
        assert "kev_listed_vulnerabilities" in stats
        assert "feeds" in stats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
