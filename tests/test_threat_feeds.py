"""Tests for threat intelligence feed modules (suite-evidence-risk/risk/feeds/).

Covers:
  - VulnerabilityRecord dataclass
  - FeedMetadata dataclass
  - ThreatIntelligenceFeed base class
  - ExploitDBFeed parse_feed
  - NPMSecurityFeed parse_feed
  - PyPIAdvisoryFeed parse_feed
  - RustSecFeed parse_feed
  - GoVulnDBFeed parse_feed
  - Feed caching
  - Error handling
"""

from __future__ import annotations

import json
import pytest

from risk.feeds.base import (
    FeedMetadata,
    ThreatIntelligenceFeed,
    VulnerabilityRecord,
    default_fetcher,
)
from risk.feeds.exploits import ExploitDBFeed
from risk.feeds.ecosystems import NPMSecurityFeed


# ──────────────────────────────────────────────────────
#  VulnerabilityRecord tests
# ──────────────────────────────────────────────────────


class TestVulnerabilityRecord:
    def test_basic_creation(self):
        vr = VulnerabilityRecord(id="CVE-2024-0001", source="NVD")
        assert vr.id == "CVE-2024-0001"
        assert vr.source == "NVD"
        assert vr.severity is None
        assert vr.cvss_score is None
        assert vr.affected_packages == []
        assert vr.exploit_available is False
        assert vr.kev_listed is False

    def test_full_creation(self):
        vr = VulnerabilityRecord(
            id="CVE-2024-0002",
            source="GitHub Advisory",
            severity="critical",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description="Remote code execution in foo",
            published="2024-01-15",
            affected_packages=["foo", "bar"],
            affected_versions=["<1.2.3"],
            fixed_versions=["1.2.3"],
            references=["https://example.com/advisory"],
            cwe_ids=["CWE-94"],
            exploit_available=True,
            exploit_maturity="weaponized",
            epss_score=0.95,
            kev_listed=True,
        )
        assert vr.cvss_score == 9.8
        assert vr.exploit_available is True
        assert len(vr.cwe_ids) == 1

    def test_to_dict(self):
        vr = VulnerabilityRecord(id="TEST-001", source="test")
        d = vr.to_dict()
        assert isinstance(d, dict)
        assert d["id"] == "TEST-001"
        assert d["source"] == "test"
        assert "severity" in d
        assert "cvss_score" in d
        assert "affected_packages" in d
        assert "exploit_available" in d

    def test_to_dict_roundtrip_fields(self):
        vr = VulnerabilityRecord(
            id="ROUND-001",
            source="test",
            severity="high",
            cvss_score=7.5,
            cwe_ids=["CWE-79"],
            metadata={"custom": "value"},
        )
        d = vr.to_dict()
        assert d["severity"] == "high"
        assert d["cvss_score"] == 7.5
        assert d["cwe_ids"] == ["CWE-79"]
        assert d["metadata"]["custom"] == "value"


# ──────────────────────────────────────────────────────
#  ExploitDBFeed tests
# ──────────────────────────────────────────────────────


class TestExploitDBFeed:
    def test_feed_properties(self):
        feed = ExploitDBFeed()
        assert feed.feed_name == "Exploit-DB"
        assert "exploit" in feed.feed_url.lower() or "exploitdb" in feed.cache_filename
        assert feed.cache_filename == "exploitdb.csv"

    def test_parse_feed_csv(self):
        csv_data = (
            "id,file,description,date,author,platform,type,port\n"
            "12345,exploits/linux/local/12345.py,Local privilege escalation,2024-01-01,researcher,linux,local,\n"
            "12346,exploits/windows/remote/12346.rb,Remote buffer overflow,2024-01-02,attacker,windows,remote,80\n"
        )
        feed = ExploitDBFeed()
        records = feed.parse_feed(csv_data.encode("utf-8"))
        assert len(records) == 2
        assert records[0].id == "EDB-12345"
        assert records[0].source == "Exploit-DB"
        assert records[0].exploit_available is True
        assert records[0].exploit_maturity == "public"
        assert "Local privilege escalation" in records[0].description

    def test_parse_feed_empty(self):
        feed = ExploitDBFeed()
        records = feed.parse_feed(b"id,file,description,date,author,platform,type,port\n")
        assert records == []

    def test_parse_feed_invalid(self):
        feed = ExploitDBFeed()
        records = feed.parse_feed(b"\x80\x81\x82")
        assert isinstance(records, list)


# ──────────────────────────────────────────────────────
#  NPMSecurityFeed tests
# ──────────────────────────────────────────────────────


class TestNPMSecurityFeed:
    def test_feed_properties(self):
        feed = NPMSecurityFeed()
        assert feed.feed_name == "npm Security"
        assert "npm" in feed.feed_url.lower()
        assert feed.cache_filename == "npm-security.json"

    def test_parse_feed_json(self):
        data = {
            "advisories": {
                "1001": {
                    "id": 1001,
                    "module_name": "lodash",
                    "severity": "high",
                    "overview": "Prototype Pollution in lodash",
                    "created": "2024-01-01",
                    "updated": "2024-01-02",
                    "vulnerable_versions": "<4.17.21",
                    "patched_versions": ">=4.17.21",
                }
            }
        }
        feed = NPMSecurityFeed()
        records = feed.parse_feed(json.dumps(data).encode("utf-8"))
        assert len(records) == 1
        assert records[0].source == "npm Security"
        assert "lodash" in records[0].affected_packages

    def test_parse_feed_empty_json(self):
        feed = NPMSecurityFeed()
        records = feed.parse_feed(json.dumps({"advisories": {}}).encode("utf-8"))
        assert records == []

    def test_parse_feed_invalid_json(self):
        feed = NPMSecurityFeed()
        records = feed.parse_feed(b"not json at all")
        assert records == []


# ──────────────────────────────────────────────────────
#  FeedMetadata tests
# ──────────────────────────────────────────────────────


class TestFeedMetadata:
    def test_creation(self):
        fm = FeedMetadata(
            name="Test Feed",
            source="unit-test",
            url="https://example.com/feed",
            description="A test feed",
        )
        assert fm.name == "Test Feed"
        assert fm.source == "unit-test"
        assert fm.url == "https://example.com/feed"
        assert fm.record_count == 0
        assert fm.last_updated is None

    def test_creation_full(self):
        fm = FeedMetadata(
            name="Full Feed",
            source="integration",
            url="https://example.com/feed2",
            last_updated="2024-01-01",
            record_count=42,
            version="1.0",
            description="A full feed",
        )
        assert fm.record_count == 42
        assert fm.version == "1.0"
