"""Language and ecosystem-specific security advisory feeds.

Integrations for npm, PyPI, RubySec, RustSec, Go, Maven, NuGet, etc.
"""

from __future__ import annotations

import json
from typing import List

from .base import ThreatIntelligenceFeed, VulnerabilityRecord


class NPMSecurityFeed(ThreatIntelligenceFeed):
    """npm Security Advisories feed."""

    @property
    def feed_name(self) -> str:
        return "npm Security"

    @property
    def feed_url(self) -> str:
        return "https://registry.npmjs.org/-/npm/v1/security/advisories"

    @property
    def cache_filename(self) -> str:
        return "npm-security.json"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse npm Security feed."""
        try:
            payload = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            self.logger.error("Failed to parse npm Security JSON: %s", exc)
            return []

        advisories = payload.get("advisories", {})
        records: List[VulnerabilityRecord] = []

        for advisory_id, advisory in advisories.items():
            record = VulnerabilityRecord(
                id=advisory.get("id", advisory_id),
                source="npm Security",
                severity=advisory.get("severity"),
                description=advisory.get("overview", ""),
                published=advisory.get("created"),
                modified=advisory.get("updated"),
                affected_packages=[advisory.get("module_name", "")],
                affected_versions=[advisory.get("vulnerable_versions", "")],
                fixed_versions=[advisory.get("patched_versions", "")],
                references=[advisory.get("url")] if advisory.get("url") else [],
                cwe_ids=[advisory.get("cwe")] if advisory.get("cwe") else [],
                ecosystem="npm",
                metadata={"recommendation": advisory.get("recommendation")},
            )
            records.append(record)

        return records


class PyPISecurityFeed(ThreatIntelligenceFeed):
    """PyPI Security Advisories feed (from PyPA advisory database)."""

    @property
    def feed_name(self) -> str:
        return "PyPI Security"

    @property
    def feed_url(self) -> str:
        return "https://github.com/pypa/advisory-database"

    @property
    def cache_filename(self) -> str:
        return "pypi-security.json"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse PyPI Security feed (uses OSV format)."""
        self.logger.info(
            "PyPI Security uses OSV format (use OSVFeed with PyPI ecosystem)"
        )
        return []


class RubySecFeed(ThreatIntelligenceFeed):
    """RubySec (Ruby gem vulnerabilities) feed."""

    @property
    def feed_name(self) -> str:
        return "RubySec"

    @property
    def feed_url(self) -> str:
        return "https://rubysec.com/advisories.json"

    @property
    def cache_filename(self) -> str:
        return "rubysec.json"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse RubySec feed."""
        try:
            advisories = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            self.logger.error("Failed to parse RubySec JSON: %s", exc)
            return []

        records: List[VulnerabilityRecord] = []

        for advisory in advisories:
            advisory_id = advisory.get("id")
            if not advisory_id:
                continue

            record = VulnerabilityRecord(
                id=advisory_id,
                source="RubySec",
                severity=advisory.get("criticality"),
                description=advisory.get("description", ""),
                published=advisory.get("date"),
                affected_packages=[advisory.get("gem", "")],
                affected_versions=advisory.get("unaffected_versions", []),
                fixed_versions=advisory.get("patched_versions", []),
                references=[advisory.get("url")] if advisory.get("url") else [],
                cwe_ids=[f"CVE-{advisory.get('cve')}" if advisory.get("cve") else ""],
                ecosystem="RubyGems",
                metadata={"title": advisory.get("title")},
            )
            records.append(record)

        return records


class RustSecFeed(ThreatIntelligenceFeed):
    """RustSec (Rust crate vulnerabilities) feed."""

    @property
    def feed_name(self) -> str:
        return "RustSec"

    @property
    def feed_url(self) -> str:
        return "https://rustsec.org/advisories.json"

    @property
    def cache_filename(self) -> str:
        return "rustsec.json"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse RustSec feed (uses OSV format)."""
        self.logger.info(
            "RustSec uses OSV format (use OSVFeed with crates.io ecosystem)"
        )
        return []


class GoVulnDBFeed(ThreatIntelligenceFeed):
    """Go Vulnerability Database feed."""

    @property
    def feed_name(self) -> str:
        return "Go Vulnerability Database"

    @property
    def feed_url(self) -> str:
        return "https://vuln.go.dev/"

    @property
    def cache_filename(self) -> str:
        return "go-vulndb.json"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse Go VulnDB feed (uses OSV format)."""
        self.logger.info("Go VulnDB uses OSV format (use OSVFeed with Go ecosystem)")
        return []


class MavenSecurityFeed(ThreatIntelligenceFeed):
    """Maven Central Security feed."""

    @property
    def feed_name(self) -> str:
        return "Maven Security"

    @property
    def feed_url(self) -> str:
        return "https://search.maven.org/"

    @property
    def cache_filename(self) -> str:
        return "maven-security.json"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse Maven Security feed (uses OSV format)."""
        self.logger.info(
            "Maven Security uses OSV format (use OSVFeed with Maven ecosystem)"
        )
        return []


class NuGetSecurityFeed(ThreatIntelligenceFeed):
    """NuGet Security Advisories feed."""

    @property
    def feed_name(self) -> str:
        return "NuGet Security"

    @property
    def feed_url(self) -> str:
        return "https://api.nuget.org/v3/index.json"

    @property
    def cache_filename(self) -> str:
        return "nuget-security.json"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse NuGet Security feed."""
        self.logger.info("NuGet Security feed requires additional API calls")
        return []


class DebianSecurityFeed(ThreatIntelligenceFeed):
    """Debian Security Tracker feed."""

    @property
    def feed_name(self) -> str:
        return "Debian Security"

    @property
    def feed_url(self) -> str:
        return "https://security-tracker.debian.org/tracker/data/json"

    @property
    def cache_filename(self) -> str:
        return "debian-security.json"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse Debian Security feed."""
        try:
            payload = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            self.logger.error("Failed to parse Debian Security JSON: %s", exc)
            return []

        records: List[VulnerabilityRecord] = []

        for cve_id, cve_data in payload.items():
            if not cve_id.startswith("CVE-"):
                continue

            description = cve_data.get("description", "")
            releases = cve_data.get("releases", {})
            affected_packages: List[str] = []

            for release_name, release_data in releases.items():
                if isinstance(release_data, dict):
                    for pkg_name in release_data.keys():
                        affected_packages.append(f"debian:{pkg_name}")

            record = VulnerabilityRecord(
                id=cve_id,
                source="Debian Security",
                description=description,
                affected_packages=list(set(affected_packages)),
                ecosystem="Debian",
                metadata={"releases": releases},
            )
            records.append(record)

        return records


class UbuntuSecurityFeed(ThreatIntelligenceFeed):
    """Ubuntu Security Notices feed."""

    @property
    def feed_name(self) -> str:
        return "Ubuntu Security"

    @property
    def feed_url(self) -> str:
        return "https://ubuntu.com/security/notices.json"

    @property
    def cache_filename(self) -> str:
        return "ubuntu-security.json"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse Ubuntu Security feed."""
        try:
            payload = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            self.logger.error("Failed to parse Ubuntu Security JSON: %s", exc)
            return []

        notices = payload.get("notices", [])
        records: List[VulnerabilityRecord] = []

        for notice in notices:
            notice_id = notice.get("id")
            if not notice_id:
                continue

            cves = notice.get("cves", [])
            description = notice.get("summary", "")

            record = VulnerabilityRecord(
                id=notice_id,
                source="Ubuntu Security",
                description=description,
                published=notice.get("published"),
                cwe_ids=cves,
                ecosystem="Ubuntu",
                metadata={"title": notice.get("title")},
            )
            records.append(record)

        return records


class AlpineSecDBFeed(ThreatIntelligenceFeed):
    """Alpine Linux Security Database feed."""

    @property
    def feed_name(self) -> str:
        return "Alpine SecDB"

    @property
    def feed_url(self) -> str:
        return "https://secdb.alpinelinux.org/"

    @property
    def cache_filename(self) -> str:
        return "alpine-secdb.json"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse Alpine SecDB feed."""
        self.logger.info("Alpine SecDB feed requires branch-specific URLs")
        return []


__all__ = [
    "NPMSecurityFeed",
    "PyPISecurityFeed",
    "RubySecFeed",
    "RustSecFeed",
    "GoVulnDBFeed",
    "MavenSecurityFeed",
    "NuGetSecurityFeed",
    "DebianSecurityFeed",
    "UbuntuSecurityFeed",
    "AlpineSecDBFeed",
]
