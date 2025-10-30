"""Vendor-specific security advisory feeds.

Integrations for major vendors: Microsoft, Apple, AWS, Azure, GCP, Oracle, Cisco, etc.
"""

from __future__ import annotations

import json
from typing import List

from .base import ThreatIntelligenceFeed, VulnerabilityRecord


class MicrosoftSecurityFeed(ThreatIntelligenceFeed):
    """Microsoft Security Response Center (MSRC) feed."""

    @property
    def feed_name(self) -> str:
        return "Microsoft Security"

    @property
    def feed_url(self) -> str:
        return "https://api.msrc.microsoft.com/cvrf/v2.0/updates"

    @property
    def cache_filename(self) -> str:
        return "microsoft-security.json"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse Microsoft Security feed."""
        try:
            payload = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            self.logger.error("Failed to parse Microsoft Security JSON: %s", exc)
            return []

        updates = payload.get("value", [])
        records: List[VulnerabilityRecord] = []

        for update in updates:
            update_id = update.get("ID")
            if not update_id:
                continue

            record = VulnerabilityRecord(
                id=update_id,
                source="Microsoft Security",
                description=update.get("Title", ""),
                published=update.get("InitialReleaseDate"),
                modified=update.get("CurrentReleaseDate"),
                severity=update.get("Severity"),
                vendor_advisory=(
                    f"https://msrc.microsoft.com/update-guide/vulnerability/{update_id}"
                ),
                metadata={"alias": update.get("Alias")},
            )
            records.append(record)

        return records


class AppleSecurityFeed(ThreatIntelligenceFeed):
    """Apple Security Updates feed."""

    @property
    def feed_name(self) -> str:
        return "Apple Security"

    @property
    def feed_url(self) -> str:
        return "https://support.apple.com/en-us/HT201222"

    @property
    def cache_filename(self) -> str:
        return "apple-security.html"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse Apple Security feed (HTML scraping required)."""
        self.logger.info("Apple Security feed requires HTML parsing (not implemented)")
        return []


class AWSSecurityFeed(ThreatIntelligenceFeed):
    """AWS Security Bulletins feed."""

    @property
    def feed_name(self) -> str:
        return "AWS Security"

    @property
    def feed_url(self) -> str:
        return "https://aws.amazon.com/security/security-bulletins/"

    @property
    def cache_filename(self) -> str:
        return "aws-security.html"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse AWS Security feed (HTML scraping required)."""
        self.logger.info("AWS Security feed requires HTML parsing (not implemented)")
        return []


class AzureSecurityFeed(ThreatIntelligenceFeed):
    """Azure Security Advisories feed."""

    @property
    def feed_name(self) -> str:
        return "Azure Security"

    @property
    def feed_url(self) -> str:
        return "https://msrc.microsoft.com/update-guide/en-us"

    @property
    def cache_filename(self) -> str:
        return "azure-security.html"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse Azure Security feed (uses Microsoft MSRC)."""
        self.logger.info("Azure Security uses Microsoft MSRC feed")
        return []


class OracleSecurityFeed(ThreatIntelligenceFeed):
    """Oracle Critical Patch Updates feed."""

    @property
    def feed_name(self) -> str:
        return "Oracle Security"

    @property
    def feed_url(self) -> str:
        return "https://www.oracle.com/security-alerts/"

    @property
    def cache_filename(self) -> str:
        return "oracle-security.html"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse Oracle Security feed (HTML scraping required)."""
        self.logger.info("Oracle Security feed requires HTML parsing (not implemented)")
        return []


class CiscoSecurityFeed(ThreatIntelligenceFeed):
    """Cisco Security Advisories feed."""

    @property
    def feed_name(self) -> str:
        return "Cisco Security"

    @property
    def feed_url(self) -> str:
        return "https://tools.cisco.com/security/center/publicationListing.x"

    @property
    def cache_filename(self) -> str:
        return "cisco-security.html"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse Cisco Security feed (HTML scraping required)."""
        self.logger.info("Cisco Security feed requires HTML parsing (not implemented)")
        return []


class VMwareSecurityFeed(ThreatIntelligenceFeed):
    """VMware Security Advisories feed."""

    @property
    def feed_name(self) -> str:
        return "VMware Security"

    @property
    def feed_url(self) -> str:
        return "https://www.vmware.com/security/advisories.html"

    @property
    def cache_filename(self) -> str:
        return "vmware-security.html"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse VMware Security feed (HTML scraping required)."""
        self.logger.info("VMware Security feed requires HTML parsing (not implemented)")
        return []


class DockerSecurityFeed(ThreatIntelligenceFeed):
    """Docker Security Advisories feed."""

    @property
    def feed_name(self) -> str:
        return "Docker Security"

    @property
    def feed_url(self) -> str:
        return "https://docs.docker.com/engine/security/"

    @property
    def cache_filename(self) -> str:
        return "docker-security.html"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse Docker Security feed (HTML scraping required)."""
        self.logger.info("Docker Security feed requires HTML parsing (not implemented)")
        return []


class KubernetesSecurityFeed(ThreatIntelligenceFeed):
    """Kubernetes Security Advisories feed."""

    @property
    def feed_name(self) -> str:
        return "Kubernetes Security"

    @property
    def feed_url(self) -> str:
        return (
            "https://storage.googleapis.com/kubernetes-security-cve-feed/security.json"
        )

    @property
    def cache_filename(self) -> str:
        return "kubernetes-security.json"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse Kubernetes Security feed."""
        try:
            payload = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            self.logger.error("Failed to parse Kubernetes Security JSON: %s", exc)
            return []

        items = payload.get("items", [])
        records: List[VulnerabilityRecord] = []

        for item in items:
            cve_id = item.get("id")
            if not cve_id:
                continue

            record = VulnerabilityRecord(
                id=cve_id,
                source="Kubernetes Security",
                description=item.get("description", ""),
                published=item.get("datePublished"),
                modified=item.get("dateUpdated"),
                severity=item.get("severity"),
                cvss_score=item.get("cvss", {}).get("score"),
                cvss_vector=item.get("cvss", {}).get("vectorString"),
                references=[item.get("url")] if item.get("url") else [],
                metadata={"affected_versions": item.get("affectedVersions", [])},
            )
            records.append(record)

        return records


__all__ = [
    "MicrosoftSecurityFeed",
    "AppleSecurityFeed",
    "AWSSecurityFeed",
    "AzureSecurityFeed",
    "OracleSecurityFeed",
    "CiscoSecurityFeed",
    "VMwareSecurityFeed",
    "DockerSecurityFeed",
    "KubernetesSecurityFeed",
]
