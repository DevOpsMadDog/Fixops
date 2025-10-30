"""Comprehensive threat intelligence feed orchestrator.

Manages multiple threat intelligence sources and provides unified access.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import FeedMetadata, FeedRegistry, VulnerabilityRecord
from .ecosystems import (
    DebianSecurityFeed,
    NPMSecurityFeed,
    RubySecFeed,
    UbuntuSecurityFeed,
)
from .exploits import (
    AbuseCHMalwareBazaarFeed,
    AbuseCHThreatFoxFeed,
    AbuseCHURLHausFeed,
    AlienVaultOTXFeed,
    ExploitDBFeed,
)
from .github import GitHubSecurityAdvisoriesFeed
from .kev import load_kev_catalog, update_kev_feed
from .nvd import NVDFeed
from .osv import OSVFeed
from .vendors import KubernetesSecurityFeed, MicrosoftSecurityFeed

LOGGER = logging.getLogger(__name__)


class ThreatIntelligenceOrchestrator:
    """Orchestrator for managing multiple threat intelligence feeds."""

    def __init__(
        self,
        cache_dir: str | Path = "data/feeds",
        github_token: Optional[str] = None,
        nvd_api_key: Optional[str] = None,
        alienvault_api_key: Optional[str] = None,
    ):
        """Initialize threat intelligence orchestrator.

        Parameters
        ----------
        cache_dir:
            Directory to cache feed data.
        github_token:
            Optional GitHub personal access token.
        nvd_api_key:
            Optional NVD API key for higher rate limits.
        alienvault_api_key:
            Optional AlienVault OTX API key.
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.registry = FeedRegistry(cache_dir=self.cache_dir)
        self.github_token = github_token
        self.nvd_api_key = nvd_api_key
        self.alienvault_api_key = alienvault_api_key

        self._register_default_feeds()

    def _register_default_feeds(self) -> None:
        """Register default threat intelligence feeds."""
        LOGGER.info("Registering default threat intelligence feeds")

        self.registry.register(OSVFeed(cache_dir=self.cache_dir))
        self.registry.register(
            NVDFeed(api_key=self.nvd_api_key, cache_dir=self.cache_dir)
        )
        self.registry.register(
            GitHubSecurityAdvisoriesFeed(
                token=self.github_token, cache_dir=self.cache_dir
            )
        )

        self.registry.register(MicrosoftSecurityFeed(cache_dir=self.cache_dir))
        self.registry.register(KubernetesSecurityFeed(cache_dir=self.cache_dir))

        self.registry.register(NPMSecurityFeed(cache_dir=self.cache_dir))
        self.registry.register(RubySecFeed(cache_dir=self.cache_dir))
        self.registry.register(DebianSecurityFeed(cache_dir=self.cache_dir))
        self.registry.register(UbuntuSecurityFeed(cache_dir=self.cache_dir))

        self.registry.register(ExploitDBFeed(cache_dir=self.cache_dir))
        self.registry.register(
            AlienVaultOTXFeed(api_key=self.alienvault_api_key, cache_dir=self.cache_dir)
        )
        self.registry.register(AbuseCHURLHausFeed(cache_dir=self.cache_dir))
        self.registry.register(AbuseCHMalwareBazaarFeed(cache_dir=self.cache_dir))
        self.registry.register(AbuseCHThreatFoxFeed(cache_dir=self.cache_dir))

        LOGGER.info(
            "Registered %d threat intelligence feeds", len(self.registry.list_feeds())
        )

    def update_all_feeds(self) -> Dict[str, bool]:
        """Update all registered feeds.

        Returns
        -------
        Dict[str, bool]
            Mapping of feed names to success status.
        """
        LOGGER.info("Updating all threat intelligence feeds")
        results = self.registry.update_all()

        try:
            update_kev_feed(cache_dir=self.cache_dir)
            results["KEV"] = True
        except Exception as exc:
            LOGGER.error("Failed to update KEV feed: %s", exc)
            results["KEV"] = False

        success_count = sum(1 for v in results.values() if v)
        LOGGER.info(
            "Updated %d/%d threat intelligence feeds successfully",
            success_count,
            len(results),
        )
        return {name: path is not None for name, path in results.items()}

    def load_all_feeds(self) -> Dict[str, List[VulnerabilityRecord]]:
        """Load all registered feeds.

        Returns
        -------
        Dict[str, List[VulnerabilityRecord]]
            Mapping of feed names to vulnerability records.
        """
        LOGGER.info("Loading all threat intelligence feeds")
        results = self.registry.load_all()

        try:
            kev_catalog = load_kev_catalog(cache_dir=self.cache_dir)
            kev_records: List[VulnerabilityRecord] = []
            for cve_id, entry in kev_catalog.items():
                record = VulnerabilityRecord(
                    id=cve_id,
                    source="KEV",
                    description=entry.get("vulnerabilityName", ""),
                    published=entry.get("dateAdded"),
                    exploit_available=True,
                    exploit_maturity="active",
                    kev_listed=True,
                    vendor_advisory=entry.get("vendorProject"),
                    metadata={
                        "required_action": entry.get("requiredAction"),
                        "due_date": entry.get("dueDate"),
                    },
                )
                kev_records.append(record)
            results["KEV"] = kev_records
        except Exception as exc:
            LOGGER.error("Failed to load KEV feed: %s", exc)

        total_records = sum(len(records) for records in results.values())
        LOGGER.info(
            "Loaded %d vulnerability records from %d feeds", total_records, len(results)
        )
        return results

    def get_all_metadata(self) -> List[FeedMetadata]:
        """Get metadata for all registered feeds.

        Returns
        -------
        List[FeedMetadata]
            List of feed metadata.
        """
        metadata = self.registry.get_all_metadata()

        kev_path = self.cache_dir / "kev.json"
        if kev_path.exists():
            try:
                kev_catalog = load_kev_catalog(cache_dir=self.cache_dir)
                metadata.append(
                    FeedMetadata(
                        name="KEV",
                        source="CISA",
                        url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                        record_count=len(kev_catalog),
                    )
                )
            except Exception as exc:
                LOGGER.debug("Failed to get KEV metadata: %s", exc)

        return metadata

    def enrich_vulnerability(
        self,
        cve_id: str,
        all_feeds: Optional[Dict[str, List[VulnerabilityRecord]]] = None,
    ) -> Dict[str, Any]:
        """Enrich a CVE with data from all threat intelligence sources.

        Parameters
        ----------
        cve_id:
            CVE identifier to enrich.
        all_feeds:
            Optional pre-loaded feeds. If None, loads all feeds.

        Returns
        -------
        Dict[str, Any]
            Enriched vulnerability data from all sources.
        """
        if all_feeds is None:
            all_feeds = self.load_all_feeds()

        enrichment: Dict[str, Any] = {
            "cve_id": cve_id,
            "sources": [],
            "severity": None,
            "cvss_score": None,
            "cvss_vector": None,
            "descriptions": [],
            "affected_packages": [],
            "exploit_available": False,
            "exploit_maturity": None,
            "kev_listed": False,
            "references": [],
            "cwe_ids": [],
        }

        for feed_name, records in all_feeds.items():
            for record in records:
                if record.id == cve_id or cve_id in record.cwe_ids:
                    enrichment["sources"].append(feed_name)

                    if record.severity and not enrichment["severity"]:
                        enrichment["severity"] = record.severity

                    if record.cvss_score and not enrichment["cvss_score"]:
                        enrichment["cvss_score"] = record.cvss_score

                    if record.cvss_vector and not enrichment["cvss_vector"]:
                        enrichment["cvss_vector"] = record.cvss_vector

                    if record.description:
                        enrichment["descriptions"].append(
                            {"source": feed_name, "text": record.description}
                        )

                    enrichment["affected_packages"].extend(record.affected_packages)

                    if record.exploit_available:
                        enrichment["exploit_available"] = True
                        if record.exploit_maturity:
                            enrichment["exploit_maturity"] = record.exploit_maturity

                    if record.kev_listed:
                        enrichment["kev_listed"] = True

                    enrichment["references"].extend(record.references)
                    enrichment["cwe_ids"].extend(record.cwe_ids)

        enrichment["affected_packages"] = list(set(enrichment["affected_packages"]))
        enrichment["references"] = list(set(enrichment["references"]))
        enrichment["cwe_ids"] = list(set(enrichment["cwe_ids"]))
        enrichment["sources"] = list(set(enrichment["sources"]))

        return enrichment

    def export_unified_feed(self, output_path: str | Path) -> None:
        """Export unified vulnerability feed from all sources.

        Parameters
        ----------
        output_path:
            Path to export unified feed JSON.
        """
        LOGGER.info("Exporting unified threat intelligence feed")
        all_feeds = self.load_all_feeds()

        unified_records: Dict[str, Dict[str, Any]] = {}

        for feed_name, records in all_feeds.items():
            for record in records:
                if record.id not in unified_records:
                    unified_records[record.id] = record.to_dict()
                    unified_records[record.id]["sources"] = [feed_name]
                else:
                    existing = unified_records[record.id]
                    existing["sources"].append(feed_name)

                    if record.severity and not existing.get("severity"):
                        existing["severity"] = record.severity

                    if record.cvss_score and not existing.get("cvss_score"):
                        existing["cvss_score"] = record.cvss_score

                    if record.exploit_available:
                        existing["exploit_available"] = True

                    if record.kev_listed:
                        existing["kev_listed"] = True

                    existing["references"].extend(record.references)
                    existing["affected_packages"].extend(record.affected_packages)

        for record in unified_records.values():
            record["references"] = list(set(record["references"]))
            record["affected_packages"] = list(set(record["affected_packages"]))
            record["sources"] = list(set(record["sources"]))

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {
                    "metadata": {
                        "total_vulnerabilities": len(unified_records),
                        "sources": len(all_feeds),
                        "feed_names": list(all_feeds.keys()),
                    },
                    "vulnerabilities": list(unified_records.values()),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        LOGGER.info(
            "Exported %d unified vulnerability records to %s",
            len(unified_records),
            output_path,
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about all threat intelligence feeds.

        Returns
        -------
        Dict[str, Any]
            Statistics about feeds and vulnerabilities.
        """
        all_feeds = self.load_all_feeds()
        metadata = self.get_all_metadata()

        total_records = sum(len(records) for records in all_feeds.values())
        exploit_count = sum(
            1
            for records in all_feeds.values()
            for record in records
            if record.exploit_available
        )
        kev_count = sum(
            1
            for records in all_feeds.values()
            for record in records
            if record.kev_listed
        )

        return {
            "total_feeds": len(all_feeds),
            "total_vulnerabilities": total_records,
            "vulnerabilities_with_exploits": exploit_count,
            "kev_listed_vulnerabilities": kev_count,
            "feeds": [
                {
                    "name": meta.name,
                    "source": meta.source,
                    "record_count": meta.record_count,
                    "last_updated": meta.last_updated,
                }
                for meta in metadata
            ],
        }


__all__ = ["ThreatIntelligenceOrchestrator"]
