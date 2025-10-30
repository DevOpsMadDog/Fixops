"""OSV (Open Source Vulnerabilities) feed integration.

OSV.dev is Google's unified vulnerability database aggregating 40+ ecosystems
including GitHub Security Advisories, PyPA, RustSec, Go vulndb, and more.
"""

from __future__ import annotations

import json
from typing import List

from .base import ThreatIntelligenceFeed, VulnerabilityRecord

DEFAULT_OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt"


class OSVFeed(ThreatIntelligenceFeed):
    """OSV (Open Source Vulnerabilities) feed."""

    @property
    def feed_name(self) -> str:
        return "OSV"

    @property
    def feed_url(self) -> str:
        return DEFAULT_OSV_URL

    @property
    def cache_filename(self) -> str:
        return "osv-ecosystems.txt"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse OSV ecosystems list.

        Note: OSV provides per-ecosystem vulnerability databases.
        This returns ecosystem metadata. Use fetch_ecosystem_vulnerabilities
        for actual vulnerability data.

        Parameters
        ----------
        data:
            Raw ecosystems list.

        Returns
        -------
        List[VulnerabilityRecord]
            Empty list (ecosystems are metadata only).
        """
        ecosystems = data.decode("utf-8").strip().split("\n")
        self.logger.info(
            "Found %d OSV ecosystems: %s", len(ecosystems), ecosystems[:10]
        )
        return []

    def fetch_ecosystem_vulnerabilities(
        self, ecosystem: str, limit: int = 1000
    ) -> List[VulnerabilityRecord]:
        """Fetch vulnerabilities for a specific ecosystem.

        Parameters
        ----------
        ecosystem:
            Ecosystem name (e.g., "PyPI", "npm", "Go", "Maven").
        limit:
            Maximum number of vulnerabilities to fetch.

        Returns
        -------
        List[VulnerabilityRecord]
            List of vulnerability records for the ecosystem.
        """
        base_url = (
            f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
        )
        self.logger.info("Fetching OSV vulnerabilities for ecosystem: %s", ecosystem)

        try:
            import zipfile
            from io import BytesIO

            zip_data = self.fetcher(base_url)
            records: List[VulnerabilityRecord] = []

            with zipfile.ZipFile(BytesIO(zip_data)) as zf:
                for name in zf.namelist()[:limit]:
                    if not name.endswith(".json"):
                        continue

                    with zf.open(name) as f:
                        vuln_data = json.load(f)
                        record = self._parse_osv_record(vuln_data, ecosystem)
                        if record:
                            records.append(record)

            self.logger.info(
                "Fetched %d vulnerabilities from OSV ecosystem: %s",
                len(records),
                ecosystem,
            )
            return records

        except Exception as exc:
            self.logger.error(
                "Failed to fetch OSV vulnerabilities for %s: %s", ecosystem, exc
            )
            return []

    def _parse_osv_record(
        self, data: dict, ecosystem: str
    ) -> VulnerabilityRecord | None:
        """Parse a single OSV vulnerability record.

        Parameters
        ----------
        data:
            OSV vulnerability JSON data.
        ecosystem:
            Ecosystem name.

        Returns
        -------
        VulnerabilityRecord | None
            Parsed vulnerability record or None if invalid.
        """
        vuln_id = data.get("id")
        if not vuln_id:
            return None

        summary = data.get("summary", "")
        details = data.get("details", "")
        description = f"{summary}\n{details}".strip() if details else summary

        affected_packages: List[str] = []
        affected_versions: List[str] = []
        fixed_versions: List[str] = []

        for affected in data.get("affected", []):
            package = affected.get("package", {})
            pkg_name = package.get("name")
            if pkg_name:
                affected_packages.append(pkg_name)

            for version_range in affected.get("ranges", []):
                events = version_range.get("events", [])
                for event in events:
                    if "introduced" in event:
                        affected_versions.append(event["introduced"])
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])

        references: List[str] = []
        for ref in data.get("references", []):
            url = ref.get("url")
            if url:
                references.append(url)

        aliases = data.get("aliases", [])
        cve_ids = [alias for alias in aliases if alias.startswith("CVE-")]

        severity = None
        cvss_score = None
        cvss_vector = None

        for severity_entry in data.get("severity", []):
            if severity_entry.get("type") == "CVSS_V3":
                cvss_vector = severity_entry.get("score")
                if cvss_vector and "/" in cvss_vector:
                    try:
                        base_score = cvss_vector.split("/")[0].split(":")[-1]
                        cvss_score = float(base_score)
                    except (ValueError, IndexError):
                        pass

        if cvss_score:
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        return VulnerabilityRecord(
            id=vuln_id,
            source="OSV",
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            description=description,
            published=data.get("published"),
            modified=data.get("modified"),
            affected_packages=affected_packages,
            affected_versions=affected_versions,
            fixed_versions=fixed_versions,
            references=references,
            cwe_ids=cve_ids,
            ecosystem=ecosystem,
            metadata={
                "aliases": aliases,
                "database_specific": data.get("database_specific", {}),
            },
        )


__all__ = ["OSVFeed", "DEFAULT_OSV_URL"]
