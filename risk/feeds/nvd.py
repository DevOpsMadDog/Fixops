"""NVD (National Vulnerability Database) feed integration.

NVD is NIST's comprehensive CVE database with CVSS scores, CPE, and CWE data.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .base import ThreatIntelligenceFeed, VulnerabilityRecord

DEFAULT_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDFeed(ThreatIntelligenceFeed):
    """NVD (National Vulnerability Database) feed."""

    def __init__(self, api_key: Optional[str] = None, **kwargs):
        """Initialize NVD feed.

        Parameters
        ----------
        api_key:
            Optional NVD API key for higher rate limits.
        **kwargs:
            Additional arguments passed to parent class.
        """
        super().__init__(**kwargs)
        self.api_key = api_key

    @property
    def feed_name(self) -> str:
        return "NVD"

    @property
    def feed_url(self) -> str:
        return DEFAULT_NVD_API_URL

    @property
    def cache_filename(self) -> str:
        return "nvd-cves.json"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse NVD CVE feed.

        Parameters
        ----------
        data:
            Raw NVD JSON data.

        Returns
        -------
        List[VulnerabilityRecord]
            List of parsed vulnerability records.
        """
        try:
            payload = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            self.logger.error("Failed to parse NVD JSON: %s", exc)
            return []

        vulnerabilities = payload.get("vulnerabilities", [])
        records: List[VulnerabilityRecord] = []

        for vuln_item in vulnerabilities:
            cve = vuln_item.get("cve", {})
            record = self._parse_nvd_cve(cve)
            if record:
                records.append(record)

        return records

    def _parse_nvd_cve(self, cve: dict) -> VulnerabilityRecord | None:
        """Parse a single NVD CVE record.

        Parameters
        ----------
        cve:
            NVD CVE JSON data.

        Returns
        -------
        VulnerabilityRecord | None
            Parsed vulnerability record or None if invalid.
        """
        cve_id = cve.get("id")
        if not cve_id:
            return None

        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        published = cve.get("published")
        modified = cve.get("lastModified")

        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_vector = None
        severity = None

        cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
        if cvss_v3:
            cvss_data = cvss_v3[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity")

        if not cvss_score and not cvss_vector:
            cvss_v2 = metrics.get("cvssMetricV2", [])
            if cvss_v2:
                cvss_data = cvss_v2[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                if cvss_score:
                    if cvss_score >= 7.0:
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"

        references: List[str] = []
        for ref in cve.get("references", []):
            url = ref.get("url")
            if url:
                references.append(url)

        weaknesses = cve.get("weaknesses", [])
        cwe_ids: List[str] = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                cwe_id = desc.get("value")
                if cwe_id and cwe_id.startswith("CWE-"):
                    cwe_ids.append(cwe_id)

        configurations = cve.get("configurations", [])
        affected_packages: List[str] = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe = cpe_match.get("criteria", "")
                    if cpe:
                        parts = cpe.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            affected_packages.append(f"{vendor}/{product}")

        return VulnerabilityRecord(
            id=cve_id,
            source="NVD",
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            description=description,
            published=published,
            modified=modified,
            affected_packages=list(set(affected_packages)),
            references=references,
            cwe_ids=cwe_ids,
            metadata={
                "configurations": configurations,
                "source_identifier": cve.get("sourceIdentifier"),
            },
        )

    def fetch_recent_cves(self, days: int = 7) -> List[VulnerabilityRecord]:
        """Fetch recent CVEs from NVD.

        Parameters
        ----------
        days:
            Number of days to look back.

        Returns
        -------
        List[VulnerabilityRecord]
            List of recent vulnerability records.
        """
        from datetime import datetime, timedelta

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        url = (
            f"{self.feed_url}?"
            f"pubStartDate={start_date.strftime('%Y-%m-%dT%H:%M:%S.000')}&"
            f"pubEndDate={end_date.strftime('%Y-%m-%dT%H:%M:%S.000')}"
        )

        if self.api_key:
            url += f"&apiKey={self.api_key}"

        try:
            self.logger.info("Fetching recent NVD CVEs (last %d days)", days)
            data = self.fetcher(url)
            records = self.parse_feed(data)
            self.logger.info("Fetched %d recent CVEs from NVD", len(records))
            return records
        except Exception as exc:
            self.logger.error("Failed to fetch recent NVD CVEs: %s", exc)
            return []


__all__ = ["NVDFeed", "DEFAULT_NVD_API_URL"]
