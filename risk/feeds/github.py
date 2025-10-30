"""GitHub Security Advisories feed integration.

GitHub Security Advisories (GHSA) provides vulnerability data for GitHub ecosystems.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .base import ThreatIntelligenceFeed, VulnerabilityRecord

DEFAULT_GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"


class GitHubSecurityAdvisoriesFeed(ThreatIntelligenceFeed):
    """GitHub Security Advisories feed."""

    def __init__(self, token: Optional[str] = None, **kwargs):
        """Initialize GitHub Security Advisories feed.

        Parameters
        ----------
        token:
            Optional GitHub personal access token for authentication.
        **kwargs:
            Additional arguments passed to parent class.
        """
        super().__init__(**kwargs)
        self.token = token

    @property
    def feed_name(self) -> str:
        return "GitHub Security Advisories"

    @property
    def feed_url(self) -> str:
        return DEFAULT_GITHUB_GRAPHQL_URL

    @property
    def cache_filename(self) -> str:
        return "github-advisories.json"

    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse GitHub Security Advisories feed.

        Parameters
        ----------
        data:
            Raw GitHub GraphQL response data.

        Returns
        -------
        List[VulnerabilityRecord]
            List of parsed vulnerability records.
        """
        try:
            payload = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            self.logger.error("Failed to parse GitHub advisories JSON: %s", exc)
            return []

        advisories = (
            payload.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
        )
        records: List[VulnerabilityRecord] = []

        for advisory in advisories:
            record = self._parse_github_advisory(advisory)
            if record:
                records.append(record)

        return records

    def _parse_github_advisory(self, advisory: dict) -> VulnerabilityRecord | None:
        """Parse a single GitHub Security Advisory.

        Parameters
        ----------
        advisory:
            GitHub advisory JSON data.

        Returns
        -------
        VulnerabilityRecord | None
            Parsed vulnerability record or None if invalid.
        """
        ghsa_id = advisory.get("ghsaId")
        if not ghsa_id:
            return None

        description = advisory.get("description", "")
        summary = advisory.get("summary", "")
        if summary and summary not in description:
            description = f"{summary}\n\n{description}"

        severity = advisory.get("severity")
        cvss_score = None
        cvss_vector = None

        cvss = advisory.get("cvss", {})
        if cvss:
            cvss_score = cvss.get("score")
            cvss_vector = cvss.get("vectorString")

        identifiers = advisory.get("identifiers", [])
        cve_ids: List[str] = []
        for identifier in identifiers:
            if identifier.get("type") == "CVE":
                cve_id = identifier.get("value")
                if cve_id:
                    cve_ids.append(cve_id)

        vulnerabilities = advisory.get("vulnerabilities", {}).get("nodes", [])
        affected_packages: List[str] = []
        affected_versions: List[str] = []
        fixed_versions: List[str] = []

        for vuln in vulnerabilities:
            package = vuln.get("package", {})
            pkg_name = package.get("name")
            ecosystem = package.get("ecosystem")
            if pkg_name:
                if ecosystem:
                    affected_packages.append(f"{ecosystem}:{pkg_name}")
                else:
                    affected_packages.append(pkg_name)

            vulnerable_version_range = vuln.get("vulnerableVersionRange")
            if vulnerable_version_range:
                affected_versions.append(vulnerable_version_range)

            first_patched_version = vuln.get("firstPatchedVersion", {})
            patched_version = first_patched_version.get("identifier")
            if patched_version:
                fixed_versions.append(patched_version)

        references: List[str] = []
        for ref in advisory.get("references", []):
            url = ref.get("url")
            if url:
                references.append(url)

        cwes = advisory.get("cwes", {}).get("nodes", [])
        cwe_ids_from_cwes: List[str] = []
        for cwe in cwes:
            cwe_id = cwe.get("cweId")
            if cwe_id:
                cwe_ids_from_cwes.append(cwe_id)

        return VulnerabilityRecord(
            id=ghsa_id,
            source="GitHub Security Advisories",
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            description=description,
            published=advisory.get("publishedAt"),
            modified=advisory.get("updatedAt"),
            affected_packages=affected_packages,
            affected_versions=affected_versions,
            fixed_versions=fixed_versions,
            references=references,
            cwe_ids=cve_ids + cwe_ids_from_cwes,
            metadata={
                "permalink": advisory.get("permalink"),
                "withdrawn_at": advisory.get("withdrawnAt"),
            },
        )

    def fetch_advisories(self, first: int = 100) -> List[VulnerabilityRecord]:
        """Fetch GitHub Security Advisories using GraphQL.

        Parameters
        ----------
        first:
            Number of advisories to fetch.

        Returns
        -------
        List[VulnerabilityRecord]
            List of vulnerability records.
        """
        query = """
        query($first: Int!) {
          securityAdvisories(first: $first, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
            nodes {
              ghsaId
              summary
              description
              severity
              publishedAt
              updatedAt
              withdrawnAt
              permalink
              cvss {
                score
                vectorString
              }
              identifiers {
                type
                value
              }
              references {
                url
              }
              cwes(first: 10) {
                nodes {
                  cweId
                  name
                }
              }
              vulnerabilities(first: 10) {
                nodes {
                  package {
                    name
                    ecosystem
                  }
                  vulnerableVersionRange
                  firstPatchedVersion {
                    identifier
                  }
                }
              }
            }
          }
        }
        """

        payload = json.dumps({"query": query, "variables": {"first": first}})

        try:
            import urllib.request

            req = urllib.request.Request(
                self.feed_url,
                data=payload.encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.token}" if self.token else "",
                },
            )

            self.logger.info("Fetching GitHub Security Advisories")
            with urllib.request.urlopen(req, timeout=30) as response:  # nosec
                data = response.read()

            records = self.parse_feed(data)
            self.logger.info("Fetched %d advisories from GitHub", len(records))
            return records

        except Exception as exc:
            self.logger.error("Failed to fetch GitHub advisories: %s", exc)
            return []


__all__ = ["GitHubSecurityAdvisoriesFeed", "DEFAULT_GITHUB_GRAPHQL_URL"]
