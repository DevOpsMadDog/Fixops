"""
DefectDojo Parser Client for ALDECI Connector Framework

Routes unknown scanner formats through DefectDojo's REST API to normalize findings.
When ALDECI encounters a scan format it doesn't recognize, this client:
1. Uploads the scan file to DefectDojo's reimport endpoint
2. DefectDojo's parsers normalize it
3. Returns findings in ALDECI's standard schema

Supports 200+ scanner types including:
Fortify, Checkmarx, SonarQube, Veracode, Burp Suite, OWASP ZAP, Nessus,
Qualys, AWS Security Hub, Azure Defender, GCP SCC, and many more.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp

from connectors._emit import emit_connector_event

logger = logging.getLogger(__name__)


class DefectDojoParserClient:
    """
    Client for DefectDojo API integration with ALDECI.

    Handles:
    - Scan file parsing through DefectDojo's 200+ parsers
    - Product and engagement management
    - Finding normalization to ALDECI schema

    Attributes:
        base_url (str): DefectDojo API base URL
        api_key (str): DefectDojo API token
        session (Optional[aiohttp.ClientSession]): Async HTTP session
    """

    # DefectDojo parser types mapping to ALDECI entity types
    SUPPORTED_PARSERS = [
        # Static Application Security Testing (SAST)
        "Fortify Scan",
        "Checkmarx Scan",
        "Checkmarx XML",
        "SonarQube API Import",
        "SonarQube Scan",
        "Veracode Scan",
        "Veracode API",
        "Semgrep JSON",
        "Bandit",
        "Pylint",
        "ESLint",
        "TSLint",
        "PMD",
        "SpotBugs",
        "FindSecBugs",
        "Brakeman",
        "Rubocop",
        "Flawfinder",
        "Clang Static Analyzer",
        "cppcheck",
        "Lizard",
        "Dependency Check",
        "Gitlab Dependency Scanning",
        "Gitlab SAST",
        "Yarn Audit",
        "NPM Audit",
        "Bundler Audit",
        "Safety Check",
        "Retirejs",
        "Shellcheck",
        "PHP Security Checker",
        "Gosec",
        "Trivy",
        "SARIF",
        # Dynamic Application Security Testing (DAST)
        "Burp Suite Pro",
        "Burp Suite Enterprise",
        "OWASP ZAP Scan",
        "OWASP ZAP API Scan",
        "Qualys WAAS",
        "Acunetix Scan",
        "AppScan Dynamic Analyzer",
        "Veracode Dynamic Analysis",
        "Rapid7 InsightAppSec",
        # Infrastructure & Cloud
        "AWS Security Hub",
        "AWS Config",
        "AWS CloudTrail",
        "Azure Security Center",
        "Azure Defender",
        "GCP Security Command Center",
        "GCP Cloud Asset Inventory",
        "Qualys VMDR",
        "Nessus",
        "Nessus Professional",
        "Rapid7 InsightVM",
        "OpenVAS",
        "Tenable Nessus",
        # Container & Kubernetes
        "Anchore Grype",
        "Anchore Engine",
        "Falco",
        "Twistlock",
        "Aqua Security",
        "Sysdig Secure",
        "Snyk",
        # Application Performance & Observability
        "New Relic Scan",
        "Datadog Scan",
        "Prometheus Scan",
        # Miscellaneous
        "Generic Findings",
        "GitLab Issue Export",
        "JIRA Issue Export",
        "CSV Export",
        "Cyclone DX",
        "SPDX",
        "Blackduck",
        "Whitesource",
        "JFrog Xray",
        "Nexus IQ",
        "Artifact Hub",
        "Helm Chart",
        "Composer",
        "Pip Freeze",
        "Npm Ls",
        "Yarn Ls",
        "Gemfile Lock",
        "Maven Dependency Tree",
        "Gradle Dependencies",
        # Code Quality
        "Code Climate",
        "Codacy",
        "Coverity Scan",
        "PVS-Studio",
        # SCAP Standards
        "SCAP Scan",
        "OpenSCAP Scan",
        # GitHub
        "GitHub Dependabot Scan",
        "GitHub Code Scanning",
        "GitHub Security Advisory",
    ]

    def __init__(
        self,
        base_url: str,
        api_key: str,
    ) -> None:
        """
        Initialize DefectDojo Parser Client.

        Args:
            base_url: DefectDojo API base URL (e.g., 'https://defectdojo.example.com/api/v2')
            api_key: DefectDojo API token for authentication
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session: Optional[aiohttp.ClientSession] = None

        # Do not log the full URL — it may contain embedded credentials.
        logger.info("DefectDojoParserClient initialized")

    async def __aenter__(self) -> DefectDojoParserClient:
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(
            headers={
                "Authorization": f"Token {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=aiohttp.ClientTimeout(total=30),
        )
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    def _ensure_session(self) -> aiohttp.ClientSession:
        """Ensure session is initialized."""
        if not self.session:
            self.session = aiohttp.ClientSession(
                headers={
                    "Authorization": f"Token {self.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=30),
            )
        return self.session

    async def parse_scan(
        self,
        scan_data: bytes,
        scan_type: str,
        product_name: str,
        engagement_name: str = "ALDECI Auto-Import",
        file_name: str = "scan_report",
    ) -> List[Dict[str, Any]]:
        """
        Upload scan file to DefectDojo and get normalized findings.

        Uploads the raw scan file to DefectDojo's reimport endpoint, which
        applies the appropriate parser and returns normalized findings.

        Args:
            scan_data: Raw scan file bytes
            scan_type: Parser type (must be in SUPPORTED_PARSERS)
            product_name: DefectDojo product name (auto-created if missing)
            engagement_name: Engagement name for grouping scans
            file_name: Name of the scan file for reference

        Returns:
            List of ALDECI-normalized finding dictionaries:
                [
                    {
                        "finding_id": str,
                        "title": str,
                        "description": str,
                        "severity": str,  # critical, high, medium, low, info
                        "cvss_score": Optional[float],
                        "cvss_vector": Optional[str],
                        "component": str,
                        "component_version": Optional[str],
                        "scanner_type": str,
                        "scanner_reference": str,  # reference from original scan
                        "status": str,  # open, verified, closed
                        "discovered_at": str,  # ISO 8601
                        "updated_at": str,  # ISO 8601
                        "steps_to_reproduce": Optional[str],
                        "remediation": Optional[str],
                        "references": List[str],
                        "product_name": str,
                        "engagement_name": str,
                    },
                    ...
                ]

        Raises:
            ValueError: If scan_type is not supported
            RuntimeError: If DefectDojo API call fails
        """
        if scan_type not in self.SUPPORTED_PARSERS:
            raise ValueError(
                f"Unsupported scanner type: {scan_type}. "
                f"Supported types: {', '.join(self.SUPPORTED_PARSERS[:10])}..."
            )

        try:
            session = self._ensure_session()

            # Ensure product exists
            product_id = await self.create_product_if_missing(product_name)
            logger.info(f"Using product_id={product_id} for {product_name}")

            # Ensure engagement exists
            engagement_id = await self.create_engagement_if_missing(
                product_id, engagement_name
            )
            logger.info(f"Using engagement_id={engagement_id}")

            # Upload scan via reimport endpoint
            logger.info(
                f"Uploading scan ({len(scan_data)} bytes) "
                f"with parser={scan_type} to product_id={product_id}"
            )

            upload_url = f"{self.base_url}/reimports/"
            files = {"file": (file_name, scan_data)}
            data = {
                "scan_type": scan_type,
                "product": product_id,
                "engagement": engagement_id,
                "create_findings": "true",
                "test_title": f"ALDECI {scan_type} Scan",
            }

            async with session.post(
                upload_url,
                files=files,
                data=data,
                timeout=aiohttp.ClientTimeout(total=300),
            ) as response:
                if response.status not in (200, 201):
                    error_text = await response.text()
                    raise RuntimeError(
                        f"DefectDojo upload failed (HTTP {response.status}): {error_text}"
                    )

                reimport_result = await response.json()
                test_id = reimport_result.get("test")

            logger.info(f"Scan uploaded to DefectDojo test_id={test_id}")

            # Fetch the normalized findings from the test
            findings = await self._fetch_findings_from_test(test_id)
            logger.info(f"Retrieved {len(findings)} findings from test_id={test_id}")

            # Normalize findings to ALDECI schema
            normalized_findings = [
                self._normalize_dd_finding(f, product_name, engagement_name)
                for f in findings
            ]

            emit_connector_event(
                connector="DefectDojoParserClient",
                org_id=product_name or "default",
                source_kind="vuln_intel",
                finding_count=len(normalized_findings),
                extra={
                    "scan_type": scan_type,
                    "product_name": product_name,
                    "engagement_name": engagement_name,
                    "test_id": test_id,
                },
            )
            return normalized_findings

        except Exception as e:
            logger.error(f"Scan parsing failed: {e}")
            raise

    async def _fetch_findings_from_test(self, test_id: int) -> List[Dict[str, Any]]:
        """
        Fetch all findings from a DefectDojo test.

        Args:
            test_id: DefectDojo test ID

        Returns:
            List of DefectDojo finding dictionaries
        """
        session = self._ensure_session()
        findings = []
        page = 1

        while True:
            url = f"{self.base_url}/findings/?test={test_id}&limit=100&offset={(page - 1) * 100}"

            async with session.get(url) as response:
                if response.status != 200:
                    logger.warning(f"Failed to fetch findings page {page}")
                    break

                data = await response.json()
                findings.extend(data.get("results", []))

                if not data.get("next"):
                    break

                page += 1

        return findings

    def _normalize_dd_finding(
        self,
        dd_finding: Dict[str, Any],
        product_name: str,
        engagement_name: str,
    ) -> Dict[str, Any]:
        """
        Convert DefectDojo finding format to ALDECI normalized schema.

        Args:
            dd_finding: DefectDojo finding dictionary
            product_name: Product name for context
            engagement_name: Engagement name for context

        Returns:
            ALDECI-normalized finding dictionary
        """
        # Map DefectDojo severity to ALDECI levels
        severity_map = {
            "Critical": "critical",
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Info": "info",
            "Informational": "info",
        }

        # Parse dates
        discovered_date = dd_finding.get("created", datetime.utcnow().isoformat())
        updated_date = dd_finding.get("updated", discovered_date)

        if isinstance(discovered_date, str):
            # Already ISO formatted
            pass
        else:
            discovered_date = discovered_date.isoformat()

        if isinstance(updated_date, str):
            pass
        else:
            updated_date = updated_date.isoformat()

        # Extract component info
        component = dd_finding.get("component_name", "unknown")
        component_version = dd_finding.get("component_version")

        return {
            "finding_id": f"dd-{dd_finding.get('id')}",
            "title": dd_finding.get("title", "Untitled Finding"),
            "description": dd_finding.get("description", ""),
            "severity": severity_map.get(
                dd_finding.get("severity", "Info"), "info"
            ),
            "cvss_score": dd_finding.get("cvssv3_score") or dd_finding.get("cvssv2_score"),
            "cvss_vector": dd_finding.get("cvssv3") or dd_finding.get("cvssv2"),
            "component": component,
            "component_version": component_version,
            "scanner_type": dd_finding.get("test_type", "unknown"),
            "scanner_reference": str(dd_finding.get("id")),
            "status": "closed" if dd_finding.get("false_p") else (
                "verified" if dd_finding.get("verified") else "open"
            ),
            "discovered_at": discovered_date,
            "updated_at": updated_date,
            "steps_to_reproduce": dd_finding.get("steps_to_reproduce"),
            "remediation": dd_finding.get("mitigation"),
            "references": [
                ref.get("url", "")
                for ref in dd_finding.get("references", [])
                if ref.get("url")
            ],
            "product_name": product_name,
            "engagement_name": engagement_name,
        }

    def get_supported_parsers(self) -> List[str]:
        """
        Get list of supported DefectDojo parsers.

        Returns:
            Sorted list of 60+ supported scanner types
        """
        return sorted(self.SUPPORTED_PARSERS)

    async def create_product_if_missing(self, name: str) -> int:
        """
        Ensure a DefectDojo product exists, creating if needed.

        Args:
            name: Product name

        Returns:
            DefectDojo product ID

        Raises:
            RuntimeError: If product creation fails
        """
        try:
            session = self._ensure_session()

            # Search for existing product
            search_url = f"{self.base_url}/products/?name={name}&limit=1"

            async with session.get(search_url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("results"):
                        product_id = data["results"][0]["id"]
                        logger.info(f"Found existing product '{name}' (id={product_id})")
                        return product_id

            # Create new product
            create_url = f"{self.base_url}/products/"
            payload = {
                "name": name,
                "description": f"Auto-created by ALDECI for {name}",
                "type": 5,  # Type 5 is typically "Custom"
            }

            async with session.post(create_url, json=payload) as response:
                if response.status not in (200, 201):
                    error_text = await response.text()
                    raise RuntimeError(
                        f"Failed to create product (HTTP {response.status}): {error_text}"
                    )

                result = await response.json()
                product_id = result["id"]
                logger.info(f"Created product '{name}' (id={product_id})")
                return product_id

        except Exception as e:
            logger.error(f"Product creation failed: {e}")
            raise

    async def create_engagement_if_missing(
        self,
        product_id: int,
        name: str,
    ) -> int:
        """
        Ensure a DefectDojo engagement exists, creating if needed.

        Engagements group related scans together for a product.

        Args:
            product_id: DefectDojo product ID
            name: Engagement name

        Returns:
            DefectDojo engagement ID

        Raises:
            RuntimeError: If engagement creation fails
        """
        try:
            session = self._ensure_session()

            # Search for existing engagement
            search_url = f"{self.base_url}/engagements/?product={product_id}&name={name}&limit=1"

            async with session.get(search_url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("results"):
                        engagement_id = data["results"][0]["id"]
                        logger.info(
                            f"Found existing engagement '{name}' (id={engagement_id})"
                        )
                        return engagement_id

            # Create new engagement
            create_url = f"{self.base_url}/engagements/"
            today = datetime.utcnow().strftime("%Y-%m-%d")
            payload = {
                "product": product_id,
                "name": name,
                "description": "Auto-created by ALDECI",
                "status": "In Progress",
                "target_start": today,
                "target_end": today,
            }

            async with session.post(create_url, json=payload) as response:
                if response.status not in (200, 201):
                    error_text = await response.text()
                    raise RuntimeError(
                        f"Failed to create engagement (HTTP {response.status}): {error_text}"
                    )

                result = await response.json()
                engagement_id = result["id"]
                logger.info(f"Created engagement '{name}' (id={engagement_id})")
                return engagement_id

        except Exception as e:
            logger.error(f"Engagement creation failed: {e}")
            raise

    async def health_check(self) -> Dict[str, Any]:
        """
        Check DefectDojo API connectivity.

        Returns:
            {
                "healthy": bool,
                "api_version": Optional[str],
                "error": Optional[str]
            }
        """
        try:
            session = self._ensure_session()

            async with session.get(
                f"{self.base_url}/",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status == 200:
                    return {
                        "healthy": True,
                        "api_version": response.headers.get("DefectDojo-Version"),
                    }
                else:
                    return {
                        "healthy": False,
                        "error": f"HTTP {response.status}",
                    }

        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "healthy": False,
                "error": str(e),
            }

    async def close(self) -> None:
        """Close the aiohttp session."""
        if self.session:
            await self.session.close()
            self.session = None
