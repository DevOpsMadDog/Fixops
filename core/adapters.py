"""Security tool adapters for ingesting findings from various scanners.

This module provides connectors for:
- GitLab: Vulnerability scanning results via GitLab API
- Azure DevOps: Security findings via Azure DevOps API
- Snyk: Native API integration for vulnerability data
- Trivy: Container/artifact scanning integration
- Prowler: AWS security posture findings
- OWASP ZAP: Dynamic security testing results
- Semgrep: SAST findings integration
- Checkov: IaC security findings
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urljoin as _urljoin  # noqa: F401

import requests
from requests import RequestException, Response


@dataclass
class AdapterFinding:
    """Normalized finding from any security tool adapter."""

    tool: str
    category: str
    severity: str
    title: str
    description: str
    rule_id: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    purl: Optional[str] = None
    resource_id: Optional[str] = None
    remediation: Optional[str] = None
    confidence: float = 1.0
    raw: Dict[str, Any] = field(default_factory=dict)
    detected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for pipeline processing."""
        return {
            "tool": self.tool,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "rule_id": self.rule_id,
            "file": self.file_path,
            "line": self.line_number,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "purl": self.purl,
            "resource_id": self.resource_id,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "raw": self.raw,
            "detected_at": self.detected_at,
        }


@dataclass
class AdapterResult:
    """Result from adapter fetch operation."""

    success: bool
    findings: List[AdapterFinding]
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class _BaseAdapter:
    """Base class for security tool adapters."""

    def __init__(self, timeout: float = 30.0) -> None:
        self.session = requests.Session()
        self.timeout = timeout

    def _request(self, method: str, url: str, **kwargs: Any) -> Response:
        return self.session.request(
            method=method, url=url, timeout=self.timeout, **kwargs
        )

    @property
    def configured(self) -> bool:
        """Check if adapter is properly configured."""
        raise NotImplementedError

    def fetch_findings(self) -> AdapterResult:
        """Fetch findings from the security tool."""
        raise NotImplementedError


class GitLabAdapter(_BaseAdapter):
    """Fetch vulnerability findings from GitLab Security Dashboard API.

    GitLab provides vulnerability scanning through:
    - SAST (Static Application Security Testing)
    - DAST (Dynamic Application Security Testing)
    - Dependency Scanning
    - Container Scanning
    - Secret Detection
    """

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 30.0) or 30.0))
        self.base_url = str(settings.get("url", "https://gitlab.com")).rstrip("/")
        self.project_id = settings.get("project_id")
        token = settings.get("token")
        token_env = settings.get("token_env", "GITLAB_TOKEN")
        if token_env:
            env_value = os.getenv(str(token_env))
            if env_value:
                token = env_value
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.project_id and self.token)

    def fetch_findings(self) -> AdapterResult:
        """Fetch vulnerabilities from GitLab project."""
        if not self.configured:
            return AdapterResult(
                success=False,
                findings=[],
                error="GitLab adapter not configured",
            )

        findings: List[AdapterFinding] = []
        try:
            # Fetch vulnerabilities from GitLab API
            endpoint = (
                f"{self.base_url}/api/v4/projects/{self.project_id}/vulnerabilities"
            )
            response = self._request(
                "GET",
                endpoint,
                headers={"PRIVATE-TOKEN": str(self.token)},
                params={"per_page": 100},
            )
            response.raise_for_status()

            for vuln in response.json():
                severity = self._normalize_severity(vuln.get("severity", "unknown"))
                category = self._map_scanner_to_category(vuln.get("report_type", ""))

                finding = AdapterFinding(
                    tool="gitlab",
                    category=category,
                    severity=severity,
                    title=vuln.get("title", "Unknown vulnerability"),
                    description=vuln.get("description", ""),
                    rule_id=vuln.get("identifiers", [{}])[0].get(
                        "value", "GITLAB-UNKNOWN"
                    )
                    if vuln.get("identifiers")
                    else "GITLAB-UNKNOWN",
                    file_path=vuln.get("location", {}).get("file"),
                    line_number=vuln.get("location", {}).get("start_line"),
                    cve_id=self._extract_cve(vuln.get("identifiers", [])),
                    cwe_id=self._extract_cwe(vuln.get("identifiers", [])),
                    remediation=vuln.get("solution"),
                    confidence=vuln.get("confidence", 1.0),
                    raw=vuln,
                )
                findings.append(finding)

            return AdapterResult(
                success=True,
                findings=findings,
                metadata={"project_id": self.project_id, "count": len(findings)},
            )

        except RequestException as exc:
            return AdapterResult(
                success=False,
                findings=[],
                error=f"GitLab API error: {exc}",
            )

    def _normalize_severity(self, severity: str) -> str:
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "low",
            "unknown": "medium",
        }
        return mapping.get(severity.lower(), "medium")

    def _map_scanner_to_category(self, report_type: str) -> str:
        mapping = {
            "sast": "sast",
            "dast": "dast",
            "dependency_scanning": "sca",
            "container_scanning": "container",
            "secret_detection": "secrets",
        }
        return mapping.get(report_type.lower(), "sast")

    def _extract_cve(self, identifiers: List[Dict[str, Any]]) -> Optional[str]:
        for ident in identifiers:
            if ident.get("type") == "cve":
                return ident.get("value")
        return None

    def _extract_cwe(self, identifiers: List[Dict[str, Any]]) -> Optional[str]:
        for ident in identifiers:
            if ident.get("type") == "cwe":
                return ident.get("value")
        return None


class AzureDevOpsAdapter(_BaseAdapter):
    """Fetch security findings from Azure DevOps Advanced Security.

    Azure DevOps provides:
    - Code scanning alerts
    - Dependency scanning alerts
    - Secret scanning alerts
    """

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 30.0) or 30.0))
        self.organization = settings.get("organization")
        self.project = settings.get("project")
        self.repository = settings.get("repository")
        token = settings.get("token")
        token_env = settings.get("token_env", "AZURE_DEVOPS_TOKEN")
        if token_env:
            env_value = os.getenv(str(token_env))
            if env_value:
                token = env_value
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.organization and self.project and self.token)

    def fetch_findings(self) -> AdapterResult:
        """Fetch alerts from Azure DevOps Advanced Security."""
        if not self.configured:
            return AdapterResult(
                success=False,
                findings=[],
                error="Azure DevOps adapter not configured",
            )

        findings: List[AdapterFinding] = []
        try:
            # Azure DevOps Advanced Security API
            base_url = (
                f"https://advsec.dev.azure.com/{self.organization}/{self.project}"
            )
            endpoint = f"{base_url}/_apis/alert/repositories/{self.repository}/alerts"

            response = self._request(
                "GET",
                endpoint,
                headers={
                    "Authorization": f"Basic {self.token}",
                    "Content-Type": "application/json",
                },
                params={"api-version": "7.2-preview.1"},
            )
            response.raise_for_status()

            data = response.json()
            for alert in data.get("value", []):
                severity = self._normalize_severity(alert.get("severity", "medium"))
                category = self._map_alert_type(alert.get("alertType", ""))

                finding = AdapterFinding(
                    tool="azure_devops",
                    category=category,
                    severity=severity,
                    title=alert.get("title", "Unknown alert"),
                    description=alert.get("description", ""),
                    rule_id=alert.get("rule", {}).get("id", "ADO-UNKNOWN"),
                    file_path=alert.get("physicalLocation", {}).get("filePath"),
                    line_number=alert.get("physicalLocation", {})
                    .get("region", {})
                    .get("startLine"),
                    cve_id=alert.get("cveId"),
                    cwe_id=alert.get("cweId"),
                    remediation=alert.get("fixGuidance"),
                    raw=alert,
                )
                findings.append(finding)

            return AdapterResult(
                success=True,
                findings=findings,
                metadata={
                    "organization": self.organization,
                    "project": self.project,
                    "count": len(findings),
                },
            )

        except RequestException as exc:
            return AdapterResult(
                success=False,
                findings=[],
                error=f"Azure DevOps API error: {exc}",
            )

    def _normalize_severity(self, severity: str) -> str:
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "note": "low",
        }
        return mapping.get(severity.lower(), "medium")

    def _map_alert_type(self, alert_type: str) -> str:
        mapping = {
            "code": "sast",
            "dependency": "sca",
            "secret": "secrets",
        }
        return mapping.get(alert_type.lower(), "sast")


class SnykAdapter(_BaseAdapter):
    """Fetch vulnerability findings from Snyk API.

    Snyk provides:
    - Open Source vulnerabilities (SCA)
    - Code vulnerabilities (SAST)
    - Container vulnerabilities
    - IaC misconfigurations
    """

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 30.0) or 30.0))
        self.base_url = str(settings.get("url", "https://api.snyk.io")).rstrip("/")
        self.org_id = settings.get("org_id")
        self.project_id = settings.get("project_id")
        token = settings.get("token")
        token_env = settings.get("token_env", "SNYK_TOKEN")
        if token_env:
            env_value = os.getenv(str(token_env))
            if env_value:
                token = env_value
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.org_id and self.token)

    def fetch_findings(self) -> AdapterResult:
        """Fetch issues from Snyk API."""
        if not self.configured:
            return AdapterResult(
                success=False,
                findings=[],
                error="Snyk adapter not configured",
            )

        findings: List[AdapterFinding] = []
        try:
            # Snyk REST API v1
            if self.project_id:
                endpoint = f"{self.base_url}/v1/org/{self.org_id}/project/{self.project_id}/aggregated-issues"
            else:
                endpoint = f"{self.base_url}/v1/org/{self.org_id}/issues"

            response = self._request(
                "POST",
                endpoint,
                headers={
                    "Authorization": f"token {self.token}",
                    "Content-Type": "application/json",
                },
                json={"includeDescription": True, "includeIntroducedThrough": True},
            )
            response.raise_for_status()

            data = response.json()
            for issue in data.get("issues", []):
                issue_data = issue.get("issueData", {})
                severity = self._normalize_severity(
                    issue_data.get("severity", "medium")
                )

                # Determine category based on issue type
                issue_type = issue.get("issueType", "vuln")
                category = "sca" if issue_type == "vuln" else "sast"

                # Extract package info for purl
                pkg_name = issue.get("pkgName", "")
                pkg_version = (
                    issue.get("pkgVersions", [""])[0]
                    if issue.get("pkgVersions")
                    else ""
                )
                purl = f"pkg:npm/{pkg_name}@{pkg_version}" if pkg_name else None

                finding = AdapterFinding(
                    tool="snyk",
                    category=category,
                    severity=severity,
                    title=issue_data.get("title", "Unknown issue"),
                    description=issue_data.get("description", ""),
                    rule_id=issue_data.get("id", "SNYK-UNKNOWN"),
                    cve_id=self._extract_cve(issue_data.get("identifiers", {})),
                    cwe_id=self._extract_cwe(issue_data.get("identifiers", {})),
                    purl=purl,
                    remediation=issue_data.get("remediation"),
                    raw=issue,
                )
                findings.append(finding)

            return AdapterResult(
                success=True,
                findings=findings,
                metadata={"org_id": self.org_id, "count": len(findings)},
            )

        except RequestException as exc:
            return AdapterResult(
                success=False,
                findings=[],
                error=f"Snyk API error: {exc}",
            )

    def _normalize_severity(self, severity: str) -> str:
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }
        return mapping.get(severity.lower(), "medium")

    def _extract_cve(self, identifiers: Dict[str, List[str]]) -> Optional[str]:
        cves = identifiers.get("CVE", [])
        return cves[0] if cves else None

    def _extract_cwe(self, identifiers: Dict[str, List[str]]) -> Optional[str]:
        cwes = identifiers.get("CWE", [])
        return cwes[0] if cwes else None


class TrivyAdapter(_BaseAdapter):
    """Parse Trivy JSON output for container/artifact vulnerabilities.

    Trivy scans:
    - Container images
    - Filesystems
    - Git repositories
    - Kubernetes clusters
    """

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__()
        self.report_path = settings.get("report_path")
        self.report_url = settings.get("report_url")
        token = settings.get("token")
        token_env = settings.get("token_env")
        if token_env:
            env_value = os.getenv(str(token_env))
            if env_value:
                token = env_value
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.report_path or self.report_url)

    def fetch_findings(self) -> AdapterResult:
        """Parse Trivy JSON report."""
        if not self.configured:
            return AdapterResult(
                success=False,
                findings=[],
                error="Trivy adapter not configured",
            )

        findings: List[AdapterFinding] = []
        try:
            # Load report from file or URL
            if self.report_path:
                with open(self.report_path, "r", encoding="utf-8") as f:
                    report = json.load(f)
            else:
                headers = {}
                if self.token:
                    headers["Authorization"] = f"Bearer {self.token}"
                response = self._request("GET", str(self.report_url), headers=headers)
                response.raise_for_status()
                report = response.json()

            # Parse Trivy JSON format
            for result in report.get("Results", []):
                target = result.get("Target", "")
                target_type = result.get("Type", "")

                for vuln in result.get("Vulnerabilities", []):
                    severity = self._normalize_severity(vuln.get("Severity", "UNKNOWN"))

                    # Build purl from package info
                    pkg_name = vuln.get("PkgName", "")
                    pkg_version = vuln.get("InstalledVersion", "")
                    pkg_type = self._map_pkg_type(target_type)
                    purl = (
                        f"pkg:{pkg_type}/{pkg_name}@{pkg_version}" if pkg_name else None
                    )

                    finding = AdapterFinding(
                        tool="trivy",
                        category="sca",
                        severity=severity,
                        title=vuln.get("Title", vuln.get("VulnerabilityID", "Unknown")),
                        description=vuln.get("Description", ""),
                        rule_id=vuln.get("VulnerabilityID", "TRIVY-UNKNOWN"),
                        cve_id=vuln.get("VulnerabilityID")
                        if vuln.get("VulnerabilityID", "").startswith("CVE-")
                        else None,
                        cwe_id=vuln.get("CweIDs", [None])[0]
                        if vuln.get("CweIDs")
                        else None,
                        purl=purl,
                        resource_id=target,
                        remediation=f"Update to {vuln.get('FixedVersion')}"
                        if vuln.get("FixedVersion")
                        else None,
                        raw=vuln,
                    )
                    findings.append(finding)

                # Parse misconfigurations
                for misconfig in result.get("Misconfigurations", []):
                    severity = self._normalize_severity(
                        misconfig.get("Severity", "UNKNOWN")
                    )

                    finding = AdapterFinding(
                        tool="trivy",
                        category="iac",
                        severity=severity,
                        title=misconfig.get("Title", "Unknown misconfiguration"),
                        description=misconfig.get("Description", ""),
                        rule_id=misconfig.get("ID", "TRIVY-MISCONFIG"),
                        file_path=target,
                        cwe_id=misconfig.get("CweIDs", [None])[0]
                        if misconfig.get("CweIDs")
                        else None,
                        remediation=misconfig.get("Resolution"),
                        raw=misconfig,
                    )
                    findings.append(finding)

            return AdapterResult(
                success=True,
                findings=findings,
                metadata={
                    "source": self.report_path or self.report_url,
                    "count": len(findings),
                },
            )

        except (RequestException, json.JSONDecodeError, IOError) as exc:
            return AdapterResult(
                success=False,
                findings=[],
                error=f"Trivy report error: {exc}",
            )

    def _normalize_severity(self, severity: str) -> str:
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "unknown": "medium",
        }
        return mapping.get(severity.lower(), "medium")

    def _map_pkg_type(self, target_type: str) -> str:
        mapping = {
            "alpine": "apk",
            "debian": "deb",
            "ubuntu": "deb",
            "redhat": "rpm",
            "centos": "rpm",
            "npm": "npm",
            "yarn": "npm",
            "pip": "pypi",
            "pipenv": "pypi",
            "poetry": "pypi",
            "gem": "gem",
            "cargo": "cargo",
            "go": "golang",
            "nuget": "nuget",
            "maven": "maven",
            "gradle": "maven",
        }
        return mapping.get(target_type.lower(), "generic")


class ProwlerAdapter(_BaseAdapter):
    """Fetch AWS security findings from Prowler.

    Prowler checks:
    - AWS CIS Benchmark
    - AWS Security Best Practices
    - GDPR, HIPAA, PCI-DSS compliance
    """

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__()
        self.report_path = settings.get("report_path")
        self.report_url = settings.get("report_url")
        token = settings.get("token")
        token_env = settings.get("token_env")
        if token_env:
            env_value = os.getenv(str(token_env))
            if env_value:
                token = env_value
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.report_path or self.report_url)

    def fetch_findings(self) -> AdapterResult:
        """Parse Prowler JSON output."""
        if not self.configured:
            return AdapterResult(
                success=False,
                findings=[],
                error="Prowler adapter not configured",
            )

        findings: List[AdapterFinding] = []
        try:
            # Load report from file or URL
            if self.report_path:
                with open(self.report_path, "r", encoding="utf-8") as f:
                    report = json.load(f)
            else:
                headers = {}
                if self.token:
                    headers["Authorization"] = f"Bearer {self.token}"
                response = self._request("GET", str(self.report_url), headers=headers)
                response.raise_for_status()
                report = response.json()

            # Handle both list and dict formats
            checks = report if isinstance(report, list) else report.get("findings", [])

            for check in checks:
                # Skip passed checks
                if check.get("Status", "").upper() == "PASS":
                    continue

                severity = self._normalize_severity(check.get("Severity", "medium"))

                finding = AdapterFinding(
                    tool="prowler",
                    category="cspm",
                    severity=severity,
                    title=check.get(
                        "CheckTitle", check.get("CheckID", "Unknown check")
                    ),
                    description=check.get("Description", ""),
                    rule_id=check.get("CheckID", "PROWLER-UNKNOWN"),
                    resource_id=check.get("ResourceArn") or check.get("ResourceId"),
                    remediation=check.get("Remediation", {})
                    .get("Recommendation", {})
                    .get("Text")
                    if isinstance(check.get("Remediation"), dict)
                    else check.get("Remediation"),
                    raw=check,
                )
                findings.append(finding)

            return AdapterResult(
                success=True,
                findings=findings,
                metadata={
                    "source": self.report_path or self.report_url,
                    "count": len(findings),
                },
            )

        except (RequestException, json.JSONDecodeError, IOError) as exc:
            return AdapterResult(
                success=False,
                findings=[],
                error=f"Prowler report error: {exc}",
            )

    def _normalize_severity(self, severity: str) -> str:
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "low",
        }
        return mapping.get(severity.lower(), "medium")


class OWASPZAPAdapter(_BaseAdapter):
    """Parse OWASP ZAP scan results for DAST findings.

    ZAP provides:
    - Active scanning
    - Passive scanning
    - Spider/crawler results
    - API scanning
    """

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 30.0) or 30.0))
        self.base_url = settings.get("url")
        self.api_key = settings.get("api_key")
        self.report_path = settings.get("report_path")
        api_key_env = settings.get("api_key_env", "ZAP_API_KEY")
        if api_key_env:
            env_value = os.getenv(str(api_key_env))
            if env_value:
                self.api_key = env_value

    @property
    def configured(self) -> bool:
        return bool((self.base_url and self.api_key) or self.report_path)

    def fetch_findings(self) -> AdapterResult:
        """Fetch alerts from ZAP API or parse JSON report."""
        if not self.configured:
            return AdapterResult(
                success=False,
                findings=[],
                error="OWASP ZAP adapter not configured",
            )

        findings: List[AdapterFinding] = []
        try:
            if self.report_path:
                # Parse JSON report
                with open(self.report_path, "r", encoding="utf-8") as f:
                    report = json.load(f)
                alerts = report.get("site", [{}])[0].get("alerts", [])
            else:
                # Fetch from ZAP API
                endpoint = f"{self.base_url}/JSON/core/view/alerts/"
                response = self._request(
                    "GET",
                    endpoint,
                    params={"apikey": self.api_key},
                )
                response.raise_for_status()
                alerts = response.json().get("alerts", [])

            for alert in alerts:
                severity = self._normalize_severity(alert.get("risk", "Medium"))

                finding = AdapterFinding(
                    tool="owasp_zap",
                    category="dast",
                    severity=severity,
                    title=alert.get("name", alert.get("alert", "Unknown alert")),
                    description=alert.get("description", ""),
                    rule_id=str(
                        alert.get("pluginId", alert.get("pluginid", "ZAP-UNKNOWN"))
                    ),
                    file_path=alert.get("url"),
                    cwe_id=f"CWE-{alert.get('cweid')}" if alert.get("cweid") else None,
                    remediation=alert.get("solution"),
                    confidence=self._normalize_confidence(
                        alert.get("confidence", "Medium")
                    ),
                    raw=alert,
                )
                findings.append(finding)

            return AdapterResult(
                success=True,
                findings=findings,
                metadata={
                    "source": self.report_path or self.base_url,
                    "count": len(findings),
                },
            )

        except (RequestException, json.JSONDecodeError, IOError) as exc:
            return AdapterResult(
                success=False,
                findings=[],
                error=f"OWASP ZAP error: {exc}",
            )

    def _normalize_severity(self, risk: str) -> str:
        mapping = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "low",
        }
        return mapping.get(risk.lower(), "medium")

    def _normalize_confidence(self, confidence: str) -> float:
        mapping = {
            "high": 0.9,
            "medium": 0.7,
            "low": 0.5,
            "false positive": 0.1,
        }
        return mapping.get(confidence.lower(), 0.7)


class SemgrepAdapter(_BaseAdapter):
    """Parse Semgrep SAST scan results.

    Semgrep provides:
    - Custom rule scanning
    - Security rules (p/security-audit)
    - Language-specific patterns
    """

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 30.0) or 30.0))
        self.report_path = settings.get("report_path")
        self.app_token = settings.get("app_token")
        self.deployment_slug = settings.get("deployment_slug")
        token_env = settings.get("token_env", "SEMGREP_APP_TOKEN")
        if token_env:
            env_value = os.getenv(str(token_env))
            if env_value:
                self.app_token = env_value

    @property
    def configured(self) -> bool:
        return bool(self.report_path or (self.app_token and self.deployment_slug))

    def fetch_findings(self) -> AdapterResult:
        """Parse Semgrep JSON output or fetch from Semgrep App."""
        if not self.configured:
            return AdapterResult(
                success=False,
                findings=[],
                error="Semgrep adapter not configured",
            )

        findings: List[AdapterFinding] = []
        try:
            if self.report_path:
                # Parse local JSON report
                with open(self.report_path, "r", encoding="utf-8") as f:
                    report = json.load(f)
                results = report.get("results", [])
            else:
                # Fetch from Semgrep App API
                endpoint = f"https://semgrep.dev/api/v1/deployments/{self.deployment_slug}/findings"
                response = self._request(
                    "GET",
                    endpoint,
                    headers={"Authorization": f"Bearer {self.app_token}"},
                )
                response.raise_for_status()
                results = response.json().get("findings", [])

            for result in results:
                # Handle both local and API formats
                if "extra" in result:
                    # Local format
                    severity = self._normalize_severity(
                        result.get("extra", {}).get("severity", "WARNING")
                    )
                    metadata = result.get("extra", {}).get("metadata", {})
                    cwe_list = metadata.get("cwe", [])
                    cwe_id = cwe_list[0] if cwe_list else None

                    finding = AdapterFinding(
                        tool="semgrep",
                        category="sast",
                        severity=severity,
                        title=result.get("extra", {}).get("message", "Semgrep finding"),
                        description=result.get("extra", {}).get("message", ""),
                        rule_id=result.get("check_id", "SEMGREP-UNKNOWN"),
                        file_path=result.get("path"),
                        line_number=result.get("start", {}).get("line"),
                        cwe_id=cwe_id,
                        remediation=result.get("extra", {}).get("fix"),
                        raw=result,
                    )
                else:
                    # API format
                    severity = self._normalize_severity(
                        result.get("severity", "medium")
                    )

                    finding = AdapterFinding(
                        tool="semgrep",
                        category="sast",
                        severity=severity,
                        title=result.get("rule_name", "Semgrep finding"),
                        description=result.get("rule_message", ""),
                        rule_id=result.get("rule_id", "SEMGREP-UNKNOWN"),
                        file_path=result.get("location", {}).get("file_path"),
                        line_number=result.get("location", {}).get("line"),
                        cwe_id=result.get("cwe"),
                        raw=result,
                    )
                findings.append(finding)

            return AdapterResult(
                success=True,
                findings=findings,
                metadata={
                    "source": self.report_path or self.deployment_slug,
                    "count": len(findings),
                },
            )

        except (RequestException, json.JSONDecodeError, IOError) as exc:
            return AdapterResult(
                success=False,
                findings=[],
                error=f"Semgrep error: {exc}",
            )

    def _normalize_severity(self, severity: str) -> str:
        mapping = {
            "error": "high",
            "warning": "medium",
            "info": "low",
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }
        return mapping.get(severity.lower(), "medium")


class CheckovAdapter(_BaseAdapter):
    """Parse Checkov IaC scan results.

    Checkov scans:
    - Terraform
    - CloudFormation
    - Kubernetes
    - ARM templates
    - Serverless Framework
    - Helm charts
    """

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__()
        self.report_path = settings.get("report_path")
        self.api_key = settings.get("api_key")
        self.repo_id = settings.get("repo_id")
        api_key_env = settings.get("api_key_env", "BC_API_KEY")
        if api_key_env:
            env_value = os.getenv(str(api_key_env))
            if env_value:
                self.api_key = env_value

    @property
    def configured(self) -> bool:
        return bool(self.report_path or (self.api_key and self.repo_id))

    def fetch_findings(self) -> AdapterResult:
        """Parse Checkov JSON output or fetch from Bridgecrew platform."""
        if not self.configured:
            return AdapterResult(
                success=False,
                findings=[],
                error="Checkov adapter not configured",
            )

        findings: List[AdapterFinding] = []
        try:
            if self.report_path:
                # Parse local JSON report
                with open(self.report_path, "r", encoding="utf-8") as f:
                    report = json.load(f)
            else:
                # Fetch from Bridgecrew API
                endpoint = f"https://www.bridgecrew.cloud/api/v1/repositories/{self.repo_id}/violations"
                response = self._request(
                    "GET",
                    endpoint,
                    headers={"Authorization": self.api_key},
                )
                response.raise_for_status()
                report = response.json()

            # Handle both formats
            if isinstance(report, list):
                # Multiple check types
                for check_type in report:
                    self._parse_check_results(check_type, findings)
            elif "results" in report:
                # Single results object
                self._parse_check_results(report, findings)
            elif "failed_checks" in report:
                # Direct failed checks
                for check in report.get("failed_checks", []):
                    self._add_finding(check, findings)

            return AdapterResult(
                success=True,
                findings=findings,
                metadata={
                    "source": self.report_path or self.repo_id,
                    "count": len(findings),
                },
            )

        except (RequestException, json.JSONDecodeError, IOError) as exc:
            return AdapterResult(
                success=False,
                findings=[],
                error=f"Checkov error: {exc}",
            )

    def _parse_check_results(
        self, check_type: Dict[str, Any], findings: List[AdapterFinding]
    ) -> None:
        """Parse results from a check type."""
        results = check_type.get("results", {})
        for check in results.get("failed_checks", []):
            self._add_finding(check, findings)

    def _add_finding(
        self, check: Dict[str, Any], findings: List[AdapterFinding]
    ) -> None:
        """Add a finding from a Checkov check."""
        severity = self._normalize_severity(check.get("severity", "MEDIUM"))

        # Extract guideline URL as remediation
        guideline = check.get("guideline")
        remediation = f"See: {guideline}" if guideline else None

        finding = AdapterFinding(
            tool="checkov",
            category="iac",
            severity=severity,
            title=check.get("check_name", check.get("check_id", "Unknown check")),
            description=check.get("description", ""),
            rule_id=check.get("check_id", "CKV-UNKNOWN"),
            file_path=check.get("file_path"),
            line_number=check.get("file_line_range", [None])[0],
            resource_id=check.get("resource"),
            remediation=remediation,
            raw=check,
        )
        findings.append(finding)

    def _normalize_severity(self, severity: str) -> str:
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "low",
        }
        return mapping.get(severity.lower(), "medium")


class AdapterRegistry:
    """Registry for managing security tool adapters."""

    def __init__(self, settings: Mapping[str, Any]):
        """Initialize adapters from settings."""
        self.gitlab = GitLabAdapter(settings.get("gitlab", {}))
        self.azure_devops = AzureDevOpsAdapter(settings.get("azure_devops", {}))
        self.snyk = SnykAdapter(settings.get("snyk", {}))
        self.trivy = TrivyAdapter(settings.get("trivy", {}))
        self.prowler = ProwlerAdapter(settings.get("prowler", {}))
        self.owasp_zap = OWASPZAPAdapter(settings.get("owasp_zap", {}))
        self.semgrep = SemgrepAdapter(settings.get("semgrep", {}))
        self.checkov = CheckovAdapter(settings.get("checkov", {}))

    def get_adapter(self, name: str) -> Optional[_BaseAdapter]:
        """Get adapter by name."""
        adapters = {
            "gitlab": self.gitlab,
            "azure_devops": self.azure_devops,
            "snyk": self.snyk,
            "trivy": self.trivy,
            "prowler": self.prowler,
            "owasp_zap": self.owasp_zap,
            "semgrep": self.semgrep,
            "checkov": self.checkov,
        }
        return adapters.get(name.lower())

    def list_configured(self) -> List[str]:
        """List all configured adapters."""
        configured = []
        for name in [
            "gitlab",
            "azure_devops",
            "snyk",
            "trivy",
            "prowler",
            "owasp_zap",
            "semgrep",
            "checkov",
        ]:
            adapter = self.get_adapter(name)
            if adapter and adapter.configured:
                configured.append(name)
        return configured

    def fetch_all(self) -> Dict[str, AdapterResult]:
        """Fetch findings from all configured adapters."""
        results = {}
        for name in self.list_configured():
            adapter = self.get_adapter(name)
            if adapter:
                results[name] = adapter.fetch_findings()
        return results


__all__ = [
    "AdapterFinding",
    "AdapterResult",
    "AdapterRegistry",
    "GitLabAdapter",
    "AzureDevOpsAdapter",
    "SnykAdapter",
    "TrivyAdapter",
    "ProwlerAdapter",
    "OWASPZAPAdapter",
    "SemgrepAdapter",
    "CheckovAdapter",
]
