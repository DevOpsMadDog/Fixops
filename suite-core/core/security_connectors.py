"""Security-tool connectors for vulnerability data ingestion.

Connectors for:
  - Snyk: REST API v1 (https://snyk.docs.apiary.io)
  - SonarQube: Web API 10.x (https://docs.sonarqube.org/latest/extension-guide/web-api/)
  - Dependabot (GitHub): GraphQL + REST via GitHub API
  - AWS Security Hub: boto3 securityhub client
  - Azure Security Center (Defender for Cloud): REST API 2023-01-01

All connectors inherit from _BaseConnector and follow the same
retry / circuit-breaker / rate-limit pattern as the core connectors.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Mapping, Optional

from core.connectors import ConnectorHealth, ConnectorOutcome, _BaseConnector

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Snyk Connector
# ---------------------------------------------------------------------------


class SnykConnector(_BaseConnector):
    """Fetch vulnerability data from Snyk REST API v1."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 15.0) or 15.0))
        self.base_url = str(settings.get("base_url") or "https://api.snyk.io").rstrip(
            "/"
        )
        self.org_id = settings.get("org_id") or settings.get("organization_id")
        token = settings.get("token")
        token_env = settings.get("token_env", "SNYK_TOKEN")
        if token_env:
            token = os.getenv(str(token_env)) or token
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.org_id and self.token)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"token {self.token}",
            "Content-Type": "application/json",
        }

    def list_projects(self) -> ConnectorOutcome:
        """List Snyk projects in the organization."""
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "snyk not configured"})
        url = f"{self.base_url}/v1/org/{self.org_id}/projects"
        try:
            resp = self._request("GET", url, headers=self._headers())
            resp.raise_for_status()
            data = resp.json()
            return ConnectorOutcome(
                "fetched",
                {
                    "projects": data.get("projects", []),
                    "count": len(data.get("projects", [])),
                },
            )
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def get_issues(self, project_id: str) -> ConnectorOutcome:
        """Fetch vulnerability issues for a Snyk project."""
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "snyk not configured"})
        url = f"{self.base_url}/v1/org/{self.org_id}/project/{project_id}/aggregated-issues"
        try:
            resp = self._request(
                "POST", url, headers=self._headers(), json={"includeDescription": True}
            )
            resp.raise_for_status()
            data = resp.json()
            issues = data.get("issues", [])
            return ConnectorOutcome("fetched", {"issues": issues, "count": len(issues)})
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def health_check(self) -> ConnectorHealth:
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Not configured"
            )
        start = time.time()
        try:
            resp = self._request(
                "GET", f"{self.base_url}/v1/org/{self.org_id}", headers=self._headers()
            )
            ms = (time.time() - start) * 1000
            if resp.status_code == 200:
                return ConnectorHealth(healthy=True, latency_ms=ms, message="OK")
            return ConnectorHealth(
                healthy=False, latency_ms=ms, message=f"HTTP {resp.status_code}"
            )
        except Exception as exc:
            return ConnectorHealth(
                healthy=False, latency_ms=(time.time() - start) * 1000, message=str(exc)
            )


# ---------------------------------------------------------------------------
# 2. SonarQube Connector
# ---------------------------------------------------------------------------


class SonarQubeConnector(_BaseConnector):
    """Fetch code quality and security findings from SonarQube Web API."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 15.0) or 15.0))
        self.base_url = str(
            settings.get("base_url") or settings.get("url") or ""
        ).rstrip("/")
        self.project_key = settings.get("project_key")
        token = settings.get("token")
        token_env = settings.get("token_env", "SONARQUBE_TOKEN")
        if token_env:
            token = os.getenv(str(token_env)) or token
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.token)

    def _headers(self) -> Dict[str, str]:
        import base64

        auth = base64.b64encode(f"{self.token}:".encode()).decode()
        return {"Authorization": f"Basic {auth}"}

    def get_issues(
        self, project_key: Optional[str] = None, severities: str = "BLOCKER,CRITICAL"
    ) -> ConnectorOutcome:
        """Fetch security hotspots and issues from SonarQube."""
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "sonarqube not configured"})
        pk = project_key or self.project_key
        url = f"{self.base_url}/api/issues/search"
        params: Dict[str, str] = {
            "types": "VULNERABILITY,SECURITY_HOTSPOT",
            "severities": severities,
            "ps": "100",
        }
        if pk:
            params["componentKeys"] = pk
        try:
            resp = self._request("GET", url, headers=self._headers(), params=params)
            resp.raise_for_status()
            data = resp.json()
            return ConnectorOutcome(
                "fetched",
                {"issues": data.get("issues", []), "total": data.get("total", 0)},
            )
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def get_quality_gate(self, project_key: Optional[str] = None) -> ConnectorOutcome:
        """Get quality gate status for a project."""
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "sonarqube not configured"})
        pk = project_key or self.project_key
        url = f"{self.base_url}/api/qualitygates/project_status"
        params = {"projectKey": pk} if pk else {}
        try:
            resp = self._request("GET", url, headers=self._headers(), params=params)
            resp.raise_for_status()
            return ConnectorOutcome("fetched", resp.json())
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def health_check(self) -> ConnectorHealth:
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Not configured"
            )
        start = time.time()
        try:
            resp = self._request(
                "GET", f"{self.base_url}/api/system/status", headers=self._headers()
            )
            ms = (time.time() - start) * 1000
            if resp.status_code == 200:
                return ConnectorHealth(healthy=True, latency_ms=ms, message="OK")
            return ConnectorHealth(
                healthy=False, latency_ms=ms, message=f"HTTP {resp.status_code}"
            )
        except Exception as exc:
            return ConnectorHealth(
                healthy=False, latency_ms=(time.time() - start) * 1000, message=str(exc)
            )


# ---------------------------------------------------------------------------
# 3. Dependabot Connector (via GitHub API)
# ---------------------------------------------------------------------------


class DependabotConnector(_BaseConnector):
    """Fetch Dependabot alerts via GitHub REST API."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 15.0) or 15.0))
        self.base_url = "https://api.github.com"
        self.owner = settings.get("owner") or settings.get("org")
        self.repo = settings.get("repo")
        token = settings.get("token")
        token_env = settings.get("token_env", "GITHUB_TOKEN")
        if token_env:
            token = os.getenv(str(token_env)) or token
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.owner and self.repo and self.token)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def list_alerts(
        self, state: str = "open", severity: Optional[str] = None
    ) -> ConnectorOutcome:
        """List Dependabot alerts for a repository."""
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "dependabot not configured"})
        url = f"{self.base_url}/repos/{self.owner}/{self.repo}/dependabot/alerts"
        params: Dict[str, str] = {"state": state, "per_page": "100"}
        if severity:
            params["severity"] = severity
        try:
            resp = self._request("GET", url, headers=self._headers(), params=params)
            resp.raise_for_status()
            alerts = resp.json()
            return ConnectorOutcome("fetched", {"alerts": alerts, "count": len(alerts)})
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def dismiss_alert(
        self, alert_number: int, reason: str = "tolerable_risk"
    ) -> ConnectorOutcome:
        """Dismiss a Dependabot alert."""
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "dependabot not configured"})
        url = f"{self.base_url}/repos/{self.owner}/{self.repo}/dependabot/alerts/{alert_number}"
        try:
            resp = self._request(
                "PATCH",
                url,
                headers=self._headers(),
                json={"state": "dismissed", "dismissed_reason": reason},
            )
            resp.raise_for_status()
            return ConnectorOutcome(
                "updated", {"alert_number": alert_number, "state": "dismissed"}
            )
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def health_check(self) -> ConnectorHealth:
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Not configured"
            )
        start = time.time()
        try:
            resp = self._request(
                "GET",
                f"{self.base_url}/repos/{self.owner}/{self.repo}",
                headers=self._headers(),
            )
            ms = (time.time() - start) * 1000
            if resp.status_code == 200:
                return ConnectorHealth(healthy=True, latency_ms=ms, message="OK")
            return ConnectorHealth(
                healthy=False, latency_ms=ms, message=f"HTTP {resp.status_code}"
            )
        except Exception as exc:
            return ConnectorHealth(
                healthy=False, latency_ms=(time.time() - start) * 1000, message=str(exc)
            )


# ---------------------------------------------------------------------------
# 4. AWS Security Hub Connector
# ---------------------------------------------------------------------------


class AWSSecurityHubConnector(_BaseConnector):
    """Fetch and manage findings from AWS Security Hub via boto3."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 30.0) or 30.0))
        self.region = settings.get("region") or os.getenv(
            "AWS_DEFAULT_REGION", "us-east-1"
        )
        self.profile = settings.get("profile")
        self._client: Any = None

    @property
    def configured(self) -> bool:
        return True  # boto3 uses env vars / instance profile

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import boto3

                session_kwargs: Dict[str, Any] = {"region_name": self.region}
                if self.profile:
                    session_kwargs["profile_name"] = self.profile
                session = boto3.Session(**session_kwargs)
                self._client = session.client("securityhub")
            except ImportError:
                logger.warning(
                    "boto3 not available; AWS Security Hub connector disabled"
                )
                return None
        return self._client

    def get_findings(
        self, severity: str = "CRITICAL", max_results: int = 100
    ) -> ConnectorOutcome:
        """Fetch findings from AWS Security Hub."""
        client = self._get_client()
        if not client:
            return ConnectorOutcome("skipped", {"reason": "boto3 not available"})
        try:
            resp = client.get_findings(
                Filters={
                    "SeverityLabel": [{"Value": severity, "Comparison": "EQUALS"}]
                },
                MaxResults=min(max_results, 100),
            )
            findings = resp.get("Findings", [])
            return ConnectorOutcome(
                "fetched", {"findings": findings, "count": len(findings)}
            )
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def batch_update_findings(
        self, finding_ids: List[Dict[str, str]], workflow_status: str = "RESOLVED"
    ) -> ConnectorOutcome:
        """Update workflow status for findings."""
        client = self._get_client()
        if not client:
            return ConnectorOutcome("skipped", {"reason": "boto3 not available"})
        try:
            client.batch_update_findings(
                FindingIdentifiers=finding_ids,
                Workflow={"Status": workflow_status},
            )
            return ConnectorOutcome(
                "updated", {"count": len(finding_ids), "status": workflow_status}
            )
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def health_check(self) -> ConnectorHealth:
        client = self._get_client()
        if not client:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="boto3 not available"
            )
        start = time.time()
        try:
            client.get_findings(MaxResults=1)
            ms = (time.time() - start) * 1000
            return ConnectorHealth(healthy=True, latency_ms=ms, message="OK")
        except Exception as exc:
            return ConnectorHealth(
                healthy=False, latency_ms=(time.time() - start) * 1000, message=str(exc)
            )


# ---------------------------------------------------------------------------
# 5. Azure Security Center (Defender for Cloud) Connector
# ---------------------------------------------------------------------------


class AzureSecurityCenterConnector(_BaseConnector):
    """Fetch security assessments from Azure Defender for Cloud REST API."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 20.0) or 20.0))
        self.subscription_id = settings.get("subscription_id") or os.getenv(
            "AZURE_SUBSCRIPTION_ID"
        )
        self.tenant_id = settings.get("tenant_id") or os.getenv("AZURE_TENANT_ID")
        self.client_id = settings.get("client_id") or os.getenv("AZURE_CLIENT_ID")
        client_secret = settings.get("client_secret")
        secret_env = settings.get("secret_env", "AZURE_CLIENT_SECRET")
        if secret_env:
            client_secret = os.getenv(str(secret_env)) or client_secret
        self.client_secret = client_secret
        self._token: Optional[str] = None

    @property
    def configured(self) -> bool:
        return bool(
            self.subscription_id
            and self.tenant_id
            and self.client_id
            and self.client_secret
        )

    def _get_token(self) -> Optional[str]:
        if self._token:
            return self._token
        if not self.configured:
            return None
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        try:
            resp = self._request(
                "POST",
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://management.azure.com/.default",
                },
            )
            resp.raise_for_status()
            self._token = resp.json().get("access_token")
            return self._token
        except Exception:
            return None

    def _headers(self) -> Dict[str, str]:
        token = self._get_token()
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def get_assessments(self) -> ConnectorOutcome:
        """Fetch security assessments for the subscription."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "azure security center not configured"}
            )
        url = (
            f"https://management.azure.com/subscriptions/{self.subscription_id}"
            f"/providers/Microsoft.Security/assessments?api-version=2021-06-01"
        )
        try:
            resp = self._request("GET", url, headers=self._headers())
            resp.raise_for_status()
            data = resp.json()
            assessments = data.get("value", [])
            return ConnectorOutcome(
                "fetched", {"assessments": assessments, "count": len(assessments)}
            )
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def get_alerts(self) -> ConnectorOutcome:
        """Fetch security alerts from Defender for Cloud."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "azure security center not configured"}
            )
        url = (
            f"https://management.azure.com/subscriptions/{self.subscription_id}"
            f"/providers/Microsoft.Security/alerts?api-version=2022-01-01"
        )
        try:
            resp = self._request("GET", url, headers=self._headers())
            resp.raise_for_status()
            data = resp.json()
            alerts = data.get("value", [])
            return ConnectorOutcome("fetched", {"alerts": alerts, "count": len(alerts)})
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def health_check(self) -> ConnectorHealth:
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Not configured"
            )
        start = time.time()
        token = self._get_token()
        ms = (time.time() - start) * 1000
        if token:
            return ConnectorHealth(
                healthy=True, latency_ms=ms, message="Authenticated OK"
            )
        return ConnectorHealth(healthy=False, latency_ms=ms, message="Auth failed")


# ---------------------------------------------------------------------------
# 6. Wiz CNAPP Connector
# ---------------------------------------------------------------------------


class WizConnector(_BaseConnector):
    """Fetch vulnerability and cloud security data from Wiz GraphQL API."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 30.0) or 30.0))
        self.base_url = str(settings.get("base_url") or "https://api.wiz.io").rstrip(
            "/"
        )
        self.client_id = settings.get("client_id")
        self.client_secret = settings.get("client_secret")
        client_secret_env = settings.get("client_secret_env", "WIZ_CLIENT_SECRET")
        if client_secret_env:
            self.client_secret = os.getenv(str(client_secret_env)) or self.client_secret
        self._token: Optional[str] = None
        self._token_expires: float = 0

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.client_id and self.client_secret)

    def _get_token(self) -> Optional[str]:
        """Get OAuth token, refreshing if needed."""
        if self._token and time.time() < self._token_expires:
            return self._token
        try:
            resp = self._request(
                "POST",
                "https://auth.wiz.io/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "audience": "wiz-api",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data["access_token"]
            self._token_expires = time.time() + data.get("expires_in", 3600) - 60
            return self._token
        except Exception as exc:
            logger.warning(f"Wiz auth failed: {exc}")
            return None

    def _headers(self) -> Dict[str, str]:
        token = self._get_token()
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def _graphql(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Any:
        """Execute a GraphQL query against Wiz API."""
        resp = self._request(
            "POST",
            f"{self.base_url}/graphql",
            headers=self._headers(),
            json={"query": query, "variables": variables or {}},
        )
        resp.raise_for_status()
        return resp.json()

    def get_issues(
        self, severity: Optional[str] = None, limit: int = 100
    ) -> ConnectorOutcome:
        """Fetch security issues from Wiz."""
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "wiz not configured"})
        query = """
        query GetIssues($first: Int, $filterBy: IssueFilters) {
            issues(first: $first, filterBy: $filterBy) {
                nodes {
                    id
                    sourceRule { id name }
                    severity
                    status
                    createdAt
                    resolvedAt
                    dueAt
                    entitySnapshot { id type name }
                }
            }
        }
        """
        filters = {}
        if severity:
            filters["severity"] = [severity.upper()]
        try:
            data = self._graphql(query, {"first": limit, "filterBy": filters})
            issues = data.get("data", {}).get("issues", {}).get("nodes", [])
            return ConnectorOutcome("fetched", {"issues": issues, "count": len(issues)})
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def get_vulnerabilities(self, limit: int = 100) -> ConnectorOutcome:
        """Fetch vulnerability findings from Wiz."""
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "wiz not configured"})
        query = """
        query GetVulnerabilities($first: Int) {
            vulnerabilityFindings(first: $first) {
                nodes {
                    id
                    name
                    CVEDescription
                    CVSSScore
                    severity
                    status
                    firstDetectedAt
                    resolvedAt
                    vendorSeverity
                    exploitabilityScore
                    hasCisaKevExploit
                    hasExploit
                }
            }
        }
        """
        try:
            data = self._graphql(query, {"first": limit})
            vulns = (
                data.get("data", {}).get("vulnerabilityFindings", {}).get("nodes", [])
            )
            return ConnectorOutcome(
                "fetched", {"vulnerabilities": vulns, "count": len(vulns)}
            )
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def get_cloud_resources(self, limit: int = 100) -> ConnectorOutcome:
        """Fetch cloud resources inventory."""
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "wiz not configured"})
        query = """
        query GetCloudResources($first: Int) {
            graphSearch(first: $first, query: "{ find {*} }") {
                nodes {
                    entities { id type name cloudPlatform }
                }
            }
        }
        """
        try:
            data = self._graphql(query, {"first": limit})
            resources = data.get("data", {}).get("graphSearch", {}).get("nodes", [])
            return ConnectorOutcome(
                "fetched", {"resources": resources, "count": len(resources)}
            )
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def health_check(self) -> ConnectorHealth:
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Not configured"
            )
        start = time.time()
        token = self._get_token()
        ms = (time.time() - start) * 1000
        if token:
            return ConnectorHealth(
                healthy=True, latency_ms=ms, message="Authenticated OK"
            )
        return ConnectorHealth(healthy=False, latency_ms=ms, message="Auth failed")


# ---------------------------------------------------------------------------
# 7. Prisma Cloud (Palo Alto CNAPP) Connector
# ---------------------------------------------------------------------------


class PrismaCloudConnector(_BaseConnector):
    """Fetch vulnerability and compliance data from Prisma Cloud REST API."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 30.0) or 30.0))
        self.base_url = str(
            settings.get("base_url") or "https://api.prismacloud.io"
        ).rstrip("/")
        self.access_key = settings.get("access_key")
        self.secret_key = settings.get("secret_key")
        secret_key_env = settings.get("secret_key_env", "PRISMA_SECRET_KEY")
        if secret_key_env:
            self.secret_key = os.getenv(str(secret_key_env)) or self.secret_key
        self._token: Optional[str] = None
        self._token_expires: float = 0

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.access_key and self.secret_key)

    def _get_token(self) -> Optional[str]:
        """Get login token, refreshing if needed."""
        if self._token and time.time() < self._token_expires:
            return self._token
        try:
            resp = self._request(
                "POST",
                f"{self.base_url}/login",
                json={"username": self.access_key, "password": self.secret_key},
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data["token"]
            self._token_expires = time.time() + 600 - 30  # Token valid ~10 mins
            return self._token
        except Exception as exc:
            logger.warning(f"Prisma Cloud auth failed: {exc}")
            return None

    def _headers(self) -> Dict[str, str]:
        token = self._get_token()
        return {"x-redlock-auth": token or "", "Content-Type": "application/json"}

    def get_alerts(self, status: str = "open", limit: int = 100) -> ConnectorOutcome:
        """Fetch security alerts from Prisma Cloud."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "prisma cloud not configured"}
            )
        url = f"{self.base_url}/alert"
        try:
            resp = self._request(
                "POST",
                url,
                headers=self._headers(),
                json={
                    "filters": [
                        {"name": "alert.status", "operator": "=", "value": status}
                    ],
                    "limit": limit,
                },
            )
            resp.raise_for_status()
            alerts = resp.json()
            return ConnectorOutcome("fetched", {"alerts": alerts, "count": len(alerts)})
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def get_vulnerabilities(self, limit: int = 100) -> ConnectorOutcome:
        """Fetch vulnerability findings from Prisma Cloud Compute."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "prisma cloud not configured"}
            )
        url = f"{self.base_url}/api/v1/images"
        try:
            resp = self._request(
                "GET", url, headers=self._headers(), params={"limit": limit}
            )
            resp.raise_for_status()
            images = resp.json()
            # Extract vulnerabilities from images
            vulns = []
            for img in images:
                for vuln in img.get("vulnerabilities", []):
                    vulns.append({**vuln, "image": img.get("id")})
            return ConnectorOutcome(
                "fetched", {"vulnerabilities": vulns, "count": len(vulns)}
            )
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def get_compliance_findings(self, limit: int = 100) -> ConnectorOutcome:
        """Fetch compliance posture findings."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "prisma cloud not configured"}
            )
        url = f"{self.base_url}/compliance/posture"
        try:
            resp = self._request(
                "POST", url, headers=self._headers(), json={"limit": limit}
            )
            resp.raise_for_status()
            data = resp.json()
            return ConnectorOutcome(
                "fetched", {"compliance": data, "count": len(data.get("items", []))}
            )
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def health_check(self) -> ConnectorHealth:
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Not configured"
            )
        start = time.time()
        token = self._get_token()
        ms = (time.time() - start) * 1000
        if token:
            return ConnectorHealth(
                healthy=True, latency_ms=ms, message="Authenticated OK"
            )
        return ConnectorHealth(healthy=False, latency_ms=ms, message="Auth failed")


# ---------------------------------------------------------------------------
# 8. Orca Security CNAPP Connector
# ---------------------------------------------------------------------------


class OrcaSecurityConnector(_BaseConnector):
    """Fetch security findings from Orca Security REST API."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 30.0) or 30.0))
        self.base_url = str(
            settings.get("base_url") or "https://api.orcasecurity.io"
        ).rstrip("/")
        self.api_token = settings.get("api_token")
        token_env = settings.get("api_token_env", "ORCA_API_TOKEN")
        if token_env:
            self.api_token = os.getenv(str(token_env)) or self.api_token

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_token)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Token {self.api_token}",
            "Content-Type": "application/json",
        }

    def get_alerts(
        self, severity: Optional[str] = None, limit: int = 100
    ) -> ConnectorOutcome:
        """Fetch security alerts from Orca."""
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "orca not configured"})
        url = f"{self.base_url}/api/alerts"
        params = {"limit": limit}
        if severity:
            params["severity"] = severity
        try:
            resp = self._request("GET", url, headers=self._headers(), params=params)
            resp.raise_for_status()
            data = resp.json()
            alerts = data.get("data", [])
            return ConnectorOutcome("fetched", {"alerts": alerts, "count": len(alerts)})
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def get_vulnerabilities(self, limit: int = 100) -> ConnectorOutcome:
        """Fetch vulnerability findings."""
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "orca not configured"})
        url = f"{self.base_url}/api/cves"
        try:
            resp = self._request(
                "GET", url, headers=self._headers(), params={"limit": limit}
            )
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("data", [])
            return ConnectorOutcome(
                "fetched", {"vulnerabilities": vulns, "count": len(vulns)}
            )
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def health_check(self) -> ConnectorHealth:
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Not configured"
            )
        start = time.time()
        try:
            resp = self._request(
                "GET", f"{self.base_url}/api/user/me", headers=self._headers()
            )
            ms = (time.time() - start) * 1000
            if resp.status_code == 200:
                return ConnectorHealth(healthy=True, latency_ms=ms, message="OK")
            return ConnectorHealth(
                healthy=False, latency_ms=ms, message=f"HTTP {resp.status_code}"
            )
        except Exception as exc:
            return ConnectorHealth(
                healthy=False, latency_ms=(time.time() - start) * 1000, message=str(exc)
            )


# ---------------------------------------------------------------------------
# 9. Lacework CNAPP Connector
# ---------------------------------------------------------------------------


class LaceworkConnector(_BaseConnector):
    """Fetch security data from Lacework API v2."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 30.0) or 30.0))
        self.account = settings.get("account")  # e.g., "yourcompany"
        self.base_url = f"https://{self.account}.lacework.net" if self.account else ""
        self.key_id = settings.get("key_id")
        self.secret = settings.get("secret")
        secret_env = settings.get("secret_env", "LACEWORK_SECRET")
        if secret_env:
            self.secret = os.getenv(str(secret_env)) or self.secret
        self._token: Optional[str] = None
        self._token_expires: float = 0

    @property
    def configured(self) -> bool:
        return bool(self.account and self.key_id and self.secret)

    def _get_token(self) -> Optional[str]:
        """Get API access token."""
        if self._token and time.time() < self._token_expires:
            return self._token
        try:
            resp = self._request(
                "POST",
                f"{self.base_url}/api/v2/access/tokens",
                json={"keyId": self.key_id, "expiryTime": 3600},
                headers={"X-LW-UAKS": self.secret, "Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data.get("token")
            self._token_expires = time.time() + 3600 - 60
            return self._token
        except Exception as exc:
            logger.warning(f"Lacework auth failed: {exc}")
            return None

    def _headers(self) -> Dict[str, str]:
        token = self._get_token()
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def get_alerts(
        self, severity: Optional[str] = None, limit: int = 100
    ) -> ConnectorOutcome:
        """Fetch security alerts."""
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "lacework not configured"})
        url = f"{self.base_url}/api/v2/Alerts"
        try:
            resp = self._request(
                "GET", url, headers=self._headers(), params={"limit": limit}
            )
            resp.raise_for_status()
            data = resp.json()
            alerts = data.get("data", [])
            if severity:
                alerts = [
                    a
                    for a in alerts
                    if a.get("severity", "").lower() == severity.lower()
                ]
            return ConnectorOutcome("fetched", {"alerts": alerts, "count": len(alerts)})
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def get_vulnerabilities(self, limit: int = 100) -> ConnectorOutcome:
        """Fetch vulnerability findings from host/container scans."""
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "lacework not configured"})
        url = f"{self.base_url}/api/v2/Vulnerabilities/Hosts/search"
        try:
            resp = self._request(
                "POST",
                url,
                headers=self._headers(),
                json={
                    "filters": [],
                    "returns": ["vulnId", "severity", "fixInfo", "cveProps"],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("data", [])
            return ConnectorOutcome(
                "fetched", {"vulnerabilities": vulns[:limit], "count": len(vulns)}
            )
        except Exception as exc:
            return ConnectorOutcome("failed", {"error": str(exc)})

    def health_check(self) -> ConnectorHealth:
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Not configured"
            )
        start = time.time()
        token = self._get_token()
        ms = (time.time() - start) * 1000
        if token:
            return ConnectorHealth(
                healthy=True, latency_ms=ms, message="Authenticated OK"
            )
        return ConnectorHealth(healthy=False, latency_ms=ms, message="Auth failed")


__all__ = [
    "SnykConnector",
    "SonarQubeConnector",
    "DependabotConnector",
    "AWSSecurityHubConnector",
    "AzureSecurityCenterConnector",
    "WizConnector",
    "PrismaCloudConnector",
    "OrcaSecurityConnector",
    "LaceworkConnector",
]
