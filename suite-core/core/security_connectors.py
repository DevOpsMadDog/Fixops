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


__all__ = [
    "SnykConnector",
    "SonarQubeConnector",
    "DependabotConnector",
    "AWSSecurityHubConnector",
    "AzureSecurityCenterConnector",
]
