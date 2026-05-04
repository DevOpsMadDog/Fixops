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

import structlog
import os
import time
from typing import Any, Dict, List, Mapping, Optional

import requests

from core.connectors import ConnectorHealth, ConnectorOutcome, _BaseConnector

logger = structlog.get_logger(__name__)

# TrustGraph event bus — optional, never blocks on failure
try:  # pragma: no cover - bus is optional
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Emit an event to the TrustGraph event bus. Never raises.

    Used by every security connector (Snyk, SonarQube, Dependabot, AWS
    SecurityHub, Azure Defender, Wiz, etc.) on every successful fetch so the
    second-brain sees both the connector activity and the resulting findings
    count without each connector having to know about TrustGraph.
    """
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio
            import inspect
            if inspect.iscoroutine(result):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    def get_issues(self, project_id: str) -> ConnectorOutcome:
        """Fetch vulnerability issues for a Snyk project."""
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "snyk not configured"})
        _emit_event(
            "security_connector.fetch.started",
            {"connector": "snyk", "project_id": project_id, "endpoint": "aggregated-issues"},
        )
        url = f"{self.base_url}/v1/org/{self.org_id}/project/{project_id}/aggregated-issues"
        try:
            resp = self._request(
                "POST", url, headers=self._headers(), json={"includeDescription": True}
            )
            resp.raise_for_status()
            data = resp.json()
            issues = data.get("issues", [])
            return ConnectorOutcome("fetched", {"issues": issues, "count": len(issues)})
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
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
            _emit_event(
                "security_connector.findings.fetched",
                {
                    "connector": "aws_securityhub",
                    "severity": severity,
                    "count": len(findings),
                },
            )
            return ConnectorOutcome(
                "fetched", {"findings": findings, "count": len(findings)}
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    def batch_import_findings(
        self, findings: List[Dict[str, Any]]
    ) -> ConnectorOutcome:
        """Batch import findings into AWS Security Hub in ASFF format.

        Uses BatchImportFindings API. Each finding must be a valid ASFF dict with
        at minimum: SchemaVersion, Id, ProductArn, GeneratorId, AwsAccountId,
        Types, CreatedAt, UpdatedAt, Severity, Title, Resources.

        Processes in batches of 100 (AWS API limit).
        """
        client = self._get_client()
        if not client:
            return ConnectorOutcome("skipped", {"reason": "boto3 not available"})

        total_imported = 0
        total_failed = 0
        errors: List[str] = []

        # Process in batches of 100 (AWS limit)
        for i in range(0, len(findings), 100):
            batch = findings[i : i + 100]
            try:
                resp = client.batch_import_findings(Findings=batch)
                total_imported += resp.get("SuccessCount", 0)
                total_failed += resp.get("FailedCount", 0)
                for fail in resp.get("FailedFindings", []):
                    errors.append(
                        f"{fail.get('Id', 'unknown')}: {fail.get('ErrorMessage', 'unknown error')}"
                    )
            except (OSError, ValueError, KeyError, RuntimeError) as exc:
                total_failed += len(batch)
                errors.append(f"Batch {i // 100}: {type(exc).__name__}")

        status = "sent" if total_failed == 0 else ("partial" if total_imported > 0 else "failed")
        return ConnectorOutcome(
            status,
            {
                "imported": total_imported,
                "failed": total_failed,
                "total": len(findings),
                "errors": errors[:10],  # Cap error messages
                "operation": "batch_import_findings",
            },
        )

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
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
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.warning("wiz_auth_failed", exc_type=type(exc).__name__)
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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    def create_issue(
        self,
        title: str,
        severity: str = "HIGH",
        description: Optional[str] = None,
        resource_id: Optional[str] = None,
        due_at: Optional[str] = None,
    ) -> ConnectorOutcome:
        """Create a Wiz Issue via GraphQL mutation.

        Args:
            title: Issue title.
            severity: CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL.
            description: Detailed description of the issue.
            resource_id: Optional Wiz resource ID to associate.
            due_at: Optional ISO8601 due date.
        """
        if not self.configured:
            return ConnectorOutcome("skipped", {"reason": "wiz not configured"})

        mutation = """
        mutation CreateIssue($input: CreateIssueInput!) {
            createIssue(input: $input) {
                issue {
                    id
                    severity
                    status
                    createdAt
                    sourceRule { id name }
                    entitySnapshot { id type name }
                }
            }
        }
        """
        variables: Dict[str, Any] = {
            "input": {
                "title": title,
                "severity": severity.upper(),
            }
        }
        if description:
            variables["input"]["description"] = description
        if resource_id:
            variables["input"]["resourceId"] = resource_id
        if due_at:
            variables["input"]["dueAt"] = due_at

        try:
            data = self._graphql(mutation, variables)
            issue = data.get("data", {}).get("createIssue", {}).get("issue", {})
            if not issue:
                errors = data.get("errors", [])
                return ConnectorOutcome(
                    "failed",
                    {
                        "reason": "wiz issue creation returned no issue",
                        "errors": [e.get("message", "") for e in errors],
                    },
                )
            return ConnectorOutcome(
                "sent",
                {
                    "issue_id": issue.get("id"),
                    "severity": issue.get("severity"),
                    "status": issue.get("status"),
                    "operation": "create_issue",
                },
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.warning("prisma_auth_failed", exc_type=type(exc).__name__)
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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.warning("lacework_auth_failed", exc_type=type(exc).__name__)
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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

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
# 10. Deepfence ThreatMapper Connector
# ---------------------------------------------------------------------------


class ThreatMapperConnector(_BaseConnector):
    """Fetch runtime vulnerability, secret, malware and compliance data from Deepfence ThreatMapper.

    ThreatMapper is an open-source CNAPP that deploys sensor agents across
    Kubernetes, Docker, ECS, Fargate and bare-metal hosts.  It discovers
    running workloads and scans them for:
      - Vulnerabilities (OS packages, language libs, container images)
      - Secrets (leaked credentials, API keys, tokens)
      - Malware (YARA-based runtime detection)
      - Compliance posture (CIS benchmarks for Linux, K8s, Docker, cloud)

    API: Deepfence Console REST API v2 (/deepfence/v2.0/)
    Auth: API key obtained after initial admin registration
    Docs: https://threatmapper.org/threatmapper/docs/v2.5/
    """

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 30.0) or 30.0))
        console_url = str(
            settings.get("console_url")
            or settings.get("base_url")
            or settings.get("url", "")
        ).rstrip("/")
        self.console_url = console_url
        self.base_url = f"{console_url}/deepfence/v2.0" if console_url else ""
        api_key = settings.get("api_key")
        api_key_env = settings.get("api_key_env", "THREATMAPPER_API_KEY")
        if api_key_env:
            api_key = os.getenv(str(api_key_env)) or api_key
        self.api_key = api_key
        self._token: Optional[str] = None
        self._token_expires: float = 0

    @property
    def configured(self) -> bool:
        return bool(self.console_url and self.api_key)

    # -- auth ---------------------------------------------------------------

    def _authenticate(self) -> Optional[str]:
        """Exchange API key for a short-lived JWT access token."""
        if self._token and time.time() < self._token_expires:
            return self._token
        try:
            resp = self._request(
                "POST",
                f"{self.base_url}/auth/token",
                json={"api_token": self.api_key},
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data.get("access_token") or data.get("token")
            # ThreatMapper tokens typically last 24 h; refresh at 23 h
            self._token_expires = time.time() + 82800
            return self._token
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.warning("threatmapper_auth_failed", exc_type=type(exc).__name__)
            return None

    def _headers(self) -> Dict[str, str]:
        token = self._authenticate()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    # -- vulnerability scans ------------------------------------------------

    def get_vulnerabilities(
        self,
        severity: Optional[str] = None,
        limit: int = 500,
    ) -> ConnectorOutcome:
        """Fetch vulnerability scan results across all nodes."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "threatmapper not configured"}
            )
        try:
            body: Dict[str, Any] = {
                "node_filter": {
                    "filters": {"compare_filter": []},
                    "in_field_filter": [],
                },
                "window": {"offset": 0, "size": limit},
            }
            if severity:
                body["node_filter"]["filters"]["compare_filter"].append(
                    {
                        "field_name": "cve_severity",
                        "field_value": severity.lower(),
                        "filter_type": "eq",
                    }
                )
            resp = self._request(
                "POST",
                f"{self.base_url}/search/vulnerability",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            vulns = (
                resp.json()
                if isinstance(resp.json(), list)
                else resp.json().get("data", [])
            )
            return ConnectorOutcome(
                "fetched", {"vulnerabilities": vulns, "count": len(vulns)}
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    # -- secret scans -------------------------------------------------------

    def get_secrets(self, limit: int = 500) -> ConnectorOutcome:
        """Fetch secret scan results (leaked creds, API keys, tokens)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "threatmapper not configured"}
            )
        try:
            body: Dict[str, Any] = {
                "node_filter": {
                    "filters": {"compare_filter": []},
                    "in_field_filter": [],
                },
                "window": {"offset": 0, "size": limit},
            }
            resp = self._request(
                "POST",
                f"{self.base_url}/search/secret",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            secrets = (
                resp.json()
                if isinstance(resp.json(), list)
                else resp.json().get("data", [])
            )
            return ConnectorOutcome(
                "fetched", {"secrets": secrets, "count": len(secrets)}
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    # -- malware scans ------------------------------------------------------

    def get_malware(self, limit: int = 500) -> ConnectorOutcome:
        """Fetch malware scan results (YARA-based detections)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "threatmapper not configured"}
            )
        try:
            body: Dict[str, Any] = {
                "node_filter": {
                    "filters": {"compare_filter": []},
                    "in_field_filter": [],
                },
                "window": {"offset": 0, "size": limit},
            }
            resp = self._request(
                "POST",
                f"{self.base_url}/search/malware",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            malware = (
                resp.json()
                if isinstance(resp.json(), list)
                else resp.json().get("data", [])
            )
            return ConnectorOutcome(
                "fetched", {"malware": malware, "count": len(malware)}
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    # -- compliance ---------------------------------------------------------

    def get_compliance_results(
        self, benchmark: Optional[str] = None, limit: int = 500
    ) -> ConnectorOutcome:
        """Fetch compliance scan results (CIS benchmarks)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "threatmapper not configured"}
            )
        try:
            body: Dict[str, Any] = {
                "node_filter": {
                    "filters": {"compare_filter": []},
                    "in_field_filter": [],
                },
                "window": {"offset": 0, "size": limit},
            }
            if benchmark:
                body["node_filter"]["filters"]["compare_filter"].append(
                    {
                        "field_name": "compliance_check_type",
                        "field_value": benchmark,
                        "filter_type": "eq",
                    }
                )
            resp = self._request(
                "POST",
                f"{self.base_url}/search/compliance",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            results = (
                resp.json()
                if isinstance(resp.json(), list)
                else resp.json().get("data", [])
            )
            return ConnectorOutcome(
                "fetched", {"compliance_results": results, "count": len(results)}
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    # -- topology / inventory -----------------------------------------------

    def get_topology(self) -> ConnectorOutcome:
        """Fetch runtime topology (hosts, containers, pods, processes)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "threatmapper not configured"}
            )
        try:
            resp = self._request(
                "GET",
                f"{self.base_url}/topology",
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()
            return ConnectorOutcome("fetched", {"topology": data})
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    # -- trigger scans ------------------------------------------------------

    def trigger_vulnerability_scan(
        self, node_ids: List[str], node_type: str = "host"
    ) -> ConnectorOutcome:
        """Start a new vulnerability scan on specified nodes."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "threatmapper not configured"}
            )
        try:
            resp = self._request(
                "POST",
                f"{self.base_url}/scan/start/vulnerability",
                headers=self._headers(),
                json={
                    "node_ids": [
                        {"node_id": nid, "node_type": node_type} for nid in node_ids
                    ],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return ConnectorOutcome(
                "success",
                {"scan_ids": data.get("scan_ids", []), "message": "Scan started"},
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    def trigger_secret_scan(
        self, node_ids: List[str], node_type: str = "host"
    ) -> ConnectorOutcome:
        """Start a new secret scan on specified nodes."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "threatmapper not configured"}
            )
        try:
            resp = self._request(
                "POST",
                f"{self.base_url}/scan/start/secret",
                headers=self._headers(),
                json={
                    "node_ids": [
                        {"node_id": nid, "node_type": node_type} for nid in node_ids
                    ],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return ConnectorOutcome(
                "success",
                {"scan_ids": data.get("scan_ids", []), "message": "Scan started"},
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    # -- health check -------------------------------------------------------

    def health_check(self) -> ConnectorHealth:
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Not configured"
            )
        start = time.time()
        token = self._authenticate()
        ms = (time.time() - start) * 1000
        if token:
            return ConnectorHealth(
                healthy=True, latency_ms=ms, message="Authenticated OK"
            )
        return ConnectorHealth(healthy=False, latency_ms=ms, message="Auth failed")


# ---------------------------------------------------------------------------
# 11. Dependency-Track Connector (OWASP SBOM Analysis)
# ---------------------------------------------------------------------------


class DependencyTrackConnector(_BaseConnector):
    """Upload SBOMs and fetch vulnerability/license findings from OWASP Dependency-Track.

    Dependency-Track is an intelligent Component Analysis platform that allows
    organizations to identify and reduce risk in the software supply chain.

    Capabilities:
      - Upload CycloneDX / SPDX SBOMs
      - Continuous vulnerability monitoring (NVD, OSS Index, GitHub Advisories, Snyk, OSV)
      - License compliance policy engine
      - Portfolio-wide impact analysis ("which apps use log4j?")
      - VEX / VDR support

    Environment variables:
      DTRACK_URL       — Base URL (default: http://localhost:8080)
      DTRACK_API_KEY   — API key with PORTFOLIO_MANAGEMENT + VIEW_PORTFOLIO permissions
    """

    def __init__(self, settings: Mapping[str, Any] | None = None):
        settings = settings or {}
        super().__init__(timeout=float(settings.get("timeout", 30.0) or 30.0))
        self.base_url = str(
            settings.get("base_url")
            or settings.get("url")
            or os.getenv("DTRACK_URL", "http://localhost:8080")
        ).rstrip("/")
        api_key = settings.get("api_key") or os.getenv("DTRACK_API_KEY", "")
        self.session.headers.update({
            "X-Api-Key": str(api_key),
            "Accept": "application/json",
        })
        self._api_key = api_key

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self._api_key)

    def health_check(self) -> ConnectorHealth:
        """Check Dependency-Track API availability."""
        import time as _time

        start = _time.time()
        try:
            resp = self._request("GET", f"{self.base_url}/api/version")
            elapsed = (_time.time() - start) * 1000
            if resp.status_code == 200:
                version_info = resp.json()
                return ConnectorHealth(
                    healthy=True,
                    latency_ms=elapsed,
                    message=f"Dependency-Track {version_info.get('version', 'unknown')} OK",
                )
            return ConnectorHealth(
                healthy=False, latency_ms=elapsed,
                message=f"HTTP {resp.status_code}",
            )
        except (requests.RequestException, ValueError) as exc:
            elapsed = (_time.time() - start) * 1000
            return ConnectorHealth(
                healthy=False, latency_ms=elapsed, message=str(exc),
            )

    # ── Project management ──────────────────────────────────────

    def get_or_create_project(
        self, name: str, version: str = "latest"
    ) -> Dict[str, Any]:
        """Get a project by name+version, or create it if it doesn't exist."""
        # Try to find existing
        resp = self._request(
            "GET",
            f"{self.base_url}/api/v1/project/lookup",
            params={"name": name, "version": version},
        )
        if resp.status_code == 200:
            return resp.json()
        # Create new project
        resp = self._request(
            "PUT",
            f"{self.base_url}/api/v1/project",
            json={"name": name, "version": version, "active": True},
        )
        resp.raise_for_status()
        return resp.json()

    def list_projects(self, page_size: int = 100, page: int = 1) -> List[Dict[str, Any]]:
        """List all projects in the portfolio."""
        resp = self._request(
            "GET",
            f"{self.base_url}/api/v1/project",
            params={"pageSize": page_size, "pageNumber": page},
        )
        resp.raise_for_status()
        return resp.json()

    # ── SBOM upload ─────────────────────────────────────────────

    def upload_sbom(
        self,
        project_name: str,
        sbom_content: str | bytes,
        project_version: str = "latest",
        auto_create: bool = True,
    ) -> ConnectorOutcome:
        """Upload a CycloneDX or SPDX SBOM to Dependency-Track.

        The SBOM is base64-encoded and sent via the BOM upload endpoint.
        Dependency-Track auto-detects the format (CycloneDX / SPDX).
        """
        import base64

        if isinstance(sbom_content, str):
            sbom_bytes = sbom_content.encode("utf-8")
        else:
            sbom_bytes = sbom_content

        encoded = base64.b64encode(sbom_bytes).decode("ascii")

        payload = {
            "projectName": project_name,
            "projectVersion": project_version,
            "autoCreate": auto_create,
            "bom": encoded,
        }

        try:
            resp = self._request(
                "PUT",
                f"{self.base_url}/api/v1/bom",
                json=payload,
            )
            if resp.status_code in (200, 201):
                data = resp.json() if resp.text else {}
                token = data.get("token", "")
                logger.info(
                    "SBOM uploaded to Dependency-Track: project=%s version=%s token=%s",
                    project_name, project_version, token,
                )
                return ConnectorOutcome(
                    status="success",
                    details={
                        "token": token,
                        "project_name": project_name,
                        "project_version": project_version,
                    },
                )
            else:
                logger.warning(
                    "DTrack SBOM upload failed: HTTP %s — %s",
                    resp.status_code, resp.text[:500],
                )
                return ConnectorOutcome(
                    status="error",
                    details={
                        "http_status": resp.status_code,
                        "error": resp.text[:500],
                    },
                )
        except (requests.RequestException, ValueError) as exc:
            logger.exception("DTrack SBOM upload error")
            return ConnectorOutcome(
                status="error", details={"error": str(exc)},
            )

    def get_bom_processing_status(self, token: str) -> Dict[str, Any]:
        """Check whether a previously uploaded BOM has been fully processed."""
        resp = self._request(
            "GET",
            f"{self.base_url}/api/v1/bom/token/{token}",
        )
        resp.raise_for_status()
        return resp.json()

    # ── Findings (vulnerabilities) ──────────────────────────────

    def fetch_findings(
        self, project_uuid: str, page_size: int = 100, page: int = 1
    ) -> ConnectorOutcome:
        """Fetch vulnerability findings for a specific project."""
        try:
            resp = self._request(
                "GET",
                f"{self.base_url}/api/v1/finding/project/{project_uuid}",
                params={"pageSize": page_size, "pageNumber": page},
            )
            resp.raise_for_status()
            findings = resp.json()
            total = int(resp.headers.get("X-Total-Count", len(findings)))

            normalized = []
            for f in findings:
                vuln = f.get("vulnerability", {})
                comp = f.get("component", {})
                normalized.append({
                    "id": vuln.get("vulnId", ""),
                    "source": vuln.get("source", "NVD"),
                    "severity": str(vuln.get("severity", "UNASSIGNED")).lower(),
                    "cvss_v3": vuln.get("cvssV3BaseScore"),
                    "epss_score": vuln.get("epssScore"),
                    "epss_percentile": vuln.get("epssPercentile"),
                    "title": vuln.get("title") or vuln.get("vulnId", ""),
                    "description": vuln.get("description", ""),
                    "component_name": comp.get("name", ""),
                    "component_version": comp.get("version", ""),
                    "component_purl": comp.get("purl", ""),
                    "component_group": comp.get("group", ""),
                    "attribution": f.get("attribution", {}),
                    "analysis_state": (f.get("analysis") or {}).get("state", ""),
                    "suppressed": f.get("isSuppressed", False),
                })

            logger.info(
                "Fetched %d/%d findings from Dependency-Track for project %s",
                len(normalized), total, project_uuid,
            )
            return ConnectorOutcome(
                status="fetched",
                details={
                    "data": normalized,
                    "total": total,
                    "page": page,
                    "page_size": page_size,
                },
            )
        except (requests.RequestException, ValueError) as exc:
            logger.exception("DTrack fetch_findings error")
            return ConnectorOutcome(
                status="error", details={"error": str(exc)},
            )

    # ── License info ────────────────────────────────────────────

    def fetch_licenses(
        self, project_uuid: str, page_size: int = 100, page: int = 1
    ) -> ConnectorOutcome:
        """Fetch component license data for a project."""
        try:
            resp = self._request(
                "GET",
                f"{self.base_url}/api/v1/component/project/{project_uuid}",
                params={"pageSize": page_size, "pageNumber": page},
            )
            resp.raise_for_status()
            components = resp.json()

            licenses: List[Dict[str, Any]] = []
            for comp in components:
                license_info = comp.get("resolvedLicense") or {}
                licenses.append({
                    "component": comp.get("name", ""),
                    "version": comp.get("version", ""),
                    "purl": comp.get("purl", ""),
                    "license_id": license_info.get("licenseId", ""),
                    "license_name": license_info.get("name", "Unknown"),
                    "is_osi_approved": license_info.get("isOsiApproved", False),
                    "is_fsf_libre": license_info.get("isFsfLibre", False),
                })

            return ConnectorOutcome(
                status="fetched",
                details={"data": licenses, "total": len(licenses)},
            )
        except (requests.RequestException, ValueError) as exc:
            logger.exception("DTrack fetch_licenses error")
            return ConnectorOutcome(
                status="error", details={"error": str(exc)},
            )

    # ── Policy violations ───────────────────────────────────────

    def fetch_policy_violations(
        self, project_uuid: str, page_size: int = 100, page: int = 1
    ) -> ConnectorOutcome:
        """Fetch policy violations (license, security, operational) for a project."""
        try:
            resp = self._request(
                "GET",
                f"{self.base_url}/api/v1/violation/project/{project_uuid}",
                params={"pageSize": page_size, "pageNumber": page},
            )
            resp.raise_for_status()
            violations = resp.json()
            return ConnectorOutcome(
                status="fetched",
                details={"data": violations, "total": len(violations)},
            )
        except (requests.RequestException, ValueError) as exc:
            logger.exception("DTrack fetch_policy_violations error")
            return ConnectorOutcome(
                status="error", details={"error": str(exc)},
            )

    # ── Portfolio metrics ───────────────────────────────────────

    def fetch_portfolio_metrics(self) -> ConnectorOutcome:
        """Fetch portfolio-wide vulnerability metrics."""
        try:
            resp = self._request(
                "GET",
                f"{self.base_url}/api/v1/metrics/portfolio/current",
            )
            resp.raise_for_status()
            return ConnectorOutcome(
                status="fetched", details={"data": resp.json()},
            )
        except (requests.RequestException, ValueError) as exc:
            logger.exception("DTrack fetch_portfolio_metrics error")
            return ConnectorOutcome(
                status="error", details={"error": str(exc)},
            )

    def fetch_project_metrics(self, project_uuid: str) -> ConnectorOutcome:
        """Fetch vulnerability metrics for a specific project."""
        try:
            resp = self._request(
                "GET",
                f"{self.base_url}/api/v1/metrics/project/{project_uuid}/current",
            )
            resp.raise_for_status()
            return ConnectorOutcome(
                status="fetched", details={"data": resp.json()},
            )
        except (requests.RequestException, ValueError) as exc:
            logger.exception("DTrack fetch_project_metrics error")
            return ConnectorOutcome(
                status="error", details={"error": str(exc)},
            )

    # ── Component search (portfolio-wide) ──────────────────────

    def search_components(
        self, query: str, page_size: int = 100, page: int = 1
    ) -> ConnectorOutcome:
        """Search components across entire portfolio (e.g. 'which apps use log4j?')."""
        try:
            resp = self._request(
                "GET",
                f"{self.base_url}/api/v1/component",
                params={"searchText": query, "pageSize": page_size, "pageNumber": page},
            )
            resp.raise_for_status()
            components = resp.json()
            total = int(resp.headers.get("X-Total-Count", len(components)))
            return ConnectorOutcome(
                status="fetched",
                details={"data": components, "total": total, "query": query},
            )
        except (requests.RequestException, ValueError) as exc:
            logger.exception("DTrack search_components error")
            return ConnectorOutcome(status="error", details={"error": str(exc)})

    def fetch_project_components(
        self, project_uuid: str, page_size: int = 100, page: int = 1
    ) -> ConnectorOutcome:
        """Fetch all components (dependencies) for a specific project."""
        try:
            resp = self._request(
                "GET",
                f"{self.base_url}/api/v1/component/project/{project_uuid}",
                params={"pageSize": page_size, "pageNumber": page},
            )
            resp.raise_for_status()
            components = resp.json()
            total = int(resp.headers.get("X-Total-Count", len(components)))

            normalized = []
            for comp in components:
                license_info = comp.get("resolvedLicense") or {}
                normalized.append({
                    "uuid": comp.get("uuid", ""),
                    "name": comp.get("name", ""),
                    "version": comp.get("version", ""),
                    "group": comp.get("group", ""),
                    "purl": comp.get("purl", ""),
                    "type": comp.get("classifier", "LIBRARY"),
                    "license": license_info.get("licenseId", ""),
                    "license_name": license_info.get("name", "Unknown"),
                    "is_internal": comp.get("isInternal", False),
                    "md5": comp.get("md5", ""),
                    "sha1": comp.get("sha1", ""),
                    "sha256": comp.get("sha256", ""),
                })

            return ConnectorOutcome(
                status="fetched",
                details={"data": normalized, "total": total},
            )
        except (requests.RequestException, ValueError) as exc:
            logger.exception("DTrack fetch_project_components error")
            return ConnectorOutcome(status="error", details={"error": str(exc)})

    # ── VEX (Vulnerability Exploitability eXchange) ────────────

    def upload_vex(
        self, project_name: str, vex_content: str | bytes, project_version: str = "latest"
    ) -> ConnectorOutcome:
        """Upload a CycloneDX VEX document to apply analysis decisions."""
        import base64

        if isinstance(vex_content, str):
            vex_bytes = vex_content.encode("utf-8")
        else:
            vex_bytes = vex_content

        encoded = base64.b64encode(vex_bytes).decode("ascii")
        payload = {
            "projectName": project_name,
            "projectVersion": project_version,
            "vex": encoded,
        }
        try:
            resp = self._request(
                "PUT",
                f"{self.base_url}/api/v1/vex",
                json=payload,
            )
            if resp.status_code in (200, 201):
                return ConnectorOutcome(
                    status="success",
                    details={"project_name": project_name, "applied": True},
                )
            return ConnectorOutcome(
                status="error",
                details={"http_status": resp.status_code, "error": resp.text[:500]},
            )
        except (requests.RequestException, ValueError) as exc:
            logger.exception("DTrack VEX upload error")
            return ConnectorOutcome(status="error", details={"error": str(exc)})

    # ── Project tags (for FixOps metadata) ─────────────────────

    def tag_project(self, project_uuid: str, tags: List[str]) -> ConnectorOutcome:
        """Add tags to a project for FixOps-level categorization."""
        try:
            tag_objects = [{"name": t} for t in tags]
            resp = self._request(
                "POST",
                f"{self.base_url}/api/v1/tag/{project_uuid}",
                json=tag_objects,
            )
            if resp.status_code in (200, 201, 204):
                return ConnectorOutcome(
                    status="success", details={"tags": tags},
                )
            return ConnectorOutcome(
                status="error",
                details={"http_status": resp.status_code, "error": resp.text[:500]},
            )
        except (requests.RequestException, ValueError) as exc:
            return ConnectorOutcome(status="error", details={"error": str(exc)})

    # ── Export BOM ─────────────────────────────────────────────

    def export_sbom(
        self, project_uuid: str, fmt: str = "json"
    ) -> ConnectorOutcome:
        """Export the current BOM for a project in CycloneDX format."""
        accept = "application/vnd.cyclonedx+json" if fmt == "json" else "application/vnd.cyclonedx+xml"
        try:
            resp = self._request(
                "GET",
                f"{self.base_url}/api/v1/bom/cyclonedx/project/{project_uuid}",
                headers={"Accept": accept},
            )
            resp.raise_for_status()
            return ConnectorOutcome(
                status="fetched",
                details={"data": resp.text, "format": f"cyclonedx-{fmt}"},
            )
        except (requests.RequestException, ValueError) as exc:
            logger.exception("DTrack export_sbom error")
            return ConnectorOutcome(status="error", details={"error": str(exc)})


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
    "ThreatMapperConnector",
    "DependencyTrackConnector",
]
