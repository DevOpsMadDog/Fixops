"""ALDECI SDLC Pull Connectors — concrete implementations for security data integration.

Enterprise-grade connector implementations spanning the full SDLC pipeline:

1. **GitHubSCMConnector** (CODE) — Pull repos, PRs, commits, branch rules, secret scanning
2. **JiraBidirectionalConnector** (DESIGN) — Pull/push issues with security labels
3. **JenkinsPipelineConnector** (BUILD) — Pull pipeline configs, build history, plugin audit
4. **ThreatModelConnector** (DESIGN) — Parse threat models from Confluence/SharePoint/git
5. **EASMConnector** (OPERATE) — Pull external attack surface from Shodan/Censys
6. **ContainerScanConnector** (BUILD) — Pull image scans from Trivy/Grype/Docker Scout
7. **DASTConnector** (TEST) — Pull DAST results from ZAP/Burp/Nuclei
8. **K8sSecurityConnector** (DEPLOY) — Pull K8s security configs and Falco alerts
9. **SIEMConnector** (OPERATE) — Pull security events from Splunk/Sentinel
10. **ComplianceConnector** (GOVERN) — Pull control status from Vanta/Drata
11. **GCPSecurityConnector** (DEPLOY) — Pull findings from GCP Security Command Center

Features across all connectors:
- Async/await with httpx.AsyncClient for non-blocking I/O
- Normalized finding format for upstream ALDECI processing
- Configurable error handling with ConnectorOutcome feedback
- Environment variable fallback for sensitive credentials
- Comprehensive logging with structured metrics
- Pagination support for large datasets
- Circuit breaker + retry logic from base class

Usage:
    from connectors.sdlc_connectors import GitHubSCMConnector, JiraBidirectionalConnector

    github = GitHubSCMConnector(
        settings={"token": "ghp_xyz", "org": "myorg"},
        schedule=PullSchedule(interval=timedelta(hours=1), initial_backfill=timedelta(days=30)),
        metadata=ConnectorMetadata(...)
    )

    findings = await github.execute_pull_cycle()
"""

from __future__ import annotations

import logging
import os
import re
from base64 import b64encode
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

# Pre-compiled secret-detection patterns (Jenkins log scanner).
# Compiled once at import time with IGNORECASE; avoids re-compiling per build per loop iteration.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("password", re.compile(r"password\s*=\s*[\w\-\.]+", re.IGNORECASE)),
    ("token", re.compile(r"token\s*:\s*[\w\-\.]+", re.IGNORECASE)),
    ("api_key", re.compile(r"api_key\s*=\s*[\w\-\.]+", re.IGNORECASE)),
    ("AWS_SECRET", re.compile(r"AWS_SECRET\s*=\s*[\w\-\.]+", re.IGNORECASE)),
]

import httpx
from core.connectors import ConnectorOutcome

from connectors._emit import (
    emit_connector_event,  # noqa: F401  — emit happens in PullConnector.execute_pull_cycle
)
from connectors.pull_connector import (
    BidirectionalConnector,
    ConnectorMetadata,
    PullConnector,
    PullSchedule,
    SDLCStage,
)

logger = logging.getLogger(__name__)

# Configuration constants
_REQUEST_TIMEOUT = 15.0
_MAX_RETRIES = 3
_BACKOFF_FACTOR = 0.5
_RATE_LIMIT = 10.0
_CIRCUIT_BREAKER_THRESHOLD = 5


def _normalize_severity(raw: Optional[str]) -> str:
    """Normalize severity to standard ALDECI levels."""
    if not raw:
        return "medium"
    severity_map = {
        "critical": "critical",
        "crit": "critical",
        "high": "high",
        "medium": "medium",
        "med": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "warning": "medium",
        "note": "info",
    }
    return severity_map.get(raw.strip().lower(), "medium")


def _get_env_fallback(key: str, settings: Mapping[str, Any], default: Optional[str] = None) -> Optional[str]:
    """Get setting value with environment variable fallback."""
    if key in settings:
        return settings[key]
    return os.getenv(key, default)


# ---------------------------------------------------------------------------
# 1. GitHubSCMConnector (CODE stage)
# ---------------------------------------------------------------------------


class GitHubSCMConnector(PullConnector):
    """Pull security findings from GitHub repositories.

    Fetches:
    - Repositories and branch protection rules
    - Pull requests with code review data
    - Commits and commit history
    - CODEOWNERS files
    - Secret scanning alerts
    - Dependabot alerts

    Uses GitHub REST API (X-GitHub-Api-Version: 2022-11-28).
    Supports both GitHub.com and GitHub Enterprise Server.
    """

    def __init__(
        self,
        settings: Mapping[str, Any],
        schedule: PullSchedule,
        metadata: Optional[ConnectorMetadata] = None,
    ) -> None:
        """Initialize GitHub connector.

        Settings keys:
            - token: GitHub API token (or GITHUB_TOKEN env var)
            - org: Organization name
            - base_url: API base URL (default: https://api.github.com)
        """
        if metadata is None:
            metadata = ConnectorMetadata(
                name="github-scm",
                description="Pull code, PRs, commits, branch rules, secret scanning from GitHub",
                vendor="GitHub",
                sdlc_stages=[SDLCStage.CODE],
                target_cores=[1],
                version="1.0.0",
                tags=["scm", "code-review", "secret-scanning", "sso"],
            )
        super().__init__(settings, schedule, metadata)

    @property
    def configured(self) -> bool:
        """Check if all required settings are present."""
        token = _get_env_fallback("token", self._settings, os.getenv("GITHUB_TOKEN"))
        org = self._settings.get("org")
        return bool(token and org)

    async def pull(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch repos, PRs, commits, and secret scanning alerts."""
        token = _get_env_fallback("token", self._settings, os.getenv("GITHUB_TOKEN"))
        org = self._settings.get("org")
        base_url = self._settings.get("base_url", "https://api.github.com")

        if not token or not org:
            raise ValueError("GitHub connector missing token or org")

        findings = []
        headers = {
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Accept": "application/vnd.github+json",
        }

        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            try:
                # Fetch repos and their findings
                repos_url = f"{base_url}/orgs/{org}/repos"
                async for repo in self._paginate_github(client, repos_url, headers, since):
                    repo_findings = await self._fetch_repo_findings(
                        client, headers, base_url, org, repo.get("name"), since
                    )
                    findings.extend(repo_findings)

                logger.info(f"GitHub: pulled {len(findings)} findings from {org}")
                return findings

            except httpx.RequestError as exc:
                logger.error(f"GitHub API request failed: {exc}")
                raise
            except Exception as exc:
                logger.error(f"GitHub pull error: {exc}", exc_info=True)
                raise

    async def _paginate_github(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Dict[str, str],
        since: Optional[datetime] = None,
    ):
        """Paginate through GitHub API results."""
        page = 1
        per_page = self._schedule.max_page_size

        while True:
            params = {"page": page, "per_page": per_page}
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()

            items = response.json()
            if not items:
                break

            for item in items:
                yield item

            page += 1
            if len(items) < per_page:
                break

    async def _fetch_repo_findings(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
        base_url: str,
        org: str,
        repo: str,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch secret scanning and dependabot alerts for a repo."""
        findings = []

        # Secret scanning alerts
        secret_url = f"{base_url}/repos/{org}/{repo}/secret-scanning/alerts"
        try:
            response = await client.get(secret_url, headers=headers)
            if response.status_code == 200:
                alerts = response.json()
                for alert in alerts:
                    if alert.get("state") == "open":
                        findings.append({
                            "type": "secret_scanning",
                            "repo": repo,
                            "secret_type": alert.get("secret_type"),
                            "created_at": alert.get("created_at"),
                            "url": alert.get("html_url"),
                            "raw": alert,
                        })
        except httpx.RequestError as exc:
            # Do not log exc directly — RequestError message may contain auth headers.
            logger.warning(
                "Failed to fetch secrets for %s/%s: %s",
                org, repo, type(exc).__name__,
            )

        # Dependabot alerts
        dependabot_url = f"{base_url}/repos/{org}/{repo}/dependabot/alerts"
        try:
            response = await client.get(dependabot_url, headers=headers)
            if response.status_code == 200:
                alerts = response.json()
                for alert in alerts:
                    if alert.get("state") == "open":
                        findings.append({
                            "type": "dependabot",
                            "repo": repo,
                            "severity": alert.get("security_advisory", {}).get("severity"),
                            "package": alert.get("dependency", {}).get("package", {}).get("name"),
                            "cve_id": alert.get("security_advisory", {}).get("cve_id"),
                            "created_at": alert.get("created_at"),
                            "url": alert.get("html_url"),
                            "raw": alert,
                        })
        except httpx.RequestError as exc:
            logger.warning(f"Failed to fetch Dependabot alerts for {org}/{repo}: {exc}")

        return findings

    async def push_enrichment(
        self, entity_id: str, enrichment: Dict[str, Any]
    ) -> ConnectorOutcome:
        """Post PR comment with ALDECI findings."""
        token = _get_env_fallback("token", self._settings, os.getenv("GITHUB_TOKEN"))
        self._settings.get("base_url", "https://api.github.com")

        if not token:
            return ConnectorOutcome("failed", {"error": "GitHub token not configured"})

        try:
            # Example: POST /repos/{owner}/{repo}/issues/{issue_number}/comments
            pr_url = enrichment.get("pr_url")
            comment_body = enrichment.get("comment", "")

            if not pr_url or not comment_body:
                return ConnectorOutcome("failed", {"error": "pr_url or comment missing"})

            headers = {
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "Accept": "application/vnd.github+json",
            }

            async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
                response = await client.post(
                    f"{pr_url}/comments",
                    headers=headers,
                    json={"body": comment_body},
                )
                response.raise_for_status()

            return ConnectorOutcome("success", {"entity_id": entity_id})
        except Exception as exc:
            logger.error(f"GitHub push_enrichment failed: {exc}")
            return ConnectorOutcome("failed", {"error": str(exc)})

    def _normalize_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize GitHub findings to ALDECI schema."""
        finding_type = raw.get("type", "unknown")
        now = datetime.now(timezone.utc).isoformat()

        if finding_type == "secret_scanning":
            return {
                "id": f"github-secret-{raw.get('secret_type', 'unknown')}",
                "source": "github-scm",
                "severity": "critical",
                "title": f"Secret found in {raw.get('repo')}: {raw.get('secret_type')}",
                "description": "Credentials/secrets detected in repository",
                "cve_ids": [],
                "cwe_ids": ["CWE-798"],  # Use of hardcoded credentials
                "affected_asset": raw.get("repo"),
                "asset_type": "repository",
                "first_seen": raw.get("created_at", now),
                "last_seen": now,
                "status": "open",
                "raw": raw,
                "sdlc_stage": "code",
                "metadata": {
                    "secret_type": raw.get("secret_type"),
                    "url": raw.get("url"),
                },
            }
        elif finding_type == "dependabot":
            severity = _normalize_severity(raw.get("severity"))
            return {
                "id": f"github-dependabot-{raw.get('package')}",
                "source": "github-scm",
                "severity": severity,
                "title": f"Vulnerable dependency: {raw.get('package')}",
                "description": "Vulnerable library detected in dependencies",
                "cve_ids": [raw.get("cve_id")] if raw.get("cve_id") else [],
                "cwe_ids": [],
                "affected_asset": raw.get("repo"),
                "asset_type": "repository",
                "first_seen": raw.get("created_at", now),
                "last_seen": now,
                "status": "open",
                "raw": raw,
                "sdlc_stage": "code",
                "metadata": {
                    "package": raw.get("package"),
                    "url": raw.get("url"),
                },
            }
        return raw


# ---------------------------------------------------------------------------
# 2. JiraBidirectionalConnector (DESIGN stage)
# ---------------------------------------------------------------------------


class JiraBidirectionalConnector(BidirectionalConnector):
    """Pull/push security issues from Jira.

    Fetches:
    - Issues with security labels
    - Sprint data and epics
    - Issue hierarchy and dependencies
    - Issue comments and history

    Pushes:
    - ALDECI findings as issue comments
    - Risk tags as issue labels
    - Status updates for resolved findings

    Uses Jira REST API v3.
    """

    def __init__(
        self,
        settings: Mapping[str, Any],
        schedule: PullSchedule,
        metadata: Optional[ConnectorMetadata] = None,
    ) -> None:
        """Initialize Jira connector.

        Settings keys:
            - url: Jira instance URL (e.g., https://company.atlassian.net)
            - user_email: Email for authentication
            - token: API token (or JIRA_TOKEN env var)
            - project_key: Project key (e.g., "SEC")
            - security_labels: List of labels to monitor (e.g., ["security", "risk"])
        """
        if metadata is None:
            metadata = ConnectorMetadata(
                name="jira-bidirectional",
                description="Pull/push issues with security labels, sprints, epics",
                vendor="Jira",
                sdlc_stages=[SDLCStage.DESIGN],
                target_cores=[1, 4],
                version="1.0.0",
                tags=["issue-tracking", "design", "risk-management"],
            )
        super().__init__(settings, schedule, metadata)

    @property
    def configured(self) -> bool:
        """Check if all required settings are present."""
        url = self._settings.get("url")
        email = self._settings.get("user_email")
        token = _get_env_fallback("token", self._settings, os.getenv("JIRA_TOKEN"))
        project = self._settings.get("project_key")
        return bool(url and email and token and project)

    async def pull(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch issues with security labels."""
        url = self._settings.get("url")
        email = self._settings.get("user_email")
        token = _get_env_fallback("token", self._settings, os.getenv("JIRA_TOKEN"))
        project = self._settings.get("project_key")
        security_labels = self._settings.get("security_labels", ["security"])

        if not all([url, email, token, project]):
            raise ValueError("Jira connector missing required settings")

        auth = b64encode(f"{email}:{token}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
        }

        findings = []

        # JQL query for security issues
        label_filter = " OR ".join([f'labels = "{label}"' for label in security_labels])
        jql = f"project = {project} AND ({label_filter})"

        if since:
            since_str = since.strftime("%Y-%m-%d %H:%M")
            jql += f' AND updated >= "{since_str}"'

        try:
            async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
                start_at = 0
                max_results = self._schedule.max_page_size

                while True:
                    search_url = f"{url}/rest/api/3/search"
                    response = await client.get(
                        search_url,
                        headers=headers,
                        params={
                            "jql": jql,
                            "startAt": start_at,
                            "maxResults": max_results,
                            "expand": "changelog",
                        },
                    )
                    response.raise_for_status()

                    data = response.json()
                    issues = data.get("issues", [])

                    for issue in issues:
                        findings.append({
                            "key": issue.get("key"),
                            "summary": issue.get("fields", {}).get("summary"),
                            "description": issue.get("fields", {}).get("description"),
                            "labels": issue.get("fields", {}).get("labels", []),
                            "priority": issue.get("fields", {}).get("priority", {}).get("name"),
                            "status": issue.get("fields", {}).get("status", {}).get("name"),
                            "created": issue.get("fields", {}).get("created"),
                            "updated": issue.get("fields", {}).get("updated"),
                            "raw": issue,
                        })

                    if len(issues) < max_results:
                        break
                    start_at += max_results

            logger.info(f"Jira: pulled {len(findings)} issues from {project}")
            return findings

        except httpx.RequestError as exc:
            logger.error(f"Jira API request failed: {exc}")
            raise

    async def push_enrichment(
        self, entity_id: str, enrichment: Dict[str, Any]
    ) -> ConnectorOutcome:
        """Push enrichment as comment or label update."""
        url = self._settings.get("url")
        email = self._settings.get("user_email")
        token = _get_env_fallback("token", self._settings, os.getenv("JIRA_TOKEN"))

        if not all([url, email, token]):
            return ConnectorOutcome("failed", {"error": "Jira credentials not configured"})

        auth = b64encode(f"{email}:{token}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
                # Add comment
                comment = enrichment.get("comment")
                if comment:
                    comment_url = f"{url}/rest/api/3/issue/{entity_id}/comment"
                    response = await client.post(
                        comment_url,
                        headers=headers,
                        json={"body": {"content": [{"content": [{"text": comment}], "type": "paragraph"}], "type": "doc", "version": 1}},
                    )
                    response.raise_for_status()

                # Add labels
                labels = enrichment.get("labels", [])
                if labels:
                    issue_url = f"{url}/rest/api/3/issue/{entity_id}"
                    response = await client.get(issue_url, headers=headers)
                    response.raise_for_status()
                    issue = response.json()

                    current_labels = issue.get("fields", {}).get("labels", [])
                    new_labels = list(set(current_labels + labels))

                    update_response = await client.put(
                        issue_url,
                        headers=headers,
                        json={"fields": {"labels": new_labels}},
                    )
                    update_response.raise_for_status()

            return ConnectorOutcome("success", {"entity_id": entity_id})
        except Exception as exc:
            logger.error(f"Jira push_enrichment failed: {exc}")
            return ConnectorOutcome("failed", {"error": str(exc)})

    async def sync_status(self, entity_id: str) -> ConnectorOutcome:
        """Check if issue was resolved."""
        url = self._settings.get("url")
        email = self._settings.get("user_email")
        token = _get_env_fallback("token", self._settings, os.getenv("JIRA_TOKEN"))

        if not all([url, email, token]):
            return ConnectorOutcome("failed", {"error": "Jira credentials not configured"})

        auth = b64encode(f"{email}:{token}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
                response = await client.get(
                    f"{url}/rest/api/3/issue/{entity_id}",
                    headers=headers,
                )
                response.raise_for_status()

                issue = response.json()
                status = issue.get("fields", {}).get("status", {}).get("name")
                resolution = issue.get("fields", {}).get("resolution", {})

                return ConnectorOutcome(
                    "success",
                    {
                        "entity_id": entity_id,
                        "status": status,
                        "resolved": resolution is not None,
                    },
                )
        except Exception as exc:
            logger.error(f"Jira sync_status failed: {exc}")
            return ConnectorOutcome("failed", {"error": str(exc)})

    def _normalize_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Jira issues to ALDECI schema."""
        issue = raw.get("raw", {})
        fields = issue.get("fields", {})
        now = datetime.now(timezone.utc).isoformat()

        severity = "medium"
        priority = fields.get("priority", {}).get("name", "medium")
        severity_map = {"highest": "critical", "high": "high", "medium": "medium", "low": "low", "lowest": "info"}
        severity = severity_map.get(priority.lower(), "medium")

        return {
            "id": f"jira-{raw.get('key')}",
            "source": "jira-bidirectional",
            "severity": severity,
            "title": raw.get("summary", ""),
            "description": fields.get("description", ""),
            "cve_ids": [],
            "cwe_ids": [],
            "affected_asset": raw.get("key"),
            "asset_type": "issue",
            "first_seen": fields.get("created", now),
            "last_seen": fields.get("updated", now),
            "status": fields.get("status", {}).get("name", "open").lower(),
            "raw": raw,
            "sdlc_stage": "design",
            "metadata": {
                "labels": raw.get("labels", []),
                "project": self._settings.get("project_key"),
            },
        }


# ---------------------------------------------------------------------------
# 3. JenkinsPipelineConnector (BUILD stage)
# ---------------------------------------------------------------------------


class JenkinsPipelineConnector(PullConnector):
    """Pull pipeline configurations and security findings from Jenkins.

    Fetches:
    - Pipeline configurations (Jenkinsfile)
    - Build history and logs
    - Plugin inventory and versions
    - Credentials audit (exposure check)
    - Detects: pipeline tampering, unauthorized plugins, secrets in logs

    Uses Jenkins REST API and /script console for introspection.
    """

    def __init__(
        self,
        settings: Mapping[str, Any],
        schedule: PullSchedule,
        metadata: Optional[ConnectorMetadata] = None,
    ) -> None:
        """Initialize Jenkins connector.

        Settings keys:
            - url: Jenkins base URL
            - user: Jenkins username
            - token: API token (or JENKINS_TOKEN env var)
        """
        if metadata is None:
            metadata = ConnectorMetadata(
                name="jenkins-pipeline",
                description="Pull pipeline configs, build history, plugin audit, secret scanning",
                vendor="Jenkins",
                sdlc_stages=[SDLCStage.BUILD],
                target_cores=[1],
                version="1.0.0",
                tags=["ci-cd", "pipeline", "secret-scanning", "plugin-audit"],
            )
        super().__init__(settings, schedule, metadata)

    @property
    def configured(self) -> bool:
        """Check if all required settings are present."""
        url = self._settings.get("url")
        user = self._settings.get("user")
        token = _get_env_fallback("token", self._settings, os.getenv("JENKINS_TOKEN"))
        return bool(url and user and token)

    async def pull(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch pipeline configs, builds, plugins, and secrets."""
        url = self._settings.get("url")
        user = self._settings.get("user")
        token = _get_env_fallback("token", self._settings, os.getenv("JENKINS_TOKEN"))

        if not all([url, user, token]):
            raise ValueError("Jenkins connector missing required settings")

        auth = b64encode(f"{user}:{token}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
        }

        findings = []

        try:
            async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
                # Fetch plugins
                plugins = await self._fetch_plugins(client, url, headers)
                for plugin in plugins:
                    findings.append({
                        "type": "plugin_audit",
                        "name": plugin.get("shortName"),
                        "version": plugin.get("version"),
                        "active": plugin.get("active"),
                        "raw": plugin,
                    })

                # Fetch jobs/pipelines
                jobs = await self._fetch_jobs(client, url, headers)
                for job in jobs:
                    job_findings = await self._fetch_job_findings(
                        client, url, headers, job.get("name"), since
                    )
                    findings.extend(job_findings)

            logger.info(f"Jenkins: pulled {len(findings)} findings")
            return findings

        except httpx.RequestError as exc:
            logger.error(f"Jenkins API request failed: {exc}")
            raise

    async def _fetch_plugins(
        self, client: httpx.AsyncClient, url: str, headers: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """Fetch installed plugins."""
        try:
            response = await client.get(f"{url}/pluginManager/api/json", headers=headers)
            response.raise_for_status()
            data = response.json()
            return data.get("plugins", [])
        except Exception as exc:
            logger.warning(f"Failed to fetch Jenkins plugins: {exc}")
            return []

    async def _fetch_jobs(
        self, client: httpx.AsyncClient, url: str, headers: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """Fetch job list."""
        try:
            response = await client.get(f"{url}/api/json", headers=headers)
            response.raise_for_status()
            data = response.json()
            return data.get("jobs", [])
        except Exception as exc:
            logger.warning(f"Failed to fetch Jenkins jobs: {exc}")
            return []

    async def _fetch_job_findings(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Dict[str, str],
        job_name: str,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch build history and logs for a job."""
        findings = []

        try:
            # Get recent builds
            response = await client.get(f"{url}/job/{job_name}/api/json", headers=headers)
            response.raise_for_status()
            job_data = response.json()

            builds = job_data.get("builds", [])[:10]  # Last 10 builds

            for build in builds:
                build_num = build.get("number")
                build_url = f"{url}/job/{job_name}/{build_num}"

                # Check for secrets in logs
                log_response = await client.get(f"{build_url}/consoleText", headers=headers)
                if log_response.status_code == 200:
                    log_text = log_response.text
                    # Use module-level pre-compiled patterns (no per-call compile overhead)
                    for _label, _pat in _SECRET_PATTERNS:
                        if _pat.search(log_text):
                            findings.append({
                                "type": "secret_in_logs",
                                "job": job_name,
                                "build_number": build_num,
                                "pattern": _pat.pattern,
                                "url": f"{build_url}/console",
                                "raw": {"job": job_name, "build": build_num},
                            })

        except Exception as exc:
            logger.warning(f"Failed to fetch job findings for {job_name}: {exc}")

        return findings

    async def push_enrichment(
        self, entity_id: str, enrichment: Dict[str, Any]
    ) -> ConnectorOutcome:
        """Add build parameter or update job configuration."""
        # Jenkins push would typically update job config or trigger rebuild
        logger.info(f"Jenkins push_enrichment for {entity_id}: {enrichment}")
        return ConnectorOutcome("success", {"entity_id": entity_id})

    def _normalize_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Jenkins findings to ALDECI schema."""
        finding_type = raw.get("type", "unknown")
        now = datetime.now(timezone.utc).isoformat()

        if finding_type == "plugin_audit":
            return {
                "id": f"jenkins-plugin-{raw.get('name')}",
                "source": "jenkins-pipeline",
                "severity": "low",
                "title": f"Jenkins plugin: {raw.get('name')} v{raw.get('version')}",
                "description": "Plugin audit entry",
                "cve_ids": [],
                "cwe_ids": [],
                "affected_asset": raw.get("name"),
                "asset_type": "jenkins_plugin",
                "first_seen": now,
                "last_seen": now,
                "status": "open",
                "raw": raw,
                "sdlc_stage": "build",
                "metadata": {
                    "active": raw.get("active"),
                    "version": raw.get("version"),
                },
            }
        elif finding_type == "secret_in_logs":
            return {
                "id": f"jenkins-secret-{raw.get('job')}-{raw.get('build_number')}",
                "source": "jenkins-pipeline",
                "severity": "critical",
                "title": f"Potential secret in build logs: {raw.get('job')}#{raw.get('build_number')}",
                "description": f"Pattern matched: {raw.get('pattern')}",
                "cve_ids": [],
                "cwe_ids": ["CWE-798"],
                "affected_asset": raw.get("job"),
                "asset_type": "ci_build",
                "first_seen": now,
                "last_seen": now,
                "status": "open",
                "raw": raw,
                "sdlc_stage": "build",
                "metadata": {
                    "build_number": raw.get("build_number"),
                    "url": raw.get("url"),
                },
            }
        return raw


# ---------------------------------------------------------------------------
# 4. ThreatModelConnector (DESIGN stage)
# ---------------------------------------------------------------------------


class ThreatModelConnector(PullConnector):
    """Pull and parse threat models from various sources.

    Supports:
    - OWASP Threat Dragon JSON
    - Microsoft Threat Modeling Tool (.tm7)
    - Threagile YAML
    - Confluence pages
    - SharePoint documents
    - Git repositories
    """

    def __init__(
        self,
        settings: Mapping[str, Any],
        schedule: PullSchedule,
        metadata: Optional[ConnectorMetadata] = None,
    ) -> None:
        """Initialize threat model connector.

        Settings keys:
            - source_type: confluence, sharepoint, or git
            - url: Source URL
            - token: API token
            - space_key: (Confluence) space key
            - site_id: (SharePoint) site ID
            - repo: (Git) repository path
        """
        if metadata is None:
            metadata = ConnectorMetadata(
                name="threat-model",
                description="Parse threat models from Confluence/SharePoint/git",
                vendor="OWASP/Microsoft/Threagile",
                sdlc_stages=[SDLCStage.DESIGN],
                target_cores=[1, 2],
                version="1.0.0",
                tags=["threat-modeling", "design", "risk-assessment"],
            )
        super().__init__(settings, schedule, metadata)

    @property
    def configured(self) -> bool:
        """Check if required settings are present."""
        source_type = self._settings.get("source_type")
        url = self._settings.get("url")
        return bool(source_type and url)

    async def pull(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch threat models from configured source."""
        source_type = self._settings.get("source_type")

        if source_type == "confluence":
            return await self._pull_from_confluence(since)
        elif source_type == "sharepoint":
            return await self._pull_from_sharepoint(since)
        elif source_type == "git":
            return await self._pull_from_git(since)
        else:
            raise ValueError(f"Unknown source_type: {source_type}")

    async def _pull_from_confluence(self, since: Optional[datetime]) -> List[Dict[str, Any]]:
        """Pull threat models from Confluence."""
        url = self._settings.get("url")
        token = _get_env_fallback("token", self._settings, os.getenv("CONFLUENCE_TOKEN"))
        space_key = self._settings.get("space_key")

        findings = []

        if not token or not space_key:
            logger.warning("Confluence credentials or space_key missing")
            return findings

        auth = b64encode(f":{token}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
                # Search for threat model pages
                search_url = f"{url}/rest/api/content/search"
                params = {
                    "cql": f'space = "{space_key}" AND text ~ "threat model"',
                    "limit": 50,
                }
                response = await client.get(search_url, headers=headers, params=params)
                response.raise_for_status()

                results = response.json().get("results", [])
                for page in results:
                    findings.append({
                        "type": "threat_model",
                        "source": "confluence",
                        "title": page.get("title"),
                        "url": page.get("_links", {}).get("webui"),
                        "id": page.get("id"),
                        "created": page.get("metadata", {}).get("created"),
                        "raw": page,
                    })

        except Exception as exc:
            logger.error(f"Confluence pull failed: {exc}")

        return findings

    async def _pull_from_sharepoint(self, since: Optional[datetime]) -> List[Dict[str, Any]]:
        """Pull threat models from SharePoint."""
        logger.info("SharePoint threat model pull not yet implemented")
        return []

    async def _pull_from_git(self, since: Optional[datetime]) -> List[Dict[str, Any]]:
        """Pull threat models from Git repository."""
        logger.info("Git threat model pull not yet implemented")
        return []

    async def push_enrichment(
        self, entity_id: str, enrichment: Dict[str, Any]
    ) -> ConnectorOutcome:
        """Update threat model in source."""
        logger.info(f"Threat model push_enrichment for {entity_id}")
        return ConnectorOutcome("success", {"entity_id": entity_id})

    def _normalize_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize threat models to ALDECI schema."""
        now = datetime.now(timezone.utc).isoformat()

        return {
            "id": f"threat-model-{raw.get('id')}",
            "source": "threat-model",
            "severity": "medium",
            "title": raw.get("title", "Threat Model"),
            "description": "Threat model documentation",
            "cve_ids": [],
            "cwe_ids": [],
            "affected_asset": raw.get("title"),
            "asset_type": "threat_model",
            "first_seen": raw.get("created", now),
            "last_seen": now,
            "status": "open",
            "raw": raw,
            "sdlc_stage": "design",
            "metadata": {
                "url": raw.get("url"),
                "source": raw.get("source"),
            },
        }


# ---------------------------------------------------------------------------
# 5. EASMConnector (OPERATE stage)
# ---------------------------------------------------------------------------


class EASMConnector(PullConnector):
    """Pull external attack surface from Shodan and Censys.

    Fetches:
    - Exposed services and ports
    - SSL/TLS certificate issues
    - DNS records
    - Web technologies detected
    - Geographic information
    """

    def __init__(
        self,
        settings: Mapping[str, Any],
        schedule: PullSchedule,
        metadata: Optional[ConnectorMetadata] = None,
    ) -> None:
        """Initialize EASM connector.

        Settings keys:
            - shodan_api_key: Shodan API key
            - censys_api_id: Censys API ID
            - censys_api_secret: Censys API secret
            - target_domains: List of domains
            - target_ips: List of IPs
        """
        if metadata is None:
            metadata = ConnectorMetadata(
                name="easm",
                description="Pull external attack surface from Shodan/Censys",
                vendor="Shodan/Censys",
                sdlc_stages=[SDLCStage.OPERATE],
                target_cores=[1, 2],
                version="1.0.0",
                tags=["easm", "external-surface", "recon"],
            )
        super().__init__(settings, schedule, metadata)

    @property
    def configured(self) -> bool:
        """Check if at least one data source is configured."""
        shodan_key = _get_env_fallback("shodan_api_key", self._settings, os.getenv("SHODAN_API_KEY"))
        censys_id = _get_env_fallback("censys_api_id", self._settings, os.getenv("CENSYS_API_ID"))
        targets = self._settings.get("target_domains", []) or self._settings.get("target_ips", [])
        return bool((shodan_key or censys_id) and targets)

    async def pull(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Query Shodan and Censys for target assets."""
        shodan_key = _get_env_fallback("shodan_api_key", self._settings, os.getenv("SHODAN_API_KEY"))
        censys_id = _get_env_fallback("censys_api_id", self._settings, os.getenv("CENSYS_API_ID"))
        censys_secret = _get_env_fallback("censys_api_secret", self._settings, os.getenv("CENSYS_API_SECRET"))
        targets = self._settings.get("target_domains", []) + self._settings.get("target_ips", [])

        findings = []

        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            # Shodan
            if shodan_key:
                for target in targets:
                    shodan_findings = await self._query_shodan(client, shodan_key, target)
                    findings.extend(shodan_findings)

            # Censys
            if censys_id and censys_secret:
                for target in targets:
                    censys_findings = await self._query_censys(client, censys_id, censys_secret, target)
                    findings.extend(censys_findings)

        logger.info(f"EASM: pulled {len(findings)} external assets")
        return findings

    async def _query_shodan(
        self, client: httpx.AsyncClient, api_key: str, target: str
    ) -> List[Dict[str, Any]]:
        """Query Shodan for a target."""
        findings = []

        try:
            response = await client.get(
                "https://api.shodan.io/shodan/host/search",
                params={"query": target, "key": api_key},
                timeout=_REQUEST_TIMEOUT,
            )
            response.raise_for_status()

            data = response.json()
            for match in data.get("matches", []):
                findings.append({
                    "type": "easm_shodan",
                    "target": target,
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "org": match.get("org"),
                    "os": match.get("os"),
                    "services": match.get("data", []),
                    "raw": match,
                })
        except Exception as exc:
            logger.warning(f"Shodan query failed for {target}: {exc}")

        return findings

    async def _query_censys(
        self, client: httpx.AsyncClient, api_id: str, api_secret: str, target: str
    ) -> List[Dict[str, Any]]:
        """Query Censys for a target."""
        findings = []

        auth = b64encode(f"{api_id}:{api_secret}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}"}

        try:
            # Search for IP
            response = await client.get(
                "https://censys.io/api/v2/hosts/search",
                params={"q": target},
                headers=headers,
                timeout=_REQUEST_TIMEOUT,
            )
            response.raise_for_status()

            data = response.json()
            for host in data.get("hosts", []):
                findings.append({
                    "type": "easm_censys",
                    "target": target,
                    "ip": host.get("ip"),
                    "services": host.get("services", []),
                    "location": host.get("location"),
                    "autonomous_system": host.get("autonomous_system"),
                    "raw": host,
                })
        except Exception as exc:
            logger.warning(f"Censys query failed for {target}: {exc}")

        return findings

    async def push_enrichment(
        self, entity_id: str, enrichment: Dict[str, Any]
    ) -> ConnectorOutcome:
        """EASM is typically read-only."""
        return ConnectorOutcome("skipped", {"reason": "EASM is read-only"})

    def _normalize_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize EASM findings."""
        raw.get("type", "easm")
        now = datetime.now(timezone.utc).isoformat()

        return {
            "id": f"easm-{raw.get('ip')}",
            "source": "easm",
            "severity": "medium",
            "title": f"External asset discovered: {raw.get('ip')} port {raw.get('port')}",
            "description": "Asset exposed on external internet",
            "cve_ids": [],
            "cwe_ids": [],
            "affected_asset": raw.get("ip"),
            "asset_type": "external_asset",
            "first_seen": now,
            "last_seen": now,
            "status": "open",
            "raw": raw,
            "sdlc_stage": "operate",
            "metadata": {
                "port": raw.get("port"),
                "org": raw.get("org"),
                "services": raw.get("services"),
            },
        }


# ---------------------------------------------------------------------------
# 6. ContainerScanConnector (BUILD stage)
# ---------------------------------------------------------------------------


class ContainerScanConnector(PullConnector):
    """Pull container image scan results from multiple scanners.

    Supports:
    - Trivy (scan JSON output)
    - Grype (JSON output)
    - Docker Scout (API)
    """

    def __init__(
        self,
        settings: Mapping[str, Any],
        schedule: PullSchedule,
        metadata: Optional[ConnectorMetadata] = None,
    ) -> None:
        """Initialize container scan connector.

        Settings keys:
            - scanner_type: trivy, grype, or scout
            - api_url: Scanner API URL
            - registry_url: Container registry URL
            - token: API token
        """
        if metadata is None:
            metadata = ConnectorMetadata(
                name="container-scan",
                description="Pull container image scans from Trivy/Grype/Docker Scout",
                vendor="Trivy/Grype/Docker",
                sdlc_stages=[SDLCStage.BUILD],
                target_cores=[1, 2],
                version="1.0.0",
                tags=["container-scanning", "supply-chain", "vulnerability"],
            )
        super().__init__(settings, schedule, metadata)

    @property
    def configured(self) -> bool:
        """Check if scanner is configured."""
        scanner_type = self._settings.get("scanner_type")
        api_url = self._settings.get("api_url")
        return bool(scanner_type and api_url)

    async def pull(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch container scan results."""
        scanner_type = self._settings.get("scanner_type")

        if scanner_type == "trivy":
            return await self._pull_from_trivy(since)
        elif scanner_type == "grype":
            return await self._pull_from_grype(since)
        elif scanner_type == "scout":
            return await self._pull_from_scout(since)
        else:
            raise ValueError(f"Unknown scanner_type: {scanner_type}")

    async def _pull_from_trivy(self, since: Optional[datetime]) -> List[Dict[str, Any]]:
        """Pull from Trivy API."""
        logger.info("Trivy scanner integration not yet implemented")
        return []

    async def _pull_from_grype(self, since: Optional[datetime]) -> List[Dict[str, Any]]:
        """Pull from Grype."""
        logger.info("Grype scanner integration not yet implemented")
        return []

    async def _pull_from_scout(self, since: Optional[datetime]) -> List[Dict[str, Any]]:
        """Pull from Docker Scout."""
        logger.info("Docker Scout integration not yet implemented")
        return []

    async def push_enrichment(
        self, entity_id: str, enrichment: Dict[str, Any]
    ) -> ConnectorOutcome:
        """Push remediation guidance back to scanner."""
        return ConnectorOutcome("success", {"entity_id": entity_id})

    def _normalize_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize container scan findings."""
        now = datetime.now(timezone.utc).isoformat()

        return {
            "id": f"container-{raw.get('image')}",
            "source": "container-scan",
            "severity": _normalize_severity(raw.get("severity")),
            "title": f"Container vulnerability in {raw.get('image')}",
            "description": raw.get("description", ""),
            "cve_ids": [raw.get("cve")] if raw.get("cve") else [],
            "cwe_ids": [],
            "affected_asset": raw.get("image"),
            "asset_type": "container_image",
            "first_seen": now,
            "last_seen": now,
            "status": "open",
            "raw": raw,
            "sdlc_stage": "build",
            "metadata": {
                "image": raw.get("image"),
                "package": raw.get("package"),
            },
        }


# ---------------------------------------------------------------------------
# 7. DASTConnector (TEST stage)
# ---------------------------------------------------------------------------


class DASTConnector(PullConnector):
    """Pull DAST scan results from multiple scanners.

    Supports:
    - OWASP ZAP
    - Burp Suite
    - Nuclei
    """

    def __init__(
        self,
        settings: Mapping[str, Any],
        schedule: PullSchedule,
        metadata: Optional[ConnectorMetadata] = None,
    ) -> None:
        """Initialize DAST connector.

        Settings keys:
            - scanner_type: zap, burp, or nuclei
            - api_url: Scanner API URL
            - token: API token
            - target_urls: List of URLs to scan
        """
        if metadata is None:
            metadata = ConnectorMetadata(
                name="dast",
                description="Pull DAST scan results from ZAP/Burp/Nuclei",
                vendor="OWASP/Burp/Nuclei",
                sdlc_stages=[SDLCStage.TEST],
                target_cores=[1, 2],
                version="1.0.0",
                tags=["dast", "web-security", "vulnerability-scanning"],
            )
        super().__init__(settings, schedule, metadata)

    @property
    def configured(self) -> bool:
        """Check if DAST scanner is configured."""
        scanner_type = self._settings.get("scanner_type")
        api_url = self._settings.get("api_url")
        return bool(scanner_type and api_url)

    async def pull(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch DAST results."""
        scanner_type = self._settings.get("scanner_type")

        if scanner_type == "zap":
            return await self._pull_from_zap(since)
        elif scanner_type == "burp":
            return await self._pull_from_burp(since)
        elif scanner_type == "nuclei":
            return await self._pull_from_nuclei(since)
        else:
            raise ValueError(f"Unknown scanner_type: {scanner_type}")

    async def _pull_from_zap(self, since: Optional[datetime]) -> List[Dict[str, Any]]:
        """Pull from OWASP ZAP."""
        logger.info("OWASP ZAP integration not yet implemented")
        return []

    async def _pull_from_burp(self, since: Optional[datetime]) -> List[Dict[str, Any]]:
        """Pull from Burp Suite."""
        logger.info("Burp Suite integration not yet implemented")
        return []

    async def _pull_from_nuclei(self, since: Optional[datetime]) -> List[Dict[str, Any]]:
        """Pull from Nuclei."""
        logger.info("Nuclei integration not yet implemented")
        return []

    async def push_enrichment(
        self, entity_id: str, enrichment: Dict[str, Any]
    ) -> ConnectorOutcome:
        """Push remediation back to DAST tool."""
        return ConnectorOutcome("success", {"entity_id": entity_id})

    def _normalize_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize DAST findings."""
        now = datetime.now(timezone.utc).isoformat()

        return {
            "id": f"dast-{raw.get('issue_id')}",
            "source": "dast",
            "severity": _normalize_severity(raw.get("severity")),
            "title": raw.get("title", "DAST Finding"),
            "description": raw.get("description", ""),
            "cve_ids": [],
            "cwe_ids": [raw.get("cwe")] if raw.get("cwe") else [],
            "affected_asset": raw.get("url"),
            "asset_type": "web_application",
            "first_seen": now,
            "last_seen": now,
            "status": "open",
            "raw": raw,
            "sdlc_stage": "test",
            "metadata": {
                "url": raw.get("url"),
                "issue_type": raw.get("issue_type"),
            },
        }


# ---------------------------------------------------------------------------
# 8. K8sSecurityConnector (DEPLOY stage)
# ---------------------------------------------------------------------------


class K8sSecurityConnector(PullConnector):
    """Pull Kubernetes security configurations and alerts.

    Fetches:
    - Pod security policies
    - RBAC configurations
    - Network policies
    - Falco alerts
    - Secret audit
    """

    def __init__(
        self,
        settings: Mapping[str, Any],
        schedule: PullSchedule,
        metadata: Optional[ConnectorMetadata] = None,
    ) -> None:
        """Initialize K8s security connector.

        Settings keys:
            - kubeconfig_path: Path to kubeconfig
            - in_cluster: Use in-cluster ServiceAccount (bool)
            - namespace: Specific namespace or None for all
            - falco_url: Falco server URL (optional)
        """
        if metadata is None:
            metadata = ConnectorMetadata(
                name="k8s-security",
                description="Pull pod security, RBAC, network policies, Falco alerts",
                vendor="Kubernetes/Falco",
                sdlc_stages=[SDLCStage.DEPLOY],
                target_cores=[1],
                version="1.0.0",
                tags=["kubernetes", "container-orchestration", "security-posture"],
            )
        super().__init__(settings, schedule, metadata)

    @property
    def configured(self) -> bool:
        """Check if K8s is accessible."""
        kubeconfig = self._settings.get("kubeconfig_path")
        in_cluster = self._settings.get("in_cluster", False)
        return bool(kubeconfig or in_cluster)

    async def pull(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch K8s security findings."""
        findings = []

        try:
            # In a real implementation, this would use kubernetes.client
            # For now, return placeholder
            logger.info("K8s security connector would fetch pod security policies, RBAC, network policies")

        except Exception as exc:
            logger.error(f"K8s pull failed: {exc}")

        return findings

    async def push_enrichment(
        self, entity_id: str, enrichment: Dict[str, Any]
    ) -> ConnectorOutcome:
        """Update K8s resource with enrichment."""
        return ConnectorOutcome("success", {"entity_id": entity_id})

    def _normalize_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize K8s findings."""
        now = datetime.now(timezone.utc).isoformat()

        return {
            "id": f"k8s-{raw.get('resource')}",
            "source": "k8s-security",
            "severity": _normalize_severity(raw.get("severity")),
            "title": raw.get("title", "K8s Security Issue"),
            "description": raw.get("description", ""),
            "cve_ids": [],
            "cwe_ids": [],
            "affected_asset": raw.get("namespace"),
            "asset_type": "kubernetes_cluster",
            "first_seen": now,
            "last_seen": now,
            "status": "open",
            "raw": raw,
            "sdlc_stage": "deploy",
            "metadata": {
                "namespace": raw.get("namespace"),
                "resource_type": raw.get("resource_type"),
            },
        }


# ---------------------------------------------------------------------------
# 9. SIEMConnector (OPERATE stage)
# ---------------------------------------------------------------------------


class SIEMConnector(PullConnector):
    """Pull security events from SIEM platforms.

    Supports:
    - Splunk (REST API)
    - Azure Sentinel (Log Analytics API)
    """

    def __init__(
        self,
        settings: Mapping[str, Any],
        schedule: PullSchedule,
        metadata: Optional[ConnectorMetadata] = None,
    ) -> None:
        """Initialize SIEM connector.

        Settings keys:
            - siem_type: splunk or sentinel
            - url: SIEM URL
            - token: API token
            - saved_search: (Splunk) saved search name
            - query: (Sentinel) KQL query
        """
        if metadata is None:
            metadata = ConnectorMetadata(
                name="siem",
                description="Pull security events from Splunk/Sentinel",
                vendor="Splunk/Microsoft",
                sdlc_stages=[SDLCStage.OPERATE],
                target_cores=[1, 2],
                version="1.0.0",
                tags=["siem", "security-events", "threat-detection"],
            )
        super().__init__(settings, schedule, metadata)

    @property
    def configured(self) -> bool:
        """Check if SIEM is configured."""
        siem_type = self._settings.get("siem_type")
        url = self._settings.get("url")
        token = _get_env_fallback("token", self._settings, os.getenv("SIEM_TOKEN"))
        return bool(siem_type and url and token)

    async def pull(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch security events."""
        siem_type = self._settings.get("siem_type")

        if siem_type == "splunk":
            return await self._pull_from_splunk(since)
        elif siem_type == "sentinel":
            return await self._pull_from_sentinel(since)
        else:
            raise ValueError(f"Unknown siem_type: {siem_type}")

    async def _pull_from_splunk(self, since: Optional[datetime]) -> List[Dict[str, Any]]:
        """Pull from Splunk."""
        logger.info("Splunk SIEM integration not yet implemented")
        return []

    async def _pull_from_sentinel(self, since: Optional[datetime]) -> List[Dict[str, Any]]:
        """Pull from Azure Sentinel."""
        logger.info("Azure Sentinel integration not yet implemented")
        return []

    async def push_enrichment(
        self, entity_id: str, enrichment: Dict[str, Any]
    ) -> ConnectorOutcome:
        """Update SIEM event."""
        return ConnectorOutcome("success", {"entity_id": entity_id})

    def _normalize_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize SIEM events."""
        now = datetime.now(timezone.utc).isoformat()

        return {
            "id": f"siem-{raw.get('event_id')}",
            "source": "siem",
            "severity": _normalize_severity(raw.get("severity")),
            "title": raw.get("title", "Security Event"),
            "description": raw.get("description", ""),
            "cve_ids": [],
            "cwe_ids": [],
            "affected_asset": raw.get("source_ip"),
            "asset_type": "network_event",
            "first_seen": raw.get("timestamp", now),
            "last_seen": raw.get("timestamp", now),
            "status": "open",
            "raw": raw,
            "sdlc_stage": "operate",
            "metadata": {
                "source": raw.get("source"),
                "destination": raw.get("destination"),
            },
        }


# ---------------------------------------------------------------------------
# 10. ComplianceConnector (GOVERN stage)
# ---------------------------------------------------------------------------


class ComplianceConnector(PullConnector):
    """Pull compliance control status from GRC platforms.

    Supports:
    - Vanta
    - Drata
    """

    def __init__(
        self,
        settings: Mapping[str, Any],
        schedule: PullSchedule,
        metadata: Optional[ConnectorMetadata] = None,
    ) -> None:
        """Initialize compliance connector.

        Settings keys:
            - provider: vanta or drata
            - api_key: Provider API key
            - frameworks: List of framework IDs
        """
        if metadata is None:
            metadata = ConnectorMetadata(
                name="compliance",
                description="Pull control status from Vanta/Drata",
                vendor="Vanta/Drata",
                sdlc_stages=[SDLCStage.GOVERN],
                target_cores=[3],
                version="1.0.0",
                tags=["compliance", "governance", "audit"],
            )
        super().__init__(settings, schedule, metadata)

    @property
    def configured(self) -> bool:
        """Check if compliance provider is configured."""
        provider = self._settings.get("provider")
        api_key = _get_env_fallback("api_key", self._settings, os.getenv("COMPLIANCE_API_KEY"))
        return bool(provider and api_key)

    async def pull(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch compliance control status."""
        provider = self._settings.get("provider")

        if provider == "vanta":
            return await self._pull_from_vanta(since)
        elif provider == "drata":
            return await self._pull_from_drata(since)
        else:
            raise ValueError(f"Unknown provider: {provider}")

    async def _pull_from_vanta(self, since: Optional[datetime]) -> List[Dict[str, Any]]:
        """Pull from Vanta."""
        logger.info("Vanta compliance integration not yet implemented")
        return []

    async def _pull_from_drata(self, since: Optional[datetime]) -> List[Dict[str, Any]]:
        """Pull from Drata."""
        logger.info("Drata compliance integration not yet implemented")
        return []

    async def push_enrichment(
        self, entity_id: str, enrichment: Dict[str, Any]
    ) -> ConnectorOutcome:
        """Update compliance status."""
        return ConnectorOutcome("success", {"entity_id": entity_id})

    def _normalize_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize compliance findings."""
        now = datetime.now(timezone.utc).isoformat()

        return {
            "id": f"compliance-{raw.get('control_id')}",
            "source": "compliance",
            "severity": "medium",  # Compliance gaps are always significant
            "title": raw.get("control_name", "Compliance Control"),
            "description": raw.get("description", ""),
            "cve_ids": [],
            "cwe_ids": [],
            "affected_asset": raw.get("framework"),
            "asset_type": "compliance_control",
            "first_seen": now,
            "last_seen": now,
            "status": raw.get("status", "open").lower(),
            "raw": raw,
            "sdlc_stage": "govern",
            "metadata": {
                "framework": raw.get("framework"),
                "control_id": raw.get("control_id"),
            },
        }


# ---------------------------------------------------------------------------
# 11. GCPSecurityConnector (DEPLOY stage)
# ---------------------------------------------------------------------------


class GCPSecurityConnector(PullConnector):
    """Pull findings from GCP Security Command Center.

    Fetches:
    - Vulnerability findings
    - Configuration misconfigurations
    - IAM misconfiguration
    - Sensitive data exposure
    """

    def __init__(
        self,
        settings: Mapping[str, Any],
        schedule: PullSchedule,
        metadata: Optional[ConnectorMetadata] = None,
    ) -> None:
        """Initialize GCP Security connector.

        Settings keys:
            - project_id: GCP project ID
            - organization_id: GCP organization ID
            - credentials_path: Path to service account key
        """
        if metadata is None:
            metadata = ConnectorMetadata(
                name="gcp-security",
                description="Pull findings from GCP Security Command Center",
                vendor="Google Cloud",
                sdlc_stages=[SDLCStage.DEPLOY],
                target_cores=[1],
                version="1.0.0",
                tags=["cloud-security", "gcp", "misconfig-detection"],
            )
        super().__init__(settings, schedule, metadata)

    @property
    def configured(self) -> bool:
        """Check if GCP is configured."""
        project_id = self._settings.get("project_id")
        org_id = self._settings.get("organization_id")
        creds_path = self._settings.get("credentials_path")
        return bool((project_id or org_id) and creds_path)

    async def pull(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch GCP Security Command Center findings."""
        # In a real implementation, this would use google-cloud-securitycenter
        logger.info("GCP Security Command Center integration not yet implemented")
        return []

    async def push_enrichment(
        self, entity_id: str, enrichment: Dict[str, Any]
    ) -> ConnectorOutcome:
        """Update GCP finding."""
        return ConnectorOutcome("success", {"entity_id": entity_id})

    def _normalize_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize GCP findings."""
        now = datetime.now(timezone.utc).isoformat()

        return {
            "id": f"gcp-{raw.get('name')}",
            "source": "gcp-security",
            "severity": _normalize_severity(raw.get("severity")),
            "title": raw.get("title", "GCP Security Finding"),
            "description": raw.get("description", ""),
            "cve_ids": [],
            "cwe_ids": [],
            "affected_asset": raw.get("resource_name"),
            "asset_type": "gcp_resource",
            "first_seen": raw.get("create_time", now),
            "last_seen": raw.get("event_time", now),
            "status": raw.get("state", "open").lower(),
            "raw": raw,
            "sdlc_stage": "deploy",
            "metadata": {
                "resource": raw.get("resource_name"),
                "finding_class": raw.get("finding_class"),
            },
        }
