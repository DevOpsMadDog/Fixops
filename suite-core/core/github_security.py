"""
ALdeci GitHub Advanced Security Integration.

Pulls code scanning alerts, Dependabot alerts, and secret scanning alerts
from GitHub repos via the GitHub REST API. Normalizes results and stores
import history per org.

Follows the trivy_integration.py pattern: mock-safe, in-memory history,
optional BrainPipeline ingestion.

GitHub API version: 2022-11-28
Docs: https://docs.github.com/en/rest/code-scanning
      https://docs.github.com/en/rest/dependabot/alerts
      https://docs.github.com/en/rest/secret-scanning

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence)
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory import history store (keyed by org_id)
# ---------------------------------------------------------------------------
_import_history: Dict[str, List[Dict[str, Any]]] = {}
_history_lock: Optional[threading.Lock] = None


def _get_lock() -> threading.Lock:
    global _history_lock
    if _history_lock is None:
        _history_lock = threading.Lock()
    return _history_lock


# ---------------------------------------------------------------------------
# Mock alert data for when no GitHub token is configured
# ---------------------------------------------------------------------------

_MOCK_CODE_SCANNING_ALERTS: List[Dict[str, Any]] = [
    {
        "number": 1,
        "state": "open",
        "rule": {
            "id": "py/sql-injection",
            "name": "SQL injection",
            "severity": "error",
            "description": "Database query built from user-controlled sources.",
        },
        "tool": {"name": "CodeQL", "version": "2.14.0"},
        "most_recent_instance": {
            "ref": "refs/heads/main",
            "location": {
                "path": "app/db.py",
                "start_line": 42,
                "end_line": 42,
            },
            "message": {"text": "This query depends on a user-provided value."},
        },
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
        "html_url": "https://github.com/mock-owner/mock-repo/security/code-scanning/1",
        "_mock": True,
    },
    {
        "number": 2,
        "state": "open",
        "rule": {
            "id": "py/path-injection",
            "name": "Path injection",
            "severity": "error",
            "description": "Uncontrolled data used in a path expression.",
        },
        "tool": {"name": "CodeQL", "version": "2.14.0"},
        "most_recent_instance": {
            "ref": "refs/heads/main",
            "location": {
                "path": "app/files.py",
                "start_line": 17,
                "end_line": 17,
            },
            "message": {"text": "Path constructed from user-controlled data."},
        },
        "created_at": "2026-01-03T00:00:00Z",
        "updated_at": "2026-01-04T00:00:00Z",
        "html_url": "https://github.com/mock-owner/mock-repo/security/code-scanning/2",
        "_mock": True,
    },
]

_MOCK_DEPENDABOT_ALERTS: List[Dict[str, Any]] = [
    {
        "number": 1,
        "state": "open",
        "dependency": {
            "package": {"ecosystem": "pip", "name": "requests"},
            "manifest_path": "requirements.txt",
        },
        "security_advisory": {
            "ghsa_id": "GHSA-mock-0001",
            "cve_id": "CVE-2023-32681",
            "summary": "Requests forwards proxy-authorization header on redirect",
            "severity": "medium",
            "cvss": {"score": 6.1},
            "vulnerable_version_range": "< 2.31.0",
            "first_patched_version": {"identifier": "2.31.0"},
        },
        "created_at": "2026-01-05T00:00:00Z",
        "updated_at": "2026-01-06T00:00:00Z",
        "html_url": "https://github.com/mock-owner/mock-repo/security/dependabot/1",
        "_mock": True,
    },
    {
        "number": 2,
        "state": "open",
        "dependency": {
            "package": {"ecosystem": "pip", "name": "pillow"},
            "manifest_path": "requirements.txt",
        },
        "security_advisory": {
            "ghsa_id": "GHSA-mock-0002",
            "cve_id": "CVE-2023-44271",
            "summary": "Pillow uncontrolled resource consumption in PIL.ImageFont.ImageFont",
            "severity": "high",
            "cvss": {"score": 7.5},
            "vulnerable_version_range": "< 10.0.1",
            "first_patched_version": {"identifier": "10.0.1"},
        },
        "created_at": "2026-01-07T00:00:00Z",
        "updated_at": "2026-01-08T00:00:00Z",
        "html_url": "https://github.com/mock-owner/mock-repo/security/dependabot/2",
        "_mock": True,
    },
]

_MOCK_SECRET_SCANNING_ALERTS: List[Dict[str, Any]] = [
    {
        "number": 1,
        "state": "open",
        "secret_type": "github_personal_access_token",
        "secret_type_display_name": "GitHub Personal Access Token",
        "secret": "ghp_mock_redacted",
        "locations_url": "https://api.github.com/repos/mock-owner/mock-repo/secret-scanning/alerts/1/locations",
        "created_at": "2026-01-09T00:00:00Z",
        "updated_at": "2026-01-10T00:00:00Z",
        "html_url": "https://github.com/mock-owner/mock-repo/security/secret-scanning/1",
        "_mock": True,
    },
]

# Severity mapping: GitHub/CodeQL → ALDECI
_SEVERITY_MAP: Dict[str, str] = {
    "critical": "critical",
    "error": "high",
    "high": "high",
    "warning": "medium",
    "medium": "medium",
    "note": "low",
    "low": "low",
    "none": "info",
    "info": "info",
}


class GitHubSecurityClient:
    """
    Pulls GitHub Advanced Security alerts (code scanning, Dependabot, secret scanning)
    for a given repository.

    Falls back to mock data when no token is configured, so the rest of
    the pipeline can be exercised without a real GitHub PAT.
    """

    GITHUB_API_BASE = "https://api.github.com"
    GITHUB_API_VERSION = "2022-11-28"
    DEFAULT_TIMEOUT = 30

    def __init__(
        self,
        token: Optional[str] = None,
        owner: Optional[str] = None,
        repo: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        """
        Configure the client with a GitHub PAT.

        Args:
            token:    GitHub Personal Access Token (or read from GITHUB_TOKEN env).
            owner:    Repository owner (user or org).
            repo:     Repository name.
            base_url: GitHub API base (override for GHES).
            timeout:  HTTP request timeout in seconds.
        """
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.owner = owner or os.environ.get("GITHUB_OWNER")
        self.repo = repo or os.environ.get("GITHUB_REPO")
        self.base_url = (base_url or self.GITHUB_API_BASE).rstrip("/")
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Configuration check
    # ------------------------------------------------------------------

    def is_configured(self) -> bool:
        """Return True if token, owner, and repo are all set."""
        return bool(self.token and self.owner and self.repo)

    # ------------------------------------------------------------------
    # Internal HTTP helper
    # ------------------------------------------------------------------

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        GET a paginated GitHub API endpoint and return all items.

        Falls back to empty list on HTTP / connection errors.
        """
        try:
            import requests  # type: ignore[import-untyped]
        except ImportError:
            logger.warning("requests library not available — returning empty list")
            return []

        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.GITHUB_API_VERSION,
        }
        all_items: List[Dict[str, Any]] = []
        page = 1
        per_page = 100

        while True:
            query = {"per_page": per_page, "page": page}
            if params:
                query.update(params)
            try:
                response = requests.get(  # nosemgrep: dynamic-urllib-use-detected
                    url, headers=headers, params=query, timeout=self.timeout
                )
                response.raise_for_status()
            except Exception as exc:
                logger.warning("GitHub API request failed for %s: %s", path, exc)
                break

            try:
                data = response.json()
            except ValueError:
                logger.warning("GitHub API returned non-JSON for %s", path)
                break

            if not isinstance(data, list):
                # Some endpoints return a dict on error
                logger.warning("Unexpected GitHub API response type for %s: %r", path, type(data))
                break

            all_items.extend(data)
            if len(data) < per_page:
                break
            page += 1

        return all_items

    def _patch(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """PATCH a GitHub API endpoint and return the response body."""
        try:
            import requests  # type: ignore[import-untyped]
        except ImportError:
            return {"error": "requests library not available"}

        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.GITHUB_API_VERSION,
        }
        try:
            response = requests.patch(url, headers=headers, json=payload, timeout=self.timeout)  # nosemgrep: dynamic-urllib-use-detected
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            logger.warning("GitHub API PATCH failed for %s: %s", path, exc)
            return {"error": str(exc)}

    # ------------------------------------------------------------------
    # Alert fetchers
    # ------------------------------------------------------------------

    def get_code_scanning_alerts(self) -> List[Dict[str, Any]]:
        """
        Fetch all open code scanning alerts for the configured repository.

        Returns mock data when not configured.
        GET /repos/{owner}/{repo}/code-scanning/alerts
        """
        if not self.is_configured():
            logger.info("GitHubSecurityClient not configured — returning mock code scanning alerts")
            return list(_MOCK_CODE_SCANNING_ALERTS)
        path = f"/repos/{self.owner}/{self.repo}/code-scanning/alerts"
        return self._get(path, {"state": "open"})

    def get_dependabot_alerts(self) -> List[Dict[str, Any]]:
        """
        Fetch all open Dependabot alerts for the configured repository.

        Returns mock data when not configured.
        GET /repos/{owner}/{repo}/dependabot/alerts
        """
        if not self.is_configured():
            logger.info("GitHubSecurityClient not configured — returning mock Dependabot alerts")
            return list(_MOCK_DEPENDABOT_ALERTS)
        path = f"/repos/{self.owner}/{self.repo}/dependabot/alerts"
        return self._get(path, {"state": "open"})

    def get_secret_scanning_alerts(self) -> List[Dict[str, Any]]:
        """
        Fetch all open secret scanning alerts for the configured repository.

        Returns mock data when not configured.
        GET /repos/{owner}/{repo}/secret-scanning/alerts
        """
        if not self.is_configured():
            logger.info("GitHubSecurityClient not configured — returning mock secret scanning alerts")  # nosemgrep: python-logger-credential-disclosure
            return list(_MOCK_SECRET_SCANNING_ALERTS)
        path = f"/repos/{self.owner}/{self.repo}/secret-scanning/alerts"
        return self._get(path, {"state": "open"})

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    def normalize_results(
        self, alerts: List[Dict[str, Any]], alert_type: str
    ) -> List[Dict[str, Any]]:
        """
        Normalize raw GitHub alert dicts into ALDECI unified finding format.

        Args:
            alerts:     Raw alert list from get_*_alerts().
            alert_type: One of ``"code_scanning"``, ``"dependabot"``, ``"secret_scanning"``.

        Returns:
            List of normalized finding dicts.
        """
        if alert_type == "code_scanning":
            return self._normalize_code_scanning(alerts)
        if alert_type == "dependabot":
            return self._normalize_dependabot(alerts)
        if alert_type == "secret_scanning":
            return self._normalize_secret_scanning(alerts)
        logger.warning("Unknown alert_type %r — returning raw alerts", alert_type)
        return alerts

    def _normalize_code_scanning(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for alert in alerts:
            rule = alert.get("rule") or {}
            tool = alert.get("tool") or {}
            instance = alert.get("most_recent_instance") or {}
            location = instance.get("location") or {}
            message = instance.get("message") or {}

            raw_sev = (rule.get("severity") or "warning").lower()
            severity = _SEVERITY_MAP.get(raw_sev, "medium")

            findings.append({
                "id": str(uuid.uuid4()),
                "source_tool": f"github_code_scanning/{tool.get('name', 'unknown')}",
                "source_id": f"gh-cs-{alert.get('number', uuid.uuid4().hex[:8])}",
                "alert_number": alert.get("number"),
                "alert_type": "code_scanning",
                "severity": severity,
                "title": rule.get("name") or rule.get("id") or "Code scanning alert",
                "description": rule.get("description") or message.get("text") or "",
                "recommendation": f"Review and fix: {rule.get('id', '')}",
                "rule_id": rule.get("id"),
                "tool_name": tool.get("name"),
                "tool_version": tool.get("version"),
                "file_path": location.get("path"),
                "start_line": location.get("start_line"),
                "end_line": location.get("end_line"),
                "ref": instance.get("ref"),
                "state": alert.get("state", "open"),
                "html_url": alert.get("html_url"),
                "created_at": alert.get("created_at"),
                "updated_at": alert.get("updated_at"),
                "is_mock": bool(alert.get("_mock")),
            })
        return findings

    def _normalize_dependabot(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for alert in alerts:
            dep = alert.get("dependency") or {}
            pkg = dep.get("package") or {}
            advisory = alert.get("security_advisory") or {}
            cvss = advisory.get("cvss") or {}
            patched = advisory.get("first_patched_version") or {}

            raw_sev = (advisory.get("severity") or "medium").lower()
            severity = _SEVERITY_MAP.get(raw_sev, "medium")

            pkg_name = pkg.get("name", "unknown")
            fix_version = patched.get("identifier", "")
            findings.append({
                "id": str(uuid.uuid4()),
                "source_tool": "github_dependabot",
                "source_id": f"gh-dep-{alert.get('number', uuid.uuid4().hex[:8])}",
                "alert_number": alert.get("number"),
                "alert_type": "dependabot",
                "severity": severity,
                "title": advisory.get("summary") or f"Dependabot: {pkg_name}",
                "description": advisory.get("summary") or "",
                "recommendation": f"Upgrade {pkg_name} to {fix_version}" if fix_version else f"Update {pkg_name}",
                "cve_id": advisory.get("cve_id"),
                "ghsa_id": advisory.get("ghsa_id"),
                "cvss_score": cvss.get("score"),
                "package_name": pkg_name,
                "package_ecosystem": pkg.get("ecosystem"),
                "vulnerable_version_range": advisory.get("vulnerable_version_range"),
                "fixed_version": fix_version,
                "manifest_path": dep.get("manifest_path"),
                "state": alert.get("state", "open"),
                "html_url": alert.get("html_url"),
                "created_at": alert.get("created_at"),
                "updated_at": alert.get("updated_at"),
                "is_mock": bool(alert.get("_mock")),
            })
        return findings

    def _normalize_secret_scanning(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for alert in alerts:
            findings.append({
                "id": str(uuid.uuid4()),
                "source_tool": "github_secret_scanning",
                "source_id": f"gh-ss-{alert.get('number', uuid.uuid4().hex[:8])}",
                "alert_number": alert.get("number"),
                "alert_type": "secret_scanning",
                "severity": "critical",  # Exposed secrets are always critical
                "title": f"Secret exposed: {alert.get('secret_type_display_name') or alert.get('secret_type', 'Unknown secret')}",
                "description": f"Secret type '{alert.get('secret_type')}' detected in repository",
                "recommendation": "Revoke and rotate the exposed secret immediately",
                "secret_type": alert.get("secret_type"),
                "secret_type_display_name": alert.get("secret_type_display_name"),
                "locations_url": alert.get("locations_url"),
                "state": alert.get("state", "open"),
                "html_url": alert.get("html_url"),
                "created_at": alert.get("created_at"),
                "updated_at": alert.get("updated_at"),
                "is_mock": bool(alert.get("_mock")),
            })
        return findings

    # ------------------------------------------------------------------
    # Dismiss
    # ------------------------------------------------------------------

    def dismiss_alert(
        self,
        alert_type: str,
        alert_number: int,
        reason: str,
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Dismiss a GitHub Advanced Security alert.

        Args:
            alert_type:   ``"code_scanning"``, ``"dependabot"``, or ``"secret_scanning"``.
            alert_number: The alert number from GitHub.
            reason:       Dismissal reason (e.g. ``"false_positive"``, ``"used_in_tests"``).
            comment:      Optional human-readable comment.

        Returns:
            Dict with ``status`` and ``details``.
        """
        if not self.is_configured():
            return {
                "status": "skipped",
                "reason": "client not configured — mock mode",
                "alert_type": alert_type,
                "alert_number": alert_number,
            }

        path_map = {
            "code_scanning": f"/repos/{self.owner}/{self.repo}/code-scanning/alerts/{alert_number}",
            "dependabot": f"/repos/{self.owner}/{self.repo}/dependabot/alerts/{alert_number}",
            "secret_scanning": f"/repos/{self.owner}/{self.repo}/secret-scanning/alerts/{alert_number}",
        }
        if alert_type not in path_map:
            return {
                "status": "error",
                "reason": f"Unknown alert_type: {alert_type}",
            }

        payload: Dict[str, Any] = {"state": "dismissed", "dismissed_reason": reason}
        if comment:
            payload["dismissed_comment"] = comment

        result = self._patch(path_map[alert_type], payload)
        if "error" in result:
            return {"status": "failed", "details": result}
        return {"status": "dismissed", "alert_type": alert_type, "alert_number": alert_number, "details": result}

    # ------------------------------------------------------------------
    # Import all
    # ------------------------------------------------------------------

    def import_all(self, org_id: str = "default") -> Dict[str, Any]:
        """
        Pull all alert types, normalize, store in import history, and optionally
        push into BrainPipeline.

        Args:
            org_id: Organisation identifier for multi-tenancy.

        Returns:
            Summary dict with import_id, counts per alert type, severity breakdown.
        """
        import_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        is_mock = not self.is_configured()

        all_findings: List[Dict[str, Any]] = []
        counts: Dict[str, int] = {}
        errors: Dict[str, str] = {}

        for alert_type, fetcher in [
            ("code_scanning", self.get_code_scanning_alerts),
            ("dependabot", self.get_dependabot_alerts),
            ("secret_scanning", self.get_secret_scanning_alerts),
        ]:
            try:
                raw = fetcher()
                normalized = self.normalize_results(raw, alert_type)
                counts[alert_type] = len(normalized)
                all_findings.extend(normalized)
            except Exception as exc:
                logger.error("Failed to import %s alerts: %s", alert_type, exc, exc_info=True)
                errors[alert_type] = str(exc)
                counts[alert_type] = 0

        # Severity breakdown
        sev_counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        for f in all_findings:
            sev = (f.get("severity") or "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        entry: Dict[str, Any] = {
            "import_id": import_id,
            "org_id": org_id,
            "owner": self.owner or "mock-owner",
            "repo": self.repo or "mock-repo",
            "started_at": started_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "status": "failed" if errors and not all_findings else "completed",
            "is_mock": is_mock,
            "total_findings": len(all_findings),
            "counts_by_type": counts,
            "severity_breakdown": sev_counts,
            "errors": errors,
            "findings": all_findings,
        }

        # Store in history
        with _get_lock():
            _import_history.setdefault(org_id, []).append(entry)

        # Best-effort pipeline ingestion
        self._try_ingest_to_pipeline(all_findings, org_id, import_id)

        # Emit each normalized finding to the TrustGraph event bus
        try:
            from core.trustgraph_event_bus import get_event_bus
            bus = get_event_bus()
            for f in all_findings:
                bus.emit("finding.created", {
                    "org_id": org_id,
                    "engine": "github",
                    "id": f.get("id") or f.get("finding_id"),
                    "cve_id": f.get("cve_id"),
                    "severity": f.get("severity", "unknown"),
                    "title": f.get("title") or f.get("name"),
                    "asset_id": f.get("asset_id"),
                    "cvss": f.get("cvss"),
                    "epss": f.get("epss"),
                    "is_mock": f.get("is_mock", is_mock),
                    **f,
                })
        except Exception:
            pass

        return entry

    def _try_ingest_to_pipeline(
        self,
        findings: List[Dict[str, Any]],
        org_id: str,
        import_id: str,
    ) -> None:
        """Push normalized findings into BrainPipeline if available."""
        if not findings:
            return
        try:
            from core.brain_pipeline import BrainPipeline, PipelineInput
            pipeline = BrainPipeline()
            pipeline_input = PipelineInput(
                org_id=org_id,
                findings=findings,
                metadata={"source": "github_security", "import_id": import_id},
            )
            pipeline.run(pipeline_input)
            logger.info(
                "Ingested %d GitHub Security findings into BrainPipeline for org=%s import=%s",
                len(findings), org_id, import_id,
            )
        except Exception as exc:
            logger.warning("BrainPipeline ingestion skipped: %s", exc)

    # ------------------------------------------------------------------
    # Import history
    # ------------------------------------------------------------------

    def get_import_history(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """
        Return import history for the given org, most recent first.

        Findings are stripped from summaries to keep responses lightweight.
        """
        with _get_lock():
            entries = list(_import_history.get(org_id, []))

        summaries = []
        for e in reversed(entries):
            summary = {k: v for k, v in e.items() if k != "findings"}
            summaries.append(summary)
        return summaries
