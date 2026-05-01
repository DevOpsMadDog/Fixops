"""
ALdeci Snyk Integration — Real Snyk REST API vulnerability data ingestion.

Connects to Snyk's REST API to pull project vulnerabilities, normalize them
via SnykNormalizer, and store findings for ingestion into the Brain Pipeline.

Usage:
    client = SnykClient(api_token="snyk-token", org_id="my-org-id")
    if client.is_configured():
        result = client.import_results(org_id="my-org-id")

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory import history store (keyed by org_id)
# ---------------------------------------------------------------------------
_import_history: Dict[str, List[Dict[str, Any]]] = {}
_history_lock = None  # lazy-init threading.Lock


def _get_lock():
    global _history_lock
    if _history_lock is None:
        import threading
        _history_lock = threading.Lock()
    return _history_lock


# ---------------------------------------------------------------------------
# Snyk REST API base URL
# ---------------------------------------------------------------------------
_SNYK_API_BASE = "https://api.snyk.io/rest"
_SNYK_API_VERSION = "2024-01-23"

# ---------------------------------------------------------------------------
# Mock data returned when no API token is configured
# ---------------------------------------------------------------------------
_MOCK_PROJECTS: List[Dict[str, Any]] = [
    {
        "id": "mock-project-001",
        "attributes": {
            "name": "mock-app/package.json",
            "type": "npm",
            "status": "active",
            "created": "2026-01-01T00:00:00.000Z",
            "lastTestedDate": "2026-01-10T00:00:00.000Z",
            "isMonitored": True,
            "totalDependencies": 42,
            "issueCountsBySeverity": {
                "critical": 1,
                "high": 3,
                "medium": 5,
                "low": 2,
            },
        },
    },
    {
        "id": "mock-project-002",
        "attributes": {
            "name": "mock-app/requirements.txt",
            "type": "pip",
            "status": "active",
            "created": "2026-01-02T00:00:00.000Z",
            "lastTestedDate": "2026-01-10T00:00:00.000Z",
            "isMonitored": True,
            "totalDependencies": 18,
            "issueCountsBySeverity": {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 4,
            },
        },
    },
]

_MOCK_ISSUES: List[Dict[str, Any]] = [
    {
        "id": "SNYK-JS-LODASH-1234567",
        "attributes": {
            "title": "Prototype Pollution",
            "type": "vuln",
            "severity": "high",
            "status": "open",
            "ignoredAt": None,
            "createdAt": "2026-01-05T00:00:00.000Z",
            "updatedAt": "2026-01-10T00:00:00.000Z",
            "coordinates": [
                {
                    "representations": [
                        {
                            "dependency": {
                                "package_name": "lodash",
                                "package_version": "4.17.15",
                            }
                        }
                    ],
                    "remedies": [{"description": "Upgrade to lodash@4.17.21"}],
                }
            ],
            "classes": [{"id": "CWE-1321", "type": "weakness"}],
            "problems": [
                {
                    "id": "CVE-2021-23337",
                    "type": "vulnerability",
                    "url": "https://security.snyk.io/vuln/SNYK-JS-LODASH-1234567",
                }
            ],
            "description": "Prototype Pollution in lodash allows attackers to modify Object.prototype.",
        },
        "relationships": {
            "scan_item": {"data": {"id": "mock-project-001", "type": "project"}}
        },
    },
    {
        "id": "SNYK-PYTHON-REQUESTS-9876543",
        "attributes": {
            "title": "Certificate Verification Bypass",
            "type": "vuln",
            "severity": "medium",
            "status": "open",
            "ignoredAt": None,
            "createdAt": "2026-01-06T00:00:00.000Z",
            "updatedAt": "2026-01-10T00:00:00.000Z",
            "coordinates": [
                {
                    "representations": [
                        {
                            "dependency": {
                                "package_name": "requests",
                                "package_version": "2.28.0",
                            }
                        }
                    ],
                    "remedies": [{"description": "Upgrade to requests@2.32.0"}],
                }
            ],
            "classes": [{"id": "CWE-295", "type": "weakness"}],
            "problems": [
                {
                    "id": "CVE-2023-32681",
                    "type": "vulnerability",
                    "url": "https://security.snyk.io/vuln/SNYK-PYTHON-REQUESTS-9876543",
                }
            ],
            "description": "Requests library does not verify SSL certificates when proxies are in use.",
        },
        "relationships": {
            "scan_item": {"data": {"id": "mock-project-002", "type": "project"}}
        },
    },
    {
        "id": "SNYK-PYTHON-PILLOW-1111111",
        "attributes": {
            "title": "Arbitrary Code Execution",
            "type": "vuln",
            "severity": "critical",
            "status": "open",
            "ignoredAt": None,
            "createdAt": "2026-01-07T00:00:00.000Z",
            "updatedAt": "2026-01-10T00:00:00.000Z",
            "coordinates": [
                {
                    "representations": [
                        {
                            "dependency": {
                                "package_name": "Pillow",
                                "package_version": "9.0.0",
                            }
                        }
                    ],
                    "remedies": [{"description": "Upgrade to Pillow@10.0.1"}],
                }
            ],
            "classes": [{"id": "CWE-78", "type": "weakness"}],
            "problems": [
                {
                    "id": "CVE-2023-44271",
                    "type": "vulnerability",
                    "url": "https://security.snyk.io/vuln/SNYK-PYTHON-PILLOW-1111111",
                }
            ],
            "description": "Uncontrolled resource consumption in Pillow via crafted image files.",
        },
        "relationships": {
            "scan_item": {"data": {"id": "mock-project-002", "type": "project"}}
        },
    },
]

_MOCK_TEST_PACKAGE_RESULT: Dict[str, Any] = {
    "ok": False,
    "packageName": "mock-package",
    "version": "1.0.0",
    "vulnerabilities": [
        {
            "id": "SNYK-MOCK-001",
            "title": "Mock Vulnerability (no API token configured)",
            "severity": "medium",
            "packageName": "mock-package",
            "version": "1.0.0",
            "description": "This is mock data. Configure SNYK_API_TOKEN for real results.",
            "identifiers": {"CVE": [], "CWE": []},
            "fixedIn": ["2.0.0"],
        }
    ],
    "is_mock": True,
}


# ---------------------------------------------------------------------------
# HTTP session with retry
# ---------------------------------------------------------------------------

def _make_session(api_token: str, retries: int = 3, backoff: float = 0.5):
    """Build a requests.Session with retry and auth headers."""
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    session = requests.Session()
    session.headers.update({
        "Authorization": f"token {api_token}",
        "Content-Type": "application/json",
        "Accept": "application/vnd.api+json",
    })
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ---------------------------------------------------------------------------
# SnykClient
# ---------------------------------------------------------------------------

class SnykClient:
    """
    REST API client for Snyk vulnerability data.

    Falls back to mock data when no API token is configured so that the
    rest of the pipeline can be exercised without real credentials.
    """

    #: Default HTTP timeout in seconds
    DEFAULT_TIMEOUT = 30

    def __init__(
        self,
        api_token: Optional[str] = None,
        org_id: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self._api_token: str = (
            api_token
            or os.environ.get("SNYK_API_TOKEN", "")
            or ""
        ).strip()
        self._org_id: str = (
            org_id
            or os.environ.get("SNYK_ORG_ID", "")
            or ""
        ).strip()
        self.timeout = timeout
        self._session = None  # lazy-init

    # ------------------------------------------------------------------
    # Configuration check
    # ------------------------------------------------------------------

    def is_configured(self) -> bool:
        """Return True if an API token is set."""
        return bool(self._api_token)

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    def _get_session(self):
        if self._session is None:
            if not self._api_token:
                return None
            self._session = _make_session(self._api_token)
        return self._session

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """
        Execute a GET against the Snyk REST API.

        Returns parsed JSON. Raises RuntimeError on HTTP errors.
        Falls back to None when no session (no token).
        """
        session = self._get_session()
        if session is None:
            return None

        url = f"{_SNYK_API_BASE}{path}"
        default_params = {"version": _SNYK_API_VERSION}
        if params:
            default_params.update(params)

        try:
            resp = session.get(url, params=default_params, timeout=self.timeout)
        except Exception as exc:
            raise RuntimeError(f"Snyk API request failed for {path}: {exc}") from exc

        if resp.status_code == 401:
            raise RuntimeError("Snyk API: Invalid or expired API token (401)")
        if resp.status_code == 403:
            raise RuntimeError(
                f"Snyk API: Insufficient permissions for {path} (403)"
            )
        if resp.status_code == 404:
            raise RuntimeError(f"Snyk API: Resource not found: {path} (404)")
        if not resp.ok:
            raise RuntimeError(
                f"Snyk API error {resp.status_code} for {path}: {resp.text[:300]}"
            )

        try:
            return resp.json()
        except Exception as exc:
            raise RuntimeError(
                f"Snyk API returned invalid JSON for {path}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    def list_projects(self) -> List[Dict[str, Any]]:
        """
        List all projects for the configured org.

        Returns:
            List of project dicts. Returns mock data when unconfigured.
        """
        if not self.is_configured():
            logger.warning(
                "Snyk API token not configured — returning mock project list. "
                "Set SNYK_API_TOKEN env var for real data."
            )
            return list(_MOCK_PROJECTS)

        org = self._org_id
        if not org:
            raise ValueError(
                "org_id is required to list projects. "
                "Set SNYK_ORG_ID or pass org_id to SnykClient."
            )

        data = self._get(f"/orgs/{org}/projects")
        if not data:
            return []

        # REST API wraps results in {"data": [...]}
        if isinstance(data, dict):
            return data.get("data", [])
        return data if isinstance(data, list) else []

    def get_project_issues(self, project_id: str) -> List[Dict[str, Any]]:
        """
        Get all open issues for a specific project.

        Args:
            project_id: Snyk project UUID.

        Returns:
            List of issue dicts. Returns mock data when unconfigured.
        """
        if not project_id or not isinstance(project_id, str):
            raise ValueError("project_id must be a non-empty string")

        if not self.is_configured():
            logger.warning(
                "Snyk API token not configured — returning mock issues for project %s.",
                project_id,
            )
            return [i for i in _MOCK_ISSUES if i.get("relationships", {}).get(
                "scan_item", {}).get("data", {}).get("id") == project_id
            ] or list(_MOCK_ISSUES)

        org = self._org_id
        if not org:
            raise ValueError("org_id is required. Set SNYK_ORG_ID or pass org_id to SnykClient.")

        data = self._get(
            f"/orgs/{org}/issues",
            params={"scan_item.id": project_id, "scan_item.type": "project"},
        )
        if not data:
            return []
        if isinstance(data, dict):
            return data.get("data", [])
        return data if isinstance(data, list) else []

    def test_package(
        self, ecosystem: str, package: str, version: str
    ) -> Dict[str, Any]:
        """
        Test a single package version for known vulnerabilities.

        Args:
            ecosystem: Package manager (npm, pip, maven, etc.)
            package:   Package name.
            version:   Package version string.

        Returns:
            Dict with vulnerability results. Returns mock data when unconfigured.
        """
        if not ecosystem or not package or not version:
            raise ValueError("ecosystem, package, and version are all required")

        if not self.is_configured():
            logger.warning(
                "Snyk API token not configured — returning mock test result for %s/%s@%s.",
                ecosystem, package, version,
            )
            result = dict(_MOCK_TEST_PACKAGE_RESULT)
            result["packageName"] = package
            result["version"] = version
            return result

        org = self._org_id
        if not org:
            raise ValueError("org_id is required. Set SNYK_ORG_ID or pass org_id to SnykClient.")

        # Snyk REST API: GET /orgs/{org}/packages/{purl}/issues
        # purl format: pkg:<ecosystem>/<package>@<version>
        purl = f"pkg:{ecosystem}/{package}@{version}"
        try:
            import urllib.parse
            encoded_purl = urllib.parse.quote(purl, safe="")
            data = self._get(f"/orgs/{org}/packages/{encoded_purl}/issues")
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"Package test failed for {purl}: {exc}") from exc

        return {
            "ok": not bool(data.get("data", [])) if isinstance(data, dict) else True,
            "packageName": package,
            "version": version,
            "ecosystem": ecosystem,
            "purl": purl,
            "vulnerabilities": data.get("data", []) if isinstance(data, dict) else [],
            "is_mock": False,
        }

    def import_results(self, org_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Pull all issues for the org, normalize them, store in history, and
        optionally push into the Brain Pipeline.

        Args:
            org_id: Override the configured org_id.

        Returns:
            List of normalized finding dicts.
        """
        effective_org = (org_id or self._org_id or "default").strip()
        import_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        is_mock = not self.is_configured()

        try:
            # Collect all issues across projects
            raw_issues: List[Dict[str, Any]] = []

            if is_mock:
                raw_issues = list(_MOCK_ISSUES)
            else:
                projects = self.list_projects()
                for project in projects:
                    project_id = project.get("id", "")
                    if not project_id:
                        continue
                    try:
                        issues = self.get_project_issues(project_id)
                        raw_issues.extend(issues)
                    except Exception as exc:
                        logger.warning(
                            "Failed to fetch issues for project %s: %s", project_id, exc
                        )

            findings = self.normalize_results(raw_issues)

            # Severity breakdown
            sev_counts: Dict[str, int] = {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
            }
            for f in findings:
                sev = (f.get("severity") or "info").lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            entry: Dict[str, Any] = {
                "import_id": import_id,
                "org_id": effective_org,
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "status": "completed",
                "is_mock": is_mock,
                "findings_count": len(findings),
                "severity_breakdown": sev_counts,
                "findings": findings,
            }

            self._try_ingest_to_pipeline(findings, effective_org, import_id)

            # Emit each normalized finding to the TrustGraph event bus
            try:
                from core.trustgraph_event_bus import get_event_bus
                bus = get_event_bus()
                for f in findings:
                    bus.emit("finding.created", {
                        "org_id": effective_org,
                        "engine": "snyk",
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

        except Exception as exc:
            logger.error("Snyk import failed for org=%s: %s", effective_org, exc, exc_info=True)
            entry = {
                "import_id": import_id,
                "org_id": effective_org,
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "status": "failed",
                "error": str(exc),
                "is_mock": is_mock,
                "findings_count": 0,
                "severity_breakdown": {},
                "findings": [],
            }

        with _get_lock():
            _import_history.setdefault(effective_org, []).append(entry)

        return entry.get("findings", [])

    def normalize_results(self, snyk_issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Convert raw Snyk REST API issues into normalized finding dicts.

        Tries SnykNormalizer from scanner_parsers first; falls back to inline
        normalization when the ingestion module is unavailable.

        Args:
            snyk_issues: List of issue objects from the Snyk REST API or mock data.

        Returns:
            List of normalized finding dicts.
        """
        if not snyk_issues:
            return []

        # Build a snyk-test-like JSON structure that SnykNormalizer understands
        snyk_test_payload = self._issues_to_snyk_test_format(snyk_issues)
        raw_bytes = json.dumps(snyk_test_payload).encode()

        try:
            from core.scanner_parsers import SnykNormalizer
            normalizer = SnykNormalizer()
            findings_raw = normalizer.normalize(raw_bytes)
            result = []
            for f in findings_raw:
                if isinstance(f, dict):
                    result.append(f)
                elif hasattr(f, "model_dump"):
                    result.append(f.model_dump())
                elif hasattr(f, "__dict__"):
                    result.append(
                        {k: v for k, v in f.__dict__.items() if not k.startswith("_")}
                    )
                else:
                    result.append({"raw": str(f)})
            return result
        except Exception as exc:
            logger.warning(
                "SnykNormalizer unavailable (%s) — using inline normalization", exc
            )
            return self._inline_normalize(snyk_issues)

    def _issues_to_snyk_test_format(
        self, issues: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Convert Snyk REST API issue objects to the snyk-test JSON format
        that SnykNormalizer expects.
        """
        vulnerabilities = []
        for issue in issues:
            attrs = issue.get("attributes", issue)
            coords = attrs.get("coordinates", [{}])
            first_coord = coords[0] if coords else {}
            representations = first_coord.get("representations", [{}])
            first_rep = representations[0] if representations else {}
            dep = first_rep.get("dependency", {})
            remedies = first_coord.get("remedies", [])
            fix_version = ""
            if remedies:
                desc = remedies[0].get("description", "")
                # Extract version from "Upgrade to pkg@version"
                parts = desc.rsplit("@", 1)
                if len(parts) == 2:
                    fix_version = parts[1].strip()

            problems = attrs.get("problems", [])
            cves = [p["id"] for p in problems if p.get("type") == "vulnerability" and p.get("id", "").startswith("CVE-")]
            classes = attrs.get("classes", [])
            cwes_raw = [c["id"].replace("CWE-", "") for c in classes if c.get("type") == "weakness" and "CWE-" in c.get("id", "")]

            vulnerabilities.append({
                "id": issue.get("id", ""),
                "title": attrs.get("title", "Snyk Finding"),
                "description": attrs.get("description", ""),
                "severity": attrs.get("severity", "medium"),
                "packageName": dep.get("package_name", attrs.get("packageName", "")),
                "version": dep.get("package_version", attrs.get("version", "")),
                "fixedIn": [fix_version] if fix_version else [],
                "identifiers": {
                    "CVE": cves,
                    "CWE": cwes_raw,
                },
                "cvssScore": attrs.get("cvssScore"),
                "url": (problems[0].get("url", "") if problems else ""),
            })

        return {
            "vulnerabilities": vulnerabilities,
            "packageName": "snyk-rest-api",
            "packageManager": "rest",
        }

    def _inline_normalize(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Minimal inline normalizer used when scanner_parsers is unavailable."""
        sev_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        }
        findings = []
        for issue in issues:
            attrs = issue.get("attributes", issue)
            coords = attrs.get("coordinates", [{}])
            first_coord = coords[0] if coords else {}
            representations = first_coord.get("representations", [{}])
            first_rep = representations[0] if representations else {}
            dep = first_rep.get("dependency", {})
            remedies = first_coord.get("remedies", [])
            fix_desc = remedies[0].get("description", "") if remedies else ""

            problems = attrs.get("problems", [])
            cves = [p["id"] for p in problems if p.get("type") == "vulnerability" and p.get("id", "").startswith("CVE-")]
            classes = attrs.get("classes", [])
            cwes = [c["id"] for c in classes if c.get("type") == "weakness"]

            sev = sev_map.get((attrs.get("severity") or "medium").lower(), "medium")
            pkg = dep.get("package_name", attrs.get("packageName", ""))
            ver = dep.get("package_version", attrs.get("version", ""))
            title = attrs.get("title", issue.get("id", "Snyk Finding"))

            findings.append({
                "id": str(uuid.uuid4()),
                "source_tool": "snyk",
                "source_id": issue.get("id", ""),
                "severity": sev,
                "title": f"{title} in {pkg}@{ver}" if pkg else title,
                "description": (attrs.get("description") or "")[:500],
                "recommendation": fix_desc,
                "cve_id": cves[0] if cves else None,
                "cwe_id": cwes[0] if cwes else None,
                "package_name": pkg,
                "package_version": ver,
                "cvss_score": attrs.get("cvssScore"),
                "tags": cves[1:] + cwes[1:],
                "url": (problems[0].get("url", "") if problems else ""),
            })
        return findings

    def get_import_history(self, org_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Return import history for the given org, most recent first.

        The findings list is stripped to keep the response lightweight.

        Args:
            org_id: Organisation identifier.

        Returns:
            List of import summary dicts (without full findings).
        """
        effective_org = (org_id or self._org_id or "default").strip()
        with _get_lock():
            entries = list(_import_history.get(effective_org, []))

        summaries = []
        for e in reversed(entries):
            summary = {k: v for k, v in e.items() if k != "findings"}
            summaries.append(summary)
        return summaries

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
                metadata={"source": "snyk", "import_id": import_id},
            )
            pipeline.run(pipeline_input)
            logger.info(
                "Ingested %d snyk findings into BrainPipeline for org=%s import=%s",
                len(findings), org_id, import_id,
            )
        except Exception as exc:
            # Non-fatal: pipeline ingestion is best-effort
            logger.warning("BrainPipeline ingestion skipped: %s", exc)
