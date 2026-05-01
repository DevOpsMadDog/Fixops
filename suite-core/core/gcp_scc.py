"""
ALdeci GCP Security Command Center Integration — Pull findings from GCP SCC.

Connects to GCP Security Command Center via a mocked google-cloud-securitycenter
interface, normalizes findings from GCP SCC format, and stores them for ingestion
into the Brain Pipeline.

Usage:
    client = GCPSecurityClient(project_id="my-project")
    if client.is_configured():
        result = client.import_findings(org_id="acme")

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""

from __future__ import annotations

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
# GCP SCC severity → normalized severity mapping
# ---------------------------------------------------------------------------
_GCP_SEVERITY_MAP: Dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "info",
    "SEVERITY_UNSPECIFIED": "info",
}

# ---------------------------------------------------------------------------
# Mock GCP Security Command Center findings (realistic SCC format)
# ---------------------------------------------------------------------------
_MOCK_FINDINGS: List[Dict[str, Any]] = [
    {
        "name": "organizations/123456789/sources/1234567890/findings/mock-001",
        "parent": "organizations/123456789/sources/1234567890",
        "resource_name": "//cloudresourcemanager.googleapis.com/projects/my-gcp-project",
        "state": "ACTIVE",
        "category": "PUBLIC_BUCKET_ACL",
        "external_uri": "https://console.cloud.google.com/storage/browser/my-public-bucket",
        "source_properties": {
            "ReactivationCount": 0,
            "ExceptionInstructions": "Add the security mark to be ignored.",
            "SeverityLevel": "High",
            "ResourcePath": "//storage.googleapis.com/my-public-bucket",
        },
        "security_marks": {"name": "organizations/123456789/sources/1234567890/findings/mock-001/securityMarks"},
        "event_time": "2026-01-01T00:00:00.000Z",
        "create_time": "2026-01-01T00:00:00.000Z",
        "severity": "HIGH",
        "finding_class": "VULNERABILITY",
        "description": "A GCS bucket has public access control lists (ACLs), "
                       "allowing public access to its content.",
        "next_steps": "Remove public ACLs from the bucket and restrict access "
                      "using IAM policies.",
        "canonical_name": "organizations/123456789/sources/1234567890/findings/mock-001",
        "mute": "UNMUTED",
        "indicator": {},
        "vulnerability": {},
        "compliances": [{"standard": "CIS GCP", "version": "1.3", "ids": ["5.1"]}],
        "contacts": {},
        "processes": [],
        "resource": {
            "name": "//storage.googleapis.com/my-public-bucket",
            "display_name": "my-public-bucket",
            "type": "google.cloud.storage.Bucket",
            "project": "projects/12345678",
            "project_display_name": "my-gcp-project",
            "parent": "//cloudresourcemanager.googleapis.com/projects/my-gcp-project",
            "parent_display_name": "my-gcp-project",
        },
    },
    {
        "name": "organizations/123456789/sources/1234567890/findings/mock-002",
        "parent": "organizations/123456789/sources/1234567890",
        "resource_name": "//container.googleapis.com/projects/my-gcp-project/clusters/prod-cluster",
        "state": "ACTIVE",
        "category": "WEB_UI_ENABLED",
        "external_uri": "https://console.cloud.google.com/kubernetes/clusters",
        "source_properties": {
            "ReactivationCount": 0,
            "SeverityLevel": "Critical",
            "ResourcePath": "//container.googleapis.com/projects/my-gcp-project/clusters/prod-cluster",
        },
        "security_marks": {"name": "organizations/123456789/sources/1234567890/findings/mock-002/securityMarks"},
        "event_time": "2026-01-02T00:00:00.000Z",
        "create_time": "2026-01-02T00:00:00.000Z",
        "severity": "CRITICAL",
        "finding_class": "MISCONFIGURATION",
        "description": "The Kubernetes web UI (dashboard) is enabled on the cluster. "
                       "The dashboard can expose the cluster to attackers.",
        "next_steps": "Disable the Kubernetes dashboard by deleting the kubernetes-dashboard "
                      "deployment from the kube-system namespace.",
        "canonical_name": "organizations/123456789/sources/1234567890/findings/mock-002",
        "mute": "UNMUTED",
        "indicator": {},
        "vulnerability": {},
        "compliances": [{"standard": "CIS GKE", "version": "1.2", "ids": ["6.10.1"]}],
        "contacts": {},
        "processes": [],
        "resource": {
            "name": "//container.googleapis.com/projects/my-gcp-project/clusters/prod-cluster",
            "display_name": "prod-cluster",
            "type": "google.container.v1.Cluster",
            "project": "projects/12345678",
            "project_display_name": "my-gcp-project",
            "parent": "//cloudresourcemanager.googleapis.com/projects/my-gcp-project",
            "parent_display_name": "my-gcp-project",
        },
    },
    {
        "name": "organizations/123456789/sources/1234567890/findings/mock-003",
        "parent": "organizations/123456789/sources/1234567890",
        "resource_name": "//cloudresourcemanager.googleapis.com/projects/my-gcp-project",
        "state": "ACTIVE",
        "category": "MFA_NOT_ENFORCED",
        "external_uri": "https://console.cloud.google.com/iam-admin/iam",
        "source_properties": {
            "ReactivationCount": 0,
            "SeverityLevel": "Medium",
            "ResourcePath": "//cloudresourcemanager.googleapis.com/projects/my-gcp-project",
        },
        "security_marks": {"name": "organizations/123456789/sources/1234567890/findings/mock-003/securityMarks"},
        "event_time": "2026-01-03T00:00:00.000Z",
        "create_time": "2026-01-03T00:00:00.000Z",
        "severity": "MEDIUM",
        "finding_class": "VULNERABILITY",
        "description": "Multi-factor authentication (MFA) is not enforced for "
                       "one or more users in this GCP project.",
        "next_steps": "Enable MFA for all users. Use Cloud Identity to enforce "
                      "2-Step Verification policies.",
        "canonical_name": "organizations/123456789/sources/1234567890/findings/mock-003",
        "mute": "UNMUTED",
        "indicator": {},
        "vulnerability": {},
        "compliances": [{"standard": "CIS GCP", "version": "1.3", "ids": ["1.2"]}],
        "contacts": {},
        "processes": [],
        "resource": {
            "name": "//cloudresourcemanager.googleapis.com/projects/my-gcp-project",
            "display_name": "my-gcp-project",
            "type": "google.cloud.resourcemanager.Project",
            "project": "projects/12345678",
            "project_display_name": "my-gcp-project",
            "parent": "//cloudresourcemanager.googleapis.com/organizations/123456789",
            "parent_display_name": "my-org",
        },
    },
    {
        "name": "organizations/123456789/sources/1234567890/findings/mock-004",
        "parent": "organizations/123456789/sources/1234567890",
        "resource_name": "//compute.googleapis.com/projects/my-gcp-project/global/firewalls/allow-all-ingress",
        "state": "ACTIVE",
        "category": "OPEN_FIREWALL",
        "external_uri": "https://console.cloud.google.com/networking/firewalls",
        "source_properties": {
            "ReactivationCount": 0,
            "SeverityLevel": "High",
            "AllowedIpRange": "0.0.0.0/0",
        },
        "security_marks": {"name": "organizations/123456789/sources/1234567890/findings/mock-004/securityMarks"},
        "event_time": "2026-01-04T00:00:00.000Z",
        "create_time": "2026-01-04T00:00:00.000Z",
        "severity": "HIGH",
        "finding_class": "MISCONFIGURATION",
        "description": "A firewall rule allows unrestricted ingress access from 0.0.0.0/0. "
                       "This exposes the resources behind it to the internet.",
        "next_steps": "Update the firewall rule to restrict ingress access to specific "
                      "IP ranges and ports.",
        "canonical_name": "organizations/123456789/sources/1234567890/findings/mock-004",
        "mute": "UNMUTED",
        "indicator": {},
        "vulnerability": {},
        "compliances": [{"standard": "CIS GCP", "version": "1.3", "ids": ["3.6", "3.7"]}],
        "contacts": {},
        "processes": [],
        "resource": {
            "name": "//compute.googleapis.com/projects/my-gcp-project/global/firewalls/allow-all-ingress",
            "display_name": "allow-all-ingress",
            "type": "google.compute.Firewall",
            "project": "projects/12345678",
            "project_display_name": "my-gcp-project",
            "parent": "//cloudresourcemanager.googleapis.com/projects/my-gcp-project",
            "parent_display_name": "my-gcp-project",
        },
    },
]

_MOCK_SOURCES: List[Dict[str, Any]] = [
    {
        "name": "organizations/123456789/sources/1234567890",
        "display_name": "Security Health Analytics",
        "description": "Managed vulnerability scanning service from GCP Security Command Center.",
        "canonical_name": "organizations/123456789/sources/1234567890",
    },
    {
        "name": "organizations/123456789/sources/9876543210",
        "display_name": "Event Threat Detection",
        "description": "GCP-managed service detecting threats in your GCP environment.",
        "canonical_name": "organizations/123456789/sources/9876543210",
    },
    {
        "name": "organizations/123456789/sources/1111111111",
        "display_name": "Container Threat Detection",
        "description": "Runtime threat detection for GKE containers.",
        "canonical_name": "organizations/123456789/sources/1111111111",
    },
]

_MOCK_ASSETS: List[Dict[str, Any]] = [
    {
        "name": "organizations/123456789/assets/asset-001",
        "security_center_properties": {
            "resource_name": "//cloudresourcemanager.googleapis.com/projects/my-gcp-project",
            "resource_type": "google.cloud.resourcemanager.Project",
            "resource_display_name": "my-gcp-project",
            "resource_project": "projects/12345678",
            "resource_project_display_name": "my-gcp-project",
        },
        "resource_properties": {
            "projectId": "my-gcp-project",
            "projectNumber": "12345678",
            "lifecycleState": "ACTIVE",
        },
        "security_marks": {"name": "organizations/123456789/assets/asset-001/securityMarks"},
        "create_time": "2025-06-01T00:00:00.000Z",
        "update_time": "2026-01-10T00:00:00.000Z",
        "canonical_name": "organizations/123456789/assets/asset-001",
    },
    {
        "name": "organizations/123456789/assets/asset-002",
        "security_center_properties": {
            "resource_name": "//storage.googleapis.com/my-public-bucket",
            "resource_type": "google.cloud.storage.Bucket",
            "resource_display_name": "my-public-bucket",
            "resource_project": "projects/12345678",
            "resource_project_display_name": "my-gcp-project",
        },
        "resource_properties": {
            "name": "my-public-bucket",
            "location": "US",
            "storageClass": "STANDARD",
        },
        "security_marks": {"name": "organizations/123456789/assets/asset-002/securityMarks"},
        "create_time": "2025-07-01T00:00:00.000Z",
        "update_time": "2026-01-10T00:00:00.000Z",
        "canonical_name": "organizations/123456789/assets/asset-002",
    },
    {
        "name": "organizations/123456789/assets/asset-003",
        "security_center_properties": {
            "resource_name": "//container.googleapis.com/projects/my-gcp-project/clusters/prod-cluster",
            "resource_type": "google.container.v1.Cluster",
            "resource_display_name": "prod-cluster",
            "resource_project": "projects/12345678",
            "resource_project_display_name": "my-gcp-project",
        },
        "resource_properties": {
            "name": "prod-cluster",
            "location": "us-central1",
            "status": "RUNNING",
        },
        "security_marks": {"name": "organizations/123456789/assets/asset-003/securityMarks"},
        "create_time": "2025-08-01T00:00:00.000Z",
        "update_time": "2026-01-10T00:00:00.000Z",
        "canonical_name": "organizations/123456789/assets/asset-003",
    },
]


# ---------------------------------------------------------------------------
# GCPSecurityClient
# ---------------------------------------------------------------------------


class GCPSecurityClient:
    """
    Client for GCP Security Command Center findings ingestion.

    Uses a mocked google-cloud-securitycenter interface — no real GCP SDK
    dependency required. Falls back to realistic mock data when no credentials
    are configured so that the rest of the pipeline can be exercised without
    GCP access.
    """

    #: Default GCP organization ID placeholder
    DEFAULT_ORG_ID = "123456789"

    def __init__(
        self,
        project_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        credentials_file: Optional[str] = None,
    ) -> None:
        self._project_id: str = (
            project_id
            or os.environ.get("GCP_PROJECT_ID", "")
            or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
            or ""
        ).strip()
        self._organization_id: str = (
            organization_id
            or os.environ.get("GCP_ORGANIZATION_ID", "")
            or self.DEFAULT_ORG_ID
        ).strip()
        self._credentials_file: str = (
            credentials_file
            or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
            or ""
        ).strip()

    # ------------------------------------------------------------------
    # Configuration check
    # ------------------------------------------------------------------

    def is_configured(self) -> bool:
        """Return True if GCP credentials and project are configured."""
        return bool(self._project_id and self._credentials_file)

    # ------------------------------------------------------------------
    # Public API methods (mock-safe)
    # ------------------------------------------------------------------

    def get_findings(
        self, filters: Optional[str] = None, source_id: str = "-"
    ) -> List[Dict[str, Any]]:
        """
        Pull findings from GCP Security Command Center.

        Args:
            filters: SCC filter string (e.g. 'severity="HIGH" AND state="ACTIVE"').
                     Passed through to ListFindings when credentials are real.
            source_id: SCC source ID to list findings from. Defaults to '-' (all sources).

        Returns:
            List of raw SCC finding dicts. Returns mock data when unconfigured.
        """
        if not self.is_configured():
            logger.warning(
                "GCP credentials not configured — returning mock SCC findings. "
                "Set GCP_PROJECT_ID and GOOGLE_APPLICATION_CREDENTIALS for real data."
            )
            return list(_MOCK_FINDINGS)

        try:
            client = self._make_scc_client()
            parent = f"organizations/{self._organization_id}/sources/{source_id}"
            request: Dict[str, Any] = {"parent": parent}
            if filters:
                request["filter"] = filters

            findings: List[Dict[str, Any]] = []
            for result in client.list_findings(request=request):
                finding = result.finding
                findings.append(self._finding_to_dict(finding))
            return findings
        except Exception as exc:
            logger.error("get_findings failed: %s", exc, exc_info=True)
            raise RuntimeError(f"GCP SCC get_findings failed: {exc}") from exc

    def get_sources(self) -> List[Dict[str, Any]]:
        """
        Retrieve Security Command Center sources.

        Returns:
            List of source dicts. Returns mock data when unconfigured.
        """
        if not self.is_configured():
            logger.warning(
                "GCP credentials not configured — returning mock SCC sources."
            )
            return list(_MOCK_SOURCES)

        try:
            client = self._make_scc_client()
            parent = f"organizations/{self._organization_id}"
            sources: List[Dict[str, Any]] = []
            for source in client.list_sources(request={"parent": parent}):
                sources.append({
                    "name": source.name,
                    "display_name": source.display_name,
                    "description": source.description,
                    "canonical_name": getattr(source, "canonical_name", source.name),
                })
            return sources
        except Exception as exc:
            logger.error("get_sources failed: %s", exc, exc_info=True)
            raise RuntimeError(f"GCP SCC get_sources failed: {exc}") from exc

    def get_assets(self) -> List[Dict[str, Any]]:
        """
        Retrieve assets from Security Command Center.

        Returns:
            List of asset dicts. Returns mock data when unconfigured.
        """
        if not self.is_configured():
            logger.warning(
                "GCP credentials not configured — returning mock SCC assets."
            )
            return list(_MOCK_ASSETS)

        try:
            client = self._make_scc_client()
            parent = f"organizations/{self._organization_id}"
            assets: List[Dict[str, Any]] = []
            for result in client.list_assets(request={"parent": parent}):
                asset = result.asset
                assets.append({
                    "name": asset.name,
                    "security_center_properties": {
                        "resource_name": asset.security_center_properties.resource_name,
                        "resource_type": asset.security_center_properties.resource_type,
                        "resource_display_name": asset.security_center_properties.resource_display_name,
                        "resource_project": asset.security_center_properties.resource_project,
                        "resource_project_display_name": asset.security_center_properties.resource_project_display_name,
                    },
                    "create_time": str(asset.create_time),
                    "update_time": str(asset.update_time),
                    "canonical_name": getattr(asset, "canonical_name", asset.name),
                })
            return assets
        except Exception as exc:
            logger.error("get_assets failed: %s", exc, exc_info=True)
            raise RuntimeError(f"GCP SCC get_assets failed: {exc}") from exc

    def import_findings(self, org_id: str = "default") -> Dict[str, Any]:
        """
        Pull findings from GCP SCC, normalize to UnifiedFinding format,
        store in history, and optionally push into the Brain Pipeline.

        Args:
            org_id: Organisation identifier for multi-tenancy.

        Returns:
            Summary dict with import_id, findings_count, severity breakdown, etc.
        """
        import_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        is_mock = not self.is_configured()

        try:
            raw_findings = self.get_findings()
            findings = self.normalize(raw_findings)

            sev_counts: Dict[str, int] = {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
            }
            for f in findings:
                sev = (f.get("severity") or "info").lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            entry: Dict[str, Any] = {
                "import_id": import_id,
                "org_id": org_id,
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "status": "completed",
                "is_mock": is_mock,
                "findings_count": len(findings),
                "severity_breakdown": sev_counts,
                "findings": findings,
            }

            self._try_ingest_to_pipeline(findings, org_id, import_id)

            # Emit each normalized finding to the TrustGraph event bus
            try:
                from core.trustgraph_event_bus import get_event_bus
                bus = get_event_bus()
                for f in findings:
                    bus.emit("finding.created", {
                        "org_id": org_id,
                        "engine": "gcp_scc",
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
            logger.error(
                "GCP SCC import failed for org=%s: %s", org_id, exc, exc_info=True
            )
            entry = {
                "import_id": import_id,
                "org_id": org_id,
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
            _import_history.setdefault(org_id, []).append(entry)

        return entry

    def normalize(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalize GCP SCC findings to UnifiedFinding dicts.

        Falls back to inline normalization so this module works standalone.

        Args:
            findings: List of raw GCP SCC finding dicts.

        Returns:
            List of normalized finding dicts.
        """
        if not findings:
            return []

        return self._inline_normalize(findings)

    def _inline_normalize(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Minimal inline GCP SCC normalizer."""
        normalized = []
        for finding in findings:
            severity_label = (finding.get("severity") or "SEVERITY_UNSPECIFIED").upper()
            sev = _GCP_SEVERITY_MAP.get(severity_label, "info")

            # Resource info
            resource = finding.get("resource", {})
            resource_type = resource.get("type", "")
            resource_name = resource.get("name", finding.get("resource_name", ""))
            resource_display_name = resource.get("display_name", "")
            project_display_name = resource.get("project_display_name", "")

            # Compliance
            compliances = finding.get("compliances", [])
            compliance_standards = [
                f"{c.get('standard', '')} {c.get('version', '')}".strip()
                for c in compliances
            ]

            normalized.append({
                "id": str(uuid.uuid4()),
                "source_tool": "gcp_security_command_center",
                "source_id": finding.get("name", ""),
                "severity": sev,
                "title": finding.get("category", "GCP SCC Finding"),
                "description": finding.get("description", ""),
                "recommendation": finding.get("next_steps", ""),
                "gcp_project_id": project_display_name,
                "gcp_organization_id": self._organization_id,
                "resource_type": resource_type,
                "resource_name": resource_name,
                "resource_display_name": resource_display_name,
                "finding_class": finding.get("finding_class", ""),
                "category": finding.get("category", ""),
                "state": finding.get("state", ""),
                "mute": finding.get("mute", "UNMUTED"),
                "compliance_standards": compliance_standards,
                "external_uri": finding.get("external_uri", ""),
                "event_time": finding.get("event_time", ""),
                "create_time": finding.get("create_time", ""),
                "tags": [finding.get("finding_class", ""), finding.get("category", "")],
            })
        return normalized

    def get_import_history(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """
        Return import history for the given org, most recent first.

        The findings list is stripped to keep the response lightweight.

        Args:
            org_id: Organisation identifier.

        Returns:
            List of import summary dicts (without full findings).
        """
        with _get_lock():
            entries = list(_import_history.get(org_id, []))

        summaries = []
        for e in reversed(entries):
            summary = {k: v for k, v in e.items() if k != "findings"}
            summaries.append(summary)
        return summaries

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_scc_client(self):
        """
        Build a google-cloud-securitycenter client.

        Raises RuntimeError if the SDK is not installed (expected in test environments).
        """
        try:
            from google.cloud import securitycenter
        except ImportError as exc:
            raise RuntimeError(
                "google-cloud-securitycenter is not installed. "
                "Install it with: pip install google-cloud-securitycenter. "
                "Without the SDK, only mock data is available."
            ) from exc

        kwargs: Dict[str, Any] = {}
        if self._credentials_file:
            from google.oauth2 import service_account
            kwargs["credentials"] = service_account.Credentials.from_service_account_file(
                self._credentials_file
            )

        return securitycenter.SecurityCenterClient(**kwargs)

    def _finding_to_dict(self, finding: Any) -> Dict[str, Any]:
        """Convert a GCP SCC Finding proto object to a plain dict."""
        try:
            resource = finding.resource
            resource_dict = {
                "name": resource.name,
                "display_name": resource.display_name,
                "type": resource.type_,
                "project": resource.project,
                "project_display_name": resource.project_display_name,
                "parent": resource.parent,
                "parent_display_name": resource.parent_display_name,
            }
        except Exception:
            resource_dict = {}

        return {
            "name": finding.name,
            "parent": finding.parent,
            "resource_name": finding.resource_name,
            "state": str(finding.state),
            "category": finding.category,
            "external_uri": finding.external_uri,
            "event_time": str(finding.event_time),
            "create_time": str(finding.create_time),
            "severity": str(finding.severity),
            "finding_class": str(finding.finding_class),
            "description": finding.description,
            "next_steps": finding.next_steps,
            "canonical_name": getattr(finding, "canonical_name", finding.name),
            "mute": str(finding.mute),
            "resource": resource_dict,
        }

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
                metadata={"source": "gcp_security_command_center", "import_id": import_id},
            )
            pipeline.run(pipeline_input)
            logger.info(
                "Ingested %d GCP SCC findings into BrainPipeline for org=%s import=%s",
                len(findings), org_id, import_id,
            )
        except Exception as exc:
            # Non-fatal: pipeline ingestion is best-effort
            logger.warning("BrainPipeline ingestion skipped: %s", exc)
