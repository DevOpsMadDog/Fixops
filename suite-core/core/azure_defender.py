"""
ALdeci Azure Defender / Microsoft Defender for Cloud Integration.

Pulls security alerts, secure score, and recommendations from Microsoft Defender
for Cloud via a mocked azure-mgmt-security interface. Normalizes findings to
UnifiedFinding format and stores them for ingestion into the Brain Pipeline.

Usage:
    client = AzureDefenderClient(subscription_id="00000000-0000-0000-0000-000000000000")
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
# Azure Defender severity → normalized severity mapping
# ---------------------------------------------------------------------------
_AZURE_SEVERITY_MAP: Dict[str, str] = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
    "Critical": "critical",
}

# ---------------------------------------------------------------------------
# Mock Azure Defender alerts (realistic format)
# ---------------------------------------------------------------------------
_MOCK_ALERTS: List[Dict[str, Any]] = [
    {
        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Security/locations/centralus/alerts/mock-alert-001",
        "name": "mock-alert-001",
        "type": "Microsoft.Security/Locations/alerts",
        "properties": {
            "alertDisplayName": "Suspicious process executed",
            "description": "A suspicious process was detected running on the virtual machine.",
            "severity": "High",
            "status": "Active",
            "compromisedEntity": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/vm-web-01",
            "resourceIdentifiers": [
                {
                    "type": "AzureResource",
                    "azureResourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/vm-web-01",
                }
            ],
            "alertUri": "https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/mock-alert-001",
            "startTimeUtc": "2026-01-05T10:00:00.000Z",
            "endTimeUtc": "2026-01-05T10:30:00.000Z",
            "systemAlertId": "mock-alert-001",
            "productName": "Azure Security Center",
            "productComponentName": "VM Protection",
            "vendorName": "Microsoft",
            "alertType": "VM_SuspiciousProcess",
            "remediationSteps": [
                "Investigate the process tree on the virtual machine.",
                "Isolate the virtual machine if compromise is confirmed.",
            ],
            "tactics": ["Execution"],
            "techniques": ["T1059"],
            "intent": "Execution",
            "isIncident": False,
            "correlationKey": "mock-corr-001",
            "extendedLinks": [],
            "timeGeneratedUtc": "2026-01-05T10:01:00.000Z",
        },
    },
    {
        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Security/locations/centralus/alerts/mock-alert-002",
        "name": "mock-alert-002",
        "type": "Microsoft.Security/Locations/alerts",
        "properties": {
            "alertDisplayName": "Possible credential theft tool detected",
            "description": "A tool used to dump credentials from memory (e.g., Mimikatz) was detected.",
            "severity": "Critical",
            "status": "Active",
            "compromisedEntity": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/vm-dc-01",
            "resourceIdentifiers": [
                {
                    "type": "AzureResource",
                    "azureResourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/vm-dc-01",
                }
            ],
            "alertUri": "https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/mock-alert-002",
            "startTimeUtc": "2026-01-06T08:00:00.000Z",
            "endTimeUtc": "2026-01-06T08:15:00.000Z",
            "systemAlertId": "mock-alert-002",
            "productName": "Azure Security Center",
            "productComponentName": "VM Protection",
            "vendorName": "Microsoft",
            "alertType": "VM_CredentialTheftTool",
            "remediationSteps": [
                "Immediately isolate the affected domain controller.",
                "Reset all privileged account credentials.",
                "Investigate lateral movement activity.",
            ],
            "tactics": ["CredentialAccess"],
            "techniques": ["T1003"],
            "intent": "CredentialAccess",
            "isIncident": False,
            "correlationKey": "mock-corr-002",
            "extendedLinks": [],
            "timeGeneratedUtc": "2026-01-06T08:01:00.000Z",
        },
    },
    {
        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Security/locations/centralus/alerts/mock-alert-003",
        "name": "mock-alert-003",
        "type": "Microsoft.Security/Locations/alerts",
        "properties": {
            "alertDisplayName": "Storage account with permissive CORS rule",
            "description": "A storage account has a CORS rule that allows any origin, which may lead to unauthorized data access.",
            "severity": "Medium",
            "status": "Active",
            "compromisedEntity": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/data-rg/providers/Microsoft.Storage/storageAccounts/mystorageaccount",
            "resourceIdentifiers": [
                {
                    "type": "AzureResource",
                    "azureResourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/data-rg/providers/Microsoft.Storage/storageAccounts/mystorageaccount",
                }
            ],
            "alertUri": "https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/mock-alert-003",
            "startTimeUtc": "2026-01-07T12:00:00.000Z",
            "endTimeUtc": "2026-01-07T12:00:00.000Z",
            "systemAlertId": "mock-alert-003",
            "productName": "Azure Security Center",
            "productComponentName": "Storage Protection",
            "vendorName": "Microsoft",
            "alertType": "Storage_PermissiveCORS",
            "remediationSteps": [
                "Review and restrict CORS rules on the storage account.",
                "Apply the principle of least privilege to allowed origins.",
            ],
            "tactics": ["InitialAccess"],
            "techniques": ["T1190"],
            "intent": "InitialAccess",
            "isIncident": False,
            "correlationKey": "mock-corr-003",
            "extendedLinks": [],
            "timeGeneratedUtc": "2026-01-07T12:01:00.000Z",
        },
    },
    {
        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Security/locations/centralus/alerts/mock-alert-004",
        "name": "mock-alert-004",
        "type": "Microsoft.Security/Locations/alerts",
        "properties": {
            "alertDisplayName": "Azure Key Vault access from suspicious IP",
            "description": "Key Vault was accessed from an IP address that is not expected for this resource.",
            "severity": "Low",
            "status": "Active",
            "compromisedEntity": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/sec-rg/providers/Microsoft.KeyVault/vaults/my-keyvault",
            "resourceIdentifiers": [
                {
                    "type": "AzureResource",
                    "azureResourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/sec-rg/providers/Microsoft.KeyVault/vaults/my-keyvault",
                }
            ],
            "alertUri": "https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/mock-alert-004",
            "startTimeUtc": "2026-01-08T15:00:00.000Z",
            "endTimeUtc": "2026-01-08T15:05:00.000Z",
            "systemAlertId": "mock-alert-004",
            "productName": "Azure Security Center",
            "productComponentName": "Key Vault Protection",
            "vendorName": "Microsoft",
            "alertType": "KV_AccessFromSuspiciousIP",
            "remediationSteps": [
                "Review Key Vault access logs.",
                "Restrict access using network rules or Private Endpoint.",
            ],
            "tactics": ["Collection"],
            "techniques": ["T1552"],
            "intent": "Collection",
            "isIncident": False,
            "correlationKey": "mock-corr-004",
            "extendedLinks": [],
            "timeGeneratedUtc": "2026-01-08T15:01:00.000Z",
        },
    },
]

# ---------------------------------------------------------------------------
# Mock secure score data
# ---------------------------------------------------------------------------
_MOCK_SECURE_SCORE: Dict[str, Any] = {
    "id": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Security/secureScores/ascScore",
    "name": "ascScore",
    "type": "Microsoft.Security/secureScores",
    "properties": {
        "displayName": "Azure Security Center",
        "score": {
            "max": 100,
            "current": 73.5,
            "percentage": 0.735,
        },
        "weight": 1,
    },
    "is_mock": True,
}

# ---------------------------------------------------------------------------
# Mock recommendations data
# ---------------------------------------------------------------------------
_MOCK_RECOMMENDATIONS: List[Dict[str, Any]] = [
    {
        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Security/assessments/mock-rec-001",
        "name": "mock-rec-001",
        "type": "Microsoft.Security/assessments",
        "properties": {
            "displayName": "MFA should be enabled for accounts with owner permissions on your subscription",
            "status": {"code": "Unhealthy", "description": "MFA is not enabled."},
            "description": "Multi-factor authentication (MFA) should be enabled for all subscription accounts with owner permissions to prevent breach of accounts.",
            "severity": "High",
            "remediationDescription": "Enable MFA for all subscription owner accounts via Azure Active Directory.",
            "category": "IdentityAndAccess",
            "userImpact": "High",
            "implementationEffort": "Low",
            "threats": ["IdentityTheft", "AccountBreach"],
            "resourceDetails": {
                "source": "Azure",
                "id": "/subscriptions/00000000-0000-0000-0000-000000000000",
            },
        },
    },
    {
        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Security/assessments/mock-rec-002",
        "name": "mock-rec-002",
        "type": "Microsoft.Security/assessments",
        "properties": {
            "displayName": "Storage accounts should restrict network access",
            "status": {"code": "Unhealthy", "description": "Network access is not restricted."},
            "description": "Audit unrestricted network access in your storage account firewall settings. Instead, configure network rules so only applications from allowed networks can access the storage account.",
            "severity": "Medium",
            "remediationDescription": "Configure network rules to restrict access to storage accounts.",
            "category": "Data",
            "userImpact": "High",
            "implementationEffort": "Moderate",
            "threats": ["DataExfiltration", "DataSpillage"],
            "resourceDetails": {
                "source": "Azure",
                "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/data-rg/providers/Microsoft.Storage/storageAccounts/mystorageaccount",
            },
        },
    },
    {
        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Security/assessments/mock-rec-003",
        "name": "mock-rec-003",
        "type": "Microsoft.Security/assessments",
        "properties": {
            "displayName": "Vulnerabilities in security configuration on your machines should be remediated",
            "status": {"code": "Unhealthy", "description": "Security misconfigurations detected."},
            "description": "Servers that do not satisfy the configured baseline will be monitored by Azure Security Center as recommendations.",
            "severity": "Low",
            "remediationDescription": "Apply the recommended security configuration baselines.",
            "category": "Compute",
            "userImpact": "Low",
            "implementationEffort": "Moderate",
            "threats": ["MissingCoverageForVulnerabilities"],
            "resourceDetails": {
                "source": "Azure",
                "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod-rg",
            },
        },
    },
]


# ---------------------------------------------------------------------------
# AzureDefenderClient
# ---------------------------------------------------------------------------


class AzureDefenderClient:
    """
    Client for Microsoft Defender for Cloud (Azure Security Center) ingestion.

    Uses a mocked azure-mgmt-security interface — no real Azure SDK dependency
    required. Falls back to realistic mock data when no credentials are configured
    so that the rest of the pipeline can be exercised without Azure access.
    """

    #: Default Azure cloud environment
    DEFAULT_CLOUD = "AzurePublicCloud"

    def __init__(
        self,
        subscription_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> None:
        self._subscription_id: str = (
            subscription_id
            or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
            or ""
        ).strip()
        self._tenant_id: str = (
            tenant_id
            or os.environ.get("AZURE_TENANT_ID", "")
            or ""
        ).strip()
        self._client_id: str = (
            client_id
            or os.environ.get("AZURE_CLIENT_ID", "")
            or ""
        ).strip()
        self._client_secret: str = (
            client_secret
            or os.environ.get("AZURE_CLIENT_SECRET", "")
            or ""
        ).strip()

    # ------------------------------------------------------------------
    # Configuration check
    # ------------------------------------------------------------------

    def is_configured(self) -> bool:
        """Return True if Azure credentials are set."""
        return bool(
            self._subscription_id
            and self._tenant_id
            and self._client_id
            and self._client_secret
        )

    # ------------------------------------------------------------------
    # Public API methods (mock-safe)
    # ------------------------------------------------------------------

    def get_alerts(self, severity_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Pull security alerts from Microsoft Defender for Cloud.

        Args:
            severity_filter: Optional severity to filter by (High, Medium, Low, Critical).

        Returns:
            List of raw alert dicts. Returns mock data when unconfigured.
        """
        if not self.is_configured():
            logger.warning(
                "Azure credentials not configured — returning mock Defender alerts. "
                "Set AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID, "
                "AZURE_CLIENT_SECRET for real data."
            )
            alerts = list(_MOCK_ALERTS)
            if severity_filter:
                alerts = [
                    a for a in alerts
                    if a.get("properties", {}).get("severity", "").lower()
                    == severity_filter.lower()
                ]
            return alerts

        try:
            client = self._make_security_client()
            raw_alerts = list(client.alerts.list())
            alerts = []
            for a in raw_alerts:
                alert_dict = a.as_dict() if hasattr(a, "as_dict") else dict(a)
                if severity_filter:
                    alert_sev = alert_dict.get("properties", {}).get("severity", "")
                    if alert_sev.lower() != severity_filter.lower():
                        continue
                alerts.append(alert_dict)
            return alerts
        except Exception as exc:
            logger.error("get_alerts failed: %s", exc, exc_info=True)
            raise RuntimeError(f"Azure Defender get_alerts failed: {exc}") from exc

    def get_secure_score(self) -> Dict[str, Any]:
        """
        Retrieve the Azure Secure Score for the subscription.

        Returns:
            Dict with score details. Returns mock data when unconfigured.
        """
        if not self.is_configured():
            logger.warning(
                "Azure credentials not configured — returning mock secure score."
            )
            return dict(_MOCK_SECURE_SCORE)

        try:
            client = self._make_security_client()
            score = client.secure_scores.get("ascScore")
            result = score.as_dict() if hasattr(score, "as_dict") else dict(score)
            result["is_mock"] = False
            return result
        except Exception as exc:
            logger.error("get_secure_score failed: %s", exc, exc_info=True)
            raise RuntimeError(f"Azure Defender get_secure_score failed: {exc}") from exc

    def get_recommendations(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieve security recommendations from Microsoft Defender for Cloud.

        Args:
            category: Optional category filter (e.g. IdentityAndAccess, Compute, Data).

        Returns:
            List of recommendation dicts. Returns mock data when unconfigured.
        """
        if not self.is_configured():
            logger.warning(
                "Azure credentials not configured — returning mock recommendations."
            )
            recs = list(_MOCK_RECOMMENDATIONS)
            if category:
                recs = [
                    r for r in recs
                    if r.get("properties", {}).get("category", "").lower()
                    == category.lower()
                ]
            return recs

        try:
            client = self._make_security_client()
            raw_recs = list(client.assessments.list("/subscriptions/" + self._subscription_id))
            recs = []
            for r in raw_recs:
                rec_dict = r.as_dict() if hasattr(r, "as_dict") else dict(r)
                if category:
                    rec_cat = rec_dict.get("properties", {}).get("category", "")
                    if rec_cat.lower() != category.lower():
                        continue
                recs.append(rec_dict)
            return recs
        except Exception as exc:
            logger.error("get_recommendations failed: %s", exc, exc_info=True)
            raise RuntimeError(f"Azure Defender get_recommendations failed: {exc}") from exc

    def import_findings(self, org_id: str = "default") -> Dict[str, Any]:
        """
        Pull alerts from Defender for Cloud, normalize to UnifiedFinding format,
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
            raw_alerts = self.get_alerts()
            # FIX-1: fold severity counting into normalize — single pass, no second loop.
            findings, sev_counts = self._normalize_with_counts(raw_alerts)

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

            # FIX-2: batch-emit all findings in one try/except — avoids per-event
            # exception-handler overhead (CPython try block setup cost) at high volume.
            try:
                from core.trustgraph_event_bus import get_event_bus
                bus = get_event_bus()
                events = [
                    {
                        "org_id": org_id,
                        "engine": "azure_defender",
                        "id": f.get("id") or f.get("finding_id"),
                        "cve_id": f.get("cve_id"),
                        "severity": f.get("severity", "unknown"),
                        "title": f.get("title") or f.get("name"),
                        "asset_id": f.get("asset_id"),
                        "cvss": f.get("cvss"),
                        "epss": f.get("epss"),
                        "is_mock": f.get("is_mock", is_mock),
                        **f,
                    }
                    for f in findings
                ]
                for ev in events:
                    bus.emit("finding.created", ev)
            except Exception:
                pass

        except Exception as exc:
            logger.error(
                "Azure Defender import failed for org=%s: %s", org_id, exc, exc_info=True
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

    def normalize(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalize Azure Defender alerts to UnifiedFinding dicts.

        Args:
            alerts: List of raw Azure Defender alert dicts.

        Returns:
            List of normalized finding dicts.
        """
        if not alerts:
            return []
        findings, _ = self._normalize_with_counts(alerts)
        return findings

    def _normalize_with_counts(
        self, alerts: List[Dict[str, Any]]
    ) -> "tuple[List[Dict[str, Any]], Dict[str, int]]":
        """Single-pass normalize + severity count.

        FIX-1: eliminates the second O(N) severity-counting loop in import_findings.
        FIX-3: pre-builds tags list once via extend instead of two list concatenations.
        """
        normalized: List[Dict[str, Any]] = []
        sev_counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        for alert in alerts:
            props = alert.get("properties", {})
            severity_label = props.get("severity", "Informational")
            sev = _AZURE_SEVERITY_MAP.get(severity_label, "info")

            # FIX-1: accumulate counts in same pass.
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

            # Resource info
            resource_identifiers = props.get("resourceIdentifiers", [])
            primary_resource = resource_identifiers[0] if resource_identifiers else {}
            resource_id = primary_resource.get("azureResourceId", "")
            resource_type = primary_resource.get("type", "AzureResource")

            # Remediation
            remediation_steps = props.get("remediationSteps", [])
            recommendation = " ".join(remediation_steps) if remediation_steps else ""

            # MITRE tactics/techniques
            tactics = props.get("tactics", [])
            techniques = props.get("techniques", [])

            # FIX-3: single list allocation with extend instead of tactics + techniques
            # which allocates a fresh list per alert.
            tags: List[str] = []
            tags.extend(tactics)
            tags.extend(techniques)

            normalized.append({
                "id": str(uuid.uuid4()),
                "source_tool": "azure_defender",
                "source_id": alert.get("id", ""),
                "alert_name": alert.get("name", ""),
                "severity": sev,
                "title": props.get("alertDisplayName", "Azure Defender Alert"),
                "description": props.get("description", ""),
                "recommendation": recommendation,
                "status": props.get("status", ""),
                "alert_type": props.get("alertType", ""),
                "product_name": props.get("productName", "Microsoft Defender for Cloud"),
                "product_component": props.get("productComponentName", ""),
                "subscription_id": self._subscription_id,
                "resource_id": resource_id,
                "resource_type": resource_type,
                "compromised_entity": props.get("compromisedEntity", ""),
                "tactics": tactics,
                "techniques": techniques,
                "intent": props.get("intent", ""),
                "is_incident": props.get("isIncident", False),
                "start_time": props.get("startTimeUtc", ""),
                "end_time": props.get("endTimeUtc", ""),
                "time_generated": props.get("timeGeneratedUtc", ""),
                "tags": tags,
            })
        return normalized, sev_counts

    def _inline_normalize(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Legacy entry-point — delegates to _normalize_with_counts."""
        findings, _ = self._normalize_with_counts(alerts)
        return findings

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

    def _make_security_client(self):
        """
        Build an azure-mgmt-security SecurityCenter client.

        Raises RuntimeError if azure-mgmt-security is not installed.
        """
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.security import SecurityCenter
        except ImportError as exc:
            raise RuntimeError(
                "azure-mgmt-security is not installed. Install it with: "
                "pip install azure-mgmt-security azure-identity. "
                "Without these packages, only mock data is available."
            ) from exc

        credential = ClientSecretCredential(
            tenant_id=self._tenant_id,
            client_id=self._client_id,
            client_secret=self._client_secret,
        )
        return SecurityCenter(credential, self._subscription_id)

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
                metadata={"source": "azure_defender", "import_id": import_id},
            )
            pipeline.run(pipeline_input)
            logger.info(
                "Ingested %d Azure Defender findings into BrainPipeline for org=%s import=%s",
                len(findings), org_id, import_id,
            )
        except Exception as exc:
            # Non-fatal: pipeline ingestion is best-effort
            logger.warning("BrainPipeline ingestion skipped: %s", exc)
