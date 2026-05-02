"""
ALdeci AWS Security Hub Integration — Pull findings from AWS Security Hub.

Connects to AWS Security Hub via the real boto3 SDK, normalizes findings
from AWS Security Finding Format (ASFF), and stores them for ingestion into
the Brain Pipeline.

NO MOCK DATA. When boto3 is missing or AWS credentials are not configured,
all endpoints return an empty result with a warning log. Tests must use
``botocore.stub.Stubber`` to inject responses.

Usage:
    client = AWSSecurityHubClient(region="us-east-1")
    if client.is_configured():
        result = client.import_findings(org_id="acme")

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
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
# TrustGraph event-bus wiring (optional, never blocks)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Emit an event to the TrustGraph event bus. Never raises."""
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
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# In-memory import history store (keyed by org_id) — thread-safe
# ---------------------------------------------------------------------------
_import_history: Dict[str, List[Dict[str, Any]]] = {}
_history_lock = threading.RLock()


def _get_lock() -> threading.RLock:
    """Return the module-level RLock (preserved API for legacy callers)."""
    return _history_lock


# ---------------------------------------------------------------------------
# ASFF severity → normalized severity mapping
# ---------------------------------------------------------------------------
_ASFF_SEVERITY_MAP: Dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "info",
}


# ---------------------------------------------------------------------------
# AWSSecurityHubClient
# ---------------------------------------------------------------------------


class AWSSecurityHubClient:
    """
    Client for AWS Security Hub findings ingestion.

    Uses real boto3 SDK. When boto3 is missing OR AWS credentials are not
    configured (no AWS_ACCESS_KEY_ID and no boto3 default credential chain),
    every public method returns an empty result and logs a warning.
    NEVER returns mock/synthetic findings.
    """

    #: Default AWS region
    DEFAULT_REGION = "us-east-1"

    def __init__(
        self,
        region: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
    ) -> None:
        self._region: str = (
            region
            or os.environ.get("AWS_DEFAULT_REGION", "")
            or os.environ.get("AWS_REGION", "")
            or self.DEFAULT_REGION
        ).strip()
        self._access_key: str = (
            access_key
            or os.environ.get("AWS_ACCESS_KEY_ID", "")
            or ""
        ).strip()
        self._secret_key: str = (
            secret_key
            or os.environ.get("AWS_SECRET_ACCESS_KEY", "")
            or ""
        ).strip()
        # Cached client used by tests via Stubber injection
        self._client: Any = None

    # ------------------------------------------------------------------
    # Configuration check
    # ------------------------------------------------------------------

    def is_configured(self) -> bool:
        """Return True iff AWS credentials are usable.

        Either explicit access/secret pair OR boto3 default credential chain
        (env, profile, IAM role) resolves successfully.
        """
        if self._access_key and self._secret_key:
            return True
        # Check boto3 default credential chain
        try:
            import boto3  # type: ignore
            session = boto3.Session(region_name=self._region)
            return session.get_credentials() is not None
        except ImportError:
            return False
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------
    # Public API methods (real boto3 only)
    # ------------------------------------------------------------------

    def get_findings(
        self, filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Pull findings from AWS Security Hub via paginated GetFindings.

        Args:
            filters: ASFF filter dict (e.g. SeverityLabel, WorkflowStatus).

        Returns:
            List of raw ASFF finding dicts. Empty list when boto3 missing
            or credentials not configured (never mock data).
        """
        client = self._make_boto3_client()
        if client is None:
            return []
        try:
            findings: List[Dict[str, Any]] = []
            kwargs: Dict[str, Any] = {}
            if filters:
                kwargs["Filters"] = filters
            # Paginated GetFindings — handle NextToken explicitly so Stubber
            # tests can drive pagination without requiring a real paginator.
            next_token: Optional[str] = None
            while True:
                call_kwargs = dict(kwargs)
                if next_token:
                    call_kwargs["NextToken"] = next_token
                resp = client.get_findings(**call_kwargs)
                findings.extend(resp.get("Findings", []))
                next_token = resp.get("NextToken")
                if not next_token:
                    break
            return findings
        except Exception as exc:  # noqa: BLE001
            logger.error("get_findings failed: %s", exc, exc_info=True)
            raise RuntimeError(
                f"AWS Security Hub get_findings failed: {exc}"
            ) from exc

    def get_insights(self) -> List[Dict[str, Any]]:
        """
        Retrieve Security Hub insights via paginated GetInsights.

        Returns:
            List of insight dicts. Empty list when unconfigured.
        """
        client = self._make_boto3_client()
        if client is None:
            return []
        try:
            insights: List[Dict[str, Any]] = []
            next_token: Optional[str] = None
            while True:
                call_kwargs: Dict[str, Any] = {}
                if next_token:
                    call_kwargs["NextToken"] = next_token
                resp = client.get_insights(**call_kwargs)
                insights.extend(resp.get("Insights", []))
                next_token = resp.get("NextToken")
                if not next_token:
                    break
            return insights
        except Exception as exc:  # noqa: BLE001
            logger.error("get_insights failed: %s", exc, exc_info=True)
            raise RuntimeError(
                f"AWS Security Hub get_insights failed: {exc}"
            ) from exc

    def get_standards_status(self) -> Dict[str, Any]:
        """
        Retrieve enabled compliance standards and their pass/fail control counts.

        Uses GetEnabledStandards + DescribeStandardsControls. Returns
        ``{"standards": [], "is_mock": False}`` when unconfigured.
        """
        client = self._make_boto3_client()
        if client is None:
            return {"standards": [], "is_mock": False}
        try:
            raw_standards: List[Dict[str, Any]] = []
            next_token: Optional[str] = None
            while True:
                call_kwargs: Dict[str, Any] = {}
                if next_token:
                    call_kwargs["NextToken"] = next_token
                resp = client.get_enabled_standards(**call_kwargs)
                raw_standards.extend(resp.get("StandardsSubscriptions", []))
                next_token = resp.get("NextToken")
                if not next_token:
                    break

            standards: List[Dict[str, Any]] = []
            for sub in raw_standards:
                arn = sub.get("StandardsArn", "")
                sub_arn = sub.get("StandardsSubscriptionArn", "")
                passed = failed = total = 0
                try:
                    ctrls_token: Optional[str] = None
                    while True:
                        ctrls_kwargs: Dict[str, Any] = {
                            "StandardsSubscriptionArn": sub_arn,
                        }
                        if ctrls_token:
                            ctrls_kwargs["NextToken"] = ctrls_token
                        ctrls_resp = client.describe_standards_controls(
                            **ctrls_kwargs
                        )
                        for ctrl in ctrls_resp.get("Controls", []):
                            total += 1
                            if ctrl.get("ControlStatus") == "ENABLED" and \
                                    ctrl.get("ComplianceStatus") == "PASSED":
                                passed += 1
                            else:
                                failed += 1
                        ctrls_token = ctrls_resp.get("NextToken")
                        if not ctrls_token:
                            break
                except Exception as ctrl_exc:  # noqa: BLE001
                    logger.warning(
                        "describe_standards_controls failed for %s: %s",
                        sub_arn, ctrl_exc,
                    )

                name = "Unknown Standard"
                if arn:
                    parts = arn.rsplit("/", 2)
                    if len(parts) >= 2:
                        name = parts[-2].replace("-", " ").title()

                standards.append({
                    "StandardsArn": arn,
                    "Name": name,
                    "Status": sub.get("StandardsStatus", "UNKNOWN"),
                    "EnabledAt": sub.get("StandardsInput", {}).get(
                        "EnabledAt", ""
                    ),
                    "ControlsCount": total,
                    "PassedControlsCount": passed,
                    "FailedControlsCount": failed,
                    "ComplianceScore": (
                        round(passed / total * 100, 1) if total else 0.0
                    ),
                })

            return {"standards": standards, "is_mock": False}
        except Exception as exc:  # noqa: BLE001
            logger.error("get_standards_status failed: %s", exc, exc_info=True)
            raise RuntimeError(
                f"AWS Security Hub get_standards_status failed: {exc}"
            ) from exc

    def import_findings(self, org_id: str = "default") -> Dict[str, Any]:
        """
        Pull findings from Security Hub, normalize them, store in history,
        and (best-effort) push into the Brain Pipeline.

        Always emits ``aws_security_hub.findings_imported`` to the TrustGraph
        event bus on success.
        """
        import_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        is_configured = self.is_configured()

        try:
            raw_findings = self.get_findings()
            findings = self.normalize_asff(raw_findings)

            sev_counts: Dict[str, int] = {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
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
                # ``is_mock`` is a legacy field name retained for back-compat.
                # It now indicates "no real AWS credentials configured" — and
                # in that case findings will be EMPTY, never synthetic.
                "is_mock": not is_configured,
                "configured": is_configured,
                "findings_count": len(findings),
                "severity_breakdown": sev_counts,
                "findings": findings,
            }

            self._try_ingest_to_pipeline(findings, org_id, import_id)
            _emit_event(
                "aws_security_hub.findings_imported",
                {
                    "import_id": import_id,
                    "org_id": org_id,
                    "findings_count": len(findings),
                    "severity_breakdown": sev_counts,
                    "configured": is_configured,
                    "region": self._region,
                },
            )

            # Emit each normalized finding to the TrustGraph event bus
            # so Brain pipeline / UI receive per-finding events (not just
            # the aggregate findings_imported event above).
            try:
                from core.trustgraph_event_bus import get_event_bus
                bus = get_event_bus()
                for f in findings:
                    bus.emit("finding.created", {
                        "org_id": org_id,
                        "engine": "aws_security_hub",
                        "id": f.get("id") or f.get("finding_id"),
                        "cve_id": f.get("cve_id"),
                        "severity": f.get("severity", "unknown"),
                        "title": f.get("title") or f.get("name"),
                        "asset_id": f.get("asset_id"),
                        "cvss": f.get("cvss"),
                        "epss": f.get("epss"),
                        "is_mock": f.get("is_mock", not is_configured),
                        **f,
                    })
            except Exception:
                pass
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Security Hub import failed for org=%s: %s",
                org_id, exc, exc_info=True,
            )
            entry = {
                "import_id": import_id,
                "org_id": org_id,
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "status": "failed",
                "error": str(exc),
                "is_mock": not is_configured,
                "configured": is_configured,
                "findings_count": 0,
                "severity_breakdown": {},
                "findings": [],
            }

        with _get_lock():
            _import_history.setdefault(org_id, []).append(entry)

        return entry

    def normalize_asff(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Normalize ASFF findings to UnifiedFinding dicts.

        Tries SecurityHubNormalizer from scanner_parsers when available;
        falls back to inline normalization so this module works standalone.
        """
        if not findings:
            return []

        # REMOVED — ``core.scanner_parsers.SecurityHubNormalizer`` does not
        # exist (the module exposes 33 vendor normalizers but no AWS Security
        # Hub one). 2026-05-03 silenced-imports audit. Always use the inline
        # normalizer below; rewire to a real ``AWSSecurityHubNormalizer``
        # if/when one is added to scanner_parsers.
        logger.debug(
            "SecurityHubNormalizer not implemented in scanner_parsers — "
            "using inline AWS Security Hub normalization (audit 2026-05-03)"
        )
        return self._inline_normalize_asff(findings)

    def _inline_normalize_asff(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Minimal inline ASFF normalizer used as a fallback."""
        normalized: List[Dict[str, Any]] = []
        for finding in findings:
            severity_label = (
                finding.get("Severity", {}).get("Label", "INFORMATIONAL").upper()
            )
            sev = _ASFF_SEVERITY_MAP.get(severity_label, "info")

            resources = finding.get("Resources", [])
            primary_resource = resources[0] if resources else {}
            resource_type = primary_resource.get("Type", "")
            resource_id = primary_resource.get("Id", "")

            remediation = finding.get("Remediation", {}).get("Recommendation", {})
            recommendation = remediation.get("Text", "")
            remediation_url = remediation.get("Url", "")

            compliance_status = finding.get("Compliance", {}).get("Status", "")

            types = finding.get("Types", [])
            category = (
                types[0].split("/")[1]
                if types and "/" in types[0] else "security"
            )

            normalized.append({
                "id": str(uuid.uuid4()),
                "source_tool": "aws_security_hub",
                "source_id": finding.get("Id", ""),
                "severity": sev,
                "title": finding.get("Title", "AWS Security Hub Finding"),
                "description": finding.get("Description", ""),
                "recommendation": f"{recommendation} {remediation_url}".strip(),
                "aws_account_id": finding.get("AwsAccountId", ""),
                "aws_region": finding.get("Region", ""),
                "generator_id": finding.get("GeneratorId", ""),
                "product_name": finding.get("ProductName", "Security Hub"),
                "resource_type": resource_type,
                "resource_id": resource_id,
                "compliance_status": compliance_status,
                "workflow_status": finding.get("Workflow", {}).get("Status", ""),
                "record_state": finding.get("RecordState", ""),
                "category": category,
                "created_at": finding.get("CreatedAt", ""),
                "updated_at": finding.get("UpdatedAt", ""),
                "tags": types,
            })
        return normalized

    def get_import_history(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """Return import history for the org, most recent first."""
        with _get_lock():
            entries = list(_import_history.get(org_id, []))

        summaries: List[Dict[str, Any]] = []
        for e in reversed(entries):
            summary = {k: v for k, v in e.items() if k != "findings"}
            summaries.append(summary)
        return summaries

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_boto3_client(self) -> Any:
        """
        Build (and cache) a boto3 securityhub client.

        Returns ``None`` when boto3 is not installed OR credentials are not
        configured. NEVER returns a mock — callers must handle ``None``.
        Tests can pre-set ``self._client`` to a Stubber-driven instance.
        """
        if self._client is not None:
            return self._client

        try:
            import boto3  # type: ignore
        except ImportError:
            logger.warning(
                "boto3 is not installed — AWS Security Hub returns empty data. "
                "Install with: pip install boto3"
            )
            return None

        if not self.is_configured():
            logger.warning(
                "AWS credentials not configured — Security Hub returns empty "
                "data. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or use "
                "the boto3 default credential chain (profile/IAM role)."
            )
            return None

        try:
            kwargs: Dict[str, Any] = {"region_name": self._region}
            if self._access_key and self._secret_key:
                kwargs["aws_access_key_id"] = self._access_key
                kwargs["aws_secret_access_key"] = self._secret_key
            self._client = boto3.client("securityhub", **kwargs)
            return self._client
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to build boto3 securityhub client: %s", exc)
            return None

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
                metadata={"source": "aws_security_hub", "import_id": import_id},
            )
            pipeline.run(pipeline_input)
            logger.info(
                "Ingested %d Security Hub findings into BrainPipeline for "
                "org=%s import=%s",
                len(findings), org_id, import_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("BrainPipeline ingestion skipped: %s", exc)


# Module-load heartbeat for TrustGraph observability
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass
