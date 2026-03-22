"""CSPM Router — Cloud Security Posture Management endpoints.

Endpoints:
  POST /api/v1/cspm/scan/terraform       — scan Terraform HCL
  POST /api/v1/cspm/scan/cloudformation   — scan CloudFormation
  POST /api/v1/cspm/scan/live             — scan live cloud account (AWS/Azure/GCP)
  POST /api/v1/cspm/scan/kubernetes       — scan K8s manifests
  GET  /api/v1/cspm/rules                 — list all CSPM rules
  GET  /api/v1/cspm/rules/{provider}      — list rules for a specific provider
  GET  /api/v1/cspm/compliance-report     — generate compliance report
  GET  /api/v1/cspm/status                — engine status
  GET  /api/v1/cspm/health                — health check
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Depends
from apps.api.dependencies import get_org_id
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cspm", tags=["CSPM"])

_MAX_CONTENT_LENGTH = 1_000_000  # 1MB max IaC content
_MAX_FILENAME_LENGTH = 255


def _sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal."""
    if ".." in filename or "/" in filename or "\\" in filename:
        safe = os.path.basename(filename)
    else:
        safe = filename
    safe = "".join(c for c in safe if c.isprintable() and c != "\x00")
    if len(safe) > _MAX_FILENAME_LENGTH:
        safe = safe[:_MAX_FILENAME_LENGTH]
    return safe or "main.tf"


class TerraformScanRequest(BaseModel):
    content: str = Field(
        ...,
        description="Terraform HCL content to scan",
        max_length=_MAX_CONTENT_LENGTH,
    )
    filename: str = Field(
        "main.tf",
        description="Filename for reporting",
        max_length=_MAX_FILENAME_LENGTH,
    )


class CloudFormationScanRequest(BaseModel):
    content: str = Field(
        ...,
        description="CloudFormation JSON/YAML content to scan",
        max_length=_MAX_CONTENT_LENGTH,
    )


class LiveScanRequest(BaseModel):
    provider: str = Field(
        ...,
        description="Cloud provider: aws, azure, or gcp",
        pattern="^(aws|azure|gcp)$",
    )
    region: str = Field(
        "us-east-1",
        description="Region to scan (AWS only)",
    )
    services: Optional[List[str]] = Field(
        None,
        description="Services to scan (e.g. ['s3', 'iam', 'ec2']). Defaults to all.",
    )
    subscription_id: Optional[str] = Field(
        None,
        description="Azure subscription ID (Azure only)",
    )
    project_id: Optional[str] = Field(
        None,
        description="GCP project ID (GCP only)",
    )


class KubernetesScanRequest(BaseModel):
    content: str = Field(
        ...,
        description="Kubernetes YAML manifest content to scan",
        max_length=_MAX_CONTENT_LENGTH,
    )
    filename: str = Field(
        "manifest.yaml",
        description="Filename for reporting",
        max_length=_MAX_FILENAME_LENGTH,
    )


@router.post("/scan/terraform")
async def scan_terraform(req: TerraformScanRequest) -> Dict[str, Any]:
    """Scan Terraform HCL for cloud misconfigurations."""
    if not req.content.strip():
        raise HTTPException(400, "Empty Terraform content provided")
    safe_filename = _sanitize_filename(req.filename)
    try:
        from core.cspm_engine import get_cspm_engine

        engine = get_cspm_engine()
        result = engine.scan_terraform(req.content, safe_filename)
        return result.to_dict()
    except ImportError as e:
        logger.exception("Terraform scan failed: %s", type(e).__name__)
        raise HTTPException(500, f"Terraform scan failed: {type(e).__name__}")


@router.post("/scan/cloudformation")
async def scan_cloudformation(req: CloudFormationScanRequest) -> Dict[str, Any]:
    """Scan CloudFormation JSON/YAML for AWS misconfigurations."""
    if not req.content.strip():
        raise HTTPException(400, "Empty CloudFormation content provided")
    try:
        from core.cspm_engine import get_cspm_engine

        engine = get_cspm_engine()
        result = engine.scan_cloudformation(req.content)
        return result.to_dict()
    except ImportError as e:
        logger.exception("CloudFormation scan failed: %s", type(e).__name__)
        raise HTTPException(500, f"CloudFormation scan failed: {type(e).__name__}")


@router.post("/scan/live")
async def scan_live(req: LiveScanRequest) -> Dict[str, Any]:
    """Scan a live cloud account for misconfigurations.

    Requires appropriate SDK credentials (boto3/azure-identity/google-cloud).
    """
    try:
        from core.cspm_engine import get_cspm_engine

        engine = get_cspm_engine()
        if req.provider == "aws":
            result = engine.scan_aws_live(
                region=req.region,
                services=req.services,
            )
        elif req.provider == "azure":
            result = engine.scan_azure_live(
                subscription_id=req.subscription_id,
            )
        elif req.provider == "gcp":
            result = engine.scan_gcp_live(
                project_id=req.project_id,
            )
        else:
            raise HTTPException(400, f"Unsupported provider: {req.provider}")
        return result.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Live scan failed: %s", type(e).__name__)
        raise HTTPException(500, f"Live scan failed: {type(e).__name__}")


@router.post("/scan/kubernetes")
async def scan_kubernetes(req: KubernetesScanRequest) -> Dict[str, Any]:
    """Scan Kubernetes YAML manifests for security misconfigurations.

    Detects privileged containers, root users, hostNetwork, missing resource limits,
    writable root filesystems, dangerous capabilities, missing probes, and more.
    """
    if not req.content.strip():
        raise HTTPException(400, "Empty Kubernetes manifest content provided")
    safe_filename = _sanitize_filename(req.filename)
    try:
        from core.cspm_engine import get_cspm_engine

        engine = get_cspm_engine()
        result = engine.scan_kubernetes(req.content, safe_filename)
        return result.to_dict()
    except Exception as e:
        logger.exception("Kubernetes scan failed: %s", type(e).__name__)
        raise HTTPException(500, f"Kubernetes scan failed: {type(e).__name__}")


@router.get("/findings")
async def list_cspm_findings(
    severity: str = None,
    limit: int = 100,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """List CSPM/IaC scan findings."""
    try:
        from core.analytics_db import AnalyticsDB
        db = AnalyticsDB()
        findings = db.list_findings(limit=limit)
        cspm_findings = []
        for f in findings:
            src = getattr(f, 'source', '') or ''
            if any(k in src.lower() for k in ('cspm', 'iac', 'terraform', 'cloud')):
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                if severity and sev.lower() != severity.lower():
                    continue
                cspm_findings.append({
                    'id': f.id,
                    'title': getattr(f, 'title', 'CSPM Finding'),
                    'severity': sev,
                    'status': f.status.value if hasattr(f.status, 'value') else str(f.status),
                    'source': src,
                    'provider': 'aws' if 'aws' in src.lower() else 'azure' if 'azure' in src.lower() else 'gcp' if 'gcp' in src.lower() else 'unknown',
                })
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
        cspm_findings = []
    return {
        'findings': cspm_findings,
        'total': len(cspm_findings),
        'scanner': 'ALdeci CSPM Engine',
    }


@router.get("/rules")
async def list_rules() -> Dict[str, Any]:
    """List all CSPM rules by provider (including K8s)."""
    from core.cspm_engine import AWS_RULES, AZURE_RULES, GCP_RULES, K8S_RULES

    def fmt(rules):
        return [
            {
                "id": r[0], "title": r[1], "severity": r[2], "cwe": r[3],
                "category": r[4], "description": r[5], "recommendation": r[6],
                "compliance_frameworks": r[7],
            }
            for r in rules
        ]

    return {
        "aws": fmt(AWS_RULES),
        "azure": fmt(AZURE_RULES),
        "gcp": fmt(GCP_RULES),
        "kubernetes": fmt(K8S_RULES),
        "total": len(AWS_RULES) + len(AZURE_RULES) + len(GCP_RULES) + len(K8S_RULES),
    }


@router.get("/rules/{provider}")
async def list_rules_by_provider(provider: str) -> Dict[str, Any]:
    """List CSPM rules for a specific provider.

    Args:
        provider: One of aws, azure, gcp, kubernetes (or k8s).
    """
    from core.cspm_engine import AWS_RULES, AZURE_RULES, GCP_RULES, K8S_RULES

    provider_map = {
        "aws": AWS_RULES,
        "azure": AZURE_RULES,
        "gcp": GCP_RULES,
        "kubernetes": K8S_RULES,
        "k8s": K8S_RULES,
    }
    rules = provider_map.get(provider.lower())
    if rules is None:
        raise HTTPException(404, f"Unknown provider: {provider}. Valid: aws, azure, gcp, kubernetes")

    def fmt(r):
        return {
            "id": r[0], "title": r[1], "severity": r[2], "cwe": r[3],
            "category": r[4], "description": r[5], "recommendation": r[6],
            "compliance_frameworks": r[7],
        }

    by_severity: Dict[str, int] = {}
    for r in rules:
        by_severity[r[2]] = by_severity.get(r[2], 0) + 1

    return {
        "provider": provider.lower(),
        "rules": [fmt(r) for r in rules],
        "total": len(rules),
        "by_severity": by_severity,
    }


@router.get("/compliance-report")
async def compliance_report(
    provider: Optional[str] = None,
    framework: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate a compliance report showing rule coverage by framework.

    Args:
        provider: Filter by provider (aws, azure, gcp, kubernetes). All if omitted.
        framework: Filter by framework prefix (e.g. 'CIS-AWS', 'SOC2', 'NIST'). All if omitted.
    """
    from core.cspm_engine import AWS_RULES, AZURE_RULES, GCP_RULES, K8S_RULES

    all_providers = {
        "aws": AWS_RULES,
        "azure": AZURE_RULES,
        "gcp": GCP_RULES,
        "kubernetes": K8S_RULES,
    }

    if provider:
        key = provider.lower()
        if key == "k8s":
            key = "kubernetes"
        if key not in all_providers:
            raise HTTPException(404, f"Unknown provider: {provider}")
        selected = {key: all_providers[key]}
    else:
        selected = all_providers

    # Build framework coverage map
    framework_coverage: Dict[str, List[Dict[str, str]]] = {}
    total_rules = 0
    by_severity: Dict[str, int] = {}

    for prov_name, rules in selected.items():
        for r in rules:
            rule_id, title, sev, cwe, cat, desc, rec, frameworks_list = r
            total_rules += 1
            by_severity[sev] = by_severity.get(sev, 0) + 1

            for fw in frameworks_list:
                if framework and not fw.upper().startswith(framework.upper()):
                    continue
                if fw not in framework_coverage:
                    framework_coverage[fw] = []
                framework_coverage[fw].append({
                    "rule_id": rule_id,
                    "title": title,
                    "severity": sev,
                    "provider": prov_name,
                })

    # Compute compliance posture summary
    frameworks_summary = []
    for fw_name, covered_rules in sorted(framework_coverage.items()):
        sev_breakdown: Dict[str, int] = {}
        for cr in covered_rules:
            sev_breakdown[cr["severity"]] = sev_breakdown.get(cr["severity"], 0) + 1
        frameworks_summary.append({
            "framework": fw_name,
            "rules_count": len(covered_rules),
            "by_severity": sev_breakdown,
        })

    return {
        "report_type": "compliance_coverage",
        "providers_scanned": list(selected.keys()),
        "total_rules": total_rules,
        "by_severity": by_severity,
        "frameworks": frameworks_summary,
        "total_frameworks": len(framework_coverage),
        "engine_version": "2.0.0",
    }


@router.get("/status")
async def cspm_status() -> Dict[str, Any]:
    from core.cspm_engine import get_cspm_engine

    engine = get_cspm_engine()
    from core.cspm_engine import AWS_RULES, AZURE_RULES, GCP_RULES, K8S_RULES

    return {
        "engine": "cspm",
        "status": "ready",
        "version": "2.0.0",
        "capabilities": ["terraform", "cloudformation", "live_aws", "live_azure", "live_gcp", "kubernetes"],
        "rules_count": {
            "aws": len(AWS_RULES),
            "azure": len(AZURE_RULES),
            "gcp": len(GCP_RULES),
            "kubernetes": len(K8S_RULES),
            "total": len(AWS_RULES) + len(AZURE_RULES) + len(GCP_RULES) + len(K8S_RULES),
        },
        "sdk_available": {
            "boto3": engine._boto3_available,
            "azure": engine._azure_available,
            "gcp": engine._gcp_available,
        },
    }


@router.get("/health")
async def cspm_health() -> Dict[str, Any]:
    """CSPM engine health check (alias for /status)."""
    return await cspm_status()
