"""
ALDECI Cloud Connector Integration Router.

Unified multi-cloud API for AWS, Azure, and GCP resource and finding ingestion.

Endpoints (all under /api/v1/cloud-connectors):
  POST   /accounts                  — register credentials for a cloud account
  DELETE /accounts/{provider}/{id}  — remove credentials
  GET    /accounts                  — list registered accounts (masked)
  GET    /accounts/health           — connector health for all or filtered accounts
  POST   /accounts/{provider}/{id}/validate — test credential connectivity
  GET    /resources                 — list resources (provider + account required)
  GET    /findings                  — list findings (provider + account required)
  GET    /posture                   — get security posture report
  POST   /sync                      — trigger a full sync for one account
  POST   /sync/organization         — sync all accounts for a provider

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-connectors",
    tags=["cloud-connectors"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton engine
# ---------------------------------------------------------------------------

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.cloud_connectors import get_engine
        _engine = get_engine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class RegisterCredentialsRequest(BaseModel):
    """Request body for registering cloud credentials."""

    provider: str = Field(..., description="Cloud provider: aws | azure | gcp")
    account_id: str = Field(..., description="AWS account ID / Azure subscription / GCP project")
    label: str = Field("default", description="Human-readable label")

    # AWS
    aws_access_key_id: Optional[str] = Field(None, description="AWS access key ID")
    aws_secret_access_key: Optional[str] = Field(None, description="AWS secret access key")
    aws_role_arn: Optional[str] = Field(None, description="AWS IAM role ARN for assume-role")
    aws_region: str = Field("us-east-1", description="AWS region")
    aws_session_token: Optional[str] = Field(None, description="AWS temporary session token")

    # Azure
    azure_tenant_id: Optional[str] = Field(None, description="Azure AD tenant ID")
    azure_client_id: Optional[str] = Field(None, description="Azure service principal client ID")
    azure_client_secret: Optional[str] = Field(None, description="Azure service principal secret")
    azure_subscription_id: Optional[str] = Field(None, description="Azure subscription ID")

    # GCP
    gcp_service_account_json: Optional[str] = Field(None, description="GCP service account JSON (raw string)")
    gcp_project_id: Optional[str] = Field(None, description="GCP project ID")


class RegisterCredentialsResponse(BaseModel):
    ok: bool
    message: str
    provider: str
    account_id: str


class AccountSummary(BaseModel):
    provider: str
    account_id: str
    label: str
    expired: Optional[bool] = None
    expires_at: Optional[str] = None


class ValidateResponse(BaseModel):
    ok: bool
    message: str
    provider: str
    account_id: str


class ResourceResponse(BaseModel):
    resource_id: str
    provider: str
    resource_type: str
    name: str
    region: str
    account_id: str
    tags: Dict[str, str] = Field(default_factory=dict)
    public_exposure: bool = False
    security_groups: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FindingResponse(BaseModel):
    finding_id: str
    provider: str
    source_service: str
    title: str
    description: str
    severity: str
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    region: Optional[str] = None
    account_id: Optional[str] = None
    remediation: Optional[str] = None
    compliance_standards: List[str] = Field(default_factory=list)


class PostureResponse(BaseModel):
    provider: str
    account_id: str
    region: Optional[str] = None
    score: float
    total_controls: int
    passed_controls: int
    failed_controls: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    frameworks: List[str] = Field(default_factory=list)
    generated_at: str
    details: Dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    provider: str
    account_id: str
    label: str
    status: str
    last_sync_at: Optional[str] = None
    last_error: Optional[str] = None
    error_count: int = 0
    consecutive_errors: int = 0
    credential_expired: bool = False
    resources_synced: int = 0
    findings_synced: int = 0


class SyncRequest(BaseModel):
    provider: str = Field(..., description="Cloud provider: aws | azure | gcp")
    account_id: str = Field(..., description="Account to sync")


class SyncOrganizationRequest(BaseModel):
    provider: str = Field(..., description="Cloud provider: aws | azure | gcp")


class SyncResponse(BaseModel):
    sync_id: str
    provider: str
    account_id: str
    started_at: str
    completed_at: Optional[str] = None
    status: str
    resources_found: int = 0
    findings_found: int = 0
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_provider(raw: str):
    from core.cloud_connectors import CloudProviderType
    try:
        return CloudProviderType(raw.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown provider '{raw}'. Must be aws | azure | gcp")


def _parse_severity(raw: Optional[str]):
    if not raw:
        return None
    from core.cloud_connectors import FindingSeverity
    try:
        return FindingSeverity(raw.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown severity '{raw}'. Must be critical|high|medium|low|info")


def _parse_resource_type(raw: Optional[str]):
    if not raw:
        return None
    from core.cloud_connectors import ResourceType
    try:
        return ResourceType(raw.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown resource_type '{raw}'")


def _resource_to_response(r) -> Dict[str, Any]:
    return {
        "resource_id": r.resource_id,
        "provider": r.provider.value,
        "resource_type": r.resource_type.value,
        "name": r.name,
        "region": r.region,
        "account_id": r.account_id,
        "tags": r.tags,
        "public_exposure": r.public_exposure,
        "security_groups": r.security_groups,
        "metadata": r.metadata,
    }


def _finding_to_response(f) -> Dict[str, Any]:
    return {
        "finding_id": f.finding_id,
        "provider": f.provider.value,
        "source_service": f.source_service,
        "title": f.title,
        "description": f.description,
        "severity": f.severity.value,
        "resource_id": f.resource_id,
        "resource_type": f.resource_type,
        "region": f.region,
        "account_id": f.account_id,
        "remediation": f.remediation,
        "compliance_standards": f.compliance_standards,
    }


def _health_to_response(h) -> Dict[str, Any]:
    return {
        "provider": h.provider.value,
        "account_id": h.account_id,
        "label": h.label,
        "status": h.status.value,
        "last_sync_at": h.last_sync_at.isoformat() if h.last_sync_at else None,
        "last_error": h.last_error,
        "error_count": h.error_count,
        "consecutive_errors": h.consecutive_errors,
        "credential_expired": h.credential_expired,
        "resources_synced": h.resources_synced,
        "findings_synced": h.findings_synced,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/accounts",
    response_model=RegisterCredentialsResponse,
    summary="Register cloud account credentials",
    status_code=201,
)
def register_account(body: RegisterCredentialsRequest):
    """
    Register credentials for a cloud provider account.

    Validates the credentials structurally before storing.
    Secrets are stored in memory (and optionally in a JSON file if the engine
    was initialised with a persist_path).
    """
    from core.cloud_connectors import CloudCredentials
    engine = _get_engine()
    provider = _parse_provider(body.provider)
    try:
        creds = CloudCredentials(
            provider=provider,
            account_id=body.account_id,
            label=body.label,
            aws_access_key_id=body.aws_access_key_id,
            aws_secret_access_key=body.aws_secret_access_key,
            aws_role_arn=body.aws_role_arn,
            aws_region=body.aws_region,
            aws_session_token=body.aws_session_token,
            azure_tenant_id=body.azure_tenant_id,
            azure_client_id=body.azure_client_id,
            azure_client_secret=body.azure_client_secret,
            azure_subscription_id=body.azure_subscription_id,
            gcp_service_account_json=body.gcp_service_account_json,
            gcp_project_id=body.gcp_project_id,
        )
        ok, msg = engine.register_credentials(creds)
        if not ok:
            raise HTTPException(status_code=422, detail=msg)
        return RegisterCredentialsResponse(
            ok=True, message=msg, provider=provider.value, account_id=body.account_id
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("register_account failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.delete(
    "/accounts/{provider}/{account_id}",
    summary="Remove registered cloud account",
)
def remove_account(provider: str, account_id: str):
    """Remove stored credentials for a cloud account."""
    engine = _get_engine()
    prov = _parse_provider(provider)
    removed = engine.remove_credentials(prov, account_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Account {provider}/{account_id} not found")
    return {"ok": True, "message": f"Account {provider}/{account_id} removed"}


@router.get(
    "/accounts",
    response_model=List[Dict[str, Any]],
    summary="List registered cloud accounts",
)
def list_accounts(
    provider: Optional[str] = Query(None, description="Filter by provider: aws | azure | gcp"),
):
    """List all registered cloud accounts with secrets masked."""
    engine = _get_engine()
    prov = _parse_provider(provider) if provider else None
    return engine.list_accounts(provider=prov)


@router.get(
    "/accounts/health",
    response_model=List[HealthResponse],
    summary="Connector health for all or filtered accounts",
)
def accounts_health(
    provider: Optional[str] = Query(None, description="Filter by provider"),
    account_id: Optional[str] = Query(None, description="Filter by account ID"),
):
    """Return health metrics (last sync, errors, quota) for cloud connectors."""
    engine = _get_engine()
    prov = _parse_provider(provider) if provider else None
    health_list = engine.health(provider=prov, account_id=account_id)
    return [_health_to_response(h) for h in health_list]


@router.post(
    "/accounts/{provider}/{account_id}/validate",
    response_model=ValidateResponse,
    summary="Validate cloud account credentials",
)
def validate_account(provider: str, account_id: str):
    """
    Test live connectivity for the stored credentials.

    Makes a real API call (STS GetCallerIdentity for AWS, token fetch for Azure,
    etc.). Returns ok=False when credentials are invalid or expired.
    """
    engine = _get_engine()
    prov = _parse_provider(provider)
    try:
        ok, msg = engine.validate_credentials(prov, account_id)
        return ValidateResponse(ok=ok, message=msg, provider=provider, account_id=account_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("validate_account failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/resources",
    response_model=List[ResourceResponse],
    summary="List cloud resources (normalized)",
)
def list_resources(
    provider: str = Query(..., description="Cloud provider: aws | azure | gcp"),
    account_id: str = Query(..., description="Account / subscription / project ID"),
    resource_type: Optional[str] = Query(None, description="Filter: compute|storage|network|database|iam|container|serverless"),
):
    """
    Return cloud resources normalized to the unified CloudResource schema.

    Falls back to stub data when cloud credentials are not configured or API
    calls fail (mirrors the AWS Security Hub router pattern).
    """
    engine = _get_engine()
    prov = _parse_provider(provider)
    rt = _parse_resource_type(resource_type)
    try:
        resources = engine.list_resources(prov, account_id, resource_type=rt)
        return [_resource_to_response(r) for r in resources]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("list_resources failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/findings",
    response_model=List[FindingResponse],
    summary="List cloud security findings (normalized)",
)
def list_findings(
    provider: str = Query(..., description="Cloud provider: aws | azure | gcp"),
    account_id: str = Query(..., description="Account / subscription / project ID"),
    severity: Optional[str] = Query(None, description="Filter: critical|high|medium|low|info"),
):
    """
    Pull and normalize security findings from:
    - AWS Security Hub (ASFF format)
    - Azure Defender for Cloud
    - GCP Security Command Center
    """
    engine = _get_engine()
    prov = _parse_provider(provider)
    sev = _parse_severity(severity)
    try:
        findings = engine.list_findings(prov, account_id, severity_filter=sev)
        return [_finding_to_response(f) for f in findings]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("list_findings failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/posture",
    response_model=PostureResponse,
    summary="Get cloud security posture report",
)
def get_posture(
    provider: str = Query(..., description="Cloud provider: aws | azure | gcp"),
    account_id: str = Query(..., description="Account / subscription / project ID"),
):
    """
    Return a security posture summary: score, control pass/fail, findings
    breakdown by severity, and compliance framework coverage.
    """
    engine = _get_engine()
    prov = _parse_provider(provider)
    try:
        report = engine.get_posture(prov, account_id)
        return {
            "provider": report.provider.value,
            "account_id": report.account_id,
            "region": report.region,
            "score": report.score,
            "total_controls": report.total_controls,
            "passed_controls": report.passed_controls,
            "failed_controls": report.failed_controls,
            "critical_findings": report.critical_findings,
            "high_findings": report.high_findings,
            "medium_findings": report.medium_findings,
            "low_findings": report.low_findings,
            "frameworks": report.frameworks,
            "generated_at": report.generated_at.isoformat(),
            "details": report.details,
        }
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("get_posture failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/sync",
    response_model=SyncResponse,
    summary="Trigger full sync for one cloud account",
)
def sync_account(body: SyncRequest):
    """
    Trigger a synchronous resource + finding sync for a single cloud account.

    Returns a SyncResult with counts and timing. Use /sync/organization to
    sync all accounts for a provider in one call.
    """
    engine = _get_engine()
    prov = _parse_provider(body.provider)
    try:
        result = engine.sync_account(prov, body.account_id)
        return {
            "sync_id": result.sync_id,
            "provider": result.provider.value,
            "account_id": result.account_id,
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "status": result.status,
            "resources_found": result.resources_found,
            "findings_found": result.findings_found,
            "error": result.error,
        }
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("sync_account failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/sync/organization",
    response_model=List[SyncResponse],
    summary="Sync all accounts for a cloud provider",
)
def sync_organization(body: SyncOrganizationRequest):
    """
    Trigger sync for every registered account under one cloud provider.

    Useful for organization-level scanning. Runs sequentially; each account
    obeys its provider's rate limiter.
    """
    engine = _get_engine()
    prov = _parse_provider(body.provider)
    try:
        results = engine.sync_organization(prov)
        return [
            {
                "sync_id": r.sync_id,
                "provider": r.provider.value,
                "account_id": r.account_id,
                "started_at": r.started_at.isoformat(),
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                "status": r.status,
                "resources_found": r.resources_found,
                "findings_found": r.findings_found,
                "error": r.error,
            }
            for r in results
        ]
    except Exception as exc:
        logger.error("sync_organization failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
