"""Connectors API Router -- manage and invoke Jira, GitHub, Slack connectors.

Endpoints:
    POST   /api/v1/connectors/register      -- Register a new connector
    GET    /api/v1/connectors                -- List registered connectors
    POST   /api/v1/connectors/test           -- Test all connectors
    POST   /api/v1/connectors/create-ticket  -- Create ticket from finding
    POST   /api/v1/connectors/{name}/test    -- Test specific connector
    DELETE /api/v1/connectors/{name}         -- Remove connector
    GET    /api/v1/connectors/health         -- Health check

Security:
    - All endpoints require API key authentication (injected by app.py)
    - Credentials are validated but never logged in plain text
    - Input is validated via Pydantic models with length limits
    - Connector names are normalised to prevent injection
"""

from __future__ import annotations

import logging
import re
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field, field_validator

try:
    from apps.api.dependencies import get_org_id as _get_org_id
except ImportError:  # pragma: no cover — test environments without full app
    def _get_org_id() -> str:  # type: ignore[misc]
        return "default"

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/connectors", tags=["connectors"])


# ---------------------------------------------------------------------------
# Pydantic models with strict validation
# ---------------------------------------------------------------------------

_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class ConnectorType(str, Enum):
    jira = "jira"
    github = "github"
    slack = "slack"


class JiraConfig(BaseModel):
    base_url: str = Field(..., max_length=2048, description="Jira instance URL")
    email: str = Field(..., max_length=254, description="Jira user email")
    api_token: str = Field(..., min_length=1, max_length=1024, description="Jira API token")
    project_key: str = Field(..., min_length=1, max_length=20, description="Jira project key")
    issue_type: str = Field("Bug", max_length=50, description="Default issue type")

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not v.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        return v

    @field_validator("project_key")
    @classmethod
    def validate_project_key(cls, v: str) -> str:
        if not re.match(r"^[A-Z][A-Z0-9_]{0,19}$", v):
            raise ValueError("project_key must be uppercase alphanumeric (e.g. PROJ)")
        return v


class GitHubConfig(BaseModel):
    token: str = Field(..., min_length=1, max_length=1024, description="GitHub personal access token")
    owner: str = Field(..., min_length=1, max_length=100, description="Repository owner/org")
    repo: str = Field(..., min_length=1, max_length=100, description="Repository name")

    @field_validator("owner", "repo")
    @classmethod
    def validate_slug(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^[a-zA-Z0-9._-]+$", v):
            raise ValueError("Must contain only alphanumeric, dots, hyphens, underscores")
        return v


class SlackConfig(BaseModel):
    webhook_url: str = Field(..., max_length=2048, description="Slack incoming webhook URL")
    channel: Optional[str] = Field(None, max_length=100, description="Override channel")

    @field_validator("webhook_url")
    @classmethod
    def validate_webhook_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("https://hooks.slack.com/"):
            raise ValueError("webhook_url must start with https://hooks.slack.com/")
        return v


class RegisterConnectorRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=63, description="Unique connector name")
    type: ConnectorType = Field(..., description="Connector type: jira, github, or slack")
    jira: Optional[JiraConfig] = None
    github: Optional[GitHubConfig] = None
    slack: Optional[SlackConfig] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip().lower()
        if not _NAME_PATTERN.match(v):
            raise ValueError(
                "name must be lowercase alphanumeric with hyphens/underscores, "
                "start with alphanumeric, max 63 chars"
            )
        return v


class FindingInput(BaseModel):
    """Security finding to create tickets from."""

    title: Optional[str] = Field(None, max_length=500)
    summary: Optional[str] = Field(None, max_length=500)
    description: Optional[str] = Field(None, max_length=50000)
    details: Optional[str] = Field(None, max_length=50000)
    severity: Optional[str] = Field("medium", max_length=20)
    cve_id: Optional[str] = Field(None, max_length=30, pattern=r"^CVE-\d{4}-\d{4,}$|^$")
    cve: Optional[str] = Field(None, max_length=30)
    cwe_id: Optional[str] = Field(None, max_length=20)
    cwe: Optional[str] = Field(None, max_length=20)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss: Optional[float] = Field(None, ge=0.0, le=10.0)
    component: Optional[str] = Field(None, max_length=500)
    package: Optional[str] = Field(None, max_length=500)
    file_path: Optional[str] = Field(None, max_length=1000)
    file: Optional[str] = Field(None, max_length=1000)
    line: Optional[int] = Field(None, ge=0)
    remediation: Optional[str] = Field(None, max_length=50000)
    fix: Optional[str] = Field(None, max_length=50000)


class CreateTicketRequest(BaseModel):
    finding: FindingInput
    targets: Optional[List[str]] = Field(
        None,
        max_length=20,
        description="Specific connector names to target; null = all",
    )

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        import re as _re

        _TARGET_RE = _re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
        cleaned: List[str] = []
        for t in v:
            normed = t.strip().lower()
            if not _TARGET_RE.match(normed):
                raise ValueError(
                    f"Invalid target connector name: '{t[:64]}'. "
                    "Must be lowercase alphanumeric with optional dashes/underscores, 1-63 chars."
                )
            cleaned.append(normed)
        return cleaned


# ---------------------------------------------------------------------------
# Singleton connector registry (initialised on first access)
# ---------------------------------------------------------------------------

# Late import to avoid circular dependency at module level
_universal: Any = None


def _get_universal():
    """Lazy-load the UniversalConnector singleton."""
    global _universal
    if _universal is None:
        from connectors.universal_connector import UniversalConnector
        _universal = UniversalConnector()
    return _universal


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def _connector_type_descriptor(ct: ConnectorType) -> Dict[str, Any]:
    """Derive connector type metadata from the Pydantic config model for that type.

    Required fields = model fields without a default value.
    Optional fields = model fields WITH a default value (including None defaults).
    This keeps /types automatically in sync with the actual validation models.
    """
    _config_map: Dict[str, type] = {
        ConnectorType.jira: JiraConfig,
        ConnectorType.github: GitHubConfig,
        ConnectorType.slack: SlackConfig,
    }
    _label_map = {
        ConnectorType.jira: ("Jira", "Atlassian Jira issue tracker"),
        ConnectorType.github: ("GitHub", "GitHub repository integration"),
        ConnectorType.slack: ("Slack", "Slack incoming webhook notifications"),
    }
    model_cls = _config_map.get(ct)
    label, description = _label_map.get(ct, (ct.value.title(), ""))

    required_fields: List[str] = []
    optional_fields: List[str] = []
    if model_cls is not None:
        for field_name, field_info in model_cls.model_fields.items():
            if field_info.is_required():
                required_fields.append(field_name)
            else:
                optional_fields.append(field_name)

    return {
        "type": ct.value,
        "label": label,
        "description": description,
        "required_fields": required_fields,
        "optional_fields": optional_fields,
    }


@router.get("/types", summary="List supported connector types")
async def list_connector_types() -> Dict[str, Any]:
    """Return all supported connector types and their required configuration fields.

    Derived from the ConnectorType enum and Pydantic config models — required/optional
    field lists are authoritative (introspected from model_fields, not hardcoded).
    """
    types = [_connector_type_descriptor(ct) for ct in ConnectorType]
    return {"types": types, "total": len(types)}


def _org_prefix(org_id: str) -> str:
    """Return the internal name prefix used to namespace connectors per-org."""
    return f"{org_id}::"


def _strip_prefix(name: str, org_id: str) -> str:
    """Strip org namespace prefix from internal connector name."""
    prefix = _org_prefix(org_id)
    return name[len(prefix):] if name.startswith(prefix) else name


@router.get("", summary="List registered connectors")
async def list_connectors(org_id: str = Depends(_get_org_id)) -> Dict[str, Any]:
    """Return metadata for connectors registered by the caller's org."""
    uc = _get_universal()
    prefix = _org_prefix(org_id)
    connectors = [
        {**c, "name": _strip_prefix(c["name"], org_id)}
        for c in uc.list_connectors()
        if c["name"].startswith(prefix)
    ]
    return {
        "connectors": connectors,
        "total": len(connectors),
    }


@router.post("/register", summary="Register a new connector")
async def register_connector(
    req: RegisterConnectorRequest,
    org_id: str = Depends(_get_org_id),
) -> Dict[str, Any]:
    """Register a Jira, GitHub, or Slack connector.

    Credentials are validated for format but not tested against the
    remote API. Use POST /test after registration to verify connectivity.
    """
    from connectors.universal_connector import (
        GitHubConnector,
        JiraConnector,
        SlackConnector,
    )

    uc = _get_universal()
    connector: Any

    if req.type == ConnectorType.jira:
        if not req.jira:
            raise HTTPException(
                status_code=422,
                detail="Jira config is required when type is 'jira'",
            )
        connector = JiraConnector(
            base_url=req.jira.base_url,
            email=req.jira.email,
            api_token=req.jira.api_token,
            project_key=req.jira.project_key,
            issue_type=req.jira.issue_type,
        )

    elif req.type == ConnectorType.github:
        if not req.github:
            raise HTTPException(
                status_code=422,
                detail="GitHub config is required when type is 'github'",
            )
        connector = GitHubConnector(
            token=req.github.token,
            owner=req.github.owner,
            repo=req.github.repo,
        )

    elif req.type == ConnectorType.slack:
        if not req.slack:
            raise HTTPException(
                status_code=422,
                detail="Slack config is required when type is 'slack'",
            )
        connector = SlackConnector(
            webhook_url=req.slack.webhook_url,
            channel=req.slack.channel,
        )

    else:
        raise HTTPException(status_code=422, detail=f"Unsupported type: {req.type}")

    # Namespace the connector name by org to prevent cross-tenant access
    internal_name = f"{_org_prefix(org_id)}{req.name}"
    uc.register(internal_name, connector)
    logger.info("Registered connector: %s (type=%s, org=%s)", req.name, req.type.value, org_id)

    return {
        "status": "registered",
        "name": req.name,
        "type": req.type.value,
        "configured": connector.configured,
    }


@router.post("/test", summary="Test all connectors")
async def test_all_connectors() -> Dict[str, Any]:
    """Test connectivity to all registered connectors."""
    uc = _get_universal()
    results = await uc.test_all()
    return results


@router.post("/create-ticket", summary="Create ticket from finding")
async def create_ticket(req: CreateTicketRequest) -> Dict[str, Any]:
    """Create tickets across one or more connectors from a security finding.

    If no targets are specified, tickets are created on ALL registered
    connectors. Each connector runs independently -- if Jira fails,
    GitHub and Slack still execute.
    """
    uc = _get_universal()

    if not uc.list_connectors():
        raise HTTPException(
            status_code=409,
            detail="No connectors registered. Use POST /api/v1/connectors/register first.",
        )

    finding_dict = req.finding.model_dump(exclude_none=True)
    results = await uc.create_tickets(finding_dict, targets=req.targets)
    return results


@router.post("/{name}/test", summary="Test a specific connector")
async def test_connector(
    name: str = Path(..., min_length=1, max_length=63),
    org_id: str = Depends(_get_org_id),
) -> Dict[str, Any]:
    """Test connectivity to a specific registered connector."""
    name_lower = name.strip().lower()
    internal_name = f"{_org_prefix(org_id)}{name_lower}"
    uc = _get_universal()
    conn = uc.get_connector(internal_name)

    if conn is None:
        raise HTTPException(
            status_code=404,
            detail=f"Connector '{name_lower}' not found",
        )

    result = await conn.test_connection()
    return result.to_dict()


@router.delete("/{name}", summary="Remove a connector")
async def remove_connector(
    name: str = Path(..., min_length=1, max_length=63),
    org_id: str = Depends(_get_org_id),
) -> Dict[str, Any]:
    """Unregister and remove a connector."""
    name_lower = name.strip().lower()
    internal_name = f"{_org_prefix(org_id)}{name_lower}"
    uc = _get_universal()

    conn = uc.get_connector(internal_name)
    if conn is None:
        raise HTTPException(
            status_code=404,
            detail=f"Connector '{name_lower}' not found",
        )

    # Close HTTP client before removing
    await conn.close()
    uc.unregister(internal_name)
    logger.info("Removed connector: %s (org=%s)", name_lower, org_id)

    return {"status": "removed", "name": name_lower}


@router.get("/{name}/health", summary="Connector-level health check")
async def connector_health(
    name: str = Path(..., min_length=1, max_length=63),
    org_id: str = Depends(_get_org_id),
) -> Dict[str, Any]:
    """Return the live health status of a single registered connector.

    Calls the connector's ``health_check()`` method which performs a real
    network probe against the upstream service (e.g. Jira /myself, GitHub
    /zen, Slack ping).  Returns latency, healthy flag, and a message from
    the connector — no mocks, no cached state.

    Raises 404 if the connector name is not registered.
    Raises 502 if the health probe itself raises an unexpected exception.
    """
    name_lower = name.strip().lower()
    internal_name = f"{_org_prefix(org_id)}{name_lower}"
    uc = _get_universal()
    conn = uc.get_connector(internal_name)

    if conn is None:
        raise HTTPException(
            status_code=404,
            detail=f"Connector '{name_lower}' not found",
        )

    try:
        health = conn.health_check()
    except Exception as exc:  # pragma: no cover — network errors in prod
        logger.error("health_check failed for connector '%s': %s", name_lower, type(exc).__name__)
        raise HTTPException(
            status_code=502,
            detail=f"Health probe failed for connector '{name_lower}': {type(exc).__name__}",
        ) from exc

    result = health.to_dict()
    result["name"] = name_lower
    return result


@router.get("/health", summary="Connectors health")
async def connectors_health(org_id: str = Depends(_get_org_id)) -> Dict[str, Any]:
    """Return health status of the connectors subsystem for the caller's org."""
    uc = _get_universal()
    prefix = _org_prefix(org_id)
    connectors = [c for c in uc.list_connectors() if c["name"].startswith(prefix)]
    configured_count = sum(1 for c in connectors if c.get("configured"))

    return {
        "status": "healthy",
        "total_connectors": len(connectors),
        "configured_connectors": configured_count,
        "connectors": [
            {
                "name": _strip_prefix(c["name"], org_id),
                "type": c["type"],
                "configured": c["configured"],
            }
            for c in connectors
        ],
    }


@router.get("/", summary="List connectors (alias)", tags=["connectors"])
async def list_connectors_root(org_id: str = Depends(_get_org_id)) -> Dict[str, Any]:
    """Alias for GET /api/v1/connectors — returns registered connectors."""
    return await list_connectors(org_id=org_id)
