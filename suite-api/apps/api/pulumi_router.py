"""Pulumi Cloud Router — ALDECI.

REST surface under prefix ``/api/v1/pulumi`` wrapping ``core.pulumi_engine``.

Endpoints
---------
* GET  /                                                                 — capability summary
* GET  /api/user                                                         — viewer profile + orgs
* GET  /api/orgs/{org}/stacks                                            — list stacks
* GET  /api/stacks/{org}/{project}/{stack}                               — stack detail
* GET  /api/stacks/{org}/{project}/{stack}/updates                       — updates list
* GET  /api/stacks/{org}/{project}/{stack}/updates/{version}             — single update
* GET  /api/stacks/{org}/{project}/{stack}/updates/latest                — latest update
* GET  /api/stacks/{org}/{project}/{stack}/exports                       — state export
* GET  /api/orgs/{org}/policygroups                                      — policy groups
* GET  /api/orgs/{org}/policygroups/{group_name}                         — single group
* GET  /api/orgs/{org}/policypacks                                       — policy packs (required + optional)
* GET  /api/orgs/{org}/policypacks/{pack_name}/versions/{version}/policies — policy details

Auth
----
api_key_auth dependency (mount layer adds scope checks — read:scans).

NO MOCKS rule
-------------
* When PULUMI_ACCESS_TOKEN is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/pulumi",
    tags=["Pulumi"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.pulumi_engine import get_pulumi_engine

    return get_pulumi_engine()


def _serve(callable_):
    """Run a Pulumi call, translating engine errors to HTTP responses."""
    from core.pulumi_engine import PulumiUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except PulumiUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas — capability + viewer
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    pulumi_access_token_present: bool
    status: str  # ok | empty | unavailable


class UserOrg(BaseModel):
    githubLogin: str = ""
    name: str = ""
    avatarUrl: str = ""


class UserResponse(BaseModel):
    name: str = ""
    githubLogin: str = ""
    email: str = ""
    avatarUrl: str = ""
    organizations: List[UserOrg] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Schemas — stacks
# ---------------------------------------------------------------------------


class StackEntry(BaseModel):
    orgName: str = ""
    projectName: str = ""
    stackName: str = ""
    lastUpdate: int = 0
    resourceCount: int = 0


class StacksListResponse(BaseModel):
    stacks: List[StackEntry] = Field(default_factory=list)
    continuationToken: str = ""


class StackSettings(BaseModel):
    secretsProvider: Any = ""


class StackDetailResponse(BaseModel):
    orgName: str = ""
    projectName: str = ""
    stackName: str = ""
    currentOperation: str = ""
    lastUpdate: int = 0
    resourceCount: int = 0
    version: int = 0
    tags: Dict[str, Any] = Field(default_factory=dict)
    links: Dict[str, Any] = Field(default_factory=dict)
    config: Dict[str, Any] = Field(default_factory=dict)
    settings: StackSettings = Field(default_factory=StackSettings)
    runtime: str = ""
    environments: List[Any] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Schemas — updates
# ---------------------------------------------------------------------------


class ResourceChanges(BaseModel):
    create: int = 0
    update: int = 0
    delete: int = 0
    replace: int = 0
    same: int = 0


class UpdateDeployment(BaseModel):
    operations: List[Any] = Field(default_factory=list)


class UpdateInfo(BaseModel):
    version: int = 0
    kind: str = ""
    startTime: int = 0
    endTime: int = 0
    message: str = ""
    environment: Dict[str, Any] = Field(default_factory=dict)
    resourceChanges: ResourceChanges = Field(default_factory=ResourceChanges)
    resourceCount: int = 0
    deployment: UpdateDeployment = Field(default_factory=UpdateDeployment)


class UpdateEntry(BaseModel):
    info: UpdateInfo = Field(default_factory=UpdateInfo)
    environment: Dict[str, Any] = Field(default_factory=dict)
    deployment: Dict[str, Any] = Field(default_factory=dict)


class UpdatesListResponse(BaseModel):
    updates: List[UpdateEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Schemas — exports
# ---------------------------------------------------------------------------


class SourcePosition(BaseModel):
    uri: str = ""
    line: int = 0
    column: int = 0


class ResourceEntry(BaseModel):
    urn: str = ""
    custom: bool = False
    id: str = ""
    type: str = ""
    inputs: Dict[str, Any] = Field(default_factory=dict)
    outputs: Dict[str, Any] = Field(default_factory=dict)
    parent: str = ""
    dependencies: List[str] = Field(default_factory=list)
    propertyDependencies: Dict[str, Any] = Field(default_factory=dict)
    provider: str = ""
    protect: bool = False
    externalDependencies: List[Any] = Field(default_factory=list)
    additionalSecretOutputs: List[str] = Field(default_factory=list)
    aliases: List[Any] = Field(default_factory=list)
    created: str = ""
    modified: str = ""
    sourcePosition: SourcePosition = Field(default_factory=SourcePosition)


class SecretsProvidersBlock(BaseModel):
    type: str = ""
    state: Dict[str, Any] = Field(default_factory=dict)


class ExportDeployment(BaseModel):
    manifest: Dict[str, Any] = Field(default_factory=dict)
    secrets_providers: List[Any] = Field(default_factory=list)
    resources: List[ResourceEntry] = Field(default_factory=list)
    pendingOperations: List[Any] = Field(default_factory=list)
    secretsProviders: SecretsProvidersBlock = Field(
        default_factory=SecretsProvidersBlock
    )


class ExportResponse(BaseModel):
    version: int = 0
    deployment: ExportDeployment = Field(default_factory=ExportDeployment)


# ---------------------------------------------------------------------------
# Schemas — policy
# ---------------------------------------------------------------------------


class PolicyGroupEntry(BaseModel):
    name: str = ""
    description: str = ""
    isOrgDefault: bool = False
    numStacks: int = 0
    numEnabledPolicyPacks: int = 0


class PolicyGroupsResponse(BaseModel):
    policyGroups: List[PolicyGroupEntry] = Field(default_factory=list)


class PolicyGroupDetailResponse(BaseModel):
    name: str = ""
    description: str = ""
    isOrgDefault: bool = False
    numStacks: int = 0
    numEnabledPolicyPacks: int = 0
    stacks: List[Any] = Field(default_factory=list)
    policyPacks: List[Any] = Field(default_factory=list)


class RequiredPolicyEntry(BaseModel):
    name: str = ""
    displayName: str = ""
    version: int = 0
    versionTag: str = ""
    latestVersion: int = 0
    latestVersionTag: str = ""
    enforcementLevel: str = ""


class PolicyPackEntry(BaseModel):
    name: str = ""
    displayName: str = ""
    latestVersion: int = 0
    latestVersionTag: str = ""


class PolicyPacksResponse(BaseModel):
    requiredPolicies: List[RequiredPolicyEntry] = Field(default_factory=list)
    policyPacks: List[PolicyPackEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilityResponse,
    summary="Pulumi Cloud capability summary",
)
async def capability_summary() -> CapabilityResponse:
    """Return the service summary — safe to call without a token."""
    eng = _engine()
    token_present = eng.api_key_present()
    status = "ok" if token_present else "unavailable"
    return CapabilityResponse(
        service="Pulumi Cloud",
        endpoints=[
            "/api/user",
            "/api/orgs/{org}/stacks",
            "/api/stacks/{org}/{project}/{stack}",
            "/api/orgs/{org}/policygroups",
            "/api/orgs/{org}/policypacks",
        ],
        pulumi_access_token_present=token_present,
        status=status,
    )


@router.get(
    "/api/user",
    response_model=UserResponse,
    summary="Pulumi viewer profile + orgs",
)
async def get_user() -> UserResponse:
    eng = _engine()
    data = _serve(lambda: eng.get_user())
    return UserResponse(**data)


@router.get(
    "/api/orgs/{org}/stacks",
    response_model=StacksListResponse,
    summary="List Pulumi stacks for an organisation",
)
async def list_stacks(
    org: str = Path(..., description="Pulumi organisation slug"),
    continuationToken: Optional[str] = Query(
        default=None, description="Pagination cursor"
    ),
    project: Optional[str] = Query(
        default=None, description="Filter by project name"
    ),
    tag: Optional[str] = Query(
        default=None, description="Filter by tag in 'k:v' form"
    ),
) -> StacksListResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_stacks(
            org=org,
            continuation_token=continuationToken,
            project=project,
            tag=tag,
        )
    )
    return StacksListResponse(**data)


@router.get(
    "/api/stacks/{org}/{project}/{stack}",
    response_model=StackDetailResponse,
    summary="Get Pulumi stack detail",
)
async def get_stack(
    org: str = Path(..., description="Pulumi organisation slug"),
    project: str = Path(..., description="Pulumi project name"),
    stack: str = Path(..., description="Pulumi stack name"),
) -> StackDetailResponse:
    eng = _engine()
    data = _serve(lambda: eng.get_stack(org=org, project=project, stack=stack))
    return StackDetailResponse(**data)


@router.get(
    "/api/stacks/{org}/{project}/{stack}/updates",
    response_model=UpdatesListResponse,
    summary="List stack updates",
)
async def list_updates(
    org: str = Path(...),
    project: str = Path(...),
    stack: str = Path(...),
    page: Optional[int] = Query(default=None, ge=1),
    pageSize: Optional[int] = Query(default=None, ge=1, le=500),
) -> UpdatesListResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_updates(
            org=org,
            project=project,
            stack=stack,
            page=page,
            page_size=pageSize,
        )
    )
    return UpdatesListResponse(**data)


@router.get(
    "/api/stacks/{org}/{project}/{stack}/updates/latest",
    response_model=UpdateEntry,
    summary="Get latest stack update",
)
async def get_latest_update(
    org: str = Path(...),
    project: str = Path(...),
    stack: str = Path(...),
) -> UpdateEntry:
    eng = _engine()
    data = _serve(
        lambda: eng.get_latest_update(org=org, project=project, stack=stack)
    )
    return UpdateEntry(**data)


@router.get(
    "/api/stacks/{org}/{project}/{stack}/updates/{version}",
    response_model=UpdateEntry,
    summary="Get single stack update by version",
)
async def get_update(
    org: str = Path(...),
    project: str = Path(...),
    stack: str = Path(...),
    version: str = Path(..., description="Update version (numeric)"),
) -> UpdateEntry:
    eng = _engine()
    data = _serve(
        lambda: eng.get_update(
            org=org, project=project, stack=stack, version=version
        )
    )
    return UpdateEntry(**data)


@router.get(
    "/api/stacks/{org}/{project}/{stack}/exports",
    response_model=ExportResponse,
    summary="Get stack state export",
)
async def get_exports(
    org: str = Path(...),
    project: str = Path(...),
    stack: str = Path(...),
) -> ExportResponse:
    eng = _engine()
    data = _serve(lambda: eng.get_exports(org=org, project=project, stack=stack))
    return ExportResponse(**data)


@router.get(
    "/api/orgs/{org}/policygroups",
    response_model=PolicyGroupsResponse,
    summary="List Pulumi policy groups",
)
async def list_policy_groups(
    org: str = Path(...),
    continuationToken: Optional[str] = Query(default=None),
) -> PolicyGroupsResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_policy_groups(
            org=org, continuation_token=continuationToken
        )
    )
    return PolicyGroupsResponse(**data)


@router.get(
    "/api/orgs/{org}/policygroups/{group_name}",
    response_model=PolicyGroupDetailResponse,
    summary="Get Pulumi policy group detail",
)
async def get_policy_group(
    org: str = Path(...),
    group_name: str = Path(...),
) -> PolicyGroupDetailResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.get_policy_group(org=org, group_name=group_name)
    )
    return PolicyGroupDetailResponse(**data)


@router.get(
    "/api/orgs/{org}/policypacks",
    response_model=PolicyPacksResponse,
    summary="List Pulumi policy packs",
)
async def list_policy_packs(
    org: str = Path(...),
    continuationToken: Optional[str] = Query(default=None),
) -> PolicyPacksResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_policy_packs(
            org=org, continuation_token=continuationToken
        )
    )
    return PolicyPacksResponse(**data)


@router.get(
    "/api/orgs/{org}/policypacks/{pack_name}/versions/{version}/policies",
    summary="Get policy details for a pack version",
)
async def get_policy_pack_policies(
    org: str = Path(...),
    pack_name: str = Path(...),
    version: str = Path(..., description="Pack version (numeric or tag)"),
) -> Dict[str, Any]:
    eng = _engine()
    data = _serve(
        lambda: eng.get_policy_pack_policies(
            org=org, pack_name=pack_name, version=version
        )
    )
    return data


__all__ = ["router"]
