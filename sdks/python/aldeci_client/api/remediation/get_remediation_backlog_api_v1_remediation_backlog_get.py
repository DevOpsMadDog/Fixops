from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_remediation_backlog_api_v1_remediation_backlog_get_response_get_remediation_backlog_api_v1_remediation_backlog_get import (
    GetRemediationBacklogApiV1RemediationBacklogGetResponseGetRemediationBacklogApiV1RemediationBacklogGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    severity: None | str | Unset = UNSET,
    sprint: None | str | Unset = UNSET,
    assignee: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_severity: None | str | Unset
    if isinstance(severity, Unset):
        json_severity = UNSET
    else:
        json_severity = severity
    params["severity"] = json_severity

    json_sprint: None | str | Unset
    if isinstance(sprint, Unset):
        json_sprint = UNSET
    else:
        json_sprint = sprint
    params["sprint"] = json_sprint

    json_assignee: None | str | Unset
    if isinstance(assignee, Unset):
        json_assignee = UNSET
    else:
        json_assignee = assignee
    params["assignee"] = json_assignee

    params["limit"] = limit

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/remediation/backlog",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetRemediationBacklogApiV1RemediationBacklogGetResponseGetRemediationBacklogApiV1RemediationBacklogGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetRemediationBacklogApiV1RemediationBacklogGetResponseGetRemediationBacklogApiV1RemediationBacklogGet.from_dict(
            response.json()
        )

        return response_200

    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetRemediationBacklogApiV1RemediationBacklogGetResponseGetRemediationBacklogApiV1RemediationBacklogGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
    sprint: None | str | Unset = UNSET,
    assignee: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetRemediationBacklogApiV1RemediationBacklogGetResponseGetRemediationBacklogApiV1RemediationBacklogGet
    | HTTPValidationError
]:
    """Get Remediation Backlog

     Return the sprint-aware security remediation backlog.

    Query parameters:
    - **severity**: Filter by severity level (critical, high, medium, low)
    - **sprint**: Pass ``current`` to return only sprint-eligible (open/active, non-overdue) tasks
    - **assignee**: Filter by assignee username; use ``unassigned`` to return tasks with no assignee
    - **limit**: Maximum number of items to return (default 50, max 500)

    Args:
        severity (None | str | Unset): Filter by severity: critical|high|medium|low
        sprint (None | str | Unset): 'current' returns only sprint-eligible tasks
        assignee (None | str | Unset): Filter by assignee; 'unassigned' returns tasks with no
            assignee
        limit (int | Unset):  Default: 50.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetRemediationBacklogApiV1RemediationBacklogGetResponseGetRemediationBacklogApiV1RemediationBacklogGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        severity=severity,
        sprint=sprint,
        assignee=assignee,
        limit=limit,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
    sprint: None | str | Unset = UNSET,
    assignee: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetRemediationBacklogApiV1RemediationBacklogGetResponseGetRemediationBacklogApiV1RemediationBacklogGet
    | HTTPValidationError
    | None
):
    """Get Remediation Backlog

     Return the sprint-aware security remediation backlog.

    Query parameters:
    - **severity**: Filter by severity level (critical, high, medium, low)
    - **sprint**: Pass ``current`` to return only sprint-eligible (open/active, non-overdue) tasks
    - **assignee**: Filter by assignee username; use ``unassigned`` to return tasks with no assignee
    - **limit**: Maximum number of items to return (default 50, max 500)

    Args:
        severity (None | str | Unset): Filter by severity: critical|high|medium|low
        sprint (None | str | Unset): 'current' returns only sprint-eligible tasks
        assignee (None | str | Unset): Filter by assignee; 'unassigned' returns tasks with no
            assignee
        limit (int | Unset):  Default: 50.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetRemediationBacklogApiV1RemediationBacklogGetResponseGetRemediationBacklogApiV1RemediationBacklogGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        severity=severity,
        sprint=sprint,
        assignee=assignee,
        limit=limit,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
    sprint: None | str | Unset = UNSET,
    assignee: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetRemediationBacklogApiV1RemediationBacklogGetResponseGetRemediationBacklogApiV1RemediationBacklogGet
    | HTTPValidationError
]:
    """Get Remediation Backlog

     Return the sprint-aware security remediation backlog.

    Query parameters:
    - **severity**: Filter by severity level (critical, high, medium, low)
    - **sprint**: Pass ``current`` to return only sprint-eligible (open/active, non-overdue) tasks
    - **assignee**: Filter by assignee username; use ``unassigned`` to return tasks with no assignee
    - **limit**: Maximum number of items to return (default 50, max 500)

    Args:
        severity (None | str | Unset): Filter by severity: critical|high|medium|low
        sprint (None | str | Unset): 'current' returns only sprint-eligible tasks
        assignee (None | str | Unset): Filter by assignee; 'unassigned' returns tasks with no
            assignee
        limit (int | Unset):  Default: 50.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetRemediationBacklogApiV1RemediationBacklogGetResponseGetRemediationBacklogApiV1RemediationBacklogGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        severity=severity,
        sprint=sprint,
        assignee=assignee,
        limit=limit,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
    sprint: None | str | Unset = UNSET,
    assignee: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetRemediationBacklogApiV1RemediationBacklogGetResponseGetRemediationBacklogApiV1RemediationBacklogGet
    | HTTPValidationError
    | None
):
    """Get Remediation Backlog

     Return the sprint-aware security remediation backlog.

    Query parameters:
    - **severity**: Filter by severity level (critical, high, medium, low)
    - **sprint**: Pass ``current`` to return only sprint-eligible (open/active, non-overdue) tasks
    - **assignee**: Filter by assignee username; use ``unassigned`` to return tasks with no assignee
    - **limit**: Maximum number of items to return (default 50, max 500)

    Args:
        severity (None | str | Unset): Filter by severity: critical|high|medium|low
        sprint (None | str | Unset): 'current' returns only sprint-eligible tasks
        assignee (None | str | Unset): Filter by assignee; 'unassigned' returns tasks with no
            assignee
        limit (int | Unset):  Default: 50.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetRemediationBacklogApiV1RemediationBacklogGetResponseGetRemediationBacklogApiV1RemediationBacklogGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            severity=severity,
            sprint=sprint,
            assignee=assignee,
            limit=limit,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
