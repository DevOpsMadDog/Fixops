from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_tasks_api_v1_remediation_tasks_get_response_list_tasks_api_v1_remediation_tasks_get import (
    ListTasksApiV1RemediationTasksGetResponseListTasksApiV1RemediationTasksGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    app_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    assignee: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    overdue_only: bool | Unset = False,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_app_id: None | str | Unset
    if isinstance(app_id, Unset):
        json_app_id = UNSET
    else:
        json_app_id = app_id
    params["app_id"] = json_app_id

    json_status: None | str | Unset
    if isinstance(status, Unset):
        json_status = UNSET
    else:
        json_status = status
    params["status"] = json_status

    json_assignee: None | str | Unset
    if isinstance(assignee, Unset):
        json_assignee = UNSET
    else:
        json_assignee = assignee
    params["assignee"] = json_assignee

    json_severity: None | str | Unset
    if isinstance(severity, Unset):
        json_severity = UNSET
    else:
        json_severity = severity
    params["severity"] = json_severity

    params["overdue_only"] = overdue_only

    params["limit"] = limit

    params["offset"] = offset

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/remediation/tasks",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | ListTasksApiV1RemediationTasksGetResponseListTasksApiV1RemediationTasksGet | None:
    if response.status_code == 200:
        response_200 = ListTasksApiV1RemediationTasksGetResponseListTasksApiV1RemediationTasksGet.from_dict(
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
) -> Response[HTTPValidationError | ListTasksApiV1RemediationTasksGetResponseListTasksApiV1RemediationTasksGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    app_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    assignee: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    overdue_only: bool | Unset = False,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | ListTasksApiV1RemediationTasksGetResponseListTasksApiV1RemediationTasksGet]:
    """List Tasks

     List remediation tasks with optional filters.

    Args:
        app_id (None | str | Unset):
        status (None | str | Unset):
        assignee (None | str | Unset):
        severity (None | str | Unset):
        overdue_only (bool | Unset):  Default: False.
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListTasksApiV1RemediationTasksGetResponseListTasksApiV1RemediationTasksGet]
    """

    kwargs = _get_kwargs(
        app_id=app_id,
        status=status,
        assignee=assignee,
        severity=severity,
        overdue_only=overdue_only,
        limit=limit,
        offset=offset,
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
    app_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    assignee: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    overdue_only: bool | Unset = False,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | ListTasksApiV1RemediationTasksGetResponseListTasksApiV1RemediationTasksGet | None:
    """List Tasks

     List remediation tasks with optional filters.

    Args:
        app_id (None | str | Unset):
        status (None | str | Unset):
        assignee (None | str | Unset):
        severity (None | str | Unset):
        overdue_only (bool | Unset):  Default: False.
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListTasksApiV1RemediationTasksGetResponseListTasksApiV1RemediationTasksGet
    """

    return sync_detailed(
        client=client,
        app_id=app_id,
        status=status,
        assignee=assignee,
        severity=severity,
        overdue_only=overdue_only,
        limit=limit,
        offset=offset,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    app_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    assignee: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    overdue_only: bool | Unset = False,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | ListTasksApiV1RemediationTasksGetResponseListTasksApiV1RemediationTasksGet]:
    """List Tasks

     List remediation tasks with optional filters.

    Args:
        app_id (None | str | Unset):
        status (None | str | Unset):
        assignee (None | str | Unset):
        severity (None | str | Unset):
        overdue_only (bool | Unset):  Default: False.
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListTasksApiV1RemediationTasksGetResponseListTasksApiV1RemediationTasksGet]
    """

    kwargs = _get_kwargs(
        app_id=app_id,
        status=status,
        assignee=assignee,
        severity=severity,
        overdue_only=overdue_only,
        limit=limit,
        offset=offset,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    app_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    assignee: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    overdue_only: bool | Unset = False,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | ListTasksApiV1RemediationTasksGetResponseListTasksApiV1RemediationTasksGet | None:
    """List Tasks

     List remediation tasks with optional filters.

    Args:
        app_id (None | str | Unset):
        status (None | str | Unset):
        assignee (None | str | Unset):
        severity (None | str | Unset):
        overdue_only (bool | Unset):  Default: False.
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListTasksApiV1RemediationTasksGetResponseListTasksApiV1RemediationTasksGet
    """

    return (
        await asyncio_detailed(
            client=client,
            app_id=app_id,
            status=status,
            assignee=assignee,
            severity=severity,
            overdue_only=overdue_only,
            limit=limit,
            offset=offset,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
