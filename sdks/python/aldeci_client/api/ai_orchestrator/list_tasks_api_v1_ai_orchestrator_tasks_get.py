from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_tasks_api_v1_ai_orchestrator_tasks_get_response_list_tasks_api_v1_ai_orchestrator_tasks_get import (
    ListTasksApiV1AiOrchestratorTasksGetResponseListTasksApiV1AiOrchestratorTasksGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    role: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_role: None | str | Unset
    if isinstance(role, Unset):
        json_role = UNSET
    else:
        json_role = role
    params["role"] = json_role

    json_status: None | str | Unset
    if isinstance(status, Unset):
        json_status = UNSET
    else:
        json_status = status
    params["status"] = json_status

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
        "url": "/api/v1/ai-orchestrator/tasks",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | ListTasksApiV1AiOrchestratorTasksGetResponseListTasksApiV1AiOrchestratorTasksGet | None:
    if response.status_code == 200:
        response_200 = ListTasksApiV1AiOrchestratorTasksGetResponseListTasksApiV1AiOrchestratorTasksGet.from_dict(
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
) -> Response[HTTPValidationError | ListTasksApiV1AiOrchestratorTasksGetResponseListTasksApiV1AiOrchestratorTasksGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    role: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | ListTasksApiV1AiOrchestratorTasksGetResponseListTasksApiV1AiOrchestratorTasksGet]:
    """List task history

     Return task history, optionally filtered by role and status.

    Args:
        role (None | str | Unset): Filter by agent role
        status (None | str | Unset): Filter by status: pending|running|completed|failed
        limit (int | Unset):  Default: 50.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListTasksApiV1AiOrchestratorTasksGetResponseListTasksApiV1AiOrchestratorTasksGet]
    """

    kwargs = _get_kwargs(
        role=role,
        status=status,
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
    role: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | ListTasksApiV1AiOrchestratorTasksGetResponseListTasksApiV1AiOrchestratorTasksGet | None:
    """List task history

     Return task history, optionally filtered by role and status.

    Args:
        role (None | str | Unset): Filter by agent role
        status (None | str | Unset): Filter by status: pending|running|completed|failed
        limit (int | Unset):  Default: 50.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListTasksApiV1AiOrchestratorTasksGetResponseListTasksApiV1AiOrchestratorTasksGet
    """

    return sync_detailed(
        client=client,
        role=role,
        status=status,
        limit=limit,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    role: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | ListTasksApiV1AiOrchestratorTasksGetResponseListTasksApiV1AiOrchestratorTasksGet]:
    """List task history

     Return task history, optionally filtered by role and status.

    Args:
        role (None | str | Unset): Filter by agent role
        status (None | str | Unset): Filter by status: pending|running|completed|failed
        limit (int | Unset):  Default: 50.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListTasksApiV1AiOrchestratorTasksGetResponseListTasksApiV1AiOrchestratorTasksGet]
    """

    kwargs = _get_kwargs(
        role=role,
        status=status,
        limit=limit,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    role: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | ListTasksApiV1AiOrchestratorTasksGetResponseListTasksApiV1AiOrchestratorTasksGet | None:
    """List task history

     Return task history, optionally filtered by role and status.

    Args:
        role (None | str | Unset): Filter by agent role
        status (None | str | Unset): Filter by status: pending|running|completed|failed
        limit (int | Unset):  Default: 50.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListTasksApiV1AiOrchestratorTasksGetResponseListTasksApiV1AiOrchestratorTasksGet
    """

    return (
        await asyncio_detailed(
            client=client,
            role=role,
            status=status,
            limit=limit,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
