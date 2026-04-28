from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.agent_task_request import AgentTaskRequest
from ...models.dispatch_agent_task_api_v1_agents_role_task_post_response_dispatch_agent_task_api_v1_agents_role_task_post import (
    DispatchAgentTaskApiV1AgentsRoleTaskPostResponseDispatchAgentTaskApiV1AgentsRoleTaskPost,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    role: str,
    *,
    body: AgentTaskRequest,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/agents/{role}/task".format(
            role=quote(str(role), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DispatchAgentTaskApiV1AgentsRoleTaskPostResponseDispatchAgentTaskApiV1AgentsRoleTaskPost
    | HTTPValidationError
    | None
):
    if response.status_code == 202:
        response_202 = (
            DispatchAgentTaskApiV1AgentsRoleTaskPostResponseDispatchAgentTaskApiV1AgentsRoleTaskPost.from_dict(
                response.json()
            )
        )

        return response_202

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
    DispatchAgentTaskApiV1AgentsRoleTaskPostResponseDispatchAgentTaskApiV1AgentsRoleTaskPost | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    role: str,
    *,
    client: AuthenticatedClient,
    body: AgentTaskRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    DispatchAgentTaskApiV1AgentsRoleTaskPostResponseDispatchAgentTaskApiV1AgentsRoleTaskPost | HTTPValidationError
]:
    """Dispatch Agent Task

     Dispatch a task to a named agent role (security_analyst, pentester, etc).

    (Multica 37c6a559)

    Args:
        role (str):
        x_org_id (None | str | Unset):
        body (AgentTaskRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DispatchAgentTaskApiV1AgentsRoleTaskPostResponseDispatchAgentTaskApiV1AgentsRoleTaskPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        role=role,
        body=body,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    role: str,
    *,
    client: AuthenticatedClient,
    body: AgentTaskRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    DispatchAgentTaskApiV1AgentsRoleTaskPostResponseDispatchAgentTaskApiV1AgentsRoleTaskPost
    | HTTPValidationError
    | None
):
    """Dispatch Agent Task

     Dispatch a task to a named agent role (security_analyst, pentester, etc).

    (Multica 37c6a559)

    Args:
        role (str):
        x_org_id (None | str | Unset):
        body (AgentTaskRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DispatchAgentTaskApiV1AgentsRoleTaskPostResponseDispatchAgentTaskApiV1AgentsRoleTaskPost | HTTPValidationError
    """

    return sync_detailed(
        role=role,
        client=client,
        body=body,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    role: str,
    *,
    client: AuthenticatedClient,
    body: AgentTaskRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    DispatchAgentTaskApiV1AgentsRoleTaskPostResponseDispatchAgentTaskApiV1AgentsRoleTaskPost | HTTPValidationError
]:
    """Dispatch Agent Task

     Dispatch a task to a named agent role (security_analyst, pentester, etc).

    (Multica 37c6a559)

    Args:
        role (str):
        x_org_id (None | str | Unset):
        body (AgentTaskRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DispatchAgentTaskApiV1AgentsRoleTaskPostResponseDispatchAgentTaskApiV1AgentsRoleTaskPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        role=role,
        body=body,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    role: str,
    *,
    client: AuthenticatedClient,
    body: AgentTaskRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    DispatchAgentTaskApiV1AgentsRoleTaskPostResponseDispatchAgentTaskApiV1AgentsRoleTaskPost
    | HTTPValidationError
    | None
):
    """Dispatch Agent Task

     Dispatch a task to a named agent role (security_analyst, pentester, etc).

    (Multica 37c6a559)

    Args:
        role (str):
        x_org_id (None | str | Unset):
        body (AgentTaskRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DispatchAgentTaskApiV1AgentsRoleTaskPostResponseDispatchAgentTaskApiV1AgentsRoleTaskPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            role=role,
            client=client,
            body=body,
            x_org_id=x_org_id,
        )
    ).parsed
