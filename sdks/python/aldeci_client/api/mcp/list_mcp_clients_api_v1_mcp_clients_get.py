from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.mcp_client import MCPClient
from ...models.mcp_client_status import MCPClientStatus
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    status: MCPClientStatus | None | Unset = UNSET,
    client_type: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_status: None | str | Unset
    if isinstance(status, Unset):
        json_status = UNSET
    elif isinstance(status, MCPClientStatus):
        json_status = status.value
    else:
        json_status = status
    params["status"] = json_status

    json_client_type: None | str | Unset
    if isinstance(client_type, Unset):
        json_client_type = UNSET
    else:
        json_client_type = client_type
    params["client_type"] = json_client_type

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/mcp/clients",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[MCPClient] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = MCPClient.from_dict(response_200_item_data)

            response_200.append(response_200_item)

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
) -> Response[HTTPValidationError | list[MCPClient]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    status: MCPClientStatus | None | Unset = UNSET,
    client_type: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[MCPClient]]:
    """List Mcp Clients

     List connected MCP clients.

    Args:
        status (MCPClientStatus | None | Unset):
        client_type (None | str | Unset):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[MCPClient]]
    """

    kwargs = _get_kwargs(
        status=status,
        client_type=client_type,
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
    status: MCPClientStatus | None | Unset = UNSET,
    client_type: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | list[MCPClient] | None:
    """List Mcp Clients

     List connected MCP clients.

    Args:
        status (MCPClientStatus | None | Unset):
        client_type (None | str | Unset):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[MCPClient]
    """

    return sync_detailed(
        client=client,
        status=status,
        client_type=client_type,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    status: MCPClientStatus | None | Unset = UNSET,
    client_type: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[MCPClient]]:
    """List Mcp Clients

     List connected MCP clients.

    Args:
        status (MCPClientStatus | None | Unset):
        client_type (None | str | Unset):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[MCPClient]]
    """

    kwargs = _get_kwargs(
        status=status,
        client_type=client_type,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    status: MCPClientStatus | None | Unset = UNSET,
    client_type: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | list[MCPClient] | None:
    """List Mcp Clients

     List connected MCP clients.

    Args:
        status (MCPClientStatus | None | Unset):
        client_type (None | str | Unset):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[MCPClient]
    """

    return (
        await asyncio_detailed(
            client=client,
            status=status,
            client_type=client_type,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
