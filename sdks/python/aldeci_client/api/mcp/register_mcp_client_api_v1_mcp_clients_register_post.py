from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.mcp_transport import MCPTransport
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: list[str] | Unset = UNSET,
    name: str | Unset = "anonymous",
    client_type: str | Unset = "agent",
    transport: MCPTransport | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["name"] = name

    params["client_type"] = client_type

    json_transport: str | Unset = UNSET
    if not isinstance(transport, Unset):
        json_transport = transport.value

    params["transport"] = json_transport

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/mcp/clients/register",
        "params": params,
    }

    if not isinstance(body, Unset):
        _kwargs["json"] = body

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = response.json()
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
) -> Response[Any | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: list[str] | Unset = UNSET,
    name: str | Unset = "anonymous",
    client_type: str | Unset = "agent",
    transport: MCPTransport | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[Any | HTTPValidationError]:
    """Register Mcp Client

     Register a new MCP client connection.

    Args:
        name (str | Unset):  Default: 'anonymous'.
        client_type (str | Unset):  Default: 'agent'.
        transport (MCPTransport | Unset):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (list[str] | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        name=name,
        client_type=client_type,
        transport=transport,
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
    body: list[str] | Unset = UNSET,
    name: str | Unset = "anonymous",
    client_type: str | Unset = "agent",
    transport: MCPTransport | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Any | HTTPValidationError | None:
    """Register Mcp Client

     Register a new MCP client connection.

    Args:
        name (str | Unset):  Default: 'anonymous'.
        client_type (str | Unset):  Default: 'agent'.
        transport (MCPTransport | Unset):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (list[str] | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
        name=name,
        client_type=client_type,
        transport=transport,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: list[str] | Unset = UNSET,
    name: str | Unset = "anonymous",
    client_type: str | Unset = "agent",
    transport: MCPTransport | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[Any | HTTPValidationError]:
    """Register Mcp Client

     Register a new MCP client connection.

    Args:
        name (str | Unset):  Default: 'anonymous'.
        client_type (str | Unset):  Default: 'agent'.
        transport (MCPTransport | Unset):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (list[str] | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        name=name,
        client_type=client_type,
        transport=transport,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: list[str] | Unset = UNSET,
    name: str | Unset = "anonymous",
    client_type: str | Unset = "agent",
    transport: MCPTransport | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Any | HTTPValidationError | None:
    """Register Mcp Client

     Register a new MCP client connection.

    Args:
        name (str | Unset):  Default: 'anonymous'.
        client_type (str | Unset):  Default: 'agent'.
        transport (MCPTransport | Unset):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (list[str] | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            name=name,
            client_type=client_type,
            transport=transport,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
