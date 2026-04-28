from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.mcp_status_api_v1_mcp_status_get_response_mcp_status_api_v1_mcp_status_get import (
    McpStatusApiV1McpStatusGetResponseMcpStatusApiV1McpStatusGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/mcp/status",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> McpStatusApiV1McpStatusGetResponseMcpStatusApiV1McpStatusGet | None:
    if response.status_code == 200:
        response_200 = McpStatusApiV1McpStatusGetResponseMcpStatusApiV1McpStatusGet.from_dict(response.json())

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[McpStatusApiV1McpStatusGetResponseMcpStatusApiV1McpStatusGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[McpStatusApiV1McpStatusGetResponseMcpStatusApiV1McpStatusGet]:
    """Mcp Status

     Status alias for MCP auto-discovery (mirrors /health).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[McpStatusApiV1McpStatusGetResponseMcpStatusApiV1McpStatusGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> McpStatusApiV1McpStatusGetResponseMcpStatusApiV1McpStatusGet | None:
    """Mcp Status

     Status alias for MCP auto-discovery (mirrors /health).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        McpStatusApiV1McpStatusGetResponseMcpStatusApiV1McpStatusGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[McpStatusApiV1McpStatusGetResponseMcpStatusApiV1McpStatusGet]:
    """Mcp Status

     Status alias for MCP auto-discovery (mirrors /health).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[McpStatusApiV1McpStatusGetResponseMcpStatusApiV1McpStatusGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> McpStatusApiV1McpStatusGetResponseMcpStatusApiV1McpStatusGet | None:
    """Mcp Status

     Status alias for MCP auto-discovery (mirrors /health).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        McpStatusApiV1McpStatusGetResponseMcpStatusApiV1McpStatusGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
