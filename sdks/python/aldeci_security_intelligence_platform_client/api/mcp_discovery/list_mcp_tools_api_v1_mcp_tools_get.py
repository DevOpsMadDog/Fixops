from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.mcp_tool_definition import MCPToolDefinition
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    category: None | str | Unset = UNSET,
    tag: None | str | Unset = UNSET,
    method: None | str | Unset = UNSET,
    search: None | str | Unset = UNSET,
    deprecated: bool | None | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_category: None | str | Unset
    if isinstance(category, Unset):
        json_category = UNSET
    else:
        json_category = category
    params["category"] = json_category

    json_tag: None | str | Unset
    if isinstance(tag, Unset):
        json_tag = UNSET
    else:
        json_tag = tag
    params["tag"] = json_tag

    json_method: None | str | Unset
    if isinstance(method, Unset):
        json_method = UNSET
    else:
        json_method = method
    params["method"] = json_method

    json_search: None | str | Unset
    if isinstance(search, Unset):
        json_search = UNSET
    else:
        json_search = search
    params["search"] = json_search

    json_deprecated: bool | None | Unset
    if isinstance(deprecated, Unset):
        json_deprecated = UNSET
    else:
        json_deprecated = deprecated
    params["deprecated"] = json_deprecated

    params["limit"] = limit

    params["offset"] = offset

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/mcp/tools",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[MCPToolDefinition] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = MCPToolDefinition.from_dict(response_200_item_data)

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
) -> Response[HTTPValidationError | list[MCPToolDefinition]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    category: None | str | Unset = UNSET,
    tag: None | str | Unset = UNSET,
    method: None | str | Unset = UNSET,
    search: None | str | Unset = UNSET,
    deprecated: bool | None | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> Response[HTTPValidationError | list[MCPToolDefinition]]:
    """List Mcp Tools

     Return the complete MCP tool catalog with optional filtering.

    This endpoint returns auto-discovered tools generated from all FastAPI
    routes registered in the application. Tools are generated once at
    startup and cached for performance.

    Supports filtering by category (query/action/analysis), tag, HTTP method,
    and free-text search across tool names and descriptions.

    Args:
        category (None | str | Unset): Filter by category: query, action, analysis
        tag (None | str | Unset): Filter by tag
        method (None | str | Unset): Filter by HTTP method: GET, POST, PUT, DELETE, PATCH
        search (None | str | Unset): Search tool names and descriptions
        deprecated (bool | None | Unset): Filter by deprecation status
        limit (int | Unset): Max tools to return Default: 100.
        offset (int | Unset): Offset for pagination Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[MCPToolDefinition]]
    """

    kwargs = _get_kwargs(
        category=category,
        tag=tag,
        method=method,
        search=search,
        deprecated=deprecated,
        limit=limit,
        offset=offset,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    category: None | str | Unset = UNSET,
    tag: None | str | Unset = UNSET,
    method: None | str | Unset = UNSET,
    search: None | str | Unset = UNSET,
    deprecated: bool | None | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> HTTPValidationError | list[MCPToolDefinition] | None:
    """List Mcp Tools

     Return the complete MCP tool catalog with optional filtering.

    This endpoint returns auto-discovered tools generated from all FastAPI
    routes registered in the application. Tools are generated once at
    startup and cached for performance.

    Supports filtering by category (query/action/analysis), tag, HTTP method,
    and free-text search across tool names and descriptions.

    Args:
        category (None | str | Unset): Filter by category: query, action, analysis
        tag (None | str | Unset): Filter by tag
        method (None | str | Unset): Filter by HTTP method: GET, POST, PUT, DELETE, PATCH
        search (None | str | Unset): Search tool names and descriptions
        deprecated (bool | None | Unset): Filter by deprecation status
        limit (int | Unset): Max tools to return Default: 100.
        offset (int | Unset): Offset for pagination Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[MCPToolDefinition]
    """

    return sync_detailed(
        client=client,
        category=category,
        tag=tag,
        method=method,
        search=search,
        deprecated=deprecated,
        limit=limit,
        offset=offset,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    category: None | str | Unset = UNSET,
    tag: None | str | Unset = UNSET,
    method: None | str | Unset = UNSET,
    search: None | str | Unset = UNSET,
    deprecated: bool | None | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> Response[HTTPValidationError | list[MCPToolDefinition]]:
    """List Mcp Tools

     Return the complete MCP tool catalog with optional filtering.

    This endpoint returns auto-discovered tools generated from all FastAPI
    routes registered in the application. Tools are generated once at
    startup and cached for performance.

    Supports filtering by category (query/action/analysis), tag, HTTP method,
    and free-text search across tool names and descriptions.

    Args:
        category (None | str | Unset): Filter by category: query, action, analysis
        tag (None | str | Unset): Filter by tag
        method (None | str | Unset): Filter by HTTP method: GET, POST, PUT, DELETE, PATCH
        search (None | str | Unset): Search tool names and descriptions
        deprecated (bool | None | Unset): Filter by deprecation status
        limit (int | Unset): Max tools to return Default: 100.
        offset (int | Unset): Offset for pagination Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[MCPToolDefinition]]
    """

    kwargs = _get_kwargs(
        category=category,
        tag=tag,
        method=method,
        search=search,
        deprecated=deprecated,
        limit=limit,
        offset=offset,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    category: None | str | Unset = UNSET,
    tag: None | str | Unset = UNSET,
    method: None | str | Unset = UNSET,
    search: None | str | Unset = UNSET,
    deprecated: bool | None | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> HTTPValidationError | list[MCPToolDefinition] | None:
    """List Mcp Tools

     Return the complete MCP tool catalog with optional filtering.

    This endpoint returns auto-discovered tools generated from all FastAPI
    routes registered in the application. Tools are generated once at
    startup and cached for performance.

    Supports filtering by category (query/action/analysis), tag, HTTP method,
    and free-text search across tool names and descriptions.

    Args:
        category (None | str | Unset): Filter by category: query, action, analysis
        tag (None | str | Unset): Filter by tag
        method (None | str | Unset): Filter by HTTP method: GET, POST, PUT, DELETE, PATCH
        search (None | str | Unset): Search tool names and descriptions
        deprecated (bool | None | Unset): Filter by deprecation status
        limit (int | Unset): Max tools to return Default: 100.
        offset (int | Unset): Offset for pagination Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[MCPToolDefinition]
    """

    return (
        await asyncio_detailed(
            client=client,
            category=category,
            tag=tag,
            method=method,
            search=search,
            deprecated=deprecated,
            limit=limit,
            offset=offset,
        )
    ).parsed
