from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.mcp_tool_call_request import MCPToolCallRequest
from ...models.mcp_tool_call_response import MCPToolCallResponse
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: MCPToolCallRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/mcp/tools/call",
        "params": params,
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | MCPToolCallResponse | None:
    if response.status_code == 200:
        response_200 = MCPToolCallResponse.from_dict(response.json())

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
) -> Response[HTTPValidationError | MCPToolCallResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: MCPToolCallRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | MCPToolCallResponse]:
    """Call Mcp Tool

     Execute an MCP tool. This is the core execution endpoint that wires
    MCP tool calls to actual FixOps backend engines.

    Supports all 8 registered MCP tools:
    - fixops_list_findings / fixops_get_finding
    - fixops_run_scan
    - fixops_generate_evidence
    - fixops_create_autofix_pr
    - fixops_get_risk_score
    - fixops_list_connectors
    - fixops_notify

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (MCPToolCallRequest): Request to execute an MCP tool.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | MCPToolCallResponse]
    """

    kwargs = _get_kwargs(
        body=body,
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
    body: MCPToolCallRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | MCPToolCallResponse | None:
    """Call Mcp Tool

     Execute an MCP tool. This is the core execution endpoint that wires
    MCP tool calls to actual FixOps backend engines.

    Supports all 8 registered MCP tools:
    - fixops_list_findings / fixops_get_finding
    - fixops_run_scan
    - fixops_generate_evidence
    - fixops_create_autofix_pr
    - fixops_get_risk_score
    - fixops_list_connectors
    - fixops_notify

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (MCPToolCallRequest): Request to execute an MCP tool.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | MCPToolCallResponse
    """

    return sync_detailed(
        client=client,
        body=body,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: MCPToolCallRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | MCPToolCallResponse]:
    """Call Mcp Tool

     Execute an MCP tool. This is the core execution endpoint that wires
    MCP tool calls to actual FixOps backend engines.

    Supports all 8 registered MCP tools:
    - fixops_list_findings / fixops_get_finding
    - fixops_run_scan
    - fixops_generate_evidence
    - fixops_create_autofix_pr
    - fixops_get_risk_score
    - fixops_list_connectors
    - fixops_notify

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (MCPToolCallRequest): Request to execute an MCP tool.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | MCPToolCallResponse]
    """

    kwargs = _get_kwargs(
        body=body,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: MCPToolCallRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | MCPToolCallResponse | None:
    """Call Mcp Tool

     Execute an MCP tool. This is the core execution endpoint that wires
    MCP tool calls to actual FixOps backend engines.

    Supports all 8 registered MCP tools:
    - fixops_list_findings / fixops_get_finding
    - fixops_run_scan
    - fixops_generate_evidence
    - fixops_create_autofix_pr
    - fixops_get_risk_score
    - fixops_list_connectors
    - fixops_notify

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (MCPToolCallRequest): Request to execute an MCP tool.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | MCPToolCallResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
