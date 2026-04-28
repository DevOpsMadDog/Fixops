from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.add_flow_api_v1_network_flows_post_response_add_flow_api_v1_network_flows_post import (
    AddFlowApiV1NetworkFlowsPostResponseAddFlowApiV1NetworkFlowsPost,
)
from ...models.add_flow_request import AddFlowRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    *,
    body: AddFlowRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/network/flows",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AddFlowApiV1NetworkFlowsPostResponseAddFlowApiV1NetworkFlowsPost | HTTPValidationError | None:
    if response.status_code == 201:
        response_201 = AddFlowApiV1NetworkFlowsPostResponseAddFlowApiV1NetworkFlowsPost.from_dict(response.json())

        return response_201

    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[AddFlowApiV1NetworkFlowsPostResponseAddFlowApiV1NetworkFlowsPost | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: AddFlowRequest,
) -> Response[AddFlowApiV1NetworkFlowsPostResponseAddFlowApiV1NetworkFlowsPost | HTTPValidationError]:
    """Add Flow

     Record an observed network flow between two zones.

    Args:
        body (AddFlowRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AddFlowApiV1NetworkFlowsPostResponseAddFlowApiV1NetworkFlowsPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: AddFlowRequest,
) -> AddFlowApiV1NetworkFlowsPostResponseAddFlowApiV1NetworkFlowsPost | HTTPValidationError | None:
    """Add Flow

     Record an observed network flow between two zones.

    Args:
        body (AddFlowRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AddFlowApiV1NetworkFlowsPostResponseAddFlowApiV1NetworkFlowsPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: AddFlowRequest,
) -> Response[AddFlowApiV1NetworkFlowsPostResponseAddFlowApiV1NetworkFlowsPost | HTTPValidationError]:
    """Add Flow

     Record an observed network flow between two zones.

    Args:
        body (AddFlowRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AddFlowApiV1NetworkFlowsPostResponseAddFlowApiV1NetworkFlowsPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: AddFlowRequest,
) -> AddFlowApiV1NetworkFlowsPostResponseAddFlowApiV1NetworkFlowsPost | HTTPValidationError | None:
    """Add Flow

     Record an observed network flow between two zones.

    Args:
        body (AddFlowRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AddFlowApiV1NetworkFlowsPostResponseAddFlowApiV1NetworkFlowsPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
