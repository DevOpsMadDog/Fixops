from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.create_risk_api_v1_risks_post_response_create_risk_api_v1_risks_post import (
    CreateRiskApiV1RisksPostResponseCreateRiskApiV1RisksPost,
)
from ...models.create_risk_request import CreateRiskRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    *,
    body: CreateRiskRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/risks",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> CreateRiskApiV1RisksPostResponseCreateRiskApiV1RisksPost | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = CreateRiskApiV1RisksPostResponseCreateRiskApiV1RisksPost.from_dict(response.json())

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
) -> Response[CreateRiskApiV1RisksPostResponseCreateRiskApiV1RisksPost | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: CreateRiskRequest,
) -> Response[CreateRiskApiV1RisksPostResponseCreateRiskApiV1RisksPost | HTTPValidationError]:
    """Create a risk

    Args:
        body (CreateRiskRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateRiskApiV1RisksPostResponseCreateRiskApiV1RisksPost | HTTPValidationError]
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
    body: CreateRiskRequest,
) -> CreateRiskApiV1RisksPostResponseCreateRiskApiV1RisksPost | HTTPValidationError | None:
    """Create a risk

    Args:
        body (CreateRiskRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateRiskApiV1RisksPostResponseCreateRiskApiV1RisksPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: CreateRiskRequest,
) -> Response[CreateRiskApiV1RisksPostResponseCreateRiskApiV1RisksPost | HTTPValidationError]:
    """Create a risk

    Args:
        body (CreateRiskRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateRiskApiV1RisksPostResponseCreateRiskApiV1RisksPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: CreateRiskRequest,
) -> CreateRiskApiV1RisksPostResponseCreateRiskApiV1RisksPost | HTTPValidationError | None:
    """Create a risk

    Args:
        body (CreateRiskRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateRiskApiV1RisksPostResponseCreateRiskApiV1RisksPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
