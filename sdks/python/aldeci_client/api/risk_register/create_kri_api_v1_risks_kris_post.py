from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.create_kri_api_v1_risks_kris_post_response_create_kri_api_v1_risks_kris_post import (
    CreateKriApiV1RisksKrisPostResponseCreateKriApiV1RisksKrisPost,
)
from ...models.create_kri_request import CreateKRIRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    *,
    body: CreateKRIRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/risks/kris",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> CreateKriApiV1RisksKrisPostResponseCreateKriApiV1RisksKrisPost | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = CreateKriApiV1RisksKrisPostResponseCreateKriApiV1RisksKrisPost.from_dict(response.json())

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
) -> Response[CreateKriApiV1RisksKrisPostResponseCreateKriApiV1RisksKrisPost | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: CreateKRIRequest,
) -> Response[CreateKriApiV1RisksKrisPostResponseCreateKriApiV1RisksKrisPost | HTTPValidationError]:
    """Create a KRI

    Args:
        body (CreateKRIRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateKriApiV1RisksKrisPostResponseCreateKriApiV1RisksKrisPost | HTTPValidationError]
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
    body: CreateKRIRequest,
) -> CreateKriApiV1RisksKrisPostResponseCreateKriApiV1RisksKrisPost | HTTPValidationError | None:
    """Create a KRI

    Args:
        body (CreateKRIRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateKriApiV1RisksKrisPostResponseCreateKriApiV1RisksKrisPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: CreateKRIRequest,
) -> Response[CreateKriApiV1RisksKrisPostResponseCreateKriApiV1RisksKrisPost | HTTPValidationError]:
    """Create a KRI

    Args:
        body (CreateKRIRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateKriApiV1RisksKrisPostResponseCreateKriApiV1RisksKrisPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: CreateKRIRequest,
) -> CreateKriApiV1RisksKrisPostResponseCreateKriApiV1RisksKrisPost | HTTPValidationError | None:
    """Create a KRI

    Args:
        body (CreateKRIRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateKriApiV1RisksKrisPostResponseCreateKriApiV1RisksKrisPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
