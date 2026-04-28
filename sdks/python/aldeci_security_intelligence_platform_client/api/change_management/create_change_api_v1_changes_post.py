from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.create_change_api_v1_changes_post_response_create_change_api_v1_changes_post import (
    CreateChangeApiV1ChangesPostResponseCreateChangeApiV1ChangesPost,
)
from ...models.create_change_request import CreateChangeRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    *,
    body: CreateChangeRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/changes",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> CreateChangeApiV1ChangesPostResponseCreateChangeApiV1ChangesPost | HTTPValidationError | None:
    if response.status_code == 201:
        response_201 = CreateChangeApiV1ChangesPostResponseCreateChangeApiV1ChangesPost.from_dict(response.json())

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
) -> Response[CreateChangeApiV1ChangesPostResponseCreateChangeApiV1ChangesPost | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: CreateChangeRequest,
) -> Response[CreateChangeApiV1ChangesPostResponseCreateChangeApiV1ChangesPost | HTTPValidationError]:
    """Create Change

     Create a new change request in DRAFT status.

    Args:
        body (CreateChangeRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateChangeApiV1ChangesPostResponseCreateChangeApiV1ChangesPost | HTTPValidationError]
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
    body: CreateChangeRequest,
) -> CreateChangeApiV1ChangesPostResponseCreateChangeApiV1ChangesPost | HTTPValidationError | None:
    """Create Change

     Create a new change request in DRAFT status.

    Args:
        body (CreateChangeRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateChangeApiV1ChangesPostResponseCreateChangeApiV1ChangesPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: CreateChangeRequest,
) -> Response[CreateChangeApiV1ChangesPostResponseCreateChangeApiV1ChangesPost | HTTPValidationError]:
    """Create Change

     Create a new change request in DRAFT status.

    Args:
        body (CreateChangeRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateChangeApiV1ChangesPostResponseCreateChangeApiV1ChangesPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: CreateChangeRequest,
) -> CreateChangeApiV1ChangesPostResponseCreateChangeApiV1ChangesPost | HTTPValidationError | None:
    """Create Change

     Create a new change request in DRAFT status.

    Args:
        body (CreateChangeRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateChangeApiV1ChangesPostResponseCreateChangeApiV1ChangesPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
