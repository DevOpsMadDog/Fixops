from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.create_freeze_period_api_v1_changes_calendar_freezes_post_response_create_freeze_period_api_v1_changes_calendar_freezes_post import (
    CreateFreezePeriodApiV1ChangesCalendarFreezesPostResponseCreateFreezePeriodApiV1ChangesCalendarFreezesPost,
)
from ...models.create_freeze_period_request import CreateFreezePeriodRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    *,
    body: CreateFreezePeriodRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/changes/calendar/freezes",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    CreateFreezePeriodApiV1ChangesCalendarFreezesPostResponseCreateFreezePeriodApiV1ChangesCalendarFreezesPost
    | HTTPValidationError
    | None
):
    if response.status_code == 201:
        response_201 = CreateFreezePeriodApiV1ChangesCalendarFreezesPostResponseCreateFreezePeriodApiV1ChangesCalendarFreezesPost.from_dict(
            response.json()
        )

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
) -> Response[
    CreateFreezePeriodApiV1ChangesCalendarFreezesPostResponseCreateFreezePeriodApiV1ChangesCalendarFreezesPost
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: CreateFreezePeriodRequest,
) -> Response[
    CreateFreezePeriodApiV1ChangesCalendarFreezesPostResponseCreateFreezePeriodApiV1ChangesCalendarFreezesPost
    | HTTPValidationError
]:
    """Create Freeze Period

     Create a new change freeze period.

    Args:
        body (CreateFreezePeriodRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateFreezePeriodApiV1ChangesCalendarFreezesPostResponseCreateFreezePeriodApiV1ChangesCalendarFreezesPost | HTTPValidationError]
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
    body: CreateFreezePeriodRequest,
) -> (
    CreateFreezePeriodApiV1ChangesCalendarFreezesPostResponseCreateFreezePeriodApiV1ChangesCalendarFreezesPost
    | HTTPValidationError
    | None
):
    """Create Freeze Period

     Create a new change freeze period.

    Args:
        body (CreateFreezePeriodRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateFreezePeriodApiV1ChangesCalendarFreezesPostResponseCreateFreezePeriodApiV1ChangesCalendarFreezesPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: CreateFreezePeriodRequest,
) -> Response[
    CreateFreezePeriodApiV1ChangesCalendarFreezesPostResponseCreateFreezePeriodApiV1ChangesCalendarFreezesPost
    | HTTPValidationError
]:
    """Create Freeze Period

     Create a new change freeze period.

    Args:
        body (CreateFreezePeriodRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateFreezePeriodApiV1ChangesCalendarFreezesPostResponseCreateFreezePeriodApiV1ChangesCalendarFreezesPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: CreateFreezePeriodRequest,
) -> (
    CreateFreezePeriodApiV1ChangesCalendarFreezesPostResponseCreateFreezePeriodApiV1ChangesCalendarFreezesPost
    | HTTPValidationError
    | None
):
    """Create Freeze Period

     Create a new change freeze period.

    Args:
        body (CreateFreezePeriodRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateFreezePeriodApiV1ChangesCalendarFreezesPostResponseCreateFreezePeriodApiV1ChangesCalendarFreezesPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
