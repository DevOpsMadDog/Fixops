from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.create_maintenance_window_api_v1_changes_calendar_windows_post_response_create_maintenance_window_api_v1_changes_calendar_windows_post import (
    CreateMaintenanceWindowApiV1ChangesCalendarWindowsPostResponseCreateMaintenanceWindowApiV1ChangesCalendarWindowsPost,
)
from ...models.create_maintenance_window_request import CreateMaintenanceWindowRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    *,
    body: CreateMaintenanceWindowRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/changes/calendar/windows",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    CreateMaintenanceWindowApiV1ChangesCalendarWindowsPostResponseCreateMaintenanceWindowApiV1ChangesCalendarWindowsPost
    | HTTPValidationError
    | None
):
    if response.status_code == 201:
        response_201 = CreateMaintenanceWindowApiV1ChangesCalendarWindowsPostResponseCreateMaintenanceWindowApiV1ChangesCalendarWindowsPost.from_dict(
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
    CreateMaintenanceWindowApiV1ChangesCalendarWindowsPostResponseCreateMaintenanceWindowApiV1ChangesCalendarWindowsPost
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
    body: CreateMaintenanceWindowRequest,
) -> Response[
    CreateMaintenanceWindowApiV1ChangesCalendarWindowsPostResponseCreateMaintenanceWindowApiV1ChangesCalendarWindowsPost
    | HTTPValidationError
]:
    """Create Maintenance Window

     Create a new maintenance window.

    Args:
        body (CreateMaintenanceWindowRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateMaintenanceWindowApiV1ChangesCalendarWindowsPostResponseCreateMaintenanceWindowApiV1ChangesCalendarWindowsPost | HTTPValidationError]
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
    body: CreateMaintenanceWindowRequest,
) -> (
    CreateMaintenanceWindowApiV1ChangesCalendarWindowsPostResponseCreateMaintenanceWindowApiV1ChangesCalendarWindowsPost
    | HTTPValidationError
    | None
):
    """Create Maintenance Window

     Create a new maintenance window.

    Args:
        body (CreateMaintenanceWindowRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateMaintenanceWindowApiV1ChangesCalendarWindowsPostResponseCreateMaintenanceWindowApiV1ChangesCalendarWindowsPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: CreateMaintenanceWindowRequest,
) -> Response[
    CreateMaintenanceWindowApiV1ChangesCalendarWindowsPostResponseCreateMaintenanceWindowApiV1ChangesCalendarWindowsPost
    | HTTPValidationError
]:
    """Create Maintenance Window

     Create a new maintenance window.

    Args:
        body (CreateMaintenanceWindowRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateMaintenanceWindowApiV1ChangesCalendarWindowsPostResponseCreateMaintenanceWindowApiV1ChangesCalendarWindowsPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: CreateMaintenanceWindowRequest,
) -> (
    CreateMaintenanceWindowApiV1ChangesCalendarWindowsPostResponseCreateMaintenanceWindowApiV1ChangesCalendarWindowsPost
    | HTTPValidationError
    | None
):
    """Create Maintenance Window

     Create a new maintenance window.

    Args:
        body (CreateMaintenanceWindowRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateMaintenanceWindowApiV1ChangesCalendarWindowsPostResponseCreateMaintenanceWindowApiV1ChangesCalendarWindowsPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
