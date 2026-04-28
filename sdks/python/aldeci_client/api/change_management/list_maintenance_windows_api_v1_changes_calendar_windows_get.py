from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.list_maintenance_windows_api_v1_changes_calendar_windows_get_response_list_maintenance_windows_api_v1_changes_calendar_windows_get import (
    ListMaintenanceWindowsApiV1ChangesCalendarWindowsGetResponseListMaintenanceWindowsApiV1ChangesCalendarWindowsGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/changes/calendar/windows",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    ListMaintenanceWindowsApiV1ChangesCalendarWindowsGetResponseListMaintenanceWindowsApiV1ChangesCalendarWindowsGet
    | None
):
    if response.status_code == 200:
        response_200 = ListMaintenanceWindowsApiV1ChangesCalendarWindowsGetResponseListMaintenanceWindowsApiV1ChangesCalendarWindowsGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    ListMaintenanceWindowsApiV1ChangesCalendarWindowsGetResponseListMaintenanceWindowsApiV1ChangesCalendarWindowsGet
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
) -> Response[
    ListMaintenanceWindowsApiV1ChangesCalendarWindowsGetResponseListMaintenanceWindowsApiV1ChangesCalendarWindowsGet
]:
    """List Maintenance Windows

     List all maintenance windows.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ListMaintenanceWindowsApiV1ChangesCalendarWindowsGetResponseListMaintenanceWindowsApiV1ChangesCalendarWindowsGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> (
    ListMaintenanceWindowsApiV1ChangesCalendarWindowsGetResponseListMaintenanceWindowsApiV1ChangesCalendarWindowsGet
    | None
):
    """List Maintenance Windows

     List all maintenance windows.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ListMaintenanceWindowsApiV1ChangesCalendarWindowsGetResponseListMaintenanceWindowsApiV1ChangesCalendarWindowsGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    ListMaintenanceWindowsApiV1ChangesCalendarWindowsGetResponseListMaintenanceWindowsApiV1ChangesCalendarWindowsGet
]:
    """List Maintenance Windows

     List all maintenance windows.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ListMaintenanceWindowsApiV1ChangesCalendarWindowsGetResponseListMaintenanceWindowsApiV1ChangesCalendarWindowsGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> (
    ListMaintenanceWindowsApiV1ChangesCalendarWindowsGetResponseListMaintenanceWindowsApiV1ChangesCalendarWindowsGet
    | None
):
    """List Maintenance Windows

     List all maintenance windows.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ListMaintenanceWindowsApiV1ChangesCalendarWindowsGetResponseListMaintenanceWindowsApiV1ChangesCalendarWindowsGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
