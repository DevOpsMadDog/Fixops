from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_pending_notifications_api_v1_collaboration_notifications_pending_get_response_get_pending_notifications_api_v1_collaboration_notifications_pending_get import (
    GetPendingNotificationsApiV1CollaborationNotificationsPendingGetResponseGetPendingNotificationsApiV1CollaborationNotificationsPendingGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    limit: int | Unset = 100,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/collaboration/notifications/pending",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetPendingNotificationsApiV1CollaborationNotificationsPendingGetResponseGetPendingNotificationsApiV1CollaborationNotificationsPendingGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetPendingNotificationsApiV1CollaborationNotificationsPendingGetResponseGetPendingNotificationsApiV1CollaborationNotificationsPendingGet.from_dict(
            response.json()
        )

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
) -> Response[
    GetPendingNotificationsApiV1CollaborationNotificationsPendingGetResponseGetPendingNotificationsApiV1CollaborationNotificationsPendingGet
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
    limit: int | Unset = 100,
) -> Response[
    GetPendingNotificationsApiV1CollaborationNotificationsPendingGetResponseGetPendingNotificationsApiV1CollaborationNotificationsPendingGet
    | HTTPValidationError
]:
    """Get Pending Notifications

     Get pending notifications for delivery.

    Args:
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetPendingNotificationsApiV1CollaborationNotificationsPendingGetResponseGetPendingNotificationsApiV1CollaborationNotificationsPendingGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> (
    GetPendingNotificationsApiV1CollaborationNotificationsPendingGetResponseGetPendingNotificationsApiV1CollaborationNotificationsPendingGet
    | HTTPValidationError
    | None
):
    """Get Pending Notifications

     Get pending notifications for delivery.

    Args:
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetPendingNotificationsApiV1CollaborationNotificationsPendingGetResponseGetPendingNotificationsApiV1CollaborationNotificationsPendingGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> Response[
    GetPendingNotificationsApiV1CollaborationNotificationsPendingGetResponseGetPendingNotificationsApiV1CollaborationNotificationsPendingGet
    | HTTPValidationError
]:
    """Get Pending Notifications

     Get pending notifications for delivery.

    Args:
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetPendingNotificationsApiV1CollaborationNotificationsPendingGetResponseGetPendingNotificationsApiV1CollaborationNotificationsPendingGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> (
    GetPendingNotificationsApiV1CollaborationNotificationsPendingGetResponseGetPendingNotificationsApiV1CollaborationNotificationsPendingGet
    | HTTPValidationError
    | None
):
    """Get Pending Notifications

     Get pending notifications for delivery.

    Args:
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetPendingNotificationsApiV1CollaborationNotificationsPendingGetResponseGetPendingNotificationsApiV1CollaborationNotificationsPendingGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            limit=limit,
        )
    ).parsed
