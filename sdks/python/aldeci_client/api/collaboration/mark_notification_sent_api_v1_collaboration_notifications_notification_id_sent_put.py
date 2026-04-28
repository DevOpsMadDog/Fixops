from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.mark_notification_sent_api_v1_collaboration_notifications_notification_id_sent_put_response_mark_notification_sent_api_v1_collaboration_notifications_notification_id_sent_put import (
    MarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPutResponseMarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPut,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    notification_id: str,
    *,
    error: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_error: None | str | Unset
    if isinstance(error, Unset):
        json_error = UNSET
    else:
        json_error = error
    params["error"] = json_error

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/collaboration/notifications/{notification_id}/sent".format(
            notification_id=quote(str(notification_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | MarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPutResponseMarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPut
    | None
):
    if response.status_code == 200:
        response_200 = MarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPutResponseMarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPut.from_dict(
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
    HTTPValidationError
    | MarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPutResponseMarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPut
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    notification_id: str,
    *,
    client: AuthenticatedClient,
    error: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | MarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPutResponseMarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPut
]:
    """Mark Notification Sent

     Mark a notification as sent or failed.

    Args:
        notification_id (str):
        error (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | MarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPutResponseMarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPut]
    """

    kwargs = _get_kwargs(
        notification_id=notification_id,
        error=error,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    notification_id: str,
    *,
    client: AuthenticatedClient,
    error: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | MarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPutResponseMarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPut
    | None
):
    """Mark Notification Sent

     Mark a notification as sent or failed.

    Args:
        notification_id (str):
        error (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | MarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPutResponseMarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPut
    """

    return sync_detailed(
        notification_id=notification_id,
        client=client,
        error=error,
    ).parsed


async def asyncio_detailed(
    notification_id: str,
    *,
    client: AuthenticatedClient,
    error: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | MarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPutResponseMarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPut
]:
    """Mark Notification Sent

     Mark a notification as sent or failed.

    Args:
        notification_id (str):
        error (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | MarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPutResponseMarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPut]
    """

    kwargs = _get_kwargs(
        notification_id=notification_id,
        error=error,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    notification_id: str,
    *,
    client: AuthenticatedClient,
    error: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | MarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPutResponseMarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPut
    | None
):
    """Mark Notification Sent

     Mark a notification as sent or failed.

    Args:
        notification_id (str):
        error (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | MarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPutResponseMarkNotificationSentApiV1CollaborationNotificationsNotificationIdSentPut
    """

    return (
        await asyncio_detailed(
            notification_id=notification_id,
            client=client,
            error=error,
        )
    ).parsed
