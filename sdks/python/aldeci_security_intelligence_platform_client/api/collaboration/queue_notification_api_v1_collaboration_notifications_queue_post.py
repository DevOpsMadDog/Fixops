from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.queue_notification_api_v1_collaboration_notifications_queue_post_response_queue_notification_api_v1_collaboration_notifications_queue_post import (
    QueueNotificationApiV1CollaborationNotificationsQueuePostResponseQueueNotificationApiV1CollaborationNotificationsQueuePost,
)
from ...models.queue_notification_request import QueueNotificationRequest
from ...types import Response


def _get_kwargs(
    *,
    body: QueueNotificationRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/collaboration/notifications/queue",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | QueueNotificationApiV1CollaborationNotificationsQueuePostResponseQueueNotificationApiV1CollaborationNotificationsQueuePost
    | None
):
    if response.status_code == 200:
        response_200 = QueueNotificationApiV1CollaborationNotificationsQueuePostResponseQueueNotificationApiV1CollaborationNotificationsQueuePost.from_dict(
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
    | QueueNotificationApiV1CollaborationNotificationsQueuePostResponseQueueNotificationApiV1CollaborationNotificationsQueuePost
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
    body: QueueNotificationRequest,
) -> Response[
    HTTPValidationError
    | QueueNotificationApiV1CollaborationNotificationsQueuePostResponseQueueNotificationApiV1CollaborationNotificationsQueuePost
]:
    """Queue Notification

     Queue a notification for delivery.

    Notification types:
    - new_critical_finding: New critical/high severity finding
    - status_change: Finding/task status changed
    - comment_mention: User was mentioned in a comment
    - sla_breach: SLA deadline approaching or breached
    - assignment: Task/finding assigned to user

    Priority levels: low, normal, high, urgent

    Args:
        body (QueueNotificationRequest): Request to queue a notification.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | QueueNotificationApiV1CollaborationNotificationsQueuePostResponseQueueNotificationApiV1CollaborationNotificationsQueuePost]
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
    body: QueueNotificationRequest,
) -> (
    HTTPValidationError
    | QueueNotificationApiV1CollaborationNotificationsQueuePostResponseQueueNotificationApiV1CollaborationNotificationsQueuePost
    | None
):
    """Queue Notification

     Queue a notification for delivery.

    Notification types:
    - new_critical_finding: New critical/high severity finding
    - status_change: Finding/task status changed
    - comment_mention: User was mentioned in a comment
    - sla_breach: SLA deadline approaching or breached
    - assignment: Task/finding assigned to user

    Priority levels: low, normal, high, urgent

    Args:
        body (QueueNotificationRequest): Request to queue a notification.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | QueueNotificationApiV1CollaborationNotificationsQueuePostResponseQueueNotificationApiV1CollaborationNotificationsQueuePost
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: QueueNotificationRequest,
) -> Response[
    HTTPValidationError
    | QueueNotificationApiV1CollaborationNotificationsQueuePostResponseQueueNotificationApiV1CollaborationNotificationsQueuePost
]:
    """Queue Notification

     Queue a notification for delivery.

    Notification types:
    - new_critical_finding: New critical/high severity finding
    - status_change: Finding/task status changed
    - comment_mention: User was mentioned in a comment
    - sla_breach: SLA deadline approaching or breached
    - assignment: Task/finding assigned to user

    Priority levels: low, normal, high, urgent

    Args:
        body (QueueNotificationRequest): Request to queue a notification.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | QueueNotificationApiV1CollaborationNotificationsQueuePostResponseQueueNotificationApiV1CollaborationNotificationsQueuePost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: QueueNotificationRequest,
) -> (
    HTTPValidationError
    | QueueNotificationApiV1CollaborationNotificationsQueuePostResponseQueueNotificationApiV1CollaborationNotificationsQueuePost
    | None
):
    """Queue Notification

     Queue a notification for delivery.

    Notification types:
    - new_critical_finding: New critical/high severity finding
    - status_change: Finding/task status changed
    - comment_mention: User was mentioned in a comment
    - sla_breach: SLA deadline approaching or breached
    - assignment: Task/finding assigned to user

    Priority levels: low, normal, high, urgent

    Args:
        body (QueueNotificationRequest): Request to queue a notification.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | QueueNotificationApiV1CollaborationNotificationsQueuePostResponseQueueNotificationApiV1CollaborationNotificationsQueuePost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
