from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.deliver_notification_api_v1_collaboration_notifications_notification_id_deliver_post_response_deliver_notification_api_v1_collaboration_notifications_notification_id_deliver_post import (
    DeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPostResponseDeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPost,
)
from ...models.deliver_notification_request import DeliverNotificationRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    notification_id: str,
    *,
    body: DeliverNotificationRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/collaboration/notifications/{notification_id}/deliver".format(
            notification_id=quote(str(notification_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPostResponseDeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = DeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPostResponseDeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPost.from_dict(
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
    DeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPostResponseDeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPost
    | HTTPValidationError
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
    body: DeliverNotificationRequest,
) -> Response[
    DeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPostResponseDeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPost
    | HTTPValidationError
]:
    """Deliver Notification

     Deliver a specific notification via configured channels.

    Supports Slack webhook and/or email (SMTP) delivery.
    Respects user notification preferences.

    Note: Slack webhook URL is read from FIXOPS_SLACK_WEBHOOK_URL environment
    variable to prevent SSRF attacks.

    Args:
        notification_id (str):
        body (DeliverNotificationRequest): Request to deliver a specific notification.

            Note: Credentials should be configured via environment variables for security:
            - FIXOPS_SLACK_WEBHOOK_URL: Slack webhook URL
            - FIXOPS_SMTP_PASSWORD: SMTP password
            Do not pass credentials in request bodies.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPostResponseDeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        notification_id=notification_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    notification_id: str,
    *,
    client: AuthenticatedClient,
    body: DeliverNotificationRequest,
) -> (
    DeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPostResponseDeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPost
    | HTTPValidationError
    | None
):
    """Deliver Notification

     Deliver a specific notification via configured channels.

    Supports Slack webhook and/or email (SMTP) delivery.
    Respects user notification preferences.

    Note: Slack webhook URL is read from FIXOPS_SLACK_WEBHOOK_URL environment
    variable to prevent SSRF attacks.

    Args:
        notification_id (str):
        body (DeliverNotificationRequest): Request to deliver a specific notification.

            Note: Credentials should be configured via environment variables for security:
            - FIXOPS_SLACK_WEBHOOK_URL: Slack webhook URL
            - FIXOPS_SMTP_PASSWORD: SMTP password
            Do not pass credentials in request bodies.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPostResponseDeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPost | HTTPValidationError
    """

    return sync_detailed(
        notification_id=notification_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    notification_id: str,
    *,
    client: AuthenticatedClient,
    body: DeliverNotificationRequest,
) -> Response[
    DeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPostResponseDeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPost
    | HTTPValidationError
]:
    """Deliver Notification

     Deliver a specific notification via configured channels.

    Supports Slack webhook and/or email (SMTP) delivery.
    Respects user notification preferences.

    Note: Slack webhook URL is read from FIXOPS_SLACK_WEBHOOK_URL environment
    variable to prevent SSRF attacks.

    Args:
        notification_id (str):
        body (DeliverNotificationRequest): Request to deliver a specific notification.

            Note: Credentials should be configured via environment variables for security:
            - FIXOPS_SLACK_WEBHOOK_URL: Slack webhook URL
            - FIXOPS_SMTP_PASSWORD: SMTP password
            Do not pass credentials in request bodies.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPostResponseDeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        notification_id=notification_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    notification_id: str,
    *,
    client: AuthenticatedClient,
    body: DeliverNotificationRequest,
) -> (
    DeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPostResponseDeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPost
    | HTTPValidationError
    | None
):
    """Deliver Notification

     Deliver a specific notification via configured channels.

    Supports Slack webhook and/or email (SMTP) delivery.
    Respects user notification preferences.

    Note: Slack webhook URL is read from FIXOPS_SLACK_WEBHOOK_URL environment
    variable to prevent SSRF attacks.

    Args:
        notification_id (str):
        body (DeliverNotificationRequest): Request to deliver a specific notification.

            Note: Credentials should be configured via environment variables for security:
            - FIXOPS_SLACK_WEBHOOK_URL: Slack webhook URL
            - FIXOPS_SMTP_PASSWORD: SMTP password
            Do not pass credentials in request bodies.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPostResponseDeliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            notification_id=notification_id,
            client=client,
            body=body,
        )
    ).parsed
