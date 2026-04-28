from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.process_notifications_request import ProcessNotificationsRequest
from ...models.process_pending_notifications_api_v1_collaboration_notifications_process_post_response_process_pending_notifications_api_v1_collaboration_notifications_process_post import (
    ProcessPendingNotificationsApiV1CollaborationNotificationsProcessPostResponseProcessPendingNotificationsApiV1CollaborationNotificationsProcessPost,
)
from ...types import Response


def _get_kwargs(
    *,
    body: ProcessNotificationsRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/collaboration/notifications/process",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | ProcessPendingNotificationsApiV1CollaborationNotificationsProcessPostResponseProcessPendingNotificationsApiV1CollaborationNotificationsProcessPost
    | None
):
    if response.status_code == 200:
        response_200 = ProcessPendingNotificationsApiV1CollaborationNotificationsProcessPostResponseProcessPendingNotificationsApiV1CollaborationNotificationsProcessPost.from_dict(
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
    | ProcessPendingNotificationsApiV1CollaborationNotificationsProcessPostResponseProcessPendingNotificationsApiV1CollaborationNotificationsProcessPost
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
    body: ProcessNotificationsRequest,
) -> Response[
    HTTPValidationError
    | ProcessPendingNotificationsApiV1CollaborationNotificationsProcessPostResponseProcessPendingNotificationsApiV1CollaborationNotificationsProcessPost
]:
    """Process Pending Notifications

     Process all pending notifications in the queue.

    This is the main worker endpoint that should be called periodically
    (e.g., by a cron job or scheduler) to deliver queued notifications.

    Supports Slack webhook and/or email (SMTP) delivery.
    Respects user notification preferences.

    Note: Slack webhook URL is read from FIXOPS_SLACK_WEBHOOK_URL environment
    variable to prevent SSRF attacks.

    Args:
        body (ProcessNotificationsRequest): Request to process pending notifications.

            Note: Credentials should be configured via environment variables for security:
            - FIXOPS_SLACK_WEBHOOK_URL: Slack webhook URL
            - FIXOPS_SMTP_PASSWORD: SMTP password
            Do not pass credentials in request bodies.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ProcessPendingNotificationsApiV1CollaborationNotificationsProcessPostResponseProcessPendingNotificationsApiV1CollaborationNotificationsProcessPost]
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
    body: ProcessNotificationsRequest,
) -> (
    HTTPValidationError
    | ProcessPendingNotificationsApiV1CollaborationNotificationsProcessPostResponseProcessPendingNotificationsApiV1CollaborationNotificationsProcessPost
    | None
):
    """Process Pending Notifications

     Process all pending notifications in the queue.

    This is the main worker endpoint that should be called periodically
    (e.g., by a cron job or scheduler) to deliver queued notifications.

    Supports Slack webhook and/or email (SMTP) delivery.
    Respects user notification preferences.

    Note: Slack webhook URL is read from FIXOPS_SLACK_WEBHOOK_URL environment
    variable to prevent SSRF attacks.

    Args:
        body (ProcessNotificationsRequest): Request to process pending notifications.

            Note: Credentials should be configured via environment variables for security:
            - FIXOPS_SLACK_WEBHOOK_URL: Slack webhook URL
            - FIXOPS_SMTP_PASSWORD: SMTP password
            Do not pass credentials in request bodies.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ProcessPendingNotificationsApiV1CollaborationNotificationsProcessPostResponseProcessPendingNotificationsApiV1CollaborationNotificationsProcessPost
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ProcessNotificationsRequest,
) -> Response[
    HTTPValidationError
    | ProcessPendingNotificationsApiV1CollaborationNotificationsProcessPostResponseProcessPendingNotificationsApiV1CollaborationNotificationsProcessPost
]:
    """Process Pending Notifications

     Process all pending notifications in the queue.

    This is the main worker endpoint that should be called periodically
    (e.g., by a cron job or scheduler) to deliver queued notifications.

    Supports Slack webhook and/or email (SMTP) delivery.
    Respects user notification preferences.

    Note: Slack webhook URL is read from FIXOPS_SLACK_WEBHOOK_URL environment
    variable to prevent SSRF attacks.

    Args:
        body (ProcessNotificationsRequest): Request to process pending notifications.

            Note: Credentials should be configured via environment variables for security:
            - FIXOPS_SLACK_WEBHOOK_URL: Slack webhook URL
            - FIXOPS_SMTP_PASSWORD: SMTP password
            Do not pass credentials in request bodies.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ProcessPendingNotificationsApiV1CollaborationNotificationsProcessPostResponseProcessPendingNotificationsApiV1CollaborationNotificationsProcessPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ProcessNotificationsRequest,
) -> (
    HTTPValidationError
    | ProcessPendingNotificationsApiV1CollaborationNotificationsProcessPostResponseProcessPendingNotificationsApiV1CollaborationNotificationsProcessPost
    | None
):
    """Process Pending Notifications

     Process all pending notifications in the queue.

    This is the main worker endpoint that should be called periodically
    (e.g., by a cron job or scheduler) to deliver queued notifications.

    Supports Slack webhook and/or email (SMTP) delivery.
    Respects user notification preferences.

    Note: Slack webhook URL is read from FIXOPS_SLACK_WEBHOOK_URL environment
    variable to prevent SSRF attacks.

    Args:
        body (ProcessNotificationsRequest): Request to process pending notifications.

            Note: Credentials should be configured via environment variables for security:
            - FIXOPS_SLACK_WEBHOOK_URL: Slack webhook URL
            - FIXOPS_SMTP_PASSWORD: SMTP password
            Do not pass credentials in request bodies.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ProcessPendingNotificationsApiV1CollaborationNotificationsProcessPostResponseProcessPendingNotificationsApiV1CollaborationNotificationsProcessPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
