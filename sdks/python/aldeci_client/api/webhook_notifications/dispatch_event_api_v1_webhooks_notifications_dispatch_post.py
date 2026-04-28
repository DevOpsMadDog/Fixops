from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.dispatch_event_api_v1_webhooks_notifications_dispatch_post_response_dispatch_event_api_v1_webhooks_notifications_dispatch_post import (
    DispatchEventApiV1WebhooksNotificationsDispatchPostResponseDispatchEventApiV1WebhooksNotificationsDispatchPost,
)
from ...models.dispatch_request import DispatchRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    *,
    body: DispatchRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/webhooks/notifications/dispatch",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DispatchEventApiV1WebhooksNotificationsDispatchPostResponseDispatchEventApiV1WebhooksNotificationsDispatchPost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = DispatchEventApiV1WebhooksNotificationsDispatchPostResponseDispatchEventApiV1WebhooksNotificationsDispatchPost.from_dict(
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
    DispatchEventApiV1WebhooksNotificationsDispatchPostResponseDispatchEventApiV1WebhooksNotificationsDispatchPost
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
    body: DispatchRequest,
) -> Response[
    DispatchEventApiV1WebhooksNotificationsDispatchPostResponseDispatchEventApiV1WebhooksNotificationsDispatchPost
    | HTTPValidationError
]:
    """Dispatch an internal event to matching webhooks

     Fire an event to all matching active webhooks. Used by internal systems.

    Args:
        body (DispatchRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DispatchEventApiV1WebhooksNotificationsDispatchPostResponseDispatchEventApiV1WebhooksNotificationsDispatchPost | HTTPValidationError]
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
    body: DispatchRequest,
) -> (
    DispatchEventApiV1WebhooksNotificationsDispatchPostResponseDispatchEventApiV1WebhooksNotificationsDispatchPost
    | HTTPValidationError
    | None
):
    """Dispatch an internal event to matching webhooks

     Fire an event to all matching active webhooks. Used by internal systems.

    Args:
        body (DispatchRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DispatchEventApiV1WebhooksNotificationsDispatchPostResponseDispatchEventApiV1WebhooksNotificationsDispatchPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: DispatchRequest,
) -> Response[
    DispatchEventApiV1WebhooksNotificationsDispatchPostResponseDispatchEventApiV1WebhooksNotificationsDispatchPost
    | HTTPValidationError
]:
    """Dispatch an internal event to matching webhooks

     Fire an event to all matching active webhooks. Used by internal systems.

    Args:
        body (DispatchRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DispatchEventApiV1WebhooksNotificationsDispatchPostResponseDispatchEventApiV1WebhooksNotificationsDispatchPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: DispatchRequest,
) -> (
    DispatchEventApiV1WebhooksNotificationsDispatchPostResponseDispatchEventApiV1WebhooksNotificationsDispatchPost
    | HTTPValidationError
    | None
):
    """Dispatch an internal event to matching webhooks

     Fire an event to all matching active webhooks. Used by internal systems.

    Args:
        body (DispatchRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DispatchEventApiV1WebhooksNotificationsDispatchPostResponseDispatchEventApiV1WebhooksNotificationsDispatchPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
