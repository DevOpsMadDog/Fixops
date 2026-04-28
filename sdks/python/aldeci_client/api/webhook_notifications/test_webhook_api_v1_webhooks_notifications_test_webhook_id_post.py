from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.test_webhook_api_v1_webhooks_notifications_test_webhook_id_post_response_test_webhook_api_v1_webhooks_notifications_test_webhook_id_post import (
    TestWebhookApiV1WebhooksNotificationsTestWebhookIdPostResponseTestWebhookApiV1WebhooksNotificationsTestWebhookIdPost,
)
from ...types import UNSET, Response


def _get_kwargs(
    webhook_id: str,
    *,
    org_id: str,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/webhooks/notifications/test/{webhook_id}".format(
            webhook_id=quote(str(webhook_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | TestWebhookApiV1WebhooksNotificationsTestWebhookIdPostResponseTestWebhookApiV1WebhooksNotificationsTestWebhookIdPost
    | None
):
    if response.status_code == 200:
        response_200 = TestWebhookApiV1WebhooksNotificationsTestWebhookIdPostResponseTestWebhookApiV1WebhooksNotificationsTestWebhookIdPost.from_dict(
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
    | TestWebhookApiV1WebhooksNotificationsTestWebhookIdPostResponseTestWebhookApiV1WebhooksNotificationsTestWebhookIdPost
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    webhook_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> Response[
    HTTPValidationError
    | TestWebhookApiV1WebhooksNotificationsTestWebhookIdPostResponseTestWebhookApiV1WebhooksNotificationsTestWebhookIdPost
]:
    """Send test payload to a webhook

     Send a test payload to verify the webhook endpoint is reachable.

    Args:
        webhook_id (str):
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TestWebhookApiV1WebhooksNotificationsTestWebhookIdPostResponseTestWebhookApiV1WebhooksNotificationsTestWebhookIdPost]
    """

    kwargs = _get_kwargs(
        webhook_id=webhook_id,
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    webhook_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> (
    HTTPValidationError
    | TestWebhookApiV1WebhooksNotificationsTestWebhookIdPostResponseTestWebhookApiV1WebhooksNotificationsTestWebhookIdPost
    | None
):
    """Send test payload to a webhook

     Send a test payload to verify the webhook endpoint is reachable.

    Args:
        webhook_id (str):
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TestWebhookApiV1WebhooksNotificationsTestWebhookIdPostResponseTestWebhookApiV1WebhooksNotificationsTestWebhookIdPost
    """

    return sync_detailed(
        webhook_id=webhook_id,
        client=client,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    webhook_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> Response[
    HTTPValidationError
    | TestWebhookApiV1WebhooksNotificationsTestWebhookIdPostResponseTestWebhookApiV1WebhooksNotificationsTestWebhookIdPost
]:
    """Send test payload to a webhook

     Send a test payload to verify the webhook endpoint is reachable.

    Args:
        webhook_id (str):
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TestWebhookApiV1WebhooksNotificationsTestWebhookIdPostResponseTestWebhookApiV1WebhooksNotificationsTestWebhookIdPost]
    """

    kwargs = _get_kwargs(
        webhook_id=webhook_id,
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    webhook_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> (
    HTTPValidationError
    | TestWebhookApiV1WebhooksNotificationsTestWebhookIdPostResponseTestWebhookApiV1WebhooksNotificationsTestWebhookIdPost
    | None
):
    """Send test payload to a webhook

     Send a test payload to verify the webhook endpoint is reachable.

    Args:
        webhook_id (str):
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TestWebhookApiV1WebhooksNotificationsTestWebhookIdPostResponseTestWebhookApiV1WebhooksNotificationsTestWebhookIdPost
    """

    return (
        await asyncio_detailed(
            webhook_id=webhook_id,
            client=client,
            org_id=org_id,
        )
    ).parsed
