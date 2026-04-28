from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.delete_webhook_api_v1_webhooks_notifications_webhook_id_delete_response_delete_webhook_api_v1_webhooks_notifications_webhook_id_delete import (
    DeleteWebhookApiV1WebhooksNotificationsWebhookIdDeleteResponseDeleteWebhookApiV1WebhooksNotificationsWebhookIdDelete,
)
from ...models.http_validation_error import HTTPValidationError
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
        "method": "delete",
        "url": "/api/v1/webhooks/notifications/{webhook_id}".format(
            webhook_id=quote(str(webhook_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DeleteWebhookApiV1WebhooksNotificationsWebhookIdDeleteResponseDeleteWebhookApiV1WebhooksNotificationsWebhookIdDelete
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = DeleteWebhookApiV1WebhooksNotificationsWebhookIdDeleteResponseDeleteWebhookApiV1WebhooksNotificationsWebhookIdDelete.from_dict(
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
    DeleteWebhookApiV1WebhooksNotificationsWebhookIdDeleteResponseDeleteWebhookApiV1WebhooksNotificationsWebhookIdDelete
    | HTTPValidationError
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
    DeleteWebhookApiV1WebhooksNotificationsWebhookIdDeleteResponseDeleteWebhookApiV1WebhooksNotificationsWebhookIdDelete
    | HTTPValidationError
]:
    """Remove a webhook

     Permanently remove a registered webhook.

    Args:
        webhook_id (str):
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteWebhookApiV1WebhooksNotificationsWebhookIdDeleteResponseDeleteWebhookApiV1WebhooksNotificationsWebhookIdDelete | HTTPValidationError]
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
    DeleteWebhookApiV1WebhooksNotificationsWebhookIdDeleteResponseDeleteWebhookApiV1WebhooksNotificationsWebhookIdDelete
    | HTTPValidationError
    | None
):
    """Remove a webhook

     Permanently remove a registered webhook.

    Args:
        webhook_id (str):
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteWebhookApiV1WebhooksNotificationsWebhookIdDeleteResponseDeleteWebhookApiV1WebhooksNotificationsWebhookIdDelete | HTTPValidationError
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
    DeleteWebhookApiV1WebhooksNotificationsWebhookIdDeleteResponseDeleteWebhookApiV1WebhooksNotificationsWebhookIdDelete
    | HTTPValidationError
]:
    """Remove a webhook

     Permanently remove a registered webhook.

    Args:
        webhook_id (str):
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteWebhookApiV1WebhooksNotificationsWebhookIdDeleteResponseDeleteWebhookApiV1WebhooksNotificationsWebhookIdDelete | HTTPValidationError]
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
    DeleteWebhookApiV1WebhooksNotificationsWebhookIdDeleteResponseDeleteWebhookApiV1WebhooksNotificationsWebhookIdDelete
    | HTTPValidationError
    | None
):
    """Remove a webhook

     Permanently remove a registered webhook.

    Args:
        webhook_id (str):
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteWebhookApiV1WebhooksNotificationsWebhookIdDeleteResponseDeleteWebhookApiV1WebhooksNotificationsWebhookIdDelete | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            webhook_id=webhook_id,
            client=client,
            org_id=org_id,
        )
    ).parsed
