from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.webhook_subscribe_api_v1_webhooks_subscribe_post_response_webhook_subscribe_api_v1_webhooks_subscribe_post import (
    WebhookSubscribeApiV1WebhooksSubscribePostResponseWebhookSubscribeApiV1WebhooksSubscribePost,
)
from ...models.webhook_subscribe_request import WebhookSubscribeRequest
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: WebhookSubscribeRequest,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/webhooks/subscribe",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | WebhookSubscribeApiV1WebhooksSubscribePostResponseWebhookSubscribeApiV1WebhooksSubscribePost
    | None
):
    if response.status_code == 201:
        response_201 = (
            WebhookSubscribeApiV1WebhooksSubscribePostResponseWebhookSubscribeApiV1WebhooksSubscribePost.from_dict(
                response.json()
            )
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
    HTTPValidationError | WebhookSubscribeApiV1WebhooksSubscribePostResponseWebhookSubscribeApiV1WebhooksSubscribePost
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
    body: WebhookSubscribeRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError | WebhookSubscribeApiV1WebhooksSubscribePostResponseWebhookSubscribeApiV1WebhooksSubscribePost
]:
    """Webhook Subscribe

     Register a webhook subscription. (Multica d36e7e48)

    Args:
        x_org_id (None | str | Unset):
        body (WebhookSubscribeRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | WebhookSubscribeApiV1WebhooksSubscribePostResponseWebhookSubscribeApiV1WebhooksSubscribePost]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: WebhookSubscribeRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | WebhookSubscribeApiV1WebhooksSubscribePostResponseWebhookSubscribeApiV1WebhooksSubscribePost
    | None
):
    """Webhook Subscribe

     Register a webhook subscription. (Multica d36e7e48)

    Args:
        x_org_id (None | str | Unset):
        body (WebhookSubscribeRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | WebhookSubscribeApiV1WebhooksSubscribePostResponseWebhookSubscribeApiV1WebhooksSubscribePost
    """

    return sync_detailed(
        client=client,
        body=body,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: WebhookSubscribeRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError | WebhookSubscribeApiV1WebhooksSubscribePostResponseWebhookSubscribeApiV1WebhooksSubscribePost
]:
    """Webhook Subscribe

     Register a webhook subscription. (Multica d36e7e48)

    Args:
        x_org_id (None | str | Unset):
        body (WebhookSubscribeRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | WebhookSubscribeApiV1WebhooksSubscribePostResponseWebhookSubscribeApiV1WebhooksSubscribePost]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: WebhookSubscribeRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | WebhookSubscribeApiV1WebhooksSubscribePostResponseWebhookSubscribeApiV1WebhooksSubscribePost
    | None
):
    """Webhook Subscribe

     Register a webhook subscription. (Multica d36e7e48)

    Args:
        x_org_id (None | str | Unset):
        body (WebhookSubscribeRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | WebhookSubscribeApiV1WebhooksSubscribePostResponseWebhookSubscribeApiV1WebhooksSubscribePost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            x_org_id=x_org_id,
        )
    ).parsed
