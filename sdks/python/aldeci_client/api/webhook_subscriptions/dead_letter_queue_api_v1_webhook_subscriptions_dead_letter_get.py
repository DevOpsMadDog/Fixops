from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.dead_letter_queue_api_v1_webhook_subscriptions_dead_letter_get_response_dead_letter_queue_api_v1_webhook_subscriptions_dead_letter_get import (
    DeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGetResponseDeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["limit"] = limit

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/webhook-subscriptions/dead-letter",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGetResponseDeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = DeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGetResponseDeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGet.from_dict(
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
    DeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGetResponseDeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGet
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
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    DeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGetResponseDeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGet
    | HTTPValidationError
]:
    """Dead Letter Queue

     Dead letter queue — subscriptions disabled due to repeated delivery failures.

    Returns subscriptions where active=0 AND failure_count >= max_retries,
    along with their most recent delivery errors.

    Args:
        limit (int | Unset):  Default: 50.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGetResponseDeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        limit=limit,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    DeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGetResponseDeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGet
    | HTTPValidationError
    | None
):
    """Dead Letter Queue

     Dead letter queue — subscriptions disabled due to repeated delivery failures.

    Returns subscriptions where active=0 AND failure_count >= max_retries,
    along with their most recent delivery errors.

    Args:
        limit (int | Unset):  Default: 50.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGetResponseDeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        limit=limit,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    DeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGetResponseDeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGet
    | HTTPValidationError
]:
    """Dead Letter Queue

     Dead letter queue — subscriptions disabled due to repeated delivery failures.

    Returns subscriptions where active=0 AND failure_count >= max_retries,
    along with their most recent delivery errors.

    Args:
        limit (int | Unset):  Default: 50.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGetResponseDeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        limit=limit,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 50,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    DeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGetResponseDeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGet
    | HTTPValidationError
    | None
):
    """Dead Letter Queue

     Dead letter queue — subscriptions disabled due to repeated delivery failures.

    Returns subscriptions where active=0 AND failure_count >= max_retries,
    along with their most recent delivery errors.

    Args:
        limit (int | Unset):  Default: 50.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGetResponseDeadLetterQueueApiV1WebhookSubscriptionsDeadLetterGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            limit=limit,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
