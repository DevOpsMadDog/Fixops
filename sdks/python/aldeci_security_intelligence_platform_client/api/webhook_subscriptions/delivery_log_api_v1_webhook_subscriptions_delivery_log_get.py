from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.delivery_log_api_v1_webhook_subscriptions_delivery_log_get_response_delivery_log_api_v1_webhook_subscriptions_delivery_log_get import (
    DeliveryLogApiV1WebhookSubscriptionsDeliveryLogGetResponseDeliveryLogApiV1WebhookSubscriptionsDeliveryLogGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    subscription_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_subscription_id: None | str | Unset
    if isinstance(subscription_id, Unset):
        json_subscription_id = UNSET
    else:
        json_subscription_id = subscription_id
    params["subscription_id"] = json_subscription_id

    json_status: None | str | Unset
    if isinstance(status, Unset):
        json_status = UNSET
    else:
        json_status = status
    params["status"] = json_status

    params["limit"] = limit

    params["offset"] = offset

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/webhook-subscriptions/delivery-log",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DeliveryLogApiV1WebhookSubscriptionsDeliveryLogGetResponseDeliveryLogApiV1WebhookSubscriptionsDeliveryLogGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = DeliveryLogApiV1WebhookSubscriptionsDeliveryLogGetResponseDeliveryLogApiV1WebhookSubscriptionsDeliveryLogGet.from_dict(
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
    DeliveryLogApiV1WebhookSubscriptionsDeliveryLogGetResponseDeliveryLogApiV1WebhookSubscriptionsDeliveryLogGet
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
    subscription_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    DeliveryLogApiV1WebhookSubscriptionsDeliveryLogGetResponseDeliveryLogApiV1WebhookSubscriptionsDeliveryLogGet
    | HTTPValidationError
]:
    """Delivery Log

     Delivery retry dashboard — list all webhook delivery attempts.

    Supports filtering by subscription_id and status (success/failed).
    Returns chronological delivery log with response codes and errors.

    Args:
        subscription_id (None | str | Unset):
        status (None | str | Unset):
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeliveryLogApiV1WebhookSubscriptionsDeliveryLogGetResponseDeliveryLogApiV1WebhookSubscriptionsDeliveryLogGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        subscription_id=subscription_id,
        status=status,
        limit=limit,
        offset=offset,
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
    subscription_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    DeliveryLogApiV1WebhookSubscriptionsDeliveryLogGetResponseDeliveryLogApiV1WebhookSubscriptionsDeliveryLogGet
    | HTTPValidationError
    | None
):
    """Delivery Log

     Delivery retry dashboard — list all webhook delivery attempts.

    Supports filtering by subscription_id and status (success/failed).
    Returns chronological delivery log with response codes and errors.

    Args:
        subscription_id (None | str | Unset):
        status (None | str | Unset):
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeliveryLogApiV1WebhookSubscriptionsDeliveryLogGetResponseDeliveryLogApiV1WebhookSubscriptionsDeliveryLogGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        subscription_id=subscription_id,
        status=status,
        limit=limit,
        offset=offset,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    subscription_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    DeliveryLogApiV1WebhookSubscriptionsDeliveryLogGetResponseDeliveryLogApiV1WebhookSubscriptionsDeliveryLogGet
    | HTTPValidationError
]:
    """Delivery Log

     Delivery retry dashboard — list all webhook delivery attempts.

    Supports filtering by subscription_id and status (success/failed).
    Returns chronological delivery log with response codes and errors.

    Args:
        subscription_id (None | str | Unset):
        status (None | str | Unset):
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeliveryLogApiV1WebhookSubscriptionsDeliveryLogGetResponseDeliveryLogApiV1WebhookSubscriptionsDeliveryLogGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        subscription_id=subscription_id,
        status=status,
        limit=limit,
        offset=offset,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    subscription_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    DeliveryLogApiV1WebhookSubscriptionsDeliveryLogGetResponseDeliveryLogApiV1WebhookSubscriptionsDeliveryLogGet
    | HTTPValidationError
    | None
):
    """Delivery Log

     Delivery retry dashboard — list all webhook delivery attempts.

    Supports filtering by subscription_id and status (success/failed).
    Returns chronological delivery log with response codes and errors.

    Args:
        subscription_id (None | str | Unset):
        status (None | str | Unset):
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeliveryLogApiV1WebhookSubscriptionsDeliveryLogGetResponseDeliveryLogApiV1WebhookSubscriptionsDeliveryLogGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            subscription_id=subscription_id,
            status=status,
            limit=limit,
            offset=offset,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
