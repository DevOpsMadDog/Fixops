from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_deliveries_api_v1_webhooks_dlq_get_response_200_item import (
    ListDeliveriesApiV1WebhooksDlqGetResponse200Item,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    status: None | str | Unset = UNSET,
    webhook_id: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_status: None | str | Unset
    if isinstance(status, Unset):
        json_status = UNSET
    else:
        json_status = status
    params["status"] = json_status

    json_webhook_id: None | str | Unset
    if isinstance(webhook_id, Unset):
        json_webhook_id = UNSET
    else:
        json_webhook_id = webhook_id
    params["webhook_id"] = json_webhook_id

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/webhooks/dlq/",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[ListDeliveriesApiV1WebhooksDlqGetResponse200Item] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = ListDeliveriesApiV1WebhooksDlqGetResponse200Item.from_dict(response_200_item_data)

            response_200.append(response_200_item)

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
) -> Response[HTTPValidationError | list[ListDeliveriesApiV1WebhooksDlqGetResponse200Item]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    webhook_id: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[ListDeliveriesApiV1WebhooksDlqGetResponse200Item]]:
    """List Deliveries

     List webhook deliveries for the current organization, with optional filters.

    Args:
        status (None | str | Unset): Filter by status
        webhook_id (None | str | Unset): Filter by webhook_id
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ListDeliveriesApiV1WebhooksDlqGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        status=status,
        webhook_id=webhook_id,
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
    status: None | str | Unset = UNSET,
    webhook_id: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | list[ListDeliveriesApiV1WebhooksDlqGetResponse200Item] | None:
    """List Deliveries

     List webhook deliveries for the current organization, with optional filters.

    Args:
        status (None | str | Unset): Filter by status
        webhook_id (None | str | Unset): Filter by webhook_id
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ListDeliveriesApiV1WebhooksDlqGetResponse200Item]
    """

    return sync_detailed(
        client=client,
        status=status,
        webhook_id=webhook_id,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    webhook_id: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[ListDeliveriesApiV1WebhooksDlqGetResponse200Item]]:
    """List Deliveries

     List webhook deliveries for the current organization, with optional filters.

    Args:
        status (None | str | Unset): Filter by status
        webhook_id (None | str | Unset): Filter by webhook_id
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ListDeliveriesApiV1WebhooksDlqGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        status=status,
        webhook_id=webhook_id,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    webhook_id: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | list[ListDeliveriesApiV1WebhooksDlqGetResponse200Item] | None:
    """List Deliveries

     List webhook deliveries for the current organization, with optional filters.

    Args:
        status (None | str | Unset): Filter by status
        webhook_id (None | str | Unset): Filter by webhook_id
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ListDeliveriesApiV1WebhooksDlqGetResponse200Item]
    """

    return (
        await asyncio_detailed(
            client=client,
            status=status,
            webhook_id=webhook_id,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
