from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.webhook_event_catalogue_api_v1_webhooks_event_catalogue_get_response_webhook_event_catalogue_api_v1_webhooks_event_catalogue_get import (
    WebhookEventCatalogueApiV1WebhooksEventCatalogueGetResponseWebhookEventCatalogueApiV1WebhooksEventCatalogueGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/webhooks/event-catalogue",
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | WebhookEventCatalogueApiV1WebhooksEventCatalogueGetResponseWebhookEventCatalogueApiV1WebhooksEventCatalogueGet
    | None
):
    if response.status_code == 200:
        response_200 = WebhookEventCatalogueApiV1WebhooksEventCatalogueGetResponseWebhookEventCatalogueApiV1WebhooksEventCatalogueGet.from_dict(
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
    | WebhookEventCatalogueApiV1WebhooksEventCatalogueGetResponseWebhookEventCatalogueApiV1WebhooksEventCatalogueGet
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
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | WebhookEventCatalogueApiV1WebhooksEventCatalogueGetResponseWebhookEventCatalogueApiV1WebhooksEventCatalogueGet
]:
    """Webhook Event Catalogue

     Return the catalogue of available webhook event types. (Multica 67a3167b)

    Args:
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | WebhookEventCatalogueApiV1WebhooksEventCatalogueGetResponseWebhookEventCatalogueApiV1WebhooksEventCatalogueGet]
    """

    kwargs = _get_kwargs(
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | WebhookEventCatalogueApiV1WebhooksEventCatalogueGetResponseWebhookEventCatalogueApiV1WebhooksEventCatalogueGet
    | None
):
    """Webhook Event Catalogue

     Return the catalogue of available webhook event types. (Multica 67a3167b)

    Args:
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | WebhookEventCatalogueApiV1WebhooksEventCatalogueGetResponseWebhookEventCatalogueApiV1WebhooksEventCatalogueGet
    """

    return sync_detailed(
        client=client,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | WebhookEventCatalogueApiV1WebhooksEventCatalogueGetResponseWebhookEventCatalogueApiV1WebhooksEventCatalogueGet
]:
    """Webhook Event Catalogue

     Return the catalogue of available webhook event types. (Multica 67a3167b)

    Args:
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | WebhookEventCatalogueApiV1WebhooksEventCatalogueGetResponseWebhookEventCatalogueApiV1WebhooksEventCatalogueGet]
    """

    kwargs = _get_kwargs(
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | WebhookEventCatalogueApiV1WebhooksEventCatalogueGetResponseWebhookEventCatalogueApiV1WebhooksEventCatalogueGet
    | None
):
    """Webhook Event Catalogue

     Return the catalogue of available webhook event types. (Multica 67a3167b)

    Args:
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | WebhookEventCatalogueApiV1WebhooksEventCatalogueGetResponseWebhookEventCatalogueApiV1WebhooksEventCatalogueGet
    """

    return (
        await asyncio_detailed(
            client=client,
            x_org_id=x_org_id,
        )
    ).parsed
