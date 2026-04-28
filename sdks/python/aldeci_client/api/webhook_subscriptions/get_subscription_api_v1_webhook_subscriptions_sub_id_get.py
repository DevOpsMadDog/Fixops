from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_subscription_api_v1_webhook_subscriptions_sub_id_get_response_get_subscription_api_v1_webhook_subscriptions_sub_id_get import (
    GetSubscriptionApiV1WebhookSubscriptionsSubIdGetResponseGetSubscriptionApiV1WebhookSubscriptionsSubIdGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    sub_id: str,
    *,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/webhook-subscriptions/{sub_id}".format(
            sub_id=quote(str(sub_id), safe=""),
        ),
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetSubscriptionApiV1WebhookSubscriptionsSubIdGetResponseGetSubscriptionApiV1WebhookSubscriptionsSubIdGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetSubscriptionApiV1WebhookSubscriptionsSubIdGetResponseGetSubscriptionApiV1WebhookSubscriptionsSubIdGet.from_dict(
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
    GetSubscriptionApiV1WebhookSubscriptionsSubIdGetResponseGetSubscriptionApiV1WebhookSubscriptionsSubIdGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    sub_id: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetSubscriptionApiV1WebhookSubscriptionsSubIdGetResponseGetSubscriptionApiV1WebhookSubscriptionsSubIdGet
    | HTTPValidationError
]:
    """Get Subscription

     Get details of a specific webhook subscription.

    Args:
        sub_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetSubscriptionApiV1WebhookSubscriptionsSubIdGetResponseGetSubscriptionApiV1WebhookSubscriptionsSubIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        sub_id=sub_id,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    sub_id: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetSubscriptionApiV1WebhookSubscriptionsSubIdGetResponseGetSubscriptionApiV1WebhookSubscriptionsSubIdGet
    | HTTPValidationError
    | None
):
    """Get Subscription

     Get details of a specific webhook subscription.

    Args:
        sub_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetSubscriptionApiV1WebhookSubscriptionsSubIdGetResponseGetSubscriptionApiV1WebhookSubscriptionsSubIdGet | HTTPValidationError
    """

    return sync_detailed(
        sub_id=sub_id,
        client=client,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    sub_id: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetSubscriptionApiV1WebhookSubscriptionsSubIdGetResponseGetSubscriptionApiV1WebhookSubscriptionsSubIdGet
    | HTTPValidationError
]:
    """Get Subscription

     Get details of a specific webhook subscription.

    Args:
        sub_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetSubscriptionApiV1WebhookSubscriptionsSubIdGetResponseGetSubscriptionApiV1WebhookSubscriptionsSubIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        sub_id=sub_id,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    sub_id: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetSubscriptionApiV1WebhookSubscriptionsSubIdGetResponseGetSubscriptionApiV1WebhookSubscriptionsSubIdGet
    | HTTPValidationError
    | None
):
    """Get Subscription

     Get details of a specific webhook subscription.

    Args:
        sub_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetSubscriptionApiV1WebhookSubscriptionsSubIdGetResponseGetSubscriptionApiV1WebhookSubscriptionsSubIdGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            sub_id=sub_id,
            client=client,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
