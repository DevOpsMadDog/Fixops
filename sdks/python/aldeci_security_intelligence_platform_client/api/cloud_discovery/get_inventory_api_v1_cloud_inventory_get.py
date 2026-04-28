from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_inventory_api_v1_cloud_inventory_get_response_get_inventory_api_v1_cloud_inventory_get import (
    GetInventoryApiV1CloudInventoryGetResponseGetInventoryApiV1CloudInventoryGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str | Unset = "default",
    provider: None | str | Unset = UNSET,
    asset_type: None | str | Unset = UNSET,
    region: None | str | Unset = UNSET,
    account_id: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    json_provider: None | str | Unset
    if isinstance(provider, Unset):
        json_provider = UNSET
    else:
        json_provider = provider
    params["provider"] = json_provider

    json_asset_type: None | str | Unset
    if isinstance(asset_type, Unset):
        json_asset_type = UNSET
    else:
        json_asset_type = asset_type
    params["asset_type"] = json_asset_type

    json_region: None | str | Unset
    if isinstance(region, Unset):
        json_region = UNSET
    else:
        json_region = region
    params["region"] = json_region

    json_account_id: None | str | Unset
    if isinstance(account_id, Unset):
        json_account_id = UNSET
    else:
        json_account_id = account_id
    params["account_id"] = json_account_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/cloud/inventory",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetInventoryApiV1CloudInventoryGetResponseGetInventoryApiV1CloudInventoryGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GetInventoryApiV1CloudInventoryGetResponseGetInventoryApiV1CloudInventoryGet.from_dict(
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
) -> Response[GetInventoryApiV1CloudInventoryGetResponseGetInventoryApiV1CloudInventoryGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    provider: None | str | Unset = UNSET,
    asset_type: None | str | Unset = UNSET,
    region: None | str | Unset = UNSET,
    account_id: None | str | Unset = UNSET,
) -> Response[GetInventoryApiV1CloudInventoryGetResponseGetInventoryApiV1CloudInventoryGet | HTTPValidationError]:
    """Get full cloud asset inventory

     Return full asset inventory with optional filters.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        provider (None | str | Unset): Filter by provider: aws | azure | gcp
        asset_type (None | str | Unset): Filter by asset type
        region (None | str | Unset): Filter by region
        account_id (None | str | Unset): Filter by account/subscription/project ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetInventoryApiV1CloudInventoryGetResponseGetInventoryApiV1CloudInventoryGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        provider=provider,
        asset_type=asset_type,
        region=region,
        account_id=account_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    provider: None | str | Unset = UNSET,
    asset_type: None | str | Unset = UNSET,
    region: None | str | Unset = UNSET,
    account_id: None | str | Unset = UNSET,
) -> GetInventoryApiV1CloudInventoryGetResponseGetInventoryApiV1CloudInventoryGet | HTTPValidationError | None:
    """Get full cloud asset inventory

     Return full asset inventory with optional filters.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        provider (None | str | Unset): Filter by provider: aws | azure | gcp
        asset_type (None | str | Unset): Filter by asset type
        region (None | str | Unset): Filter by region
        account_id (None | str | Unset): Filter by account/subscription/project ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetInventoryApiV1CloudInventoryGetResponseGetInventoryApiV1CloudInventoryGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        provider=provider,
        asset_type=asset_type,
        region=region,
        account_id=account_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    provider: None | str | Unset = UNSET,
    asset_type: None | str | Unset = UNSET,
    region: None | str | Unset = UNSET,
    account_id: None | str | Unset = UNSET,
) -> Response[GetInventoryApiV1CloudInventoryGetResponseGetInventoryApiV1CloudInventoryGet | HTTPValidationError]:
    """Get full cloud asset inventory

     Return full asset inventory with optional filters.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        provider (None | str | Unset): Filter by provider: aws | azure | gcp
        asset_type (None | str | Unset): Filter by asset type
        region (None | str | Unset): Filter by region
        account_id (None | str | Unset): Filter by account/subscription/project ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetInventoryApiV1CloudInventoryGetResponseGetInventoryApiV1CloudInventoryGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        provider=provider,
        asset_type=asset_type,
        region=region,
        account_id=account_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    provider: None | str | Unset = UNSET,
    asset_type: None | str | Unset = UNSET,
    region: None | str | Unset = UNSET,
    account_id: None | str | Unset = UNSET,
) -> GetInventoryApiV1CloudInventoryGetResponseGetInventoryApiV1CloudInventoryGet | HTTPValidationError | None:
    """Get full cloud asset inventory

     Return full asset inventory with optional filters.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        provider (None | str | Unset): Filter by provider: aws | azure | gcp
        asset_type (None | str | Unset): Filter by asset type
        region (None | str | Unset): Filter by region
        account_id (None | str | Unset): Filter by account/subscription/project ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetInventoryApiV1CloudInventoryGetResponseGetInventoryApiV1CloudInventoryGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            provider=provider,
            asset_type=asset_type,
            region=region,
            account_id=account_id,
        )
    ).parsed
