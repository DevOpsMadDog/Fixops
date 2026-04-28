from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.update_item_api_v1_marketplace_items_item_id_put_response_update_item_api_v1_marketplace_items_item_id_put import (
    UpdateItemApiV1MarketplaceItemsItemIdPutResponseUpdateItemApiV1MarketplaceItemsItemIdPut,
)
from ...models.update_request import UpdateRequest
from ...types import Response


def _get_kwargs(
    item_id: str,
    *,
    body: UpdateRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/marketplace/items/{item_id}".format(
            item_id=quote(str(item_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | UpdateItemApiV1MarketplaceItemsItemIdPutResponseUpdateItemApiV1MarketplaceItemsItemIdPut
    | None
):
    if response.status_code == 200:
        response_200 = (
            UpdateItemApiV1MarketplaceItemsItemIdPutResponseUpdateItemApiV1MarketplaceItemsItemIdPut.from_dict(
                response.json()
            )
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
    HTTPValidationError | UpdateItemApiV1MarketplaceItemsItemIdPutResponseUpdateItemApiV1MarketplaceItemsItemIdPut
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    item_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateRequest,
) -> Response[
    HTTPValidationError | UpdateItemApiV1MarketplaceItemsItemIdPutResponseUpdateItemApiV1MarketplaceItemsItemIdPut
]:
    """Update Item

     Update an existing marketplace item.

    Args:
        item_id (str):
        body (UpdateRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdateItemApiV1MarketplaceItemsItemIdPutResponseUpdateItemApiV1MarketplaceItemsItemIdPut]
    """

    kwargs = _get_kwargs(
        item_id=item_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    item_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateRequest,
) -> (
    HTTPValidationError
    | UpdateItemApiV1MarketplaceItemsItemIdPutResponseUpdateItemApiV1MarketplaceItemsItemIdPut
    | None
):
    """Update Item

     Update an existing marketplace item.

    Args:
        item_id (str):
        body (UpdateRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdateItemApiV1MarketplaceItemsItemIdPutResponseUpdateItemApiV1MarketplaceItemsItemIdPut
    """

    return sync_detailed(
        item_id=item_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    item_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateRequest,
) -> Response[
    HTTPValidationError | UpdateItemApiV1MarketplaceItemsItemIdPutResponseUpdateItemApiV1MarketplaceItemsItemIdPut
]:
    """Update Item

     Update an existing marketplace item.

    Args:
        item_id (str):
        body (UpdateRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdateItemApiV1MarketplaceItemsItemIdPutResponseUpdateItemApiV1MarketplaceItemsItemIdPut]
    """

    kwargs = _get_kwargs(
        item_id=item_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    item_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateRequest,
) -> (
    HTTPValidationError
    | UpdateItemApiV1MarketplaceItemsItemIdPutResponseUpdateItemApiV1MarketplaceItemsItemIdPut
    | None
):
    """Update Item

     Update an existing marketplace item.

    Args:
        item_id (str):
        body (UpdateRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdateItemApiV1MarketplaceItemsItemIdPutResponseUpdateItemApiV1MarketplaceItemsItemIdPut
    """

    return (
        await asyncio_detailed(
            item_id=item_id,
            client=client,
            body=body,
        )
    ).parsed
