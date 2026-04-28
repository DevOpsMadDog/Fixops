from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.purchase_item_api_v1_marketplace_purchase_item_id_post_response_purchase_item_api_v1_marketplace_purchase_item_id_post import (
    PurchaseItemApiV1MarketplacePurchaseItemIdPostResponsePurchaseItemApiV1MarketplacePurchaseItemIdPost,
)
from ...models.purchase_request import PurchaseRequest
from ...types import UNSET, Response


def _get_kwargs(
    item_id: str,
    *,
    body: PurchaseRequest,
    purchaser: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    params: dict[str, Any] = {}

    params["purchaser"] = purchaser

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/marketplace/purchase/{item_id}".format(
            item_id=quote(str(item_id), safe=""),
        ),
        "params": params,
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | PurchaseItemApiV1MarketplacePurchaseItemIdPostResponsePurchaseItemApiV1MarketplacePurchaseItemIdPost
    | None
):
    if response.status_code == 200:
        response_200 = PurchaseItemApiV1MarketplacePurchaseItemIdPostResponsePurchaseItemApiV1MarketplacePurchaseItemIdPost.from_dict(
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
    | PurchaseItemApiV1MarketplacePurchaseItemIdPostResponsePurchaseItemApiV1MarketplacePurchaseItemIdPost
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
    body: PurchaseRequest,
    purchaser: str,
) -> Response[
    HTTPValidationError
    | PurchaseItemApiV1MarketplacePurchaseItemIdPostResponsePurchaseItemApiV1MarketplacePurchaseItemIdPost
]:
    """Purchase Item

     Purchase a marketplace item and get download token.

    Args:
        item_id (str):
        purchaser (str): Purchaser name
        body (PurchaseRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | PurchaseItemApiV1MarketplacePurchaseItemIdPostResponsePurchaseItemApiV1MarketplacePurchaseItemIdPost]
    """

    kwargs = _get_kwargs(
        item_id=item_id,
        body=body,
        purchaser=purchaser,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    item_id: str,
    *,
    client: AuthenticatedClient,
    body: PurchaseRequest,
    purchaser: str,
) -> (
    HTTPValidationError
    | PurchaseItemApiV1MarketplacePurchaseItemIdPostResponsePurchaseItemApiV1MarketplacePurchaseItemIdPost
    | None
):
    """Purchase Item

     Purchase a marketplace item and get download token.

    Args:
        item_id (str):
        purchaser (str): Purchaser name
        body (PurchaseRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | PurchaseItemApiV1MarketplacePurchaseItemIdPostResponsePurchaseItemApiV1MarketplacePurchaseItemIdPost
    """

    return sync_detailed(
        item_id=item_id,
        client=client,
        body=body,
        purchaser=purchaser,
    ).parsed


async def asyncio_detailed(
    item_id: str,
    *,
    client: AuthenticatedClient,
    body: PurchaseRequest,
    purchaser: str,
) -> Response[
    HTTPValidationError
    | PurchaseItemApiV1MarketplacePurchaseItemIdPostResponsePurchaseItemApiV1MarketplacePurchaseItemIdPost
]:
    """Purchase Item

     Purchase a marketplace item and get download token.

    Args:
        item_id (str):
        purchaser (str): Purchaser name
        body (PurchaseRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | PurchaseItemApiV1MarketplacePurchaseItemIdPostResponsePurchaseItemApiV1MarketplacePurchaseItemIdPost]
    """

    kwargs = _get_kwargs(
        item_id=item_id,
        body=body,
        purchaser=purchaser,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    item_id: str,
    *,
    client: AuthenticatedClient,
    body: PurchaseRequest,
    purchaser: str,
) -> (
    HTTPValidationError
    | PurchaseItemApiV1MarketplacePurchaseItemIdPostResponsePurchaseItemApiV1MarketplacePurchaseItemIdPost
    | None
):
    """Purchase Item

     Purchase a marketplace item and get download token.

    Args:
        item_id (str):
        purchaser (str): Purchaser name
        body (PurchaseRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | PurchaseItemApiV1MarketplacePurchaseItemIdPostResponsePurchaseItemApiV1MarketplacePurchaseItemIdPost
    """

    return (
        await asyncio_detailed(
            item_id=item_id,
            client=client,
            body=body,
            purchaser=purchaser,
        )
    ).parsed
