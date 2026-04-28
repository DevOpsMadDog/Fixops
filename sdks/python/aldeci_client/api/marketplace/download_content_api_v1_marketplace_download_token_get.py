from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.download_content_api_v1_marketplace_download_token_get_response_download_content_api_v1_marketplace_download_token_get import (
    DownloadContentApiV1MarketplaceDownloadTokenGetResponseDownloadContentApiV1MarketplaceDownloadTokenGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    token: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/marketplace/download/{token}".format(
            token=quote(str(token), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DownloadContentApiV1MarketplaceDownloadTokenGetResponseDownloadContentApiV1MarketplaceDownloadTokenGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = DownloadContentApiV1MarketplaceDownloadTokenGetResponseDownloadContentApiV1MarketplaceDownloadTokenGet.from_dict(
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
    DownloadContentApiV1MarketplaceDownloadTokenGetResponseDownloadContentApiV1MarketplaceDownloadTokenGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    token: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    DownloadContentApiV1MarketplaceDownloadTokenGetResponseDownloadContentApiV1MarketplaceDownloadTokenGet
    | HTTPValidationError
]:
    """Download Content

     Download purchased content using a valid token.

    Args:
        token (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DownloadContentApiV1MarketplaceDownloadTokenGetResponseDownloadContentApiV1MarketplaceDownloadTokenGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        token=token,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    token: str,
    *,
    client: AuthenticatedClient,
) -> (
    DownloadContentApiV1MarketplaceDownloadTokenGetResponseDownloadContentApiV1MarketplaceDownloadTokenGet
    | HTTPValidationError
    | None
):
    """Download Content

     Download purchased content using a valid token.

    Args:
        token (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DownloadContentApiV1MarketplaceDownloadTokenGetResponseDownloadContentApiV1MarketplaceDownloadTokenGet | HTTPValidationError
    """

    return sync_detailed(
        token=token,
        client=client,
    ).parsed


async def asyncio_detailed(
    token: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    DownloadContentApiV1MarketplaceDownloadTokenGetResponseDownloadContentApiV1MarketplaceDownloadTokenGet
    | HTTPValidationError
]:
    """Download Content

     Download purchased content using a valid token.

    Args:
        token (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DownloadContentApiV1MarketplaceDownloadTokenGetResponseDownloadContentApiV1MarketplaceDownloadTokenGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        token=token,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    token: str,
    *,
    client: AuthenticatedClient,
) -> (
    DownloadContentApiV1MarketplaceDownloadTokenGetResponseDownloadContentApiV1MarketplaceDownloadTokenGet
    | HTTPValidationError
    | None
):
    """Download Content

     Download purchased content using a valid token.

    Args:
        token (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DownloadContentApiV1MarketplaceDownloadTokenGetResponseDownloadContentApiV1MarketplaceDownloadTokenGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            token=token,
            client=client,
        )
    ).parsed
