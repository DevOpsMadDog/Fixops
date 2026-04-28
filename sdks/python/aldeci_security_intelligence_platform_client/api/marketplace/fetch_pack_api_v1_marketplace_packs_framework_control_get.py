from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.fetch_pack_api_v1_marketplace_packs_framework_control_get_response_fetch_pack_api_v1_marketplace_packs_framework_control_get import (
    FetchPackApiV1MarketplacePacksFrameworkControlGetResponseFetchPackApiV1MarketplacePacksFrameworkControlGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    framework: str,
    control: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/marketplace/packs/{framework}/{control}".format(
            framework=quote(str(framework), safe=""),
            control=quote(str(control), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    FetchPackApiV1MarketplacePacksFrameworkControlGetResponseFetchPackApiV1MarketplacePacksFrameworkControlGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = FetchPackApiV1MarketplacePacksFrameworkControlGetResponseFetchPackApiV1MarketplacePacksFrameworkControlGet.from_dict(
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
    FetchPackApiV1MarketplacePacksFrameworkControlGetResponseFetchPackApiV1MarketplacePacksFrameworkControlGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    framework: str,
    control: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    FetchPackApiV1MarketplacePacksFrameworkControlGetResponseFetchPackApiV1MarketplacePacksFrameworkControlGet
    | HTTPValidationError
]:
    """Fetch Pack

     Fetch a remediation pack for a specific framework and control.

    Args:
        framework (str):
        control (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[FetchPackApiV1MarketplacePacksFrameworkControlGetResponseFetchPackApiV1MarketplacePacksFrameworkControlGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        framework=framework,
        control=control,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    framework: str,
    control: str,
    *,
    client: AuthenticatedClient,
) -> (
    FetchPackApiV1MarketplacePacksFrameworkControlGetResponseFetchPackApiV1MarketplacePacksFrameworkControlGet
    | HTTPValidationError
    | None
):
    """Fetch Pack

     Fetch a remediation pack for a specific framework and control.

    Args:
        framework (str):
        control (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        FetchPackApiV1MarketplacePacksFrameworkControlGetResponseFetchPackApiV1MarketplacePacksFrameworkControlGet | HTTPValidationError
    """

    return sync_detailed(
        framework=framework,
        control=control,
        client=client,
    ).parsed


async def asyncio_detailed(
    framework: str,
    control: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    FetchPackApiV1MarketplacePacksFrameworkControlGetResponseFetchPackApiV1MarketplacePacksFrameworkControlGet
    | HTTPValidationError
]:
    """Fetch Pack

     Fetch a remediation pack for a specific framework and control.

    Args:
        framework (str):
        control (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[FetchPackApiV1MarketplacePacksFrameworkControlGetResponseFetchPackApiV1MarketplacePacksFrameworkControlGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        framework=framework,
        control=control,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    framework: str,
    control: str,
    *,
    client: AuthenticatedClient,
) -> (
    FetchPackApiV1MarketplacePacksFrameworkControlGetResponseFetchPackApiV1MarketplacePacksFrameworkControlGet
    | HTTPValidationError
    | None
):
    """Fetch Pack

     Fetch a remediation pack for a specific framework and control.

    Args:
        framework (str):
        control (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        FetchPackApiV1MarketplacePacksFrameworkControlGetResponseFetchPackApiV1MarketplacePacksFrameworkControlGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            framework=framework,
            control=control,
            client=client,
        )
    ).parsed
