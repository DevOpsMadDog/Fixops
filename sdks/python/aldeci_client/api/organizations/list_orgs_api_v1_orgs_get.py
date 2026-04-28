from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_orgs_api_v1_orgs_get_response_200_item import ListOrgsApiV1OrgsGetResponse200Item
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    include_discovered: bool | Unset = True,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["include_discovered"] = include_discovered

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/orgs",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[ListOrgsApiV1OrgsGetResponse200Item] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = ListOrgsApiV1OrgsGetResponse200Item.from_dict(response_200_item_data)

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
) -> Response[HTTPValidationError | list[ListOrgsApiV1OrgsGetResponse200Item]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    include_discovered: bool | Unset = True,
) -> Response[HTTPValidationError | list[ListOrgsApiV1OrgsGetResponse200Item]]:
    """List Orgs

     List all known organisations.

    Returns registered orgs plus any org_ids discovered by scanning engine
    SQLite databases (when ``include_discovered=true``).

    Args:
        include_discovered (bool | Unset): Include org_ids discovered from engine databases
            Default: True.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ListOrgsApiV1OrgsGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        include_discovered=include_discovered,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    include_discovered: bool | Unset = True,
) -> HTTPValidationError | list[ListOrgsApiV1OrgsGetResponse200Item] | None:
    """List Orgs

     List all known organisations.

    Returns registered orgs plus any org_ids discovered by scanning engine
    SQLite databases (when ``include_discovered=true``).

    Args:
        include_discovered (bool | Unset): Include org_ids discovered from engine databases
            Default: True.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ListOrgsApiV1OrgsGetResponse200Item]
    """

    return sync_detailed(
        client=client,
        include_discovered=include_discovered,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    include_discovered: bool | Unset = True,
) -> Response[HTTPValidationError | list[ListOrgsApiV1OrgsGetResponse200Item]]:
    """List Orgs

     List all known organisations.

    Returns registered orgs plus any org_ids discovered by scanning engine
    SQLite databases (when ``include_discovered=true``).

    Args:
        include_discovered (bool | Unset): Include org_ids discovered from engine databases
            Default: True.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ListOrgsApiV1OrgsGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        include_discovered=include_discovered,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    include_discovered: bool | Unset = True,
) -> HTTPValidationError | list[ListOrgsApiV1OrgsGetResponse200Item] | None:
    """List Orgs

     List all known organisations.

    Returns registered orgs plus any org_ids discovered by scanning engine
    SQLite databases (when ``include_discovered=true``).

    Args:
        include_discovered (bool | Unset): Include org_ids discovered from engine databases
            Default: True.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ListOrgsApiV1OrgsGetResponse200Item]
    """

    return (
        await asyncio_detailed(
            client=client,
            include_discovered=include_discovered,
        )
    ).parsed
