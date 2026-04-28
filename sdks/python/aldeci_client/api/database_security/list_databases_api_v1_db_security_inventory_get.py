from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.list_databases_api_v1_db_security_inventory_get_response_list_databases_api_v1_db_security_inventory_get import (
    ListDatabasesApiV1DbSecurityInventoryGetResponseListDatabasesApiV1DbSecurityInventoryGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/db-security/inventory",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ListDatabasesApiV1DbSecurityInventoryGetResponseListDatabasesApiV1DbSecurityInventoryGet | None:
    if response.status_code == 200:
        response_200 = (
            ListDatabasesApiV1DbSecurityInventoryGetResponseListDatabasesApiV1DbSecurityInventoryGet.from_dict(
                response.json()
            )
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ListDatabasesApiV1DbSecurityInventoryGetResponseListDatabasesApiV1DbSecurityInventoryGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[ListDatabasesApiV1DbSecurityInventoryGetResponseListDatabasesApiV1DbSecurityInventoryGet]:
    """List Databases

     List all registered databases with inventory summary.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ListDatabasesApiV1DbSecurityInventoryGetResponseListDatabasesApiV1DbSecurityInventoryGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> ListDatabasesApiV1DbSecurityInventoryGetResponseListDatabasesApiV1DbSecurityInventoryGet | None:
    """List Databases

     List all registered databases with inventory summary.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ListDatabasesApiV1DbSecurityInventoryGetResponseListDatabasesApiV1DbSecurityInventoryGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[ListDatabasesApiV1DbSecurityInventoryGetResponseListDatabasesApiV1DbSecurityInventoryGet]:
    """List Databases

     List all registered databases with inventory summary.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ListDatabasesApiV1DbSecurityInventoryGetResponseListDatabasesApiV1DbSecurityInventoryGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> ListDatabasesApiV1DbSecurityInventoryGetResponseListDatabasesApiV1DbSecurityInventoryGet | None:
    """List Databases

     List all registered databases with inventory summary.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ListDatabasesApiV1DbSecurityInventoryGetResponseListDatabasesApiV1DbSecurityInventoryGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
