from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.remove_database_api_v1_db_security_inventory_db_id_delete_response_remove_database_api_v1_db_security_inventory_db_id_delete import (
    RemoveDatabaseApiV1DbSecurityInventoryDbIdDeleteResponseRemoveDatabaseApiV1DbSecurityInventoryDbIdDelete,
)
from ...types import Response


def _get_kwargs(
    db_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/db-security/inventory/{db_id}".format(
            db_id=quote(str(db_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | RemoveDatabaseApiV1DbSecurityInventoryDbIdDeleteResponseRemoveDatabaseApiV1DbSecurityInventoryDbIdDelete
    | None
):
    if response.status_code == 200:
        response_200 = RemoveDatabaseApiV1DbSecurityInventoryDbIdDeleteResponseRemoveDatabaseApiV1DbSecurityInventoryDbIdDelete.from_dict(
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
    | RemoveDatabaseApiV1DbSecurityInventoryDbIdDeleteResponseRemoveDatabaseApiV1DbSecurityInventoryDbIdDelete
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    db_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    HTTPValidationError
    | RemoveDatabaseApiV1DbSecurityInventoryDbIdDeleteResponseRemoveDatabaseApiV1DbSecurityInventoryDbIdDelete
]:
    """Remove Database

     Remove a database from the inventory.

    Args:
        db_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RemoveDatabaseApiV1DbSecurityInventoryDbIdDeleteResponseRemoveDatabaseApiV1DbSecurityInventoryDbIdDelete]
    """

    kwargs = _get_kwargs(
        db_id=db_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    db_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    HTTPValidationError
    | RemoveDatabaseApiV1DbSecurityInventoryDbIdDeleteResponseRemoveDatabaseApiV1DbSecurityInventoryDbIdDelete
    | None
):
    """Remove Database

     Remove a database from the inventory.

    Args:
        db_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RemoveDatabaseApiV1DbSecurityInventoryDbIdDeleteResponseRemoveDatabaseApiV1DbSecurityInventoryDbIdDelete
    """

    return sync_detailed(
        db_id=db_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    db_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    HTTPValidationError
    | RemoveDatabaseApiV1DbSecurityInventoryDbIdDeleteResponseRemoveDatabaseApiV1DbSecurityInventoryDbIdDelete
]:
    """Remove Database

     Remove a database from the inventory.

    Args:
        db_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RemoveDatabaseApiV1DbSecurityInventoryDbIdDeleteResponseRemoveDatabaseApiV1DbSecurityInventoryDbIdDelete]
    """

    kwargs = _get_kwargs(
        db_id=db_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    db_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    HTTPValidationError
    | RemoveDatabaseApiV1DbSecurityInventoryDbIdDeleteResponseRemoveDatabaseApiV1DbSecurityInventoryDbIdDelete
    | None
):
    """Remove Database

     Remove a database from the inventory.

    Args:
        db_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RemoveDatabaseApiV1DbSecurityInventoryDbIdDeleteResponseRemoveDatabaseApiV1DbSecurityInventoryDbIdDelete
    """

    return (
        await asyncio_detailed(
            db_id=db_id,
            client=client,
        )
    ).parsed
