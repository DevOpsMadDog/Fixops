from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.add_database_api_v1_db_security_inventory_post_response_add_database_api_v1_db_security_inventory_post import (
    AddDatabaseApiV1DbSecurityInventoryPostResponseAddDatabaseApiV1DbSecurityInventoryPost,
)
from ...models.add_database_request import AddDatabaseRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    *,
    body: AddDatabaseRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/db-security/inventory",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    AddDatabaseApiV1DbSecurityInventoryPostResponseAddDatabaseApiV1DbSecurityInventoryPost | HTTPValidationError | None
):
    if response.status_code == 200:
        response_200 = AddDatabaseApiV1DbSecurityInventoryPostResponseAddDatabaseApiV1DbSecurityInventoryPost.from_dict(
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
    AddDatabaseApiV1DbSecurityInventoryPostResponseAddDatabaseApiV1DbSecurityInventoryPost | HTTPValidationError
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
    body: AddDatabaseRequest,
) -> Response[
    AddDatabaseApiV1DbSecurityInventoryPostResponseAddDatabaseApiV1DbSecurityInventoryPost | HTTPValidationError
]:
    """Add Database

     Register a database in the inventory.

    Tracks type, version, host, port, TLS status, backup configuration,
    and public-facing exposure for downstream scanning.

    Args:
        body (AddDatabaseRequest): Register a database in the inventory.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AddDatabaseApiV1DbSecurityInventoryPostResponseAddDatabaseApiV1DbSecurityInventoryPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: AddDatabaseRequest,
) -> (
    AddDatabaseApiV1DbSecurityInventoryPostResponseAddDatabaseApiV1DbSecurityInventoryPost | HTTPValidationError | None
):
    """Add Database

     Register a database in the inventory.

    Tracks type, version, host, port, TLS status, backup configuration,
    and public-facing exposure for downstream scanning.

    Args:
        body (AddDatabaseRequest): Register a database in the inventory.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AddDatabaseApiV1DbSecurityInventoryPostResponseAddDatabaseApiV1DbSecurityInventoryPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: AddDatabaseRequest,
) -> Response[
    AddDatabaseApiV1DbSecurityInventoryPostResponseAddDatabaseApiV1DbSecurityInventoryPost | HTTPValidationError
]:
    """Add Database

     Register a database in the inventory.

    Tracks type, version, host, port, TLS status, backup configuration,
    and public-facing exposure for downstream scanning.

    Args:
        body (AddDatabaseRequest): Register a database in the inventory.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AddDatabaseApiV1DbSecurityInventoryPostResponseAddDatabaseApiV1DbSecurityInventoryPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: AddDatabaseRequest,
) -> (
    AddDatabaseApiV1DbSecurityInventoryPostResponseAddDatabaseApiV1DbSecurityInventoryPost | HTTPValidationError | None
):
    """Add Database

     Register a database in the inventory.

    Tracks type, version, host, port, TLS status, backup configuration,
    and public-facing exposure for downstream scanning.

    Args:
        body (AddDatabaseRequest): Register a database in the inventory.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AddDatabaseApiV1DbSecurityInventoryPostResponseAddDatabaseApiV1DbSecurityInventoryPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
