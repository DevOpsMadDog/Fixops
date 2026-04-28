from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.delete_tenant_response import DeleteTenantResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    org_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/tenants/{org_id}".format(
            org_id=quote(str(org_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> DeleteTenantResponse | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = DeleteTenantResponse.from_dict(response.json())

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
) -> Response[DeleteTenantResponse | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    org_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[DeleteTenantResponse | HTTPValidationError]:
    """Delete tenant data

     Permanently delete all data for the specified tenant. This operation is irreversible. Requires admin
    access.

    Args:
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteTenantResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    org_id: str,
    *,
    client: AuthenticatedClient,
) -> DeleteTenantResponse | HTTPValidationError | None:
    """Delete tenant data

     Permanently delete all data for the specified tenant. This operation is irreversible. Requires admin
    access.

    Args:
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteTenantResponse | HTTPValidationError
    """

    return sync_detailed(
        org_id=org_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[DeleteTenantResponse | HTTPValidationError]:
    """Delete tenant data

     Permanently delete all data for the specified tenant. This operation is irreversible. Requires admin
    access.

    Args:
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteTenantResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    *,
    client: AuthenticatedClient,
) -> DeleteTenantResponse | HTTPValidationError | None:
    """Delete tenant data

     Permanently delete all data for the specified tenant. This operation is irreversible. Requires admin
    access.

    Args:
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteTenantResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            client=client,
        )
    ).parsed
