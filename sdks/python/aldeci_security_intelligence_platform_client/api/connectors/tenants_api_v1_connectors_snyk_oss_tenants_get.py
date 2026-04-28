from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.tenants_api_v1_connectors_snyk_oss_tenants_get_response_tenants_api_v1_connectors_snyk_oss_tenants_get import (
    TenantsApiV1ConnectorsSnykOssTenantsGetResponseTenantsApiV1ConnectorsSnykOssTenantsGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/connectors/snyk-oss/tenants",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> TenantsApiV1ConnectorsSnykOssTenantsGetResponseTenantsApiV1ConnectorsSnykOssTenantsGet | None:
    if response.status_code == 200:
        response_200 = TenantsApiV1ConnectorsSnykOssTenantsGetResponseTenantsApiV1ConnectorsSnykOssTenantsGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[TenantsApiV1ConnectorsSnykOssTenantsGetResponseTenantsApiV1ConnectorsSnykOssTenantsGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[TenantsApiV1ConnectorsSnykOssTenantsGetResponseTenantsApiV1ConnectorsSnykOssTenantsGet]:
    """Tenants

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[TenantsApiV1ConnectorsSnykOssTenantsGetResponseTenantsApiV1ConnectorsSnykOssTenantsGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> TenantsApiV1ConnectorsSnykOssTenantsGetResponseTenantsApiV1ConnectorsSnykOssTenantsGet | None:
    """Tenants

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        TenantsApiV1ConnectorsSnykOssTenantsGetResponseTenantsApiV1ConnectorsSnykOssTenantsGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[TenantsApiV1ConnectorsSnykOssTenantsGetResponseTenantsApiV1ConnectorsSnykOssTenantsGet]:
    """Tenants

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[TenantsApiV1ConnectorsSnykOssTenantsGetResponseTenantsApiV1ConnectorsSnykOssTenantsGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> TenantsApiV1ConnectorsSnykOssTenantsGetResponseTenantsApiV1ConnectorsSnykOssTenantsGet | None:
    """Tenants

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        TenantsApiV1ConnectorsSnykOssTenantsGetResponseTenantsApiV1ConnectorsSnykOssTenantsGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
