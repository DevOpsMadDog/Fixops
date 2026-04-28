from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.tenants_api_v1_connectors_container_security_tenants_get_response_tenants_api_v1_connectors_container_security_tenants_get import (
    TenantsApiV1ConnectorsContainerSecurityTenantsGetResponseTenantsApiV1ConnectorsContainerSecurityTenantsGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    tenants_root: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_tenants_root: None | str | Unset
    if isinstance(tenants_root, Unset):
        json_tenants_root = UNSET
    else:
        json_tenants_root = tenants_root
    params["tenants_root"] = json_tenants_root

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/connectors/container-security/tenants",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | TenantsApiV1ConnectorsContainerSecurityTenantsGetResponseTenantsApiV1ConnectorsContainerSecurityTenantsGet
    | None
):
    if response.status_code == 200:
        response_200 = TenantsApiV1ConnectorsContainerSecurityTenantsGetResponseTenantsApiV1ConnectorsContainerSecurityTenantsGet.from_dict(
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
    | TenantsApiV1ConnectorsContainerSecurityTenantsGetResponseTenantsApiV1ConnectorsContainerSecurityTenantsGet
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
    tenants_root: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | TenantsApiV1ConnectorsContainerSecurityTenantsGetResponseTenantsApiV1ConnectorsContainerSecurityTenantsGet
]:
    """Tenants

    Args:
        tenants_root (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TenantsApiV1ConnectorsContainerSecurityTenantsGetResponseTenantsApiV1ConnectorsContainerSecurityTenantsGet]
    """

    kwargs = _get_kwargs(
        tenants_root=tenants_root,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    tenants_root: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | TenantsApiV1ConnectorsContainerSecurityTenantsGetResponseTenantsApiV1ConnectorsContainerSecurityTenantsGet
    | None
):
    """Tenants

    Args:
        tenants_root (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TenantsApiV1ConnectorsContainerSecurityTenantsGetResponseTenantsApiV1ConnectorsContainerSecurityTenantsGet
    """

    return sync_detailed(
        client=client,
        tenants_root=tenants_root,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    tenants_root: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | TenantsApiV1ConnectorsContainerSecurityTenantsGetResponseTenantsApiV1ConnectorsContainerSecurityTenantsGet
]:
    """Tenants

    Args:
        tenants_root (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TenantsApiV1ConnectorsContainerSecurityTenantsGetResponseTenantsApiV1ConnectorsContainerSecurityTenantsGet]
    """

    kwargs = _get_kwargs(
        tenants_root=tenants_root,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    tenants_root: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | TenantsApiV1ConnectorsContainerSecurityTenantsGetResponseTenantsApiV1ConnectorsContainerSecurityTenantsGet
    | None
):
    """Tenants

    Args:
        tenants_root (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TenantsApiV1ConnectorsContainerSecurityTenantsGetResponseTenantsApiV1ConnectorsContainerSecurityTenantsGet
    """

    return (
        await asyncio_detailed(
            client=client,
            tenants_root=tenants_root,
        )
    ).parsed
