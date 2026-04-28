from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.network_topology_api_v1_network_topology_get_response_network_topology_api_v1_network_topology_get import (
    NetworkTopologyApiV1NetworkTopologyGetResponseNetworkTopologyApiV1NetworkTopologyGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str | Unset = "default",
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/network/topology",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | NetworkTopologyApiV1NetworkTopologyGetResponseNetworkTopologyApiV1NetworkTopologyGet | None:
    if response.status_code == 200:
        response_200 = NetworkTopologyApiV1NetworkTopologyGetResponseNetworkTopologyApiV1NetworkTopologyGet.from_dict(
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
    HTTPValidationError | NetworkTopologyApiV1NetworkTopologyGetResponseNetworkTopologyApiV1NetworkTopologyGet
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
    org_id: str | Unset = "default",
) -> Response[
    HTTPValidationError | NetworkTopologyApiV1NetworkTopologyGetResponseNetworkTopologyApiV1NetworkTopologyGet
]:
    """Network topology map

     Build and return a topology map from registered assets.

    Returns assets grouped by VLAN or asset type, with total asset count.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | NetworkTopologyApiV1NetworkTopologyGetResponseNetworkTopologyApiV1NetworkTopologyGet]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> HTTPValidationError | NetworkTopologyApiV1NetworkTopologyGetResponseNetworkTopologyApiV1NetworkTopologyGet | None:
    """Network topology map

     Build and return a topology map from registered assets.

    Returns assets grouped by VLAN or asset type, with total asset count.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | NetworkTopologyApiV1NetworkTopologyGetResponseNetworkTopologyApiV1NetworkTopologyGet
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> Response[
    HTTPValidationError | NetworkTopologyApiV1NetworkTopologyGetResponseNetworkTopologyApiV1NetworkTopologyGet
]:
    """Network topology map

     Build and return a topology map from registered assets.

    Returns assets grouped by VLAN or asset type, with total asset count.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | NetworkTopologyApiV1NetworkTopologyGetResponseNetworkTopologyApiV1NetworkTopologyGet]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> HTTPValidationError | NetworkTopologyApiV1NetworkTopologyGetResponseNetworkTopologyApiV1NetworkTopologyGet | None:
    """Network topology map

     Build and return a topology map from registered assets.

    Returns assets grouped by VLAN or asset type, with total asset count.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | NetworkTopologyApiV1NetworkTopologyGetResponseNetworkTopologyApiV1NetworkTopologyGet
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
        )
    ).parsed
