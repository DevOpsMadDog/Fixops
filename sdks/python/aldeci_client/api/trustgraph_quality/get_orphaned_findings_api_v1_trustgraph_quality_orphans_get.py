from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_orphaned_findings_api_v1_trustgraph_quality_orphans_get_response_200_item import (
    GetOrphanedFindingsApiV1TrustgraphQualityOrphansGetResponse200Item,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    include_assets: bool | Unset = False,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["include_assets"] = include_assets

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/trustgraph/quality/orphans",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[GetOrphanedFindingsApiV1TrustgraphQualityOrphansGetResponse200Item] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = GetOrphanedFindingsApiV1TrustgraphQualityOrphansGetResponse200Item.from_dict(
                response_200_item_data
            )

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
) -> Response[HTTPValidationError | list[GetOrphanedFindingsApiV1TrustgraphQualityOrphansGetResponse200Item]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    include_assets: bool | Unset = False,
) -> Response[HTTPValidationError | list[GetOrphanedFindingsApiV1TrustgraphQualityOrphansGetResponse200Item]]:
    """Get Orphaned Findings

     Find security findings (Core 2) not connected to any other TrustGraph entity.

    Args:
        include_assets: If true, also returns disconnected assets from Core 1.

    Returns:
        List of orphaned entity dicts.

    Args:
        include_assets (bool | Unset): Also include disconnected assets from Core 1 Default:
            False.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetOrphanedFindingsApiV1TrustgraphQualityOrphansGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        include_assets=include_assets,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    include_assets: bool | Unset = False,
) -> HTTPValidationError | list[GetOrphanedFindingsApiV1TrustgraphQualityOrphansGetResponse200Item] | None:
    """Get Orphaned Findings

     Find security findings (Core 2) not connected to any other TrustGraph entity.

    Args:
        include_assets: If true, also returns disconnected assets from Core 1.

    Returns:
        List of orphaned entity dicts.

    Args:
        include_assets (bool | Unset): Also include disconnected assets from Core 1 Default:
            False.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetOrphanedFindingsApiV1TrustgraphQualityOrphansGetResponse200Item]
    """

    return sync_detailed(
        client=client,
        include_assets=include_assets,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    include_assets: bool | Unset = False,
) -> Response[HTTPValidationError | list[GetOrphanedFindingsApiV1TrustgraphQualityOrphansGetResponse200Item]]:
    """Get Orphaned Findings

     Find security findings (Core 2) not connected to any other TrustGraph entity.

    Args:
        include_assets: If true, also returns disconnected assets from Core 1.

    Returns:
        List of orphaned entity dicts.

    Args:
        include_assets (bool | Unset): Also include disconnected assets from Core 1 Default:
            False.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetOrphanedFindingsApiV1TrustgraphQualityOrphansGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        include_assets=include_assets,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    include_assets: bool | Unset = False,
) -> HTTPValidationError | list[GetOrphanedFindingsApiV1TrustgraphQualityOrphansGetResponse200Item] | None:
    """Get Orphaned Findings

     Find security findings (Core 2) not connected to any other TrustGraph entity.

    Args:
        include_assets: If true, also returns disconnected assets from Core 1.

    Returns:
        List of orphaned entity dicts.

    Args:
        include_assets (bool | Unset): Also include disconnected assets from Core 1 Default:
            False.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetOrphanedFindingsApiV1TrustgraphQualityOrphansGetResponse200Item]
    """

    return (
        await asyncio_detailed(
            client=client,
            include_assets=include_assets,
        )
    ).parsed
