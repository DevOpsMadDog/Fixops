from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_recent_cves_api_v1_threat_intel_cves_recent_get_response_200_item import (
    GetRecentCvesApiV1ThreatIntelCvesRecentGetResponse200Item,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    limit: int | Unset = 100,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/threat-intel/cves/recent",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[GetRecentCvesApiV1ThreatIntelCvesRecentGetResponse200Item] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = GetRecentCvesApiV1ThreatIntelCvesRecentGetResponse200Item.from_dict(
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
) -> Response[HTTPValidationError | list[GetRecentCvesApiV1ThreatIntelCvesRecentGetResponse200Item]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> Response[HTTPValidationError | list[GetRecentCvesApiV1ThreatIntelCvesRecentGetResponse200Item]]:
    """Get Recent Cves

     Return the most recently cached CVEs enriched with EPSS scores.

    CVEs are served from the local SQLite cache. Call ``/refresh`` to
    pull the latest data from NVD / EPSS / CISA KEV.

    Args:
        limit (int | Unset): Max CVEs to return Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetRecentCvesApiV1ThreatIntelCvesRecentGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> HTTPValidationError | list[GetRecentCvesApiV1ThreatIntelCvesRecentGetResponse200Item] | None:
    """Get Recent Cves

     Return the most recently cached CVEs enriched with EPSS scores.

    CVEs are served from the local SQLite cache. Call ``/refresh`` to
    pull the latest data from NVD / EPSS / CISA KEV.

    Args:
        limit (int | Unset): Max CVEs to return Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetRecentCvesApiV1ThreatIntelCvesRecentGetResponse200Item]
    """

    return sync_detailed(
        client=client,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> Response[HTTPValidationError | list[GetRecentCvesApiV1ThreatIntelCvesRecentGetResponse200Item]]:
    """Get Recent Cves

     Return the most recently cached CVEs enriched with EPSS scores.

    CVEs are served from the local SQLite cache. Call ``/refresh`` to
    pull the latest data from NVD / EPSS / CISA KEV.

    Args:
        limit (int | Unset): Max CVEs to return Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetRecentCvesApiV1ThreatIntelCvesRecentGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> HTTPValidationError | list[GetRecentCvesApiV1ThreatIntelCvesRecentGetResponse200Item] | None:
    """Get Recent Cves

     Return the most recently cached CVEs enriched with EPSS scores.

    CVEs are served from the local SQLite cache. Call ``/refresh`` to
    pull the latest data from NVD / EPSS / CISA KEV.

    Args:
        limit (int | Unset): Max CVEs to return Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetRecentCvesApiV1ThreatIntelCvesRecentGetResponse200Item]
    """

    return (
        await asyncio_detailed(
            client=client,
            limit=limit,
        )
    ).parsed
