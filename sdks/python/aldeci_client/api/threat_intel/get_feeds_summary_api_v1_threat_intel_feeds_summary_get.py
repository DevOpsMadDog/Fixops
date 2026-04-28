from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_feeds_summary_api_v1_threat_intel_feeds_summary_get_response_get_feeds_summary_api_v1_threat_intel_feeds_summary_get import (
    GetFeedsSummaryApiV1ThreatIntelFeedsSummaryGetResponseGetFeedsSummaryApiV1ThreatIntelFeedsSummaryGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/threat-intel/feeds/summary",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetFeedsSummaryApiV1ThreatIntelFeedsSummaryGetResponseGetFeedsSummaryApiV1ThreatIntelFeedsSummaryGet | None:
    if response.status_code == 200:
        response_200 = GetFeedsSummaryApiV1ThreatIntelFeedsSummaryGetResponseGetFeedsSummaryApiV1ThreatIntelFeedsSummaryGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[GetFeedsSummaryApiV1ThreatIntelFeedsSummaryGetResponseGetFeedsSummaryApiV1ThreatIntelFeedsSummaryGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetFeedsSummaryApiV1ThreatIntelFeedsSummaryGetResponseGetFeedsSummaryApiV1ThreatIntelFeedsSummaryGet]:
    """Get Feeds Summary

     Aggregated stats: total IOCs, counts by type and source.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetFeedsSummaryApiV1ThreatIntelFeedsSummaryGetResponseGetFeedsSummaryApiV1ThreatIntelFeedsSummaryGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> GetFeedsSummaryApiV1ThreatIntelFeedsSummaryGetResponseGetFeedsSummaryApiV1ThreatIntelFeedsSummaryGet | None:
    """Get Feeds Summary

     Aggregated stats: total IOCs, counts by type and source.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetFeedsSummaryApiV1ThreatIntelFeedsSummaryGetResponseGetFeedsSummaryApiV1ThreatIntelFeedsSummaryGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetFeedsSummaryApiV1ThreatIntelFeedsSummaryGetResponseGetFeedsSummaryApiV1ThreatIntelFeedsSummaryGet]:
    """Get Feeds Summary

     Aggregated stats: total IOCs, counts by type and source.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetFeedsSummaryApiV1ThreatIntelFeedsSummaryGetResponseGetFeedsSummaryApiV1ThreatIntelFeedsSummaryGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> GetFeedsSummaryApiV1ThreatIntelFeedsSummaryGetResponseGetFeedsSummaryApiV1ThreatIntelFeedsSummaryGet | None:
    """Get Feeds Summary

     Aggregated stats: total IOCs, counts by type and source.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetFeedsSummaryApiV1ThreatIntelFeedsSummaryGetResponseGetFeedsSummaryApiV1ThreatIntelFeedsSummaryGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
