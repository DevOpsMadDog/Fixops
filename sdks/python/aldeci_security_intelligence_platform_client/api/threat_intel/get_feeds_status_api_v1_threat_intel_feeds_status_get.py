from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_feeds_status_api_v1_threat_intel_feeds_status_get_response_get_feeds_status_api_v1_threat_intel_feeds_status_get import (
    GetFeedsStatusApiV1ThreatIntelFeedsStatusGetResponseGetFeedsStatusApiV1ThreatIntelFeedsStatusGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/threat-intel/feeds/status",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetFeedsStatusApiV1ThreatIntelFeedsStatusGetResponseGetFeedsStatusApiV1ThreatIntelFeedsStatusGet | None:
    if response.status_code == 200:
        response_200 = (
            GetFeedsStatusApiV1ThreatIntelFeedsStatusGetResponseGetFeedsStatusApiV1ThreatIntelFeedsStatusGet.from_dict(
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
) -> Response[GetFeedsStatusApiV1ThreatIntelFeedsStatusGetResponseGetFeedsStatusApiV1ThreatIntelFeedsStatusGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetFeedsStatusApiV1ThreatIntelFeedsStatusGetResponseGetFeedsStatusApiV1ThreatIntelFeedsStatusGet]:
    """Get Feeds Status

     Return status of all configured threat intelligence feeds.

    Reports: name, last_updated, ioc_count, health status.
    Feeds without API keys report health=no_api_key.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetFeedsStatusApiV1ThreatIntelFeedsStatusGetResponseGetFeedsStatusApiV1ThreatIntelFeedsStatusGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> GetFeedsStatusApiV1ThreatIntelFeedsStatusGetResponseGetFeedsStatusApiV1ThreatIntelFeedsStatusGet | None:
    """Get Feeds Status

     Return status of all configured threat intelligence feeds.

    Reports: name, last_updated, ioc_count, health status.
    Feeds without API keys report health=no_api_key.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetFeedsStatusApiV1ThreatIntelFeedsStatusGetResponseGetFeedsStatusApiV1ThreatIntelFeedsStatusGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetFeedsStatusApiV1ThreatIntelFeedsStatusGetResponseGetFeedsStatusApiV1ThreatIntelFeedsStatusGet]:
    """Get Feeds Status

     Return status of all configured threat intelligence feeds.

    Reports: name, last_updated, ioc_count, health status.
    Feeds without API keys report health=no_api_key.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetFeedsStatusApiV1ThreatIntelFeedsStatusGetResponseGetFeedsStatusApiV1ThreatIntelFeedsStatusGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> GetFeedsStatusApiV1ThreatIntelFeedsStatusGetResponseGetFeedsStatusApiV1ThreatIntelFeedsStatusGet | None:
    """Get Feeds Status

     Return status of all configured threat intelligence feeds.

    Reports: name, last_updated, ioc_count, health status.
    Feeds without API keys report health=no_api_key.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetFeedsStatusApiV1ThreatIntelFeedsStatusGetResponseGetFeedsStatusApiV1ThreatIntelFeedsStatusGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
