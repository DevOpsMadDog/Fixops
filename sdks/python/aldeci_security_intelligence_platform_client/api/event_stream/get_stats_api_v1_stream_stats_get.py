from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_stats_api_v1_stream_stats_get_response_get_stats_api_v1_stream_stats_get import (
    GetStatsApiV1StreamStatsGetResponseGetStatsApiV1StreamStatsGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/stream/stats",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetStatsApiV1StreamStatsGetResponseGetStatsApiV1StreamStatsGet | None:
    if response.status_code == 200:
        response_200 = GetStatsApiV1StreamStatsGetResponseGetStatsApiV1StreamStatsGet.from_dict(response.json())

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[GetStatsApiV1StreamStatsGetResponseGetStatsApiV1StreamStatsGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetStatsApiV1StreamStatsGetResponseGetStatsApiV1StreamStatsGet]:
    """Event stream statistics

     Return per-channel statistics:
    - events_per_channel
    - subscribers_per_channel
    - history_size_per_channel
    - total_published / total_subscribers

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetStatsApiV1StreamStatsGetResponseGetStatsApiV1StreamStatsGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> GetStatsApiV1StreamStatsGetResponseGetStatsApiV1StreamStatsGet | None:
    """Event stream statistics

     Return per-channel statistics:
    - events_per_channel
    - subscribers_per_channel
    - history_size_per_channel
    - total_published / total_subscribers

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetStatsApiV1StreamStatsGetResponseGetStatsApiV1StreamStatsGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetStatsApiV1StreamStatsGetResponseGetStatsApiV1StreamStatsGet]:
    """Event stream statistics

     Return per-channel statistics:
    - events_per_channel
    - subscribers_per_channel
    - history_size_per_channel
    - total_published / total_subscribers

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetStatsApiV1StreamStatsGetResponseGetStatsApiV1StreamStatsGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> GetStatsApiV1StreamStatsGetResponseGetStatsApiV1StreamStatsGet | None:
    """Event stream statistics

     Return per-channel statistics:
    - events_per_channel
    - subscribers_per_channel
    - history_size_per_channel
    - total_published / total_subscribers

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetStatsApiV1StreamStatsGetResponseGetStatsApiV1StreamStatsGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
