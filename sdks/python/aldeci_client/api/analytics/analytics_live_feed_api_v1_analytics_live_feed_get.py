from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.analytics_live_feed_api_v1_analytics_live_feed_get_response_analytics_live_feed_api_v1_analytics_live_feed_get import (
    AnalyticsLiveFeedApiV1AnalyticsLiveFeedGetResponseAnalyticsLiveFeedApiV1AnalyticsLiveFeedGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/analytics/live-feed",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AnalyticsLiveFeedApiV1AnalyticsLiveFeedGetResponseAnalyticsLiveFeedApiV1AnalyticsLiveFeedGet | None:
    if response.status_code == 200:
        response_200 = (
            AnalyticsLiveFeedApiV1AnalyticsLiveFeedGetResponseAnalyticsLiveFeedApiV1AnalyticsLiveFeedGet.from_dict(
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
) -> Response[AnalyticsLiveFeedApiV1AnalyticsLiveFeedGetResponseAnalyticsLiveFeedApiV1AnalyticsLiveFeedGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[AnalyticsLiveFeedApiV1AnalyticsLiveFeedGetResponseAnalyticsLiveFeedApiV1AnalyticsLiveFeedGet]:
    """Analytics Live Feed

     Live feed of recent findings/events.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AnalyticsLiveFeedApiV1AnalyticsLiveFeedGetResponseAnalyticsLiveFeedApiV1AnalyticsLiveFeedGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> AnalyticsLiveFeedApiV1AnalyticsLiveFeedGetResponseAnalyticsLiveFeedApiV1AnalyticsLiveFeedGet | None:
    """Analytics Live Feed

     Live feed of recent findings/events.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AnalyticsLiveFeedApiV1AnalyticsLiveFeedGetResponseAnalyticsLiveFeedApiV1AnalyticsLiveFeedGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[AnalyticsLiveFeedApiV1AnalyticsLiveFeedGetResponseAnalyticsLiveFeedApiV1AnalyticsLiveFeedGet]:
    """Analytics Live Feed

     Live feed of recent findings/events.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AnalyticsLiveFeedApiV1AnalyticsLiveFeedGetResponseAnalyticsLiveFeedApiV1AnalyticsLiveFeedGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> AnalyticsLiveFeedApiV1AnalyticsLiveFeedGetResponseAnalyticsLiveFeedApiV1AnalyticsLiveFeedGet | None:
    """Analytics Live Feed

     Live feed of recent findings/events.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AnalyticsLiveFeedApiV1AnalyticsLiveFeedGetResponseAnalyticsLiveFeedApiV1AnalyticsLiveFeedGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
