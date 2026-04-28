from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_analytics_api_v1_gateway_analytics_get_response_get_analytics_api_v1_gateway_analytics_get import (
    GetAnalyticsApiV1GatewayAnalyticsGetResponseGetAnalyticsApiV1GatewayAnalyticsGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    hours: int | Unset = 24,
    limit: int | Unset = 10,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["hours"] = hours

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/gateway/analytics",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetAnalyticsApiV1GatewayAnalyticsGetResponseGetAnalyticsApiV1GatewayAnalyticsGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GetAnalyticsApiV1GatewayAnalyticsGetResponseGetAnalyticsApiV1GatewayAnalyticsGet.from_dict(
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
) -> Response[GetAnalyticsApiV1GatewayAnalyticsGetResponseGetAnalyticsApiV1GatewayAnalyticsGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    hours: int | Unset = 24,
    limit: int | Unset = 10,
) -> Response[GetAnalyticsApiV1GatewayAnalyticsGetResponseGetAnalyticsApiV1GatewayAnalyticsGet | HTTPValidationError]:
    """Get Analytics

     Return API usage analytics summary:
    - Per-endpoint stats (calls, error rate, latency percentiles)
    - Top consumers by API key
    - Error rate summary
    - Overall latency percentiles

    Args:
        hours (int | Unset): Lookback window in hours Default: 24.
        limit (int | Unset): Max results for top consumers Default: 10.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetAnalyticsApiV1GatewayAnalyticsGetResponseGetAnalyticsApiV1GatewayAnalyticsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        hours=hours,
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    hours: int | Unset = 24,
    limit: int | Unset = 10,
) -> GetAnalyticsApiV1GatewayAnalyticsGetResponseGetAnalyticsApiV1GatewayAnalyticsGet | HTTPValidationError | None:
    """Get Analytics

     Return API usage analytics summary:
    - Per-endpoint stats (calls, error rate, latency percentiles)
    - Top consumers by API key
    - Error rate summary
    - Overall latency percentiles

    Args:
        hours (int | Unset): Lookback window in hours Default: 24.
        limit (int | Unset): Max results for top consumers Default: 10.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetAnalyticsApiV1GatewayAnalyticsGetResponseGetAnalyticsApiV1GatewayAnalyticsGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        hours=hours,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    hours: int | Unset = 24,
    limit: int | Unset = 10,
) -> Response[GetAnalyticsApiV1GatewayAnalyticsGetResponseGetAnalyticsApiV1GatewayAnalyticsGet | HTTPValidationError]:
    """Get Analytics

     Return API usage analytics summary:
    - Per-endpoint stats (calls, error rate, latency percentiles)
    - Top consumers by API key
    - Error rate summary
    - Overall latency percentiles

    Args:
        hours (int | Unset): Lookback window in hours Default: 24.
        limit (int | Unset): Max results for top consumers Default: 10.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetAnalyticsApiV1GatewayAnalyticsGetResponseGetAnalyticsApiV1GatewayAnalyticsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        hours=hours,
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    hours: int | Unset = 24,
    limit: int | Unset = 10,
) -> GetAnalyticsApiV1GatewayAnalyticsGetResponseGetAnalyticsApiV1GatewayAnalyticsGet | HTTPValidationError | None:
    """Get Analytics

     Return API usage analytics summary:
    - Per-endpoint stats (calls, error rate, latency percentiles)
    - Top consumers by API key
    - Error rate summary
    - Overall latency percentiles

    Args:
        hours (int | Unset): Lookback window in hours Default: 24.
        limit (int | Unset): Max results for top consumers Default: 10.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetAnalyticsApiV1GatewayAnalyticsGetResponseGetAnalyticsApiV1GatewayAnalyticsGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            hours=hours,
            limit=limit,
        )
    ).parsed
