from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_trends_api_v1_metrics_trends_get_response_200_item import (
    GetTrendsApiV1MetricsTrendsGetResponse200Item,
)
from ...models.http_validation_error import HTTPValidationError
from ...models.trend_period import TrendPeriod
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    period: TrendPeriod | Unset = UNSET,
    periods: int | Unset = 12,
    until: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_period: str | Unset = UNSET
    if not isinstance(period, Unset):
        json_period = period.value

    params["period"] = json_period

    params["periods"] = periods

    json_until: None | str | Unset
    if isinstance(until, Unset):
        json_until = UNSET
    else:
        json_until = until
    params["until"] = json_until

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/metrics/trends",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[GetTrendsApiV1MetricsTrendsGetResponse200Item] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = GetTrendsApiV1MetricsTrendsGetResponse200Item.from_dict(response_200_item_data)

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
) -> Response[HTTPValidationError | list[GetTrendsApiV1MetricsTrendsGetResponse200Item]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    period: TrendPeriod | Unset = UNSET,
    periods: int | Unset = 12,
    until: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[GetTrendsApiV1MetricsTrendsGetResponse200Item]]:
    """Time-series trend data

     Generate time-series data for vulnerability backlog, risk score, compliance percentage, and incident
    count. Supports weekly, monthly, and quarterly rollups.

    Args:
        period (TrendPeriod | Unset):
        periods (int | Unset): Number of periods to return Default: 12.
        until (None | str | Unset): End of last bucket (ISO 8601)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetTrendsApiV1MetricsTrendsGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        period=period,
        periods=periods,
        until=until,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    period: TrendPeriod | Unset = UNSET,
    periods: int | Unset = 12,
    until: None | str | Unset = UNSET,
) -> HTTPValidationError | list[GetTrendsApiV1MetricsTrendsGetResponse200Item] | None:
    """Time-series trend data

     Generate time-series data for vulnerability backlog, risk score, compliance percentage, and incident
    count. Supports weekly, monthly, and quarterly rollups.

    Args:
        period (TrendPeriod | Unset):
        periods (int | Unset): Number of periods to return Default: 12.
        until (None | str | Unset): End of last bucket (ISO 8601)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetTrendsApiV1MetricsTrendsGetResponse200Item]
    """

    return sync_detailed(
        client=client,
        period=period,
        periods=periods,
        until=until,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    period: TrendPeriod | Unset = UNSET,
    periods: int | Unset = 12,
    until: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[GetTrendsApiV1MetricsTrendsGetResponse200Item]]:
    """Time-series trend data

     Generate time-series data for vulnerability backlog, risk score, compliance percentage, and incident
    count. Supports weekly, monthly, and quarterly rollups.

    Args:
        period (TrendPeriod | Unset):
        periods (int | Unset): Number of periods to return Default: 12.
        until (None | str | Unset): End of last bucket (ISO 8601)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetTrendsApiV1MetricsTrendsGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        period=period,
        periods=periods,
        until=until,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    period: TrendPeriod | Unset = UNSET,
    periods: int | Unset = 12,
    until: None | str | Unset = UNSET,
) -> HTTPValidationError | list[GetTrendsApiV1MetricsTrendsGetResponse200Item] | None:
    """Time-series trend data

     Generate time-series data for vulnerability backlog, risk score, compliance percentage, and incident
    count. Supports weekly, monthly, and quarterly rollups.

    Args:
        period (TrendPeriod | Unset):
        periods (int | Unset): Number of periods to return Default: 12.
        until (None | str | Unset): End of last bucket (ISO 8601)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetTrendsApiV1MetricsTrendsGetResponse200Item]
    """

    return (
        await asyncio_detailed(
            client=client,
            period=period,
            periods=periods,
            until=until,
        )
    ).parsed
