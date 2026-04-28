from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.time_series_request import TimeSeriesRequest
from ...models.time_series_response import TimeSeriesResponse
from ...types import Response


def _get_kwargs(
    *,
    body: TimeSeriesRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/anomaly-ml/detect/timeseries",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | TimeSeriesResponse | None:
    if response.status_code == 200:
        response_200 = TimeSeriesResponse.from_dict(response.json())

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
) -> Response[HTTPValidationError | TimeSeriesResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: TimeSeriesRequest,
) -> Response[HTTPValidationError | TimeSeriesResponse]:
    """Time-series anomaly detection (spike/drop/trend/seasonality)

     Analyse time-series data for a metric, detecting:
    - SPIKE: sudden increase > 3x baseline mean
    - DROP: sudden decrease to < 0.2x baseline mean
    - TREND_UP/DOWN: sustained directional change > 20% over recent window
    - SEASONALITY_VIOLATION: z-score > 4.0 vs historical distribution

    Args:
        body (TimeSeriesRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TimeSeriesResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: TimeSeriesRequest,
) -> HTTPValidationError | TimeSeriesResponse | None:
    """Time-series anomaly detection (spike/drop/trend/seasonality)

     Analyse time-series data for a metric, detecting:
    - SPIKE: sudden increase > 3x baseline mean
    - DROP: sudden decrease to < 0.2x baseline mean
    - TREND_UP/DOWN: sustained directional change > 20% over recent window
    - SEASONALITY_VIOLATION: z-score > 4.0 vs historical distribution

    Args:
        body (TimeSeriesRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TimeSeriesResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: TimeSeriesRequest,
) -> Response[HTTPValidationError | TimeSeriesResponse]:
    """Time-series anomaly detection (spike/drop/trend/seasonality)

     Analyse time-series data for a metric, detecting:
    - SPIKE: sudden increase > 3x baseline mean
    - DROP: sudden decrease to < 0.2x baseline mean
    - TREND_UP/DOWN: sustained directional change > 20% over recent window
    - SEASONALITY_VIOLATION: z-score > 4.0 vs historical distribution

    Args:
        body (TimeSeriesRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TimeSeriesResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: TimeSeriesRequest,
) -> HTTPValidationError | TimeSeriesResponse | None:
    """Time-series anomaly detection (spike/drop/trend/seasonality)

     Analyse time-series data for a metric, detecting:
    - SPIKE: sudden increase > 3x baseline mean
    - DROP: sudden decrease to < 0.2x baseline mean
    - TREND_UP/DOWN: sustained directional change > 20% over recent window
    - SEASONALITY_VIOLATION: z-score > 4.0 vs historical distribution

    Args:
        body (TimeSeriesRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TimeSeriesResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
