from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.record_metric_request import RecordMetricRequest
from ...models.record_metric_response import RecordMetricResponse
from ...types import Response


def _get_kwargs(
    *,
    body: RecordMetricRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/anomalies/metrics",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | RecordMetricResponse | None:
    if response.status_code == 200:
        response_200 = RecordMetricResponse.from_dict(response.json())

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
) -> Response[HTTPValidationError | RecordMetricResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: RecordMetricRequest,
) -> Response[HTTPValidationError | RecordMetricResponse]:
    """Record a metric data point

     Store a time-series data point for the named metric.

    Returns the SQLite row ID of the inserted record.

    Args:
        body (RecordMetricRequest): Body for recording a metric data point.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RecordMetricResponse]
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
    body: RecordMetricRequest,
) -> HTTPValidationError | RecordMetricResponse | None:
    """Record a metric data point

     Store a time-series data point for the named metric.

    Returns the SQLite row ID of the inserted record.

    Args:
        body (RecordMetricRequest): Body for recording a metric data point.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RecordMetricResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: RecordMetricRequest,
) -> Response[HTTPValidationError | RecordMetricResponse]:
    """Record a metric data point

     Store a time-series data point for the named metric.

    Returns the SQLite row ID of the inserted record.

    Args:
        body (RecordMetricRequest): Body for recording a metric data point.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RecordMetricResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: RecordMetricRequest,
) -> HTTPValidationError | RecordMetricResponse | None:
    """Record a metric data point

     Store a time-series data point for the named metric.

    Returns the SQLite row ID of the inserted record.

    Args:
        body (RecordMetricRequest): Body for recording a metric data point.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RecordMetricResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
