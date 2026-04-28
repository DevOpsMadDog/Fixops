from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.baseline_stats import BaselineStats
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    metric_name: str,
    *,
    org_id: str | Unset = "default",
    window_days: int | Unset = 30,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params["window_days"] = window_days

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/anomalies/baseline/{metric_name}".format(
            metric_name=quote(str(metric_name), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> BaselineStats | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = BaselineStats.from_dict(response.json())

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
) -> Response[BaselineStats | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    metric_name: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    window_days: int | Unset = 30,
) -> Response[BaselineStats | HTTPValidationError]:
    """Statistical baseline for a metric

     Compute mean, std-dev, min, max over the lookback window for the metric.

    Returns 404 if there are fewer than 2 data points in the window.

    Args:
        metric_name (str):
        org_id (str | Unset): Organisation ID Default: 'default'.
        window_days (int | Unset): Lookback window in days Default: 30.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[BaselineStats | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        metric_name=metric_name,
        org_id=org_id,
        window_days=window_days,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    metric_name: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    window_days: int | Unset = 30,
) -> BaselineStats | HTTPValidationError | None:
    """Statistical baseline for a metric

     Compute mean, std-dev, min, max over the lookback window for the metric.

    Returns 404 if there are fewer than 2 data points in the window.

    Args:
        metric_name (str):
        org_id (str | Unset): Organisation ID Default: 'default'.
        window_days (int | Unset): Lookback window in days Default: 30.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        BaselineStats | HTTPValidationError
    """

    return sync_detailed(
        metric_name=metric_name,
        client=client,
        org_id=org_id,
        window_days=window_days,
    ).parsed


async def asyncio_detailed(
    metric_name: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    window_days: int | Unset = 30,
) -> Response[BaselineStats | HTTPValidationError]:
    """Statistical baseline for a metric

     Compute mean, std-dev, min, max over the lookback window for the metric.

    Returns 404 if there are fewer than 2 data points in the window.

    Args:
        metric_name (str):
        org_id (str | Unset): Organisation ID Default: 'default'.
        window_days (int | Unset): Lookback window in days Default: 30.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[BaselineStats | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        metric_name=metric_name,
        org_id=org_id,
        window_days=window_days,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    metric_name: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    window_days: int | Unset = 30,
) -> BaselineStats | HTTPValidationError | None:
    """Statistical baseline for a metric

     Compute mean, std-dev, min, max over the lookback window for the metric.

    Returns 404 if there are fewer than 2 data points in the window.

    Args:
        metric_name (str):
        org_id (str | Unset): Organisation ID Default: 'default'.
        window_days (int | Unset): Lookback window in days Default: 30.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        BaselineStats | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            metric_name=metric_name,
            client=client,
            org_id=org_id,
            window_days=window_days,
        )
    ).parsed
