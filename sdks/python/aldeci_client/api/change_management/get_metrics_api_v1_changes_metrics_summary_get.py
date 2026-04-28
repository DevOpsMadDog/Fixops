from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_metrics_api_v1_changes_metrics_summary_get_response_get_metrics_api_v1_changes_metrics_summary_get import (
    GetMetricsApiV1ChangesMetricsSummaryGetResponseGetMetricsApiV1ChangesMetricsSummaryGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    period_days: int | Unset = 30,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["period_days"] = period_days

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/changes/metrics/summary",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetMetricsApiV1ChangesMetricsSummaryGetResponseGetMetricsApiV1ChangesMetricsSummaryGet | HTTPValidationError | None
):
    if response.status_code == 200:
        response_200 = GetMetricsApiV1ChangesMetricsSummaryGetResponseGetMetricsApiV1ChangesMetricsSummaryGet.from_dict(
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
) -> Response[
    GetMetricsApiV1ChangesMetricsSummaryGetResponseGetMetricsApiV1ChangesMetricsSummaryGet | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    period_days: int | Unset = 30,
) -> Response[
    GetMetricsApiV1ChangesMetricsSummaryGetResponseGetMetricsApiV1ChangesMetricsSummaryGet | HTTPValidationError
]:
    """Get Metrics

     Get change management metrics for the specified period.

    Args:
        period_days (int | Unset):  Default: 30.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetMetricsApiV1ChangesMetricsSummaryGetResponseGetMetricsApiV1ChangesMetricsSummaryGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        period_days=period_days,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    period_days: int | Unset = 30,
) -> (
    GetMetricsApiV1ChangesMetricsSummaryGetResponseGetMetricsApiV1ChangesMetricsSummaryGet | HTTPValidationError | None
):
    """Get Metrics

     Get change management metrics for the specified period.

    Args:
        period_days (int | Unset):  Default: 30.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetMetricsApiV1ChangesMetricsSummaryGetResponseGetMetricsApiV1ChangesMetricsSummaryGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        period_days=period_days,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    period_days: int | Unset = 30,
) -> Response[
    GetMetricsApiV1ChangesMetricsSummaryGetResponseGetMetricsApiV1ChangesMetricsSummaryGet | HTTPValidationError
]:
    """Get Metrics

     Get change management metrics for the specified period.

    Args:
        period_days (int | Unset):  Default: 30.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetMetricsApiV1ChangesMetricsSummaryGetResponseGetMetricsApiV1ChangesMetricsSummaryGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        period_days=period_days,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    period_days: int | Unset = 30,
) -> (
    GetMetricsApiV1ChangesMetricsSummaryGetResponseGetMetricsApiV1ChangesMetricsSummaryGet | HTTPValidationError | None
):
    """Get Metrics

     Get change management metrics for the specified period.

    Args:
        period_days (int | Unset):  Default: 30.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetMetricsApiV1ChangesMetricsSummaryGetResponseGetMetricsApiV1ChangesMetricsSummaryGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            period_days=period_days,
        )
    ).parsed
