from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.metrics_endpoint_api_v1_metrics_get_response_metrics_endpoint_api_v1_metrics_get import (
    MetricsEndpointApiV1MetricsGetResponseMetricsEndpointApiV1MetricsGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/metrics",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> MetricsEndpointApiV1MetricsGetResponseMetricsEndpointApiV1MetricsGet | None:
    if response.status_code == 200:
        response_200 = MetricsEndpointApiV1MetricsGetResponseMetricsEndpointApiV1MetricsGet.from_dict(response.json())

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[MetricsEndpointApiV1MetricsGetResponseMetricsEndpointApiV1MetricsGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[MetricsEndpointApiV1MetricsGetResponseMetricsEndpointApiV1MetricsGet]:
    """Metrics Endpoint

     Return basic metrics in JSON format.

    For Prometheus metrics, use the /metrics endpoint exposed by OpenTelemetry.
    This endpoint provides application-level metrics in JSON format.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[MetricsEndpointApiV1MetricsGetResponseMetricsEndpointApiV1MetricsGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
) -> MetricsEndpointApiV1MetricsGetResponseMetricsEndpointApiV1MetricsGet | None:
    """Metrics Endpoint

     Return basic metrics in JSON format.

    For Prometheus metrics, use the /metrics endpoint exposed by OpenTelemetry.
    This endpoint provides application-level metrics in JSON format.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        MetricsEndpointApiV1MetricsGetResponseMetricsEndpointApiV1MetricsGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[MetricsEndpointApiV1MetricsGetResponseMetricsEndpointApiV1MetricsGet]:
    """Metrics Endpoint

     Return basic metrics in JSON format.

    For Prometheus metrics, use the /metrics endpoint exposed by OpenTelemetry.
    This endpoint provides application-level metrics in JSON format.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[MetricsEndpointApiV1MetricsGetResponseMetricsEndpointApiV1MetricsGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
) -> MetricsEndpointApiV1MetricsGetResponseMetricsEndpointApiV1MetricsGet | None:
    """Metrics Endpoint

     Return basic metrics in JSON format.

    For Prometheus metrics, use the /metrics endpoint exposed by OpenTelemetry.
    This endpoint provides application-level metrics in JSON format.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        MetricsEndpointApiV1MetricsGetResponseMetricsEndpointApiV1MetricsGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
