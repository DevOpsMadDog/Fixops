from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/metrics",
    }

    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Any | None:
    if response.status_code == 200:
        return None

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Any]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[Any]:
    """Prometheus Metrics

     Prometheus metrics endpoint.

    Exposes:
      - fixops_http_requests_total{method, endpoint, status_code}
      - fixops_http_request_duration_seconds{method, endpoint}
      - fixops_active_connections
      - fixops_pipeline_executions_total{status}
      - fixops_pipeline_duration_seconds
      - fixops_errors_total{error_type}

    Scrape with: ``prometheus.yml`` job ``scrape_configs[].static_configs.targets``
    pointing at ``host:8000``, path ``/metrics``.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[Any]:
    """Prometheus Metrics

     Prometheus metrics endpoint.

    Exposes:
      - fixops_http_requests_total{method, endpoint, status_code}
      - fixops_http_request_duration_seconds{method, endpoint}
      - fixops_active_connections
      - fixops_pipeline_executions_total{status}
      - fixops_pipeline_duration_seconds
      - fixops_errors_total{error_type}

    Scrape with: ``prometheus.yml`` job ``scrape_configs[].static_configs.targets``
    pointing at ``host:8000``, path ``/metrics``.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)
