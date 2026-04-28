from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.endpoint_health_api_v1_system_endpoint_health_get_response_endpoint_health_api_v1_system_endpoint_health_get import (
    EndpointHealthApiV1SystemEndpointHealthGetResponseEndpointHealthApiV1SystemEndpointHealthGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/system/endpoint-health",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> EndpointHealthApiV1SystemEndpointHealthGetResponseEndpointHealthApiV1SystemEndpointHealthGet | None:
    if response.status_code == 200:
        response_200 = (
            EndpointHealthApiV1SystemEndpointHealthGetResponseEndpointHealthApiV1SystemEndpointHealthGet.from_dict(
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
) -> Response[EndpointHealthApiV1SystemEndpointHealthGetResponseEndpointHealthApiV1SystemEndpointHealthGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[EndpointHealthApiV1SystemEndpointHealthGetResponseEndpointHealthApiV1SystemEndpointHealthGet]:
    """Top-50 endpoint health snapshot

     Return per-path health for the top 50 API prefixes.

    Derives status, avg_latency_ms, p95_latency_ms, error_rate, and
    request_count from the in-memory request log ring buffer.
    Returns static OK entries for prefixes with no recent traffic.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EndpointHealthApiV1SystemEndpointHealthGetResponseEndpointHealthApiV1SystemEndpointHealthGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> EndpointHealthApiV1SystemEndpointHealthGetResponseEndpointHealthApiV1SystemEndpointHealthGet | None:
    """Top-50 endpoint health snapshot

     Return per-path health for the top 50 API prefixes.

    Derives status, avg_latency_ms, p95_latency_ms, error_rate, and
    request_count from the in-memory request log ring buffer.
    Returns static OK entries for prefixes with no recent traffic.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EndpointHealthApiV1SystemEndpointHealthGetResponseEndpointHealthApiV1SystemEndpointHealthGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[EndpointHealthApiV1SystemEndpointHealthGetResponseEndpointHealthApiV1SystemEndpointHealthGet]:
    """Top-50 endpoint health snapshot

     Return per-path health for the top 50 API prefixes.

    Derives status, avg_latency_ms, p95_latency_ms, error_rate, and
    request_count from the in-memory request log ring buffer.
    Returns static OK entries for prefixes with no recent traffic.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EndpointHealthApiV1SystemEndpointHealthGetResponseEndpointHealthApiV1SystemEndpointHealthGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> EndpointHealthApiV1SystemEndpointHealthGetResponseEndpointHealthApiV1SystemEndpointHealthGet | None:
    """Top-50 endpoint health snapshot

     Return per-path health for the top 50 API prefixes.

    Derives status, avg_latency_ms, p95_latency_ms, error_rate, and
    request_count from the in-memory request log ring buffer.
    Returns static OK entries for prefixes with no recent traffic.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EndpointHealthApiV1SystemEndpointHealthGetResponseEndpointHealthApiV1SystemEndpointHealthGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
