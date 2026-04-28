from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.system_metrics_api_v1_system_metrics_get_response_system_metrics_api_v1_system_metrics_get import (
    SystemMetricsApiV1SystemMetricsGetResponseSystemMetricsApiV1SystemMetricsGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/system/metrics",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> SystemMetricsApiV1SystemMetricsGetResponseSystemMetricsApiV1SystemMetricsGet | None:
    if response.status_code == 200:
        response_200 = SystemMetricsApiV1SystemMetricsGetResponseSystemMetricsApiV1SystemMetricsGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[SystemMetricsApiV1SystemMetricsGetResponseSystemMetricsApiV1SystemMetricsGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[SystemMetricsApiV1SystemMetricsGetResponseSystemMetricsApiV1SystemMetricsGet]:
    """System metrics

     Return system performance metrics for the Platform Admin (Hasan) persona.

    Includes uptime, memory, CPU, request counts, and database stats.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[SystemMetricsApiV1SystemMetricsGetResponseSystemMetricsApiV1SystemMetricsGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> SystemMetricsApiV1SystemMetricsGetResponseSystemMetricsApiV1SystemMetricsGet | None:
    """System metrics

     Return system performance metrics for the Platform Admin (Hasan) persona.

    Includes uptime, memory, CPU, request counts, and database stats.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        SystemMetricsApiV1SystemMetricsGetResponseSystemMetricsApiV1SystemMetricsGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[SystemMetricsApiV1SystemMetricsGetResponseSystemMetricsApiV1SystemMetricsGet]:
    """System metrics

     Return system performance metrics for the Platform Admin (Hasan) persona.

    Includes uptime, memory, CPU, request counts, and database stats.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[SystemMetricsApiV1SystemMetricsGetResponseSystemMetricsApiV1SystemMetricsGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> SystemMetricsApiV1SystemMetricsGetResponseSystemMetricsApiV1SystemMetricsGet | None:
    """System metrics

     Return system performance metrics for the Platform Admin (Hasan) persona.

    Includes uptime, memory, CPU, request counts, and database stats.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        SystemMetricsApiV1SystemMetricsGetResponseSystemMetricsApiV1SystemMetricsGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
