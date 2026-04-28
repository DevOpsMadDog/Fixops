from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.deep_health_check_api_v1_health_deep_get_response_deep_health_check_api_v1_health_deep_get import (
    DeepHealthCheckApiV1HealthDeepGetResponseDeepHealthCheckApiV1HealthDeepGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/health/deep",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> DeepHealthCheckApiV1HealthDeepGetResponseDeepHealthCheckApiV1HealthDeepGet | None:
    if response.status_code == 200:
        response_200 = DeepHealthCheckApiV1HealthDeepGetResponseDeepHealthCheckApiV1HealthDeepGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[DeepHealthCheckApiV1HealthDeepGetResponseDeepHealthCheckApiV1HealthDeepGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[DeepHealthCheckApiV1HealthDeepGetResponseDeepHealthCheckApiV1HealthDeepGet]:
    """Deep Health Check

     Deep health check — verifies each subsystem individually.

    Checks:
      - database:        SQLite SELECT 1 on the primary audit DB
      - scanners:        importability of all 8 scanner engine modules
      - brain_pipeline:  importability of core.brain_pipeline.BrainPipeline
      - disk_space:      evidence storage directory free space (warn <1 GB)
      - memory:          process RSS via /proc/self/status or psutil

    Returns HTTP 200 when all critical checks pass, 503 when any critical
    check fails.  Scanner/memory checks are non-critical (degraded).

    No auth required — same as the liveness probe.  Do NOT put secrets in
    this response.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeepHealthCheckApiV1HealthDeepGetResponseDeepHealthCheckApiV1HealthDeepGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
) -> DeepHealthCheckApiV1HealthDeepGetResponseDeepHealthCheckApiV1HealthDeepGet | None:
    """Deep Health Check

     Deep health check — verifies each subsystem individually.

    Checks:
      - database:        SQLite SELECT 1 on the primary audit DB
      - scanners:        importability of all 8 scanner engine modules
      - brain_pipeline:  importability of core.brain_pipeline.BrainPipeline
      - disk_space:      evidence storage directory free space (warn <1 GB)
      - memory:          process RSS via /proc/self/status or psutil

    Returns HTTP 200 when all critical checks pass, 503 when any critical
    check fails.  Scanner/memory checks are non-critical (degraded).

    No auth required — same as the liveness probe.  Do NOT put secrets in
    this response.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeepHealthCheckApiV1HealthDeepGetResponseDeepHealthCheckApiV1HealthDeepGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[DeepHealthCheckApiV1HealthDeepGetResponseDeepHealthCheckApiV1HealthDeepGet]:
    """Deep Health Check

     Deep health check — verifies each subsystem individually.

    Checks:
      - database:        SQLite SELECT 1 on the primary audit DB
      - scanners:        importability of all 8 scanner engine modules
      - brain_pipeline:  importability of core.brain_pipeline.BrainPipeline
      - disk_space:      evidence storage directory free space (warn <1 GB)
      - memory:          process RSS via /proc/self/status or psutil

    Returns HTTP 200 when all critical checks pass, 503 when any critical
    check fails.  Scanner/memory checks are non-critical (degraded).

    No auth required — same as the liveness probe.  Do NOT put secrets in
    this response.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeepHealthCheckApiV1HealthDeepGetResponseDeepHealthCheckApiV1HealthDeepGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
) -> DeepHealthCheckApiV1HealthDeepGetResponseDeepHealthCheckApiV1HealthDeepGet | None:
    """Deep Health Check

     Deep health check — verifies each subsystem individually.

    Checks:
      - database:        SQLite SELECT 1 on the primary audit DB
      - scanners:        importability of all 8 scanner engine modules
      - brain_pipeline:  importability of core.brain_pipeline.BrainPipeline
      - disk_space:      evidence storage directory free space (warn <1 GB)
      - memory:          process RSS via /proc/self/status or psutil

    Returns HTTP 200 when all critical checks pass, 503 when any critical
    check fails.  Scanner/memory checks are non-critical (degraded).

    No auth required — same as the liveness probe.  Do NOT put secrets in
    this response.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeepHealthCheckApiV1HealthDeepGetResponseDeepHealthCheckApiV1HealthDeepGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
