from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.database_health_check_api_v1_health_database_get_response_database_health_check_api_v1_health_database_get import (
    DatabaseHealthCheckApiV1HealthDatabaseGetResponseDatabaseHealthCheckApiV1HealthDatabaseGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/health/database",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> DatabaseHealthCheckApiV1HealthDatabaseGetResponseDatabaseHealthCheckApiV1HealthDatabaseGet | None:
    if response.status_code == 200:
        response_200 = (
            DatabaseHealthCheckApiV1HealthDatabaseGetResponseDatabaseHealthCheckApiV1HealthDatabaseGet.from_dict(
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
) -> Response[DatabaseHealthCheckApiV1HealthDatabaseGetResponseDatabaseHealthCheckApiV1HealthDatabaseGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[DatabaseHealthCheckApiV1HealthDatabaseGetResponseDatabaseHealthCheckApiV1HealthDatabaseGet]:
    """Database Health Check

     Enterprise database health check.

    Reports connectivity and pool/file stats for the configured backend:
      - PostgreSQL (production): SELECT 1 + pool stats (size, checked_in/out)
      - SQLite (local dev / air-gap): SELECT 1 + file size + journal_mode

    Returns HTTP 200 when healthy, HTTP 503 when the database is unreachable.
    Non-critical: a degraded database does NOT fail the liveness probe.

    No auth required (same as other health probes).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DatabaseHealthCheckApiV1HealthDatabaseGetResponseDatabaseHealthCheckApiV1HealthDatabaseGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
) -> DatabaseHealthCheckApiV1HealthDatabaseGetResponseDatabaseHealthCheckApiV1HealthDatabaseGet | None:
    """Database Health Check

     Enterprise database health check.

    Reports connectivity and pool/file stats for the configured backend:
      - PostgreSQL (production): SELECT 1 + pool stats (size, checked_in/out)
      - SQLite (local dev / air-gap): SELECT 1 + file size + journal_mode

    Returns HTTP 200 when healthy, HTTP 503 when the database is unreachable.
    Non-critical: a degraded database does NOT fail the liveness probe.

    No auth required (same as other health probes).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DatabaseHealthCheckApiV1HealthDatabaseGetResponseDatabaseHealthCheckApiV1HealthDatabaseGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[DatabaseHealthCheckApiV1HealthDatabaseGetResponseDatabaseHealthCheckApiV1HealthDatabaseGet]:
    """Database Health Check

     Enterprise database health check.

    Reports connectivity and pool/file stats for the configured backend:
      - PostgreSQL (production): SELECT 1 + pool stats (size, checked_in/out)
      - SQLite (local dev / air-gap): SELECT 1 + file size + journal_mode

    Returns HTTP 200 when healthy, HTTP 503 when the database is unreachable.
    Non-critical: a degraded database does NOT fail the liveness probe.

    No auth required (same as other health probes).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DatabaseHealthCheckApiV1HealthDatabaseGetResponseDatabaseHealthCheckApiV1HealthDatabaseGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
) -> DatabaseHealthCheckApiV1HealthDatabaseGetResponseDatabaseHealthCheckApiV1HealthDatabaseGet | None:
    """Database Health Check

     Enterprise database health check.

    Reports connectivity and pool/file stats for the configured backend:
      - PostgreSQL (production): SELECT 1 + pool stats (size, checked_in/out)
      - SQLite (local dev / air-gap): SELECT 1 + file size + journal_mode

    Returns HTTP 200 when healthy, HTTP 503 when the database is unreachable.
    Non-critical: a degraded database does NOT fail the liveness probe.

    No auth required (same as other health probes).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DatabaseHealthCheckApiV1HealthDatabaseGetResponseDatabaseHealthCheckApiV1HealthDatabaseGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
