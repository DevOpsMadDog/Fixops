from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.db_stats_api_v1_system_db_stats_get_response_db_stats_api_v1_system_db_stats_get import (
    DbStatsApiV1SystemDbStatsGetResponseDbStatsApiV1SystemDbStatsGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/system/db-stats",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> DbStatsApiV1SystemDbStatsGetResponseDbStatsApiV1SystemDbStatsGet | None:
    if response.status_code == 200:
        response_200 = DbStatsApiV1SystemDbStatsGetResponseDbStatsApiV1SystemDbStatsGet.from_dict(response.json())

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[DbStatsApiV1SystemDbStatsGetResponseDbStatsApiV1SystemDbStatsGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[DbStatsApiV1SystemDbStatsGetResponseDbStatsApiV1SystemDbStatsGet]:
    """Database health and size statistics

     Return health and size information for all SQLite databases.

    Useful for monitoring disk usage, detecting growth, and planning
    capacity (e.g. when to consider migrating to PostgreSQL).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DbStatsApiV1SystemDbStatsGetResponseDbStatsApiV1SystemDbStatsGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> DbStatsApiV1SystemDbStatsGetResponseDbStatsApiV1SystemDbStatsGet | None:
    """Database health and size statistics

     Return health and size information for all SQLite databases.

    Useful for monitoring disk usage, detecting growth, and planning
    capacity (e.g. when to consider migrating to PostgreSQL).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DbStatsApiV1SystemDbStatsGetResponseDbStatsApiV1SystemDbStatsGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[DbStatsApiV1SystemDbStatsGetResponseDbStatsApiV1SystemDbStatsGet]:
    """Database health and size statistics

     Return health and size information for all SQLite databases.

    Useful for monitoring disk usage, detecting growth, and planning
    capacity (e.g. when to consider migrating to PostgreSQL).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DbStatsApiV1SystemDbStatsGetResponseDbStatsApiV1SystemDbStatsGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> DbStatsApiV1SystemDbStatsGetResponseDbStatsApiV1SystemDbStatsGet | None:
    """Database health and size statistics

     Return health and size information for all SQLite databases.

    Useful for monitoring disk usage, detecting growth, and planning
    capacity (e.g. when to consider migrating to PostgreSQL).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DbStatsApiV1SystemDbStatsGetResponseDbStatsApiV1SystemDbStatsGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
