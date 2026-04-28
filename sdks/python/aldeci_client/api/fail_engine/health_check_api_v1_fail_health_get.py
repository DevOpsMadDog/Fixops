from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.health_check_api_v1_fail_health_get_response_health_check_api_v1_fail_health_get import (
    HealthCheckApiV1FailHealthGetResponseHealthCheckApiV1FailHealthGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/fail/health",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HealthCheckApiV1FailHealthGetResponseHealthCheckApiV1FailHealthGet | None:
    if response.status_code == 200:
        response_200 = HealthCheckApiV1FailHealthGetResponseHealthCheckApiV1FailHealthGet.from_dict(response.json())

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[HealthCheckApiV1FailHealthGetResponseHealthCheckApiV1FailHealthGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[HealthCheckApiV1FailHealthGetResponseHealthCheckApiV1FailHealthGet]:
    """FAIL Engine health check

     Health check for the FAIL Engine (suite-attack edition).

    Returns engine version, scenario count, and database path.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HealthCheckApiV1FailHealthGetResponseHealthCheckApiV1FailHealthGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> HealthCheckApiV1FailHealthGetResponseHealthCheckApiV1FailHealthGet | None:
    """FAIL Engine health check

     Health check for the FAIL Engine (suite-attack edition).

    Returns engine version, scenario count, and database path.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HealthCheckApiV1FailHealthGetResponseHealthCheckApiV1FailHealthGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[HealthCheckApiV1FailHealthGetResponseHealthCheckApiV1FailHealthGet]:
    """FAIL Engine health check

     Health check for the FAIL Engine (suite-attack edition).

    Returns engine version, scenario count, and database path.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HealthCheckApiV1FailHealthGetResponseHealthCheckApiV1FailHealthGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> HealthCheckApiV1FailHealthGetResponseHealthCheckApiV1FailHealthGet | None:
    """FAIL Engine health check

     Health check for the FAIL Engine (suite-attack edition).

    Returns engine version, scenario count, and database path.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HealthCheckApiV1FailHealthGetResponseHealthCheckApiV1FailHealthGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
