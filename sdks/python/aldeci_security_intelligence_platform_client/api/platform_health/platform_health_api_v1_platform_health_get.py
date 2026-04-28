from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.platform_health_api_v1_platform_health_get_response_platform_health_api_v1_platform_health_get import (
    PlatformHealthApiV1PlatformHealthGetResponsePlatformHealthApiV1PlatformHealthGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/platform/health",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> PlatformHealthApiV1PlatformHealthGetResponsePlatformHealthApiV1PlatformHealthGet | None:
    if response.status_code == 200:
        response_200 = PlatformHealthApiV1PlatformHealthGetResponsePlatformHealthApiV1PlatformHealthGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[PlatformHealthApiV1PlatformHealthGetResponsePlatformHealthApiV1PlatformHealthGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[PlatformHealthApiV1PlatformHealthGetResponsePlatformHealthApiV1PlatformHealthGet]:
    """Platform health dashboard — comprehensive at-a-glance snapshot

     Return a single comprehensive platform health snapshot.

    Aggregates:
    - Engine health (total / healthy / degraded)
    - Router coverage (total / mounted)
    - Frontend page wiring (pages / wired to API)
    - Test suite totals and Beast Mode passing count
    - Live data counts (brain nodes, alerts, vulns, assets, compliance frameworks)
    - Feed status (active / configured)
    - TrustGraph wiring stats
    - Intelligence mesh status

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PlatformHealthApiV1PlatformHealthGetResponsePlatformHealthApiV1PlatformHealthGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> PlatformHealthApiV1PlatformHealthGetResponsePlatformHealthApiV1PlatformHealthGet | None:
    """Platform health dashboard — comprehensive at-a-glance snapshot

     Return a single comprehensive platform health snapshot.

    Aggregates:
    - Engine health (total / healthy / degraded)
    - Router coverage (total / mounted)
    - Frontend page wiring (pages / wired to API)
    - Test suite totals and Beast Mode passing count
    - Live data counts (brain nodes, alerts, vulns, assets, compliance frameworks)
    - Feed status (active / configured)
    - TrustGraph wiring stats
    - Intelligence mesh status

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PlatformHealthApiV1PlatformHealthGetResponsePlatformHealthApiV1PlatformHealthGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[PlatformHealthApiV1PlatformHealthGetResponsePlatformHealthApiV1PlatformHealthGet]:
    """Platform health dashboard — comprehensive at-a-glance snapshot

     Return a single comprehensive platform health snapshot.

    Aggregates:
    - Engine health (total / healthy / degraded)
    - Router coverage (total / mounted)
    - Frontend page wiring (pages / wired to API)
    - Test suite totals and Beast Mode passing count
    - Live data counts (brain nodes, alerts, vulns, assets, compliance frameworks)
    - Feed status (active / configured)
    - TrustGraph wiring stats
    - Intelligence mesh status

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PlatformHealthApiV1PlatformHealthGetResponsePlatformHealthApiV1PlatformHealthGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> PlatformHealthApiV1PlatformHealthGetResponsePlatformHealthApiV1PlatformHealthGet | None:
    """Platform health dashboard — comprehensive at-a-glance snapshot

     Return a single comprehensive platform health snapshot.

    Aggregates:
    - Engine health (total / healthy / degraded)
    - Router coverage (total / mounted)
    - Frontend page wiring (pages / wired to API)
    - Test suite totals and Beast Mode passing count
    - Live data counts (brain nodes, alerts, vulns, assets, compliance frameworks)
    - Feed status (active / configured)
    - TrustGraph wiring stats
    - Intelligence mesh status

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PlatformHealthApiV1PlatformHealthGetResponsePlatformHealthApiV1PlatformHealthGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
