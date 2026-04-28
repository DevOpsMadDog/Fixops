from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.health_check_api_v1_health_get_response_health_check_api_v1_health_get import (
    HealthCheckApiV1HealthGetResponseHealthCheckApiV1HealthGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/health",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HealthCheckApiV1HealthGetResponseHealthCheckApiV1HealthGet | None:
    if response.status_code == 200:
        response_200 = HealthCheckApiV1HealthGetResponseHealthCheckApiV1HealthGet.from_dict(response.json())

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[HealthCheckApiV1HealthGetResponseHealthCheckApiV1HealthGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[HealthCheckApiV1HealthGetResponseHealthCheckApiV1HealthGet]:
    """Health Check

     Liveness probe endpoint for Kubernetes.

    Returns 200 OK if the service is alive and can handle requests.
    This endpoint should be lightweight and always return quickly.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HealthCheckApiV1HealthGetResponseHealthCheckApiV1HealthGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
) -> HealthCheckApiV1HealthGetResponseHealthCheckApiV1HealthGet | None:
    """Health Check

     Liveness probe endpoint for Kubernetes.

    Returns 200 OK if the service is alive and can handle requests.
    This endpoint should be lightweight and always return quickly.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HealthCheckApiV1HealthGetResponseHealthCheckApiV1HealthGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[HealthCheckApiV1HealthGetResponseHealthCheckApiV1HealthGet]:
    """Health Check

     Liveness probe endpoint for Kubernetes.

    Returns 200 OK if the service is alive and can handle requests.
    This endpoint should be lightweight and always return quickly.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HealthCheckApiV1HealthGetResponseHealthCheckApiV1HealthGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
) -> HealthCheckApiV1HealthGetResponseHealthCheckApiV1HealthGet | None:
    """Health Check

     Liveness probe endpoint for Kubernetes.

    Returns 200 OK if the service is alive and can handle requests.
    This endpoint should be lightweight and always return quickly.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HealthCheckApiV1HealthGetResponseHealthCheckApiV1HealthGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
