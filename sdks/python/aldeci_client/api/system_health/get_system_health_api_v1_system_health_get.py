from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_system_health_api_v1_system_health_get_response_get_system_health_api_v1_system_health_get import (
    GetSystemHealthApiV1SystemHealthGetResponseGetSystemHealthApiV1SystemHealthGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/system/health",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetSystemHealthApiV1SystemHealthGetResponseGetSystemHealthApiV1SystemHealthGet | None:
    if response.status_code == 200:
        response_200 = GetSystemHealthApiV1SystemHealthGetResponseGetSystemHealthApiV1SystemHealthGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[GetSystemHealthApiV1SystemHealthGetResponseGetSystemHealthApiV1SystemHealthGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetSystemHealthApiV1SystemHealthGetResponseGetSystemHealthApiV1SystemHealthGet]:
    """Full system health report

     Return a full system health report aggregating all subsystems.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetSystemHealthApiV1SystemHealthGetResponseGetSystemHealthApiV1SystemHealthGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> GetSystemHealthApiV1SystemHealthGetResponseGetSystemHealthApiV1SystemHealthGet | None:
    """Full system health report

     Return a full system health report aggregating all subsystems.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetSystemHealthApiV1SystemHealthGetResponseGetSystemHealthApiV1SystemHealthGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetSystemHealthApiV1SystemHealthGetResponseGetSystemHealthApiV1SystemHealthGet]:
    """Full system health report

     Return a full system health report aggregating all subsystems.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetSystemHealthApiV1SystemHealthGetResponseGetSystemHealthApiV1SystemHealthGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> GetSystemHealthApiV1SystemHealthGetResponseGetSystemHealthApiV1SystemHealthGet | None:
    """Full system health report

     Return a full system health report aggregating all subsystems.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetSystemHealthApiV1SystemHealthGetResponseGetSystemHealthApiV1SystemHealthGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
