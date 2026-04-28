from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_version_stats_api_v1_gateway_version_stats_get_response_get_version_stats_api_v1_gateway_version_stats_get import (
    GetVersionStatsApiV1GatewayVersionStatsGetResponseGetVersionStatsApiV1GatewayVersionStatsGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/gateway/version-stats",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetVersionStatsApiV1GatewayVersionStatsGetResponseGetVersionStatsApiV1GatewayVersionStatsGet | None:
    if response.status_code == 200:
        response_200 = (
            GetVersionStatsApiV1GatewayVersionStatsGetResponseGetVersionStatsApiV1GatewayVersionStatsGet.from_dict(
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
) -> Response[GetVersionStatsApiV1GatewayVersionStatsGetResponseGetVersionStatsApiV1GatewayVersionStatsGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetVersionStatsApiV1GatewayVersionStatsGetResponseGetVersionStatsApiV1GatewayVersionStatsGet]:
    """Get Version Stats

     Return API version usage statistics and deprecation alerts.

    Shows which clients are still using deprecated API versions
    and the distribution of usage across all supported versions.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetVersionStatsApiV1GatewayVersionStatsGetResponseGetVersionStatsApiV1GatewayVersionStatsGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> GetVersionStatsApiV1GatewayVersionStatsGetResponseGetVersionStatsApiV1GatewayVersionStatsGet | None:
    """Get Version Stats

     Return API version usage statistics and deprecation alerts.

    Shows which clients are still using deprecated API versions
    and the distribution of usage across all supported versions.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetVersionStatsApiV1GatewayVersionStatsGetResponseGetVersionStatsApiV1GatewayVersionStatsGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetVersionStatsApiV1GatewayVersionStatsGetResponseGetVersionStatsApiV1GatewayVersionStatsGet]:
    """Get Version Stats

     Return API version usage statistics and deprecation alerts.

    Shows which clients are still using deprecated API versions
    and the distribution of usage across all supported versions.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetVersionStatsApiV1GatewayVersionStatsGetResponseGetVersionStatsApiV1GatewayVersionStatsGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> GetVersionStatsApiV1GatewayVersionStatsGetResponseGetVersionStatsApiV1GatewayVersionStatsGet | None:
    """Get Version Stats

     Return API version usage statistics and deprecation alerts.

    Shows which clients are still using deprecated API versions
    and the distribution of usage across all supported versions.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetVersionStatsApiV1GatewayVersionStatsGetResponseGetVersionStatsApiV1GatewayVersionStatsGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
