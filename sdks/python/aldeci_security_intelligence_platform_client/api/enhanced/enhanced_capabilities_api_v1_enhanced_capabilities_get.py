from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enhanced_capabilities_api_v1_enhanced_capabilities_get_response_enhanced_capabilities_api_v1_enhanced_capabilities_get import (
    EnhancedCapabilitiesApiV1EnhancedCapabilitiesGetResponseEnhancedCapabilitiesApiV1EnhancedCapabilitiesGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/enhanced/capabilities",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> EnhancedCapabilitiesApiV1EnhancedCapabilitiesGetResponseEnhancedCapabilitiesApiV1EnhancedCapabilitiesGet | None:
    if response.status_code == 200:
        response_200 = EnhancedCapabilitiesApiV1EnhancedCapabilitiesGetResponseEnhancedCapabilitiesApiV1EnhancedCapabilitiesGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[EnhancedCapabilitiesApiV1EnhancedCapabilitiesGetResponseEnhancedCapabilitiesApiV1EnhancedCapabilitiesGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[EnhancedCapabilitiesApiV1EnhancedCapabilitiesGetResponseEnhancedCapabilitiesApiV1EnhancedCapabilitiesGet]:
    """Enhanced Capabilities

     Expose engine telemetry and supported providers.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EnhancedCapabilitiesApiV1EnhancedCapabilitiesGetResponseEnhancedCapabilitiesApiV1EnhancedCapabilitiesGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> EnhancedCapabilitiesApiV1EnhancedCapabilitiesGetResponseEnhancedCapabilitiesApiV1EnhancedCapabilitiesGet | None:
    """Enhanced Capabilities

     Expose engine telemetry and supported providers.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EnhancedCapabilitiesApiV1EnhancedCapabilitiesGetResponseEnhancedCapabilitiesApiV1EnhancedCapabilitiesGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[EnhancedCapabilitiesApiV1EnhancedCapabilitiesGetResponseEnhancedCapabilitiesApiV1EnhancedCapabilitiesGet]:
    """Enhanced Capabilities

     Expose engine telemetry and supported providers.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EnhancedCapabilitiesApiV1EnhancedCapabilitiesGetResponseEnhancedCapabilitiesApiV1EnhancedCapabilitiesGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> EnhancedCapabilitiesApiV1EnhancedCapabilitiesGetResponseEnhancedCapabilitiesApiV1EnhancedCapabilitiesGet | None:
    """Enhanced Capabilities

     Expose engine telemetry and supported providers.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EnhancedCapabilitiesApiV1EnhancedCapabilitiesGetResponseEnhancedCapabilitiesApiV1EnhancedCapabilitiesGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
