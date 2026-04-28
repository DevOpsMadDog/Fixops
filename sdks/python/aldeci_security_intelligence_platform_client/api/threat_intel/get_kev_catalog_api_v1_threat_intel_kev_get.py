from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_kev_catalog_api_v1_threat_intel_kev_get_response_get_kev_catalog_api_v1_threat_intel_kev_get import (
    GetKevCatalogApiV1ThreatIntelKevGetResponseGetKevCatalogApiV1ThreatIntelKevGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/threat-intel/kev",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetKevCatalogApiV1ThreatIntelKevGetResponseGetKevCatalogApiV1ThreatIntelKevGet | None:
    if response.status_code == 200:
        response_200 = GetKevCatalogApiV1ThreatIntelKevGetResponseGetKevCatalogApiV1ThreatIntelKevGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[GetKevCatalogApiV1ThreatIntelKevGetResponseGetKevCatalogApiV1ThreatIntelKevGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetKevCatalogApiV1ThreatIntelKevGetResponseGetKevCatalogApiV1ThreatIntelKevGet]:
    """Get Kev Catalog

     Return the current CISA Known Exploited Vulnerabilities catalog from cache.

    The catalog is refreshed on each call to ``/refresh``.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetKevCatalogApiV1ThreatIntelKevGetResponseGetKevCatalogApiV1ThreatIntelKevGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> GetKevCatalogApiV1ThreatIntelKevGetResponseGetKevCatalogApiV1ThreatIntelKevGet | None:
    """Get Kev Catalog

     Return the current CISA Known Exploited Vulnerabilities catalog from cache.

    The catalog is refreshed on each call to ``/refresh``.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetKevCatalogApiV1ThreatIntelKevGetResponseGetKevCatalogApiV1ThreatIntelKevGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetKevCatalogApiV1ThreatIntelKevGetResponseGetKevCatalogApiV1ThreatIntelKevGet]:
    """Get Kev Catalog

     Return the current CISA Known Exploited Vulnerabilities catalog from cache.

    The catalog is refreshed on each call to ``/refresh``.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetKevCatalogApiV1ThreatIntelKevGetResponseGetKevCatalogApiV1ThreatIntelKevGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> GetKevCatalogApiV1ThreatIntelKevGetResponseGetKevCatalogApiV1ThreatIntelKevGet | None:
    """Get Kev Catalog

     Return the current CISA Known Exploited Vulnerabilities catalog from cache.

    The catalog is refreshed on each call to ``/refresh``.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetKevCatalogApiV1ThreatIntelKevGetResponseGetKevCatalogApiV1ThreatIntelKevGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
