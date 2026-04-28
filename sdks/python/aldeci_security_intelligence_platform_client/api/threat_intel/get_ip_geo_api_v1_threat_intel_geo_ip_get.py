from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_ip_geo_api_v1_threat_intel_geo_ip_get_response_get_ip_geo_api_v1_threat_intel_geo_ip_get import (
    GetIpGeoApiV1ThreatIntelGeoIpGetResponseGetIpGeoApiV1ThreatIntelGeoIpGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    ip: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/threat-intel/geo/{ip}".format(
            ip=quote(str(ip), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetIpGeoApiV1ThreatIntelGeoIpGetResponseGetIpGeoApiV1ThreatIntelGeoIpGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GetIpGeoApiV1ThreatIntelGeoIpGetResponseGetIpGeoApiV1ThreatIntelGeoIpGet.from_dict(
            response.json()
        )

        return response_200

    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[GetIpGeoApiV1ThreatIntelGeoIpGetResponseGetIpGeoApiV1ThreatIntelGeoIpGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    ip: str,
    *,
    client: AuthenticatedClient,
) -> Response[GetIpGeoApiV1ThreatIntelGeoIpGetResponseGetIpGeoApiV1ThreatIntelGeoIpGet | HTTPValidationError]:
    """Get Ip Geo

     Return geo/ASN/reputation data for an IP address.

    Uses Shodan InternetDB (no auth required) for open port/vuln data.
    Also checks AbuseIPDB if ABUSEIPDB_API_KEY is configured.
    Checks Feodo C2 blocklist for C2 classification.

    Args:
        ip (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetIpGeoApiV1ThreatIntelGeoIpGetResponseGetIpGeoApiV1ThreatIntelGeoIpGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        ip=ip,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    ip: str,
    *,
    client: AuthenticatedClient,
) -> GetIpGeoApiV1ThreatIntelGeoIpGetResponseGetIpGeoApiV1ThreatIntelGeoIpGet | HTTPValidationError | None:
    """Get Ip Geo

     Return geo/ASN/reputation data for an IP address.

    Uses Shodan InternetDB (no auth required) for open port/vuln data.
    Also checks AbuseIPDB if ABUSEIPDB_API_KEY is configured.
    Checks Feodo C2 blocklist for C2 classification.

    Args:
        ip (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetIpGeoApiV1ThreatIntelGeoIpGetResponseGetIpGeoApiV1ThreatIntelGeoIpGet | HTTPValidationError
    """

    return sync_detailed(
        ip=ip,
        client=client,
    ).parsed


async def asyncio_detailed(
    ip: str,
    *,
    client: AuthenticatedClient,
) -> Response[GetIpGeoApiV1ThreatIntelGeoIpGetResponseGetIpGeoApiV1ThreatIntelGeoIpGet | HTTPValidationError]:
    """Get Ip Geo

     Return geo/ASN/reputation data for an IP address.

    Uses Shodan InternetDB (no auth required) for open port/vuln data.
    Also checks AbuseIPDB if ABUSEIPDB_API_KEY is configured.
    Checks Feodo C2 blocklist for C2 classification.

    Args:
        ip (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetIpGeoApiV1ThreatIntelGeoIpGetResponseGetIpGeoApiV1ThreatIntelGeoIpGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        ip=ip,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    ip: str,
    *,
    client: AuthenticatedClient,
) -> GetIpGeoApiV1ThreatIntelGeoIpGetResponseGetIpGeoApiV1ThreatIntelGeoIpGet | HTTPValidationError | None:
    """Get Ip Geo

     Return geo/ASN/reputation data for an IP address.

    Uses Shodan InternetDB (no auth required) for open port/vuln data.
    Also checks AbuseIPDB if ABUSEIPDB_API_KEY is configured.
    Checks Feodo C2 blocklist for C2 classification.

    Args:
        ip (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetIpGeoApiV1ThreatIntelGeoIpGetResponseGetIpGeoApiV1ThreatIntelGeoIpGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            ip=ip,
            client=client,
        )
    ).parsed
