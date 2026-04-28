from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.ioc_lookup_request import IOCLookupRequest
from ...models.lookup_ioc_api_v1_threat_intel_iocs_lookup_post_response_lookup_ioc_api_v1_threat_intel_iocs_lookup_post import (
    LookupIocApiV1ThreatIntelIocsLookupPostResponseLookupIocApiV1ThreatIntelIocsLookupPost,
)
from ...types import Response


def _get_kwargs(
    *,
    body: IOCLookupRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/threat-intel/iocs/lookup",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError | LookupIocApiV1ThreatIntelIocsLookupPostResponseLookupIocApiV1ThreatIntelIocsLookupPost | None
):
    if response.status_code == 200:
        response_200 = LookupIocApiV1ThreatIntelIocsLookupPostResponseLookupIocApiV1ThreatIntelIocsLookupPost.from_dict(
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
) -> Response[
    HTTPValidationError | LookupIocApiV1ThreatIntelIocsLookupPostResponseLookupIocApiV1ThreatIntelIocsLookupPost
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: IOCLookupRequest,
) -> Response[
    HTTPValidationError | LookupIocApiV1ThreatIntelIocsLookupPostResponseLookupIocApiV1ThreatIntelIocsLookupPost
]:
    """Lookup Ioc

     Lookup a specific IOC value across all available feeds.

    Checks: Feodo C2 blocklist (IPs), CISA KEV (CVE IDs).
    Returns all matching feed hits plus auto-detected IOC type.

    Args:
        body (IOCLookupRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | LookupIocApiV1ThreatIntelIocsLookupPostResponseLookupIocApiV1ThreatIntelIocsLookupPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: IOCLookupRequest,
) -> (
    HTTPValidationError | LookupIocApiV1ThreatIntelIocsLookupPostResponseLookupIocApiV1ThreatIntelIocsLookupPost | None
):
    """Lookup Ioc

     Lookup a specific IOC value across all available feeds.

    Checks: Feodo C2 blocklist (IPs), CISA KEV (CVE IDs).
    Returns all matching feed hits plus auto-detected IOC type.

    Args:
        body (IOCLookupRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | LookupIocApiV1ThreatIntelIocsLookupPostResponseLookupIocApiV1ThreatIntelIocsLookupPost
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: IOCLookupRequest,
) -> Response[
    HTTPValidationError | LookupIocApiV1ThreatIntelIocsLookupPostResponseLookupIocApiV1ThreatIntelIocsLookupPost
]:
    """Lookup Ioc

     Lookup a specific IOC value across all available feeds.

    Checks: Feodo C2 blocklist (IPs), CISA KEV (CVE IDs).
    Returns all matching feed hits plus auto-detected IOC type.

    Args:
        body (IOCLookupRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | LookupIocApiV1ThreatIntelIocsLookupPostResponseLookupIocApiV1ThreatIntelIocsLookupPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: IOCLookupRequest,
) -> (
    HTTPValidationError | LookupIocApiV1ThreatIntelIocsLookupPostResponseLookupIocApiV1ThreatIntelIocsLookupPost | None
):
    """Lookup Ioc

     Lookup a specific IOC value across all available feeds.

    Checks: Feodo C2 blocklist (IPs), CISA KEV (CVE IDs).
    Returns all matching feed hits plus auto-detected IOC type.

    Args:
        body (IOCLookupRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | LookupIocApiV1ThreatIntelIocsLookupPostResponseLookupIocApiV1ThreatIntelIocsLookupPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
