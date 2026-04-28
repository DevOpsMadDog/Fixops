from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.scan_fleet_api_v1_connectors_snyk_oss_scan_fleet_post_response_scan_fleet_api_v1_connectors_snyk_oss_scan_fleet_post import (
    ScanFleetApiV1ConnectorsSnykOssScanFleetPostResponseScanFleetApiV1ConnectorsSnykOssScanFleetPost,
)
from ...models.scan_fleet_request import ScanFleetRequest
from ...types import Response


def _get_kwargs(
    *,
    body: ScanFleetRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/connectors/snyk-oss/scan-fleet",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | ScanFleetApiV1ConnectorsSnykOssScanFleetPostResponseScanFleetApiV1ConnectorsSnykOssScanFleetPost
    | None
):
    if response.status_code == 200:
        response_200 = (
            ScanFleetApiV1ConnectorsSnykOssScanFleetPostResponseScanFleetApiV1ConnectorsSnykOssScanFleetPost.from_dict(
                response.json()
            )
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
    HTTPValidationError
    | ScanFleetApiV1ConnectorsSnykOssScanFleetPostResponseScanFleetApiV1ConnectorsSnykOssScanFleetPost
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
    body: ScanFleetRequest,
) -> Response[
    HTTPValidationError
    | ScanFleetApiV1ConnectorsSnykOssScanFleetPostResponseScanFleetApiV1ConnectorsSnykOssScanFleetPost
]:
    """Scan Fleet

    Args:
        body (ScanFleetRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ScanFleetApiV1ConnectorsSnykOssScanFleetPostResponseScanFleetApiV1ConnectorsSnykOssScanFleetPost]
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
    body: ScanFleetRequest,
) -> (
    HTTPValidationError
    | ScanFleetApiV1ConnectorsSnykOssScanFleetPostResponseScanFleetApiV1ConnectorsSnykOssScanFleetPost
    | None
):
    """Scan Fleet

    Args:
        body (ScanFleetRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ScanFleetApiV1ConnectorsSnykOssScanFleetPostResponseScanFleetApiV1ConnectorsSnykOssScanFleetPost
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ScanFleetRequest,
) -> Response[
    HTTPValidationError
    | ScanFleetApiV1ConnectorsSnykOssScanFleetPostResponseScanFleetApiV1ConnectorsSnykOssScanFleetPost
]:
    """Scan Fleet

    Args:
        body (ScanFleetRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ScanFleetApiV1ConnectorsSnykOssScanFleetPostResponseScanFleetApiV1ConnectorsSnykOssScanFleetPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ScanFleetRequest,
) -> (
    HTTPValidationError
    | ScanFleetApiV1ConnectorsSnykOssScanFleetPostResponseScanFleetApiV1ConnectorsSnykOssScanFleetPost
    | None
):
    """Scan Fleet

    Args:
        body (ScanFleetRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ScanFleetApiV1ConnectorsSnykOssScanFleetPostResponseScanFleetApiV1ConnectorsSnykOssScanFleetPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
