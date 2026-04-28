from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_secure_score_api_v1_scan_azure_defender_secure_score_get_response_get_secure_score_api_v1_scan_azure_defender_secure_score_get import (
    GetSecureScoreApiV1ScanAzureDefenderSecureScoreGetResponseGetSecureScoreApiV1ScanAzureDefenderSecureScoreGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/scan/azure-defender/secure-score",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetSecureScoreApiV1ScanAzureDefenderSecureScoreGetResponseGetSecureScoreApiV1ScanAzureDefenderSecureScoreGet | None
):
    if response.status_code == 200:
        response_200 = GetSecureScoreApiV1ScanAzureDefenderSecureScoreGetResponseGetSecureScoreApiV1ScanAzureDefenderSecureScoreGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetSecureScoreApiV1ScanAzureDefenderSecureScoreGetResponseGetSecureScoreApiV1ScanAzureDefenderSecureScoreGet
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
) -> Response[
    GetSecureScoreApiV1ScanAzureDefenderSecureScoreGetResponseGetSecureScoreApiV1ScanAzureDefenderSecureScoreGet
]:
    """Get Azure Secure Score

     Retrieve the Azure Secure Score for the configured subscription.

    Returns mock data when Azure credentials are not configured.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetSecureScoreApiV1ScanAzureDefenderSecureScoreGetResponseGetSecureScoreApiV1ScanAzureDefenderSecureScoreGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> (
    GetSecureScoreApiV1ScanAzureDefenderSecureScoreGetResponseGetSecureScoreApiV1ScanAzureDefenderSecureScoreGet | None
):
    """Get Azure Secure Score

     Retrieve the Azure Secure Score for the configured subscription.

    Returns mock data when Azure credentials are not configured.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetSecureScoreApiV1ScanAzureDefenderSecureScoreGetResponseGetSecureScoreApiV1ScanAzureDefenderSecureScoreGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    GetSecureScoreApiV1ScanAzureDefenderSecureScoreGetResponseGetSecureScoreApiV1ScanAzureDefenderSecureScoreGet
]:
    """Get Azure Secure Score

     Retrieve the Azure Secure Score for the configured subscription.

    Returns mock data when Azure credentials are not configured.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetSecureScoreApiV1ScanAzureDefenderSecureScoreGetResponseGetSecureScoreApiV1ScanAzureDefenderSecureScoreGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> (
    GetSecureScoreApiV1ScanAzureDefenderSecureScoreGetResponseGetSecureScoreApiV1ScanAzureDefenderSecureScoreGet | None
):
    """Get Azure Secure Score

     Retrieve the Azure Secure Score for the configured subscription.

    Returns mock data when Azure credentials are not configured.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetSecureScoreApiV1ScanAzureDefenderSecureScoreGetResponseGetSecureScoreApiV1ScanAzureDefenderSecureScoreGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
