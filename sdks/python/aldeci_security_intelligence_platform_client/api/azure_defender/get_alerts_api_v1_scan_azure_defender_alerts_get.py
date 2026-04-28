from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_alerts_api_v1_scan_azure_defender_alerts_get_response_200_item import (
    GetAlertsApiV1ScanAzureDefenderAlertsGetResponse200Item,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    severity: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_severity: None | str | Unset
    if isinstance(severity, Unset):
        json_severity = UNSET
    else:
        json_severity = severity
    params["severity"] = json_severity

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/scan/azure-defender/alerts",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[GetAlertsApiV1ScanAzureDefenderAlertsGetResponse200Item] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = GetAlertsApiV1ScanAzureDefenderAlertsGetResponse200Item.from_dict(
                response_200_item_data
            )

            response_200.append(response_200_item)

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
) -> Response[HTTPValidationError | list[GetAlertsApiV1ScanAzureDefenderAlertsGetResponse200Item]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[GetAlertsApiV1ScanAzureDefenderAlertsGetResponse200Item]]:
    """Pull security alerts from Microsoft Defender for Cloud

     Pull security alerts from Microsoft Defender for Cloud.

    Supports optional filtering by severity.
    Returns mock data when Azure credentials are not configured.

    Args:
        severity (None | str | Unset): Filter by severity: Critical, High, Medium, Low

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetAlertsApiV1ScanAzureDefenderAlertsGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        severity=severity,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
) -> HTTPValidationError | list[GetAlertsApiV1ScanAzureDefenderAlertsGetResponse200Item] | None:
    """Pull security alerts from Microsoft Defender for Cloud

     Pull security alerts from Microsoft Defender for Cloud.

    Supports optional filtering by severity.
    Returns mock data when Azure credentials are not configured.

    Args:
        severity (None | str | Unset): Filter by severity: Critical, High, Medium, Low

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetAlertsApiV1ScanAzureDefenderAlertsGetResponse200Item]
    """

    return sync_detailed(
        client=client,
        severity=severity,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[GetAlertsApiV1ScanAzureDefenderAlertsGetResponse200Item]]:
    """Pull security alerts from Microsoft Defender for Cloud

     Pull security alerts from Microsoft Defender for Cloud.

    Supports optional filtering by severity.
    Returns mock data when Azure credentials are not configured.

    Args:
        severity (None | str | Unset): Filter by severity: Critical, High, Medium, Low

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetAlertsApiV1ScanAzureDefenderAlertsGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        severity=severity,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
) -> HTTPValidationError | list[GetAlertsApiV1ScanAzureDefenderAlertsGetResponse200Item] | None:
    """Pull security alerts from Microsoft Defender for Cloud

     Pull security alerts from Microsoft Defender for Cloud.

    Supports optional filtering by severity.
    Returns mock data when Azure credentials are not configured.

    Args:
        severity (None | str | Unset): Filter by severity: Critical, High, Medium, Low

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetAlertsApiV1ScanAzureDefenderAlertsGetResponse200Item]
    """

    return (
        await asyncio_detailed(
            client=client,
            severity=severity,
        )
    ).parsed
