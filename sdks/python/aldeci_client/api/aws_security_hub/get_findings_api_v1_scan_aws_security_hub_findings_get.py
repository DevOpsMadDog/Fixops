from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_findings_api_v1_scan_aws_security_hub_findings_get_response_200_item import (
    GetFindingsApiV1ScanAwsSecurityHubFindingsGetResponse200Item,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    severity: None | str | Unset = UNSET,
    workflow_status: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_severity: None | str | Unset
    if isinstance(severity, Unset):
        json_severity = UNSET
    else:
        json_severity = severity
    params["severity"] = json_severity

    json_workflow_status: None | str | Unset
    if isinstance(workflow_status, Unset):
        json_workflow_status = UNSET
    else:
        json_workflow_status = workflow_status
    params["workflow_status"] = json_workflow_status

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/scan/aws-security-hub/findings",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[GetFindingsApiV1ScanAwsSecurityHubFindingsGetResponse200Item] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = GetFindingsApiV1ScanAwsSecurityHubFindingsGetResponse200Item.from_dict(
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
) -> Response[HTTPValidationError | list[GetFindingsApiV1ScanAwsSecurityHubFindingsGetResponse200Item]]:
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
    workflow_status: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[GetFindingsApiV1ScanAwsSecurityHubFindingsGetResponse200Item]]:
    """Pull raw ASFF findings from Security Hub

     Pull raw AWS Security Finding Format (ASFF) findings from Security Hub.

    Supports optional filtering by severity and workflow status.
    Returns mock data when AWS credentials are not configured.

    Args:
        severity (None | str | Unset): Filter by severity label: CRITICAL, HIGH, MEDIUM, LOW,
            INFORMATIONAL
        workflow_status (None | str | Unset): Filter by workflow status: NEW, NOTIFIED, RESOLVED,
            SUPPRESSED

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetFindingsApiV1ScanAwsSecurityHubFindingsGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        severity=severity,
        workflow_status=workflow_status,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
    workflow_status: None | str | Unset = UNSET,
) -> HTTPValidationError | list[GetFindingsApiV1ScanAwsSecurityHubFindingsGetResponse200Item] | None:
    """Pull raw ASFF findings from Security Hub

     Pull raw AWS Security Finding Format (ASFF) findings from Security Hub.

    Supports optional filtering by severity and workflow status.
    Returns mock data when AWS credentials are not configured.

    Args:
        severity (None | str | Unset): Filter by severity label: CRITICAL, HIGH, MEDIUM, LOW,
            INFORMATIONAL
        workflow_status (None | str | Unset): Filter by workflow status: NEW, NOTIFIED, RESOLVED,
            SUPPRESSED

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetFindingsApiV1ScanAwsSecurityHubFindingsGetResponse200Item]
    """

    return sync_detailed(
        client=client,
        severity=severity,
        workflow_status=workflow_status,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
    workflow_status: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[GetFindingsApiV1ScanAwsSecurityHubFindingsGetResponse200Item]]:
    """Pull raw ASFF findings from Security Hub

     Pull raw AWS Security Finding Format (ASFF) findings from Security Hub.

    Supports optional filtering by severity and workflow status.
    Returns mock data when AWS credentials are not configured.

    Args:
        severity (None | str | Unset): Filter by severity label: CRITICAL, HIGH, MEDIUM, LOW,
            INFORMATIONAL
        workflow_status (None | str | Unset): Filter by workflow status: NEW, NOTIFIED, RESOLVED,
            SUPPRESSED

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetFindingsApiV1ScanAwsSecurityHubFindingsGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        severity=severity,
        workflow_status=workflow_status,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
    workflow_status: None | str | Unset = UNSET,
) -> HTTPValidationError | list[GetFindingsApiV1ScanAwsSecurityHubFindingsGetResponse200Item] | None:
    """Pull raw ASFF findings from Security Hub

     Pull raw AWS Security Finding Format (ASFF) findings from Security Hub.

    Supports optional filtering by severity and workflow status.
    Returns mock data when AWS credentials are not configured.

    Args:
        severity (None | str | Unset): Filter by severity label: CRITICAL, HIGH, MEDIUM, LOW,
            INFORMATIONAL
        workflow_status (None | str | Unset): Filter by workflow status: NEW, NOTIFIED, RESOLVED,
            SUPPRESSED

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetFindingsApiV1ScanAwsSecurityHubFindingsGetResponse200Item]
    """

    return (
        await asyncio_detailed(
            client=client,
            severity=severity,
            workflow_status=workflow_status,
        )
    ).parsed
