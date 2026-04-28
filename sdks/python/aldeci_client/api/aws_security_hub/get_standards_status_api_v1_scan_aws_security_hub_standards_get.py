from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_standards_status_api_v1_scan_aws_security_hub_standards_get_response_get_standards_status_api_v1_scan_aws_security_hub_standards_get import (
    GetStandardsStatusApiV1ScanAwsSecurityHubStandardsGetResponseGetStandardsStatusApiV1ScanAwsSecurityHubStandardsGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/scan/aws-security-hub/standards",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetStandardsStatusApiV1ScanAwsSecurityHubStandardsGetResponseGetStandardsStatusApiV1ScanAwsSecurityHubStandardsGet
    | None
):
    if response.status_code == 200:
        response_200 = GetStandardsStatusApiV1ScanAwsSecurityHubStandardsGetResponseGetStandardsStatusApiV1ScanAwsSecurityHubStandardsGet.from_dict(
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
    GetStandardsStatusApiV1ScanAwsSecurityHubStandardsGetResponseGetStandardsStatusApiV1ScanAwsSecurityHubStandardsGet
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
    GetStandardsStatusApiV1ScanAwsSecurityHubStandardsGetResponseGetStandardsStatusApiV1ScanAwsSecurityHubStandardsGet
]:
    """Get enabled compliance standards status

     Retrieve enabled compliance standards (CIS, PCI DSS, AWS FSBP) and their
    pass/fail control counts.

    Returns mock data when AWS credentials are not configured.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetStandardsStatusApiV1ScanAwsSecurityHubStandardsGetResponseGetStandardsStatusApiV1ScanAwsSecurityHubStandardsGet]
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
    GetStandardsStatusApiV1ScanAwsSecurityHubStandardsGetResponseGetStandardsStatusApiV1ScanAwsSecurityHubStandardsGet
    | None
):
    """Get enabled compliance standards status

     Retrieve enabled compliance standards (CIS, PCI DSS, AWS FSBP) and their
    pass/fail control counts.

    Returns mock data when AWS credentials are not configured.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetStandardsStatusApiV1ScanAwsSecurityHubStandardsGetResponseGetStandardsStatusApiV1ScanAwsSecurityHubStandardsGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    GetStandardsStatusApiV1ScanAwsSecurityHubStandardsGetResponseGetStandardsStatusApiV1ScanAwsSecurityHubStandardsGet
]:
    """Get enabled compliance standards status

     Retrieve enabled compliance standards (CIS, PCI DSS, AWS FSBP) and their
    pass/fail control counts.

    Returns mock data when AWS credentials are not configured.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetStandardsStatusApiV1ScanAwsSecurityHubStandardsGetResponseGetStandardsStatusApiV1ScanAwsSecurityHubStandardsGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> (
    GetStandardsStatusApiV1ScanAwsSecurityHubStandardsGetResponseGetStandardsStatusApiV1ScanAwsSecurityHubStandardsGet
    | None
):
    """Get enabled compliance standards status

     Retrieve enabled compliance standards (CIS, PCI DSS, AWS FSBP) and their
    pass/fail control counts.

    Returns mock data when AWS credentials are not configured.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetStandardsStatusApiV1ScanAwsSecurityHubStandardsGetResponseGetStandardsStatusApiV1ScanAwsSecurityHubStandardsGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
