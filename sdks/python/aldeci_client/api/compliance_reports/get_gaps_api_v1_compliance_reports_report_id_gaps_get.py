from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_gaps_api_v1_compliance_reports_report_id_gaps_get_response_get_gaps_api_v1_compliance_reports_report_id_gaps_get import (
    GetGapsApiV1ComplianceReportsReportIdGapsGetResponseGetGapsApiV1ComplianceReportsReportIdGapsGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    report_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/compliance-reports/{report_id}/gaps".format(
            report_id=quote(str(report_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetGapsApiV1ComplianceReportsReportIdGapsGetResponseGetGapsApiV1ComplianceReportsReportIdGapsGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            GetGapsApiV1ComplianceReportsReportIdGapsGetResponseGetGapsApiV1ComplianceReportsReportIdGapsGet.from_dict(
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
    GetGapsApiV1ComplianceReportsReportIdGapsGetResponseGetGapsApiV1ComplianceReportsReportIdGapsGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    report_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetGapsApiV1ComplianceReportsReportIdGapsGetResponseGetGapsApiV1ComplianceReportsReportIdGapsGet
    | HTTPValidationError
]:
    """Get Gaps

     Return only the gap controls from a compliance report.

    Args:
        report_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetGapsApiV1ComplianceReportsReportIdGapsGetResponseGetGapsApiV1ComplianceReportsReportIdGapsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        report_id=report_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    report_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetGapsApiV1ComplianceReportsReportIdGapsGetResponseGetGapsApiV1ComplianceReportsReportIdGapsGet
    | HTTPValidationError
    | None
):
    """Get Gaps

     Return only the gap controls from a compliance report.

    Args:
        report_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetGapsApiV1ComplianceReportsReportIdGapsGetResponseGetGapsApiV1ComplianceReportsReportIdGapsGet | HTTPValidationError
    """

    return sync_detailed(
        report_id=report_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    report_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetGapsApiV1ComplianceReportsReportIdGapsGetResponseGetGapsApiV1ComplianceReportsReportIdGapsGet
    | HTTPValidationError
]:
    """Get Gaps

     Return only the gap controls from a compliance report.

    Args:
        report_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetGapsApiV1ComplianceReportsReportIdGapsGetResponseGetGapsApiV1ComplianceReportsReportIdGapsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        report_id=report_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    report_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetGapsApiV1ComplianceReportsReportIdGapsGetResponseGetGapsApiV1ComplianceReportsReportIdGapsGet
    | HTTPValidationError
    | None
):
    """Get Gaps

     Return only the gap controls from a compliance report.

    Args:
        report_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetGapsApiV1ComplianceReportsReportIdGapsGetResponseGetGapsApiV1ComplianceReportsReportIdGapsGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            report_id=report_id,
            client=client,
        )
    ).parsed
