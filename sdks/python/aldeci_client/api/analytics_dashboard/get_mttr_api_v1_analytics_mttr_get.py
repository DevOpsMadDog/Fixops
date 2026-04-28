from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_mttr_api_v1_analytics_mttr_get_response_get_mttr_api_v1_analytics_mttr_get import (
    GetMttrApiV1AnalyticsMttrGetResponseGetMttrApiV1AnalyticsMttrGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str | Unset = "default",
    severity: None | str | Unset = UNSET,
    period_days: int | Unset = 30,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    json_severity: None | str | Unset
    if isinstance(severity, Unset):
        json_severity = UNSET
    else:
        json_severity = severity
    params["severity"] = json_severity

    params["period_days"] = period_days

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/analytics/mttr",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetMttrApiV1AnalyticsMttrGetResponseGetMttrApiV1AnalyticsMttrGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GetMttrApiV1AnalyticsMttrGetResponseGetMttrApiV1AnalyticsMttrGet.from_dict(response.json())

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
) -> Response[GetMttrApiV1AnalyticsMttrGetResponseGetMttrApiV1AnalyticsMttrGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    severity: None | str | Unset = UNSET,
    period_days: int | Unset = 30,
) -> Response[GetMttrApiV1AnalyticsMttrGetResponseGetMttrApiV1AnalyticsMttrGet | HTTPValidationError]:
    """Get Mttr

     Mean time to remediate (hours) — average time from first opened to resolved.

    Args:
        org_id (str | Unset): Organisation identifier Default: 'default'.
        severity (None | str | Unset): Filter by severity (critical/high/medium/low/info)
        period_days (int | Unset): Look-back window in days Default: 30.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetMttrApiV1AnalyticsMttrGetResponseGetMttrApiV1AnalyticsMttrGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        severity=severity,
        period_days=period_days,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    severity: None | str | Unset = UNSET,
    period_days: int | Unset = 30,
) -> GetMttrApiV1AnalyticsMttrGetResponseGetMttrApiV1AnalyticsMttrGet | HTTPValidationError | None:
    """Get Mttr

     Mean time to remediate (hours) — average time from first opened to resolved.

    Args:
        org_id (str | Unset): Organisation identifier Default: 'default'.
        severity (None | str | Unset): Filter by severity (critical/high/medium/low/info)
        period_days (int | Unset): Look-back window in days Default: 30.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetMttrApiV1AnalyticsMttrGetResponseGetMttrApiV1AnalyticsMttrGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        severity=severity,
        period_days=period_days,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    severity: None | str | Unset = UNSET,
    period_days: int | Unset = 30,
) -> Response[GetMttrApiV1AnalyticsMttrGetResponseGetMttrApiV1AnalyticsMttrGet | HTTPValidationError]:
    """Get Mttr

     Mean time to remediate (hours) — average time from first opened to resolved.

    Args:
        org_id (str | Unset): Organisation identifier Default: 'default'.
        severity (None | str | Unset): Filter by severity (critical/high/medium/low/info)
        period_days (int | Unset): Look-back window in days Default: 30.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetMttrApiV1AnalyticsMttrGetResponseGetMttrApiV1AnalyticsMttrGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        severity=severity,
        period_days=period_days,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    severity: None | str | Unset = UNSET,
    period_days: int | Unset = 30,
) -> GetMttrApiV1AnalyticsMttrGetResponseGetMttrApiV1AnalyticsMttrGet | HTTPValidationError | None:
    """Get Mttr

     Mean time to remediate (hours) — average time from first opened to resolved.

    Args:
        org_id (str | Unset): Organisation identifier Default: 'default'.
        severity (None | str | Unset): Filter by severity (critical/high/medium/low/info)
        period_days (int | Unset): Look-back window in days Default: 30.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetMttrApiV1AnalyticsMttrGetResponseGetMttrApiV1AnalyticsMttrGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            severity=severity,
            period_days=period_days,
        )
    ).parsed
