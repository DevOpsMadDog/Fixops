from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.false_positive_rate_api_v1_analytics_false_positive_rate_get_response_false_positive_rate_api_v1_analytics_false_positive_rate_get import (
    FalsePositiveRateApiV1AnalyticsFalsePositiveRateGetResponseFalsePositiveRateApiV1AnalyticsFalsePositiveRateGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    scanner: None | str | Unset = UNSET,
    cwe_id: None | str | Unset = UNSET,
    app_id: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_scanner: None | str | Unset
    if isinstance(scanner, Unset):
        json_scanner = UNSET
    else:
        json_scanner = scanner
    params["scanner"] = json_scanner

    json_cwe_id: None | str | Unset
    if isinstance(cwe_id, Unset):
        json_cwe_id = UNSET
    else:
        json_cwe_id = cwe_id
    params["cwe_id"] = json_cwe_id

    json_app_id: None | str | Unset
    if isinstance(app_id, Unset):
        json_app_id = UNSET
    else:
        json_app_id = app_id
    params["app_id"] = json_app_id

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/analytics/false-positive-rate",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    FalsePositiveRateApiV1AnalyticsFalsePositiveRateGetResponseFalsePositiveRateApiV1AnalyticsFalsePositiveRateGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = FalsePositiveRateApiV1AnalyticsFalsePositiveRateGetResponseFalsePositiveRateApiV1AnalyticsFalsePositiveRateGet.from_dict(
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
    FalsePositiveRateApiV1AnalyticsFalsePositiveRateGetResponseFalsePositiveRateApiV1AnalyticsFalsePositiveRateGet
    | HTTPValidationError
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
    scanner: None | str | Unset = UNSET,
    cwe_id: None | str | Unset = UNSET,
    app_id: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
) -> Response[
    FalsePositiveRateApiV1AnalyticsFalsePositiveRateGetResponseFalsePositiveRateApiV1AnalyticsFalsePositiveRateGet
    | HTTPValidationError
]:
    """False Positive Rate

     [V3] Get false-positive rate from analyst feedback.

    Breaks down FP rate by scanner, CWE, and overall. Supports
    filtering by scanner, CWE, app_id, or org_id.

    Query params:
        scanner: Filter by scanner name (e.g. 'semgrep')
        cwe_id: Filter by CWE (e.g. 'CWE-79')
        app_id: Filter by application
        org_id: Filter by organization

    Args:
        scanner (None | str | Unset):
        cwe_id (None | str | Unset):
        app_id (None | str | Unset):
        org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[FalsePositiveRateApiV1AnalyticsFalsePositiveRateGetResponseFalsePositiveRateApiV1AnalyticsFalsePositiveRateGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        scanner=scanner,
        cwe_id=cwe_id,
        app_id=app_id,
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    scanner: None | str | Unset = UNSET,
    cwe_id: None | str | Unset = UNSET,
    app_id: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
) -> (
    FalsePositiveRateApiV1AnalyticsFalsePositiveRateGetResponseFalsePositiveRateApiV1AnalyticsFalsePositiveRateGet
    | HTTPValidationError
    | None
):
    """False Positive Rate

     [V3] Get false-positive rate from analyst feedback.

    Breaks down FP rate by scanner, CWE, and overall. Supports
    filtering by scanner, CWE, app_id, or org_id.

    Query params:
        scanner: Filter by scanner name (e.g. 'semgrep')
        cwe_id: Filter by CWE (e.g. 'CWE-79')
        app_id: Filter by application
        org_id: Filter by organization

    Args:
        scanner (None | str | Unset):
        cwe_id (None | str | Unset):
        app_id (None | str | Unset):
        org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        FalsePositiveRateApiV1AnalyticsFalsePositiveRateGetResponseFalsePositiveRateApiV1AnalyticsFalsePositiveRateGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        scanner=scanner,
        cwe_id=cwe_id,
        app_id=app_id,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    scanner: None | str | Unset = UNSET,
    cwe_id: None | str | Unset = UNSET,
    app_id: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
) -> Response[
    FalsePositiveRateApiV1AnalyticsFalsePositiveRateGetResponseFalsePositiveRateApiV1AnalyticsFalsePositiveRateGet
    | HTTPValidationError
]:
    """False Positive Rate

     [V3] Get false-positive rate from analyst feedback.

    Breaks down FP rate by scanner, CWE, and overall. Supports
    filtering by scanner, CWE, app_id, or org_id.

    Query params:
        scanner: Filter by scanner name (e.g. 'semgrep')
        cwe_id: Filter by CWE (e.g. 'CWE-79')
        app_id: Filter by application
        org_id: Filter by organization

    Args:
        scanner (None | str | Unset):
        cwe_id (None | str | Unset):
        app_id (None | str | Unset):
        org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[FalsePositiveRateApiV1AnalyticsFalsePositiveRateGetResponseFalsePositiveRateApiV1AnalyticsFalsePositiveRateGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        scanner=scanner,
        cwe_id=cwe_id,
        app_id=app_id,
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    scanner: None | str | Unset = UNSET,
    cwe_id: None | str | Unset = UNSET,
    app_id: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
) -> (
    FalsePositiveRateApiV1AnalyticsFalsePositiveRateGetResponseFalsePositiveRateApiV1AnalyticsFalsePositiveRateGet
    | HTTPValidationError
    | None
):
    """False Positive Rate

     [V3] Get false-positive rate from analyst feedback.

    Breaks down FP rate by scanner, CWE, and overall. Supports
    filtering by scanner, CWE, app_id, or org_id.

    Query params:
        scanner: Filter by scanner name (e.g. 'semgrep')
        cwe_id: Filter by CWE (e.g. 'CWE-79')
        app_id: Filter by application
        org_id: Filter by organization

    Args:
        scanner (None | str | Unset):
        cwe_id (None | str | Unset):
        app_id (None | str | Unset):
        org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        FalsePositiveRateApiV1AnalyticsFalsePositiveRateGetResponseFalsePositiveRateApiV1AnalyticsFalsePositiveRateGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            scanner=scanner,
            cwe_id=cwe_id,
            app_id=app_id,
            org_id=org_id,
        )
    ).parsed
