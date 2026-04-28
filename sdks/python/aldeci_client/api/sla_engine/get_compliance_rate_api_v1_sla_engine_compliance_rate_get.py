from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_compliance_rate_api_v1_sla_engine_compliance_rate_get_response_get_compliance_rate_api_v1_sla_engine_compliance_rate_get import (
    GetComplianceRateApiV1SlaEngineComplianceRateGetResponseGetComplianceRateApiV1SlaEngineComplianceRateGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    days: int | Unset = 30,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["days"] = days

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/sla-engine/compliance-rate",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetComplianceRateApiV1SlaEngineComplianceRateGetResponseGetComplianceRateApiV1SlaEngineComplianceRateGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetComplianceRateApiV1SlaEngineComplianceRateGetResponseGetComplianceRateApiV1SlaEngineComplianceRateGet.from_dict(
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
    GetComplianceRateApiV1SlaEngineComplianceRateGetResponseGetComplianceRateApiV1SlaEngineComplianceRateGet
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
    days: int | Unset = 30,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetComplianceRateApiV1SlaEngineComplianceRateGetResponseGetComplianceRateApiV1SlaEngineComplianceRateGet
    | HTTPValidationError
]:
    """SLA compliance rate for past N days

     Calculate SLA compliance rate: % of resolved findings fixed within deadline.

    Args:
        days (int | Unset):  Default: 30.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetComplianceRateApiV1SlaEngineComplianceRateGetResponseGetComplianceRateApiV1SlaEngineComplianceRateGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        days=days,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    days: int | Unset = 30,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetComplianceRateApiV1SlaEngineComplianceRateGetResponseGetComplianceRateApiV1SlaEngineComplianceRateGet
    | HTTPValidationError
    | None
):
    """SLA compliance rate for past N days

     Calculate SLA compliance rate: % of resolved findings fixed within deadline.

    Args:
        days (int | Unset):  Default: 30.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetComplianceRateApiV1SlaEngineComplianceRateGetResponseGetComplianceRateApiV1SlaEngineComplianceRateGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        days=days,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    days: int | Unset = 30,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetComplianceRateApiV1SlaEngineComplianceRateGetResponseGetComplianceRateApiV1SlaEngineComplianceRateGet
    | HTTPValidationError
]:
    """SLA compliance rate for past N days

     Calculate SLA compliance rate: % of resolved findings fixed within deadline.

    Args:
        days (int | Unset):  Default: 30.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetComplianceRateApiV1SlaEngineComplianceRateGetResponseGetComplianceRateApiV1SlaEngineComplianceRateGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        days=days,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    days: int | Unset = 30,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetComplianceRateApiV1SlaEngineComplianceRateGetResponseGetComplianceRateApiV1SlaEngineComplianceRateGet
    | HTTPValidationError
    | None
):
    """SLA compliance rate for past N days

     Calculate SLA compliance rate: % of resolved findings fixed within deadline.

    Args:
        days (int | Unset):  Default: 30.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetComplianceRateApiV1SlaEngineComplianceRateGetResponseGetComplianceRateApiV1SlaEngineComplianceRateGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            days=days,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
