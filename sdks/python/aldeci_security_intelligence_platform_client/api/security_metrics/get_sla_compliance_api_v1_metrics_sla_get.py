from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_sla_compliance_api_v1_metrics_sla_get_response_200_item import (
    GetSlaComplianceApiV1MetricsSlaGetResponse200Item,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    days: int | Unset = 30,
    since: None | str | Unset = UNSET,
    until: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["days"] = days

    json_since: None | str | Unset
    if isinstance(since, Unset):
        json_since = UNSET
    else:
        json_since = since
    params["since"] = json_since

    json_until: None | str | Unset
    if isinstance(until, Unset):
        json_until = UNSET
    else:
        json_until = until
    params["until"] = json_until

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/metrics/sla",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[GetSlaComplianceApiV1MetricsSlaGetResponse200Item] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = GetSlaComplianceApiV1MetricsSlaGetResponse200Item.from_dict(response_200_item_data)

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
) -> Response[HTTPValidationError | list[GetSlaComplianceApiV1MetricsSlaGetResponse200Item]]:
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
    since: None | str | Unset = UNSET,
    until: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[GetSlaComplianceApiV1MetricsSlaGetResponse200Item]]:
    """SLA compliance per severity

     Track SLA compliance for Critical (24h), High (7d), Medium (30d), and Low (90d) findings. Returns
    breach rate, average overdue time, and worst-offender team/repo.

    Args:
        days (int | Unset):  Default: 30.
        since (None | str | Unset):
        until (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetSlaComplianceApiV1MetricsSlaGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        days=days,
        since=since,
        until=until,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    days: int | Unset = 30,
    since: None | str | Unset = UNSET,
    until: None | str | Unset = UNSET,
) -> HTTPValidationError | list[GetSlaComplianceApiV1MetricsSlaGetResponse200Item] | None:
    """SLA compliance per severity

     Track SLA compliance for Critical (24h), High (7d), Medium (30d), and Low (90d) findings. Returns
    breach rate, average overdue time, and worst-offender team/repo.

    Args:
        days (int | Unset):  Default: 30.
        since (None | str | Unset):
        until (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetSlaComplianceApiV1MetricsSlaGetResponse200Item]
    """

    return sync_detailed(
        client=client,
        days=days,
        since=since,
        until=until,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    days: int | Unset = 30,
    since: None | str | Unset = UNSET,
    until: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[GetSlaComplianceApiV1MetricsSlaGetResponse200Item]]:
    """SLA compliance per severity

     Track SLA compliance for Critical (24h), High (7d), Medium (30d), and Low (90d) findings. Returns
    breach rate, average overdue time, and worst-offender team/repo.

    Args:
        days (int | Unset):  Default: 30.
        since (None | str | Unset):
        until (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetSlaComplianceApiV1MetricsSlaGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        days=days,
        since=since,
        until=until,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    days: int | Unset = 30,
    since: None | str | Unset = UNSET,
    until: None | str | Unset = UNSET,
) -> HTTPValidationError | list[GetSlaComplianceApiV1MetricsSlaGetResponse200Item] | None:
    """SLA compliance per severity

     Track SLA compliance for Critical (24h), High (7d), Medium (30d), and Low (90d) findings. Returns
    breach rate, average overdue time, and worst-offender team/repo.

    Args:
        days (int | Unset):  Default: 30.
        since (None | str | Unset):
        until (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetSlaComplianceApiV1MetricsSlaGetResponse200Item]
    """

    return (
        await asyncio_detailed(
            client=client,
            days=days,
            since=since,
            until=until,
        )
    ).parsed
