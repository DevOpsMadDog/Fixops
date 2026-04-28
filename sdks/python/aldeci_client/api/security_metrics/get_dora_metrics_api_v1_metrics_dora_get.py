from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_dora_metrics_api_v1_metrics_dora_get_response_get_dora_metrics_api_v1_metrics_dora_get import (
    GetDoraMetricsApiV1MetricsDoraGetResponseGetDoraMetricsApiV1MetricsDoraGet,
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
        "url": "/api/v1/metrics/dora",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetDoraMetricsApiV1MetricsDoraGetResponseGetDoraMetricsApiV1MetricsDoraGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GetDoraMetricsApiV1MetricsDoraGetResponseGetDoraMetricsApiV1MetricsDoraGet.from_dict(
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
) -> Response[GetDoraMetricsApiV1MetricsDoraGetResponseGetDoraMetricsApiV1MetricsDoraGet | HTTPValidationError]:
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
) -> Response[GetDoraMetricsApiV1MetricsDoraGetResponseGetDoraMetricsApiV1MetricsDoraGet | HTTPValidationError]:
    """DORA-like security metrics

     Compute Mean Time to Detect (MTTD), Mean Time to Contain (MTTC), Mean Time to Remediate (MTTR), and
    Change Failure Rate for the requested time window.

    Args:
        days (int | Unset): Lookback window in days Default: 30.
        since (None | str | Unset): Window start (ISO 8601)
        until (None | str | Unset): Window end (ISO 8601)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetDoraMetricsApiV1MetricsDoraGetResponseGetDoraMetricsApiV1MetricsDoraGet | HTTPValidationError]
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
) -> GetDoraMetricsApiV1MetricsDoraGetResponseGetDoraMetricsApiV1MetricsDoraGet | HTTPValidationError | None:
    """DORA-like security metrics

     Compute Mean Time to Detect (MTTD), Mean Time to Contain (MTTC), Mean Time to Remediate (MTTR), and
    Change Failure Rate for the requested time window.

    Args:
        days (int | Unset): Lookback window in days Default: 30.
        since (None | str | Unset): Window start (ISO 8601)
        until (None | str | Unset): Window end (ISO 8601)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetDoraMetricsApiV1MetricsDoraGetResponseGetDoraMetricsApiV1MetricsDoraGet | HTTPValidationError
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
) -> Response[GetDoraMetricsApiV1MetricsDoraGetResponseGetDoraMetricsApiV1MetricsDoraGet | HTTPValidationError]:
    """DORA-like security metrics

     Compute Mean Time to Detect (MTTD), Mean Time to Contain (MTTC), Mean Time to Remediate (MTTR), and
    Change Failure Rate for the requested time window.

    Args:
        days (int | Unset): Lookback window in days Default: 30.
        since (None | str | Unset): Window start (ISO 8601)
        until (None | str | Unset): Window end (ISO 8601)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetDoraMetricsApiV1MetricsDoraGetResponseGetDoraMetricsApiV1MetricsDoraGet | HTTPValidationError]
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
) -> GetDoraMetricsApiV1MetricsDoraGetResponseGetDoraMetricsApiV1MetricsDoraGet | HTTPValidationError | None:
    """DORA-like security metrics

     Compute Mean Time to Detect (MTTD), Mean Time to Contain (MTTC), Mean Time to Remediate (MTTR), and
    Change Failure Rate for the requested time window.

    Args:
        days (int | Unset): Lookback window in days Default: 30.
        since (None | str | Unset): Window start (ISO 8601)
        until (None | str | Unset): Window end (ISO 8601)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetDoraMetricsApiV1MetricsDoraGetResponseGetDoraMetricsApiV1MetricsDoraGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            days=days,
            since=since,
            until=until,
        )
    ).parsed
