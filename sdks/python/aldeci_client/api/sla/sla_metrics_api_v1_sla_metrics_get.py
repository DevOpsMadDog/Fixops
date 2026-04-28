from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.sla_metrics_api_v1_sla_metrics_get_response_sla_metrics_api_v1_sla_metrics_get import (
    SlaMetricsApiV1SlaMetricsGetResponseSlaMetricsApiV1SlaMetricsGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/sla/metrics",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> SlaMetricsApiV1SlaMetricsGetResponseSlaMetricsApiV1SlaMetricsGet | None:
    if response.status_code == 200:
        response_200 = SlaMetricsApiV1SlaMetricsGetResponseSlaMetricsApiV1SlaMetricsGet.from_dict(response.json())

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[SlaMetricsApiV1SlaMetricsGetResponseSlaMetricsApiV1SlaMetricsGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[SlaMetricsApiV1SlaMetricsGetResponseSlaMetricsApiV1SlaMetricsGet]:
    """Sla Metrics

     Detailed SLA metrics — MTTR, team breakdown, escalations.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[SlaMetricsApiV1SlaMetricsGetResponseSlaMetricsApiV1SlaMetricsGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> SlaMetricsApiV1SlaMetricsGetResponseSlaMetricsApiV1SlaMetricsGet | None:
    """Sla Metrics

     Detailed SLA metrics — MTTR, team breakdown, escalations.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        SlaMetricsApiV1SlaMetricsGetResponseSlaMetricsApiV1SlaMetricsGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[SlaMetricsApiV1SlaMetricsGetResponseSlaMetricsApiV1SlaMetricsGet]:
    """Sla Metrics

     Detailed SLA metrics — MTTR, team breakdown, escalations.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[SlaMetricsApiV1SlaMetricsGetResponseSlaMetricsApiV1SlaMetricsGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> SlaMetricsApiV1SlaMetricsGetResponseSlaMetricsApiV1SlaMetricsGet | None:
    """Sla Metrics

     Detailed SLA metrics — MTTR, team breakdown, escalations.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        SlaMetricsApiV1SlaMetricsGetResponseSlaMetricsApiV1SlaMetricsGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
