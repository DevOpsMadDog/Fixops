from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.analytics_risk_overview_api_v1_analytics_risk_overview_get_response_analytics_risk_overview_api_v1_analytics_risk_overview_get import (
    AnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGetResponseAnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/analytics/risk-overview",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    AnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGetResponseAnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGet | None
):
    if response.status_code == 200:
        response_200 = AnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGetResponseAnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGet.from_dict(
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
    AnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGetResponseAnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGet
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
    AnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGetResponseAnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGet
]:
    """Analytics Risk Overview

     Risk overview from analytics data.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGetResponseAnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGet]
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
    AnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGetResponseAnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGet | None
):
    """Analytics Risk Overview

     Risk overview from analytics data.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGetResponseAnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    AnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGetResponseAnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGet
]:
    """Analytics Risk Overview

     Risk overview from analytics data.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGetResponseAnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> (
    AnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGetResponseAnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGet | None
):
    """Analytics Risk Overview

     Risk overview from analytics data.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGetResponseAnalyticsRiskOverviewApiV1AnalyticsRiskOverviewGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
