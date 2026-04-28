from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.executive_summary_api_v1_analytics_executive_get_response_executive_summary_api_v1_analytics_executive_get import (
    ExecutiveSummaryApiV1AnalyticsExecutiveGetResponseExecutiveSummaryApiV1AnalyticsExecutiveGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/analytics/executive",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ExecutiveSummaryApiV1AnalyticsExecutiveGetResponseExecutiveSummaryApiV1AnalyticsExecutiveGet | None:
    if response.status_code == 200:
        response_200 = (
            ExecutiveSummaryApiV1AnalyticsExecutiveGetResponseExecutiveSummaryApiV1AnalyticsExecutiveGet.from_dict(
                response.json()
            )
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ExecutiveSummaryApiV1AnalyticsExecutiveGetResponseExecutiveSummaryApiV1AnalyticsExecutiveGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[ExecutiveSummaryApiV1AnalyticsExecutiveGetResponseExecutiveSummaryApiV1AnalyticsExecutiveGet]:
    """Executive Summary

     Executive summary — CISO/CTO-level KPIs, risk posture, compliance.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ExecutiveSummaryApiV1AnalyticsExecutiveGetResponseExecutiveSummaryApiV1AnalyticsExecutiveGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> ExecutiveSummaryApiV1AnalyticsExecutiveGetResponseExecutiveSummaryApiV1AnalyticsExecutiveGet | None:
    """Executive Summary

     Executive summary — CISO/CTO-level KPIs, risk posture, compliance.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ExecutiveSummaryApiV1AnalyticsExecutiveGetResponseExecutiveSummaryApiV1AnalyticsExecutiveGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[ExecutiveSummaryApiV1AnalyticsExecutiveGetResponseExecutiveSummaryApiV1AnalyticsExecutiveGet]:
    """Executive Summary

     Executive summary — CISO/CTO-level KPIs, risk posture, compliance.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ExecutiveSummaryApiV1AnalyticsExecutiveGetResponseExecutiveSummaryApiV1AnalyticsExecutiveGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> ExecutiveSummaryApiV1AnalyticsExecutiveGetResponseExecutiveSummaryApiV1AnalyticsExecutiveGet | None:
    """Executive Summary

     Executive summary — CISO/CTO-level KPIs, risk posture, compliance.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ExecutiveSummaryApiV1AnalyticsExecutiveGetResponseExecutiveSummaryApiV1AnalyticsExecutiveGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
