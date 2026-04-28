from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.analytics_sla_api_v1_analytics_sla_get_response_analytics_sla_api_v1_analytics_sla_get import (
    AnalyticsSlaApiV1AnalyticsSlaGetResponseAnalyticsSlaApiV1AnalyticsSlaGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/analytics/sla",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AnalyticsSlaApiV1AnalyticsSlaGetResponseAnalyticsSlaApiV1AnalyticsSlaGet | None:
    if response.status_code == 200:
        response_200 = AnalyticsSlaApiV1AnalyticsSlaGetResponseAnalyticsSlaApiV1AnalyticsSlaGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[AnalyticsSlaApiV1AnalyticsSlaGetResponseAnalyticsSlaApiV1AnalyticsSlaGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[AnalyticsSlaApiV1AnalyticsSlaGetResponseAnalyticsSlaApiV1AnalyticsSlaGet]:
    """Analytics Sla

     SLA compliance analytics from findings data.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AnalyticsSlaApiV1AnalyticsSlaGetResponseAnalyticsSlaApiV1AnalyticsSlaGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> AnalyticsSlaApiV1AnalyticsSlaGetResponseAnalyticsSlaApiV1AnalyticsSlaGet | None:
    """Analytics Sla

     SLA compliance analytics from findings data.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AnalyticsSlaApiV1AnalyticsSlaGetResponseAnalyticsSlaApiV1AnalyticsSlaGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[AnalyticsSlaApiV1AnalyticsSlaGetResponseAnalyticsSlaApiV1AnalyticsSlaGet]:
    """Analytics Sla

     SLA compliance analytics from findings data.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AnalyticsSlaApiV1AnalyticsSlaGetResponseAnalyticsSlaApiV1AnalyticsSlaGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> AnalyticsSlaApiV1AnalyticsSlaGetResponseAnalyticsSlaApiV1AnalyticsSlaGet | None:
    """Analytics Sla

     SLA compliance analytics from findings data.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AnalyticsSlaApiV1AnalyticsSlaGetResponseAnalyticsSlaApiV1AnalyticsSlaGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
