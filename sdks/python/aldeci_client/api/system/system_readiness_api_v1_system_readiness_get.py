from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.system_readiness_api_v1_system_readiness_get_response_system_readiness_api_v1_system_readiness_get import (
    SystemReadinessApiV1SystemReadinessGetResponseSystemReadinessApiV1SystemReadinessGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/system/readiness",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> SystemReadinessApiV1SystemReadinessGetResponseSystemReadinessApiV1SystemReadinessGet | None:
    if response.status_code == 200:
        response_200 = SystemReadinessApiV1SystemReadinessGetResponseSystemReadinessApiV1SystemReadinessGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[SystemReadinessApiV1SystemReadinessGetResponseSystemReadinessApiV1SystemReadinessGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[SystemReadinessApiV1SystemReadinessGetResponseSystemReadinessApiV1SystemReadinessGet]:
    """Full deployment readiness assessment

     Comprehensive readiness check -- the first thing a customer runs after deploy.

    Reports every integration, database, feed, and scanner with its status,
    computes an overall readiness score (0-100), and provides actionable
    recommendations for anything that is missing or degraded.

    **No authentication required.**  Secret values are NEVER exposed --
    only whether the corresponding env var is set.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[SystemReadinessApiV1SystemReadinessGetResponseSystemReadinessApiV1SystemReadinessGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> SystemReadinessApiV1SystemReadinessGetResponseSystemReadinessApiV1SystemReadinessGet | None:
    """Full deployment readiness assessment

     Comprehensive readiness check -- the first thing a customer runs after deploy.

    Reports every integration, database, feed, and scanner with its status,
    computes an overall readiness score (0-100), and provides actionable
    recommendations for anything that is missing or degraded.

    **No authentication required.**  Secret values are NEVER exposed --
    only whether the corresponding env var is set.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        SystemReadinessApiV1SystemReadinessGetResponseSystemReadinessApiV1SystemReadinessGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[SystemReadinessApiV1SystemReadinessGetResponseSystemReadinessApiV1SystemReadinessGet]:
    """Full deployment readiness assessment

     Comprehensive readiness check -- the first thing a customer runs after deploy.

    Reports every integration, database, feed, and scanner with its status,
    computes an overall readiness score (0-100), and provides actionable
    recommendations for anything that is missing or degraded.

    **No authentication required.**  Secret values are NEVER exposed --
    only whether the corresponding env var is set.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[SystemReadinessApiV1SystemReadinessGetResponseSystemReadinessApiV1SystemReadinessGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> SystemReadinessApiV1SystemReadinessGetResponseSystemReadinessApiV1SystemReadinessGet | None:
    """Full deployment readiness assessment

     Comprehensive readiness check -- the first thing a customer runs after deploy.

    Reports every integration, database, feed, and scanner with its status,
    computes an overall readiness score (0-100), and provides actionable
    recommendations for anything that is missing or degraded.

    **No authentication required.**  Secret values are NEVER exposed --
    only whether the corresponding env var is set.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        SystemReadinessApiV1SystemReadinessGetResponseSystemReadinessApiV1SystemReadinessGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
