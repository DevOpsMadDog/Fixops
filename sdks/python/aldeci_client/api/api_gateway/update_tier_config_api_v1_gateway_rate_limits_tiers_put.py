from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.update_tier_config_api_v1_gateway_rate_limits_tiers_put_response_update_tier_config_api_v1_gateway_rate_limits_tiers_put import (
    UpdateTierConfigApiV1GatewayRateLimitsTiersPutResponseUpdateTierConfigApiV1GatewayRateLimitsTiersPut,
)
from ...models.update_tier_config_request import UpdateTierConfigRequest
from ...types import Response


def _get_kwargs(
    *,
    body: UpdateTierConfigRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/gateway/rate-limits/tiers",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | UpdateTierConfigApiV1GatewayRateLimitsTiersPutResponseUpdateTierConfigApiV1GatewayRateLimitsTiersPut
    | None
):
    if response.status_code == 200:
        response_200 = UpdateTierConfigApiV1GatewayRateLimitsTiersPutResponseUpdateTierConfigApiV1GatewayRateLimitsTiersPut.from_dict(
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
    HTTPValidationError
    | UpdateTierConfigApiV1GatewayRateLimitsTiersPutResponseUpdateTierConfigApiV1GatewayRateLimitsTiersPut
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
    body: UpdateTierConfigRequest,
) -> Response[
    HTTPValidationError
    | UpdateTierConfigApiV1GatewayRateLimitsTiersPutResponseUpdateTierConfigApiV1GatewayRateLimitsTiersPut
]:
    """Update Tier Config

     Update the rate limit configuration for a plan tier.

    Args:
        body (UpdateTierConfigRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdateTierConfigApiV1GatewayRateLimitsTiersPutResponseUpdateTierConfigApiV1GatewayRateLimitsTiersPut]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: UpdateTierConfigRequest,
) -> (
    HTTPValidationError
    | UpdateTierConfigApiV1GatewayRateLimitsTiersPutResponseUpdateTierConfigApiV1GatewayRateLimitsTiersPut
    | None
):
    """Update Tier Config

     Update the rate limit configuration for a plan tier.

    Args:
        body (UpdateTierConfigRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdateTierConfigApiV1GatewayRateLimitsTiersPutResponseUpdateTierConfigApiV1GatewayRateLimitsTiersPut
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: UpdateTierConfigRequest,
) -> Response[
    HTTPValidationError
    | UpdateTierConfigApiV1GatewayRateLimitsTiersPutResponseUpdateTierConfigApiV1GatewayRateLimitsTiersPut
]:
    """Update Tier Config

     Update the rate limit configuration for a plan tier.

    Args:
        body (UpdateTierConfigRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdateTierConfigApiV1GatewayRateLimitsTiersPutResponseUpdateTierConfigApiV1GatewayRateLimitsTiersPut]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: UpdateTierConfigRequest,
) -> (
    HTTPValidationError
    | UpdateTierConfigApiV1GatewayRateLimitsTiersPutResponseUpdateTierConfigApiV1GatewayRateLimitsTiersPut
    | None
):
    """Update Tier Config

     Update the rate limit configuration for a plan tier.

    Args:
        body (UpdateTierConfigRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdateTierConfigApiV1GatewayRateLimitsTiersPutResponseUpdateTierConfigApiV1GatewayRateLimitsTiersPut
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
