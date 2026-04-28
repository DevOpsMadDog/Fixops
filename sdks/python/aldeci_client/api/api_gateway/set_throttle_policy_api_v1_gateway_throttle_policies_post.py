from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.set_throttle_policy_api_v1_gateway_throttle_policies_post_response_set_throttle_policy_api_v1_gateway_throttle_policies_post import (
    SetThrottlePolicyApiV1GatewayThrottlePoliciesPostResponseSetThrottlePolicyApiV1GatewayThrottlePoliciesPost,
)
from ...models.throttle_policy_request import ThrottlePolicyRequest
from ...types import Response


def _get_kwargs(
    *,
    body: ThrottlePolicyRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/gateway/throttle-policies",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | SetThrottlePolicyApiV1GatewayThrottlePoliciesPostResponseSetThrottlePolicyApiV1GatewayThrottlePoliciesPost
    | None
):
    if response.status_code == 201:
        response_201 = SetThrottlePolicyApiV1GatewayThrottlePoliciesPostResponseSetThrottlePolicyApiV1GatewayThrottlePoliciesPost.from_dict(
            response.json()
        )

        return response_201

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
    | SetThrottlePolicyApiV1GatewayThrottlePoliciesPostResponseSetThrottlePolicyApiV1GatewayThrottlePoliciesPost
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
    body: ThrottlePolicyRequest,
) -> Response[
    HTTPValidationError
    | SetThrottlePolicyApiV1GatewayThrottlePoliciesPostResponseSetThrottlePolicyApiV1GatewayThrottlePoliciesPost
]:
    """Set Throttle Policy

     Set a custom throttle policy for a specific API key or IP.

    Overrides the plan tier defaults for that target. Use this to impose
    stricter limits on abusive callers or grant higher limits to VIP keys.

    Args:
        body (ThrottlePolicyRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SetThrottlePolicyApiV1GatewayThrottlePoliciesPostResponseSetThrottlePolicyApiV1GatewayThrottlePoliciesPost]
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
    body: ThrottlePolicyRequest,
) -> (
    HTTPValidationError
    | SetThrottlePolicyApiV1GatewayThrottlePoliciesPostResponseSetThrottlePolicyApiV1GatewayThrottlePoliciesPost
    | None
):
    """Set Throttle Policy

     Set a custom throttle policy for a specific API key or IP.

    Overrides the plan tier defaults for that target. Use this to impose
    stricter limits on abusive callers or grant higher limits to VIP keys.

    Args:
        body (ThrottlePolicyRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SetThrottlePolicyApiV1GatewayThrottlePoliciesPostResponseSetThrottlePolicyApiV1GatewayThrottlePoliciesPost
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ThrottlePolicyRequest,
) -> Response[
    HTTPValidationError
    | SetThrottlePolicyApiV1GatewayThrottlePoliciesPostResponseSetThrottlePolicyApiV1GatewayThrottlePoliciesPost
]:
    """Set Throttle Policy

     Set a custom throttle policy for a specific API key or IP.

    Overrides the plan tier defaults for that target. Use this to impose
    stricter limits on abusive callers or grant higher limits to VIP keys.

    Args:
        body (ThrottlePolicyRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SetThrottlePolicyApiV1GatewayThrottlePoliciesPostResponseSetThrottlePolicyApiV1GatewayThrottlePoliciesPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ThrottlePolicyRequest,
) -> (
    HTTPValidationError
    | SetThrottlePolicyApiV1GatewayThrottlePoliciesPostResponseSetThrottlePolicyApiV1GatewayThrottlePoliciesPost
    | None
):
    """Set Throttle Policy

     Set a custom throttle policy for a specific API key or IP.

    Overrides the plan tier defaults for that target. Use this to impose
    stricter limits on abusive callers or grant higher limits to VIP keys.

    Args:
        body (ThrottlePolicyRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SetThrottlePolicyApiV1GatewayThrottlePoliciesPostResponseSetThrottlePolicyApiV1GatewayThrottlePoliciesPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
