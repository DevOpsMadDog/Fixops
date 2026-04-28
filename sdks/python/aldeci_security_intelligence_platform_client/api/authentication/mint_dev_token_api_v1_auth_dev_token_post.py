from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.dev_token_request import DevTokenRequest
from ...models.dev_token_response import DevTokenResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    *,
    body: DevTokenRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/auth/dev-token",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> DevTokenResponse | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = DevTokenResponse.from_dict(response.json())

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
) -> Response[DevTokenResponse | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: DevTokenRequest,
) -> Response[DevTokenResponse | HTTPValidationError]:
    """Mint a short-lived JWT for local dev / Playwright (FIXOPS_DEV_MODE=true required)

     Mint a short-lived JWT for dev/Playwright workflows.

    Gated by FIXOPS_DEV_MODE=true. In production this returns 403.
    Every successful mint is audit-logged with org_id, role, email, IP.

    Args:
        body (DevTokenRequest): Request body for /api/v1/auth/dev-token.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DevTokenResponse | HTTPValidationError]
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
    body: DevTokenRequest,
) -> DevTokenResponse | HTTPValidationError | None:
    """Mint a short-lived JWT for local dev / Playwright (FIXOPS_DEV_MODE=true required)

     Mint a short-lived JWT for dev/Playwright workflows.

    Gated by FIXOPS_DEV_MODE=true. In production this returns 403.
    Every successful mint is audit-logged with org_id, role, email, IP.

    Args:
        body (DevTokenRequest): Request body for /api/v1/auth/dev-token.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DevTokenResponse | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: DevTokenRequest,
) -> Response[DevTokenResponse | HTTPValidationError]:
    """Mint a short-lived JWT for local dev / Playwright (FIXOPS_DEV_MODE=true required)

     Mint a short-lived JWT for dev/Playwright workflows.

    Gated by FIXOPS_DEV_MODE=true. In production this returns 403.
    Every successful mint is audit-logged with org_id, role, email, IP.

    Args:
        body (DevTokenRequest): Request body for /api/v1/auth/dev-token.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DevTokenResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: DevTokenRequest,
) -> DevTokenResponse | HTTPValidationError | None:
    """Mint a short-lived JWT for local dev / Playwright (FIXOPS_DEV_MODE=true required)

     Mint a short-lived JWT for dev/Playwright workflows.

    Gated by FIXOPS_DEV_MODE=true. In production this returns 403.
    Every successful mint is audit-logged with org_id, role, email, IP.

    Args:
        body (DevTokenRequest): Request body for /api/v1/auth/dev-token.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DevTokenResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
