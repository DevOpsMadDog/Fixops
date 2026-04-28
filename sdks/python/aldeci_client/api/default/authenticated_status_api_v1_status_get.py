from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.authenticated_status_api_v1_status_get_response_authenticated_status_api_v1_status_get import (
    AuthenticatedStatusApiV1StatusGetResponseAuthenticatedStatusApiV1StatusGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/status",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AuthenticatedStatusApiV1StatusGetResponseAuthenticatedStatusApiV1StatusGet | None:
    if response.status_code == 200:
        response_200 = AuthenticatedStatusApiV1StatusGetResponseAuthenticatedStatusApiV1StatusGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[AuthenticatedStatusApiV1StatusGetResponseAuthenticatedStatusApiV1StatusGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[AuthenticatedStatusApiV1StatusGetResponseAuthenticatedStatusApiV1StatusGet]:
    """Authenticated Status

     Authenticated status endpoint.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AuthenticatedStatusApiV1StatusGetResponseAuthenticatedStatusApiV1StatusGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> AuthenticatedStatusApiV1StatusGetResponseAuthenticatedStatusApiV1StatusGet | None:
    """Authenticated Status

     Authenticated status endpoint.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AuthenticatedStatusApiV1StatusGetResponseAuthenticatedStatusApiV1StatusGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[AuthenticatedStatusApiV1StatusGetResponseAuthenticatedStatusApiV1StatusGet]:
    """Authenticated Status

     Authenticated status endpoint.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AuthenticatedStatusApiV1StatusGetResponseAuthenticatedStatusApiV1StatusGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> AuthenticatedStatusApiV1StatusGetResponseAuthenticatedStatusApiV1StatusGet | None:
    """Authenticated Status

     Authenticated status endpoint.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AuthenticatedStatusApiV1StatusGetResponseAuthenticatedStatusApiV1StatusGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
