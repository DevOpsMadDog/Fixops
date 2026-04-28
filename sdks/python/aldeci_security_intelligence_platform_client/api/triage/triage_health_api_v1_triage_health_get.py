from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.triage_health_api_v1_triage_health_get_response_triage_health_api_v1_triage_health_get import (
    TriageHealthApiV1TriageHealthGetResponseTriageHealthApiV1TriageHealthGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/triage/health",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> TriageHealthApiV1TriageHealthGetResponseTriageHealthApiV1TriageHealthGet | None:
    if response.status_code == 200:
        response_200 = TriageHealthApiV1TriageHealthGetResponseTriageHealthApiV1TriageHealthGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[TriageHealthApiV1TriageHealthGetResponseTriageHealthApiV1TriageHealthGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[TriageHealthApiV1TriageHealthGetResponseTriageHealthApiV1TriageHealthGet]:
    """Triage Health

     Health check for triage subsystem.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[TriageHealthApiV1TriageHealthGetResponseTriageHealthApiV1TriageHealthGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> TriageHealthApiV1TriageHealthGetResponseTriageHealthApiV1TriageHealthGet | None:
    """Triage Health

     Health check for triage subsystem.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        TriageHealthApiV1TriageHealthGetResponseTriageHealthApiV1TriageHealthGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[TriageHealthApiV1TriageHealthGetResponseTriageHealthApiV1TriageHealthGet]:
    """Triage Health

     Health check for triage subsystem.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[TriageHealthApiV1TriageHealthGetResponseTriageHealthApiV1TriageHealthGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> TriageHealthApiV1TriageHealthGetResponseTriageHealthApiV1TriageHealthGet | None:
    """Triage Health

     Health check for triage subsystem.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        TriageHealthApiV1TriageHealthGetResponseTriageHealthApiV1TriageHealthGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
