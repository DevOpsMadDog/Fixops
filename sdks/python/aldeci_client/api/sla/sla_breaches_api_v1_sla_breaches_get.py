from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.sla_breaches_api_v1_sla_breaches_get_response_sla_breaches_api_v1_sla_breaches_get import (
    SlaBreachesApiV1SlaBreachesGetResponseSlaBreachesApiV1SlaBreachesGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/sla/breaches",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> SlaBreachesApiV1SlaBreachesGetResponseSlaBreachesApiV1SlaBreachesGet | None:
    if response.status_code == 200:
        response_200 = SlaBreachesApiV1SlaBreachesGetResponseSlaBreachesApiV1SlaBreachesGet.from_dict(response.json())

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[SlaBreachesApiV1SlaBreachesGetResponseSlaBreachesApiV1SlaBreachesGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[SlaBreachesApiV1SlaBreachesGetResponseSlaBreachesApiV1SlaBreachesGet]:
    """Sla Breaches

     List current SLA breaches (task-level, legacy view).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[SlaBreachesApiV1SlaBreachesGetResponseSlaBreachesApiV1SlaBreachesGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> SlaBreachesApiV1SlaBreachesGetResponseSlaBreachesApiV1SlaBreachesGet | None:
    """Sla Breaches

     List current SLA breaches (task-level, legacy view).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        SlaBreachesApiV1SlaBreachesGetResponseSlaBreachesApiV1SlaBreachesGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[SlaBreachesApiV1SlaBreachesGetResponseSlaBreachesApiV1SlaBreachesGet]:
    """Sla Breaches

     List current SLA breaches (task-level, legacy view).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[SlaBreachesApiV1SlaBreachesGetResponseSlaBreachesApiV1SlaBreachesGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> SlaBreachesApiV1SlaBreachesGetResponseSlaBreachesApiV1SlaBreachesGet | None:
    """Sla Breaches

     List current SLA breaches (task-level, legacy view).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        SlaBreachesApiV1SlaBreachesGetResponseSlaBreachesApiV1SlaBreachesGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
