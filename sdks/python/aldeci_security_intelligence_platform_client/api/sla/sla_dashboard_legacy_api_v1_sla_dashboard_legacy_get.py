from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.sla_dashboard_legacy_api_v1_sla_dashboard_legacy_get_response_sla_dashboard_legacy_api_v1_sla_dashboard_legacy_get import (
    SlaDashboardLegacyApiV1SlaDashboardLegacyGetResponseSlaDashboardLegacyApiV1SlaDashboardLegacyGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/sla/dashboard-legacy",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> SlaDashboardLegacyApiV1SlaDashboardLegacyGetResponseSlaDashboardLegacyApiV1SlaDashboardLegacyGet | None:
    if response.status_code == 200:
        response_200 = (
            SlaDashboardLegacyApiV1SlaDashboardLegacyGetResponseSlaDashboardLegacyApiV1SlaDashboardLegacyGet.from_dict(
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
) -> Response[SlaDashboardLegacyApiV1SlaDashboardLegacyGetResponseSlaDashboardLegacyApiV1SlaDashboardLegacyGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[SlaDashboardLegacyApiV1SlaDashboardLegacyGetResponseSlaDashboardLegacyApiV1SlaDashboardLegacyGet]:
    """Sla Dashboard Legacy

     Legacy SLA compliance dashboard — breach counts from remediation tasks.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[SlaDashboardLegacyApiV1SlaDashboardLegacyGetResponseSlaDashboardLegacyApiV1SlaDashboardLegacyGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> SlaDashboardLegacyApiV1SlaDashboardLegacyGetResponseSlaDashboardLegacyApiV1SlaDashboardLegacyGet | None:
    """Sla Dashboard Legacy

     Legacy SLA compliance dashboard — breach counts from remediation tasks.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        SlaDashboardLegacyApiV1SlaDashboardLegacyGetResponseSlaDashboardLegacyApiV1SlaDashboardLegacyGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[SlaDashboardLegacyApiV1SlaDashboardLegacyGetResponseSlaDashboardLegacyApiV1SlaDashboardLegacyGet]:
    """Sla Dashboard Legacy

     Legacy SLA compliance dashboard — breach counts from remediation tasks.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[SlaDashboardLegacyApiV1SlaDashboardLegacyGetResponseSlaDashboardLegacyApiV1SlaDashboardLegacyGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> SlaDashboardLegacyApiV1SlaDashboardLegacyGetResponseSlaDashboardLegacyApiV1SlaDashboardLegacyGet | None:
    """Sla Dashboard Legacy

     Legacy SLA compliance dashboard — breach counts from remediation tasks.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        SlaDashboardLegacyApiV1SlaDashboardLegacyGetResponseSlaDashboardLegacyApiV1SlaDashboardLegacyGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
