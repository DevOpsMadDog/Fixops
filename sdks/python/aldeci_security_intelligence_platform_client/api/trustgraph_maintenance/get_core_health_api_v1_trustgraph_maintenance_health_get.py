from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_core_health_api_v1_trustgraph_maintenance_health_get_response_get_core_health_api_v1_trustgraph_maintenance_health_get import (
    GetCoreHealthApiV1TrustgraphMaintenanceHealthGetResponseGetCoreHealthApiV1TrustgraphMaintenanceHealthGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/trustgraph/maintenance/health",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetCoreHealthApiV1TrustgraphMaintenanceHealthGetResponseGetCoreHealthApiV1TrustgraphMaintenanceHealthGet | None:
    if response.status_code == 200:
        response_200 = GetCoreHealthApiV1TrustgraphMaintenanceHealthGetResponseGetCoreHealthApiV1TrustgraphMaintenanceHealthGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[GetCoreHealthApiV1TrustgraphMaintenanceHealthGetResponseGetCoreHealthApiV1TrustgraphMaintenanceHealthGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetCoreHealthApiV1TrustgraphMaintenanceHealthGetResponseGetCoreHealthApiV1TrustgraphMaintenanceHealthGet]:
    """Get Core Health

     Get health scores (0-100) for all 5 Knowledge Cores.

    Score penalises:
    - Low entity connectivity (no relationships)
    - High staleness (not updated in 30 days)
    - Missing required fields (severity in Core 2)

    Returns:
        Dict mapping core_id string to health details and score.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetCoreHealthApiV1TrustgraphMaintenanceHealthGetResponseGetCoreHealthApiV1TrustgraphMaintenanceHealthGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> GetCoreHealthApiV1TrustgraphMaintenanceHealthGetResponseGetCoreHealthApiV1TrustgraphMaintenanceHealthGet | None:
    """Get Core Health

     Get health scores (0-100) for all 5 Knowledge Cores.

    Score penalises:
    - Low entity connectivity (no relationships)
    - High staleness (not updated in 30 days)
    - Missing required fields (severity in Core 2)

    Returns:
        Dict mapping core_id string to health details and score.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetCoreHealthApiV1TrustgraphMaintenanceHealthGetResponseGetCoreHealthApiV1TrustgraphMaintenanceHealthGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetCoreHealthApiV1TrustgraphMaintenanceHealthGetResponseGetCoreHealthApiV1TrustgraphMaintenanceHealthGet]:
    """Get Core Health

     Get health scores (0-100) for all 5 Knowledge Cores.

    Score penalises:
    - Low entity connectivity (no relationships)
    - High staleness (not updated in 30 days)
    - Missing required fields (severity in Core 2)

    Returns:
        Dict mapping core_id string to health details and score.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetCoreHealthApiV1TrustgraphMaintenanceHealthGetResponseGetCoreHealthApiV1TrustgraphMaintenanceHealthGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> GetCoreHealthApiV1TrustgraphMaintenanceHealthGetResponseGetCoreHealthApiV1TrustgraphMaintenanceHealthGet | None:
    """Get Core Health

     Get health scores (0-100) for all 5 Knowledge Cores.

    Score penalises:
    - Low entity connectivity (no relationships)
    - High staleness (not updated in 30 days)
    - Missing required fields (severity in Core 2)

    Returns:
        Dict mapping core_id string to health details and score.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetCoreHealthApiV1TrustgraphMaintenanceHealthGetResponseGetCoreHealthApiV1TrustgraphMaintenanceHealthGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
