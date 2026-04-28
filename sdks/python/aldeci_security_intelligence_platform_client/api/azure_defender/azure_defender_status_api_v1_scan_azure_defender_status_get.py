from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.azure_status_response import AzureStatusResponse
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/scan/azure-defender/status",
    }

    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> AzureStatusResponse | None:
    if response.status_code == 200:
        response_200 = AzureStatusResponse.from_dict(response.json())

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[AzureStatusResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[AzureStatusResponse]:
    """Check Azure Defender configuration

     Return whether Azure credentials are configured.

    When unconfigured all endpoints return mock data so the pipeline
    can be exercised without real Azure credentials.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AzureStatusResponse]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> AzureStatusResponse | None:
    """Check Azure Defender configuration

     Return whether Azure credentials are configured.

    When unconfigured all endpoints return mock data so the pipeline
    can be exercised without real Azure credentials.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AzureStatusResponse
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[AzureStatusResponse]:
    """Check Azure Defender configuration

     Return whether Azure credentials are configured.

    When unconfigured all endpoints return mock data so the pipeline
    can be exercised without real Azure credentials.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AzureStatusResponse]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> AzureStatusResponse | None:
    """Check Azure Defender configuration

     Return whether Azure credentials are configured.

    When unconfigured all endpoints return mock data so the pipeline
    can be exercised without real Azure credentials.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AzureStatusResponse
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
