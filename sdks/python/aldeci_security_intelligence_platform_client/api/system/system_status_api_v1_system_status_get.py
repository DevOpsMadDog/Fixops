from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.system_status_api_v1_system_status_get_response_system_status_api_v1_system_status_get import (
    SystemStatusApiV1SystemStatusGetResponseSystemStatusApiV1SystemStatusGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/system/status",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> SystemStatusApiV1SystemStatusGetResponseSystemStatusApiV1SystemStatusGet | None:
    if response.status_code == 200:
        response_200 = SystemStatusApiV1SystemStatusGetResponseSystemStatusApiV1SystemStatusGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[SystemStatusApiV1SystemStatusGetResponseSystemStatusApiV1SystemStatusGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[SystemStatusApiV1SystemStatusGetResponseSystemStatusApiV1SystemStatusGet]:
    """System status overview

     Return simplified system status for dashboards.

    Provides a quick UP/DOWN status with key indicators derived from real checks.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[SystemStatusApiV1SystemStatusGetResponseSystemStatusApiV1SystemStatusGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> SystemStatusApiV1SystemStatusGetResponseSystemStatusApiV1SystemStatusGet | None:
    """System status overview

     Return simplified system status for dashboards.

    Provides a quick UP/DOWN status with key indicators derived from real checks.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        SystemStatusApiV1SystemStatusGetResponseSystemStatusApiV1SystemStatusGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[SystemStatusApiV1SystemStatusGetResponseSystemStatusApiV1SystemStatusGet]:
    """System status overview

     Return simplified system status for dashboards.

    Provides a quick UP/DOWN status with key indicators derived from real checks.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[SystemStatusApiV1SystemStatusGetResponseSystemStatusApiV1SystemStatusGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> SystemStatusApiV1SystemStatusGetResponseSystemStatusApiV1SystemStatusGet | None:
    """System status overview

     Return simplified system status for dashboards.

    Provides a quick UP/DOWN status with key indicators derived from real checks.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        SystemStatusApiV1SystemStatusGetResponseSystemStatusApiV1SystemStatusGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
