from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_version_api_v1_version_get_response_get_version_api_v1_version_get import (
    GetVersionApiV1VersionGetResponseGetVersionApiV1VersionGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/version",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetVersionApiV1VersionGetResponseGetVersionApiV1VersionGet | None:
    if response.status_code == 200:
        response_200 = GetVersionApiV1VersionGetResponseGetVersionApiV1VersionGet.from_dict(response.json())

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[GetVersionApiV1VersionGetResponseGetVersionApiV1VersionGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[GetVersionApiV1VersionGetResponseGetVersionApiV1VersionGet]:
    """API version information

     Return API version metadata.

    Response fields:
    - **version**: Semantic version of the ALDECI API (e.g. ``1.0.0``)
    - **build_date**: Date the current build was produced (``YYYY-MM-DD``)
    - **git_commit**: Short git SHA of the deployed revision
    - **deprecated_endpoints**: Count of currently deprecated API paths
    - **timestamp**: UTC timestamp of this response

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetVersionApiV1VersionGetResponseGetVersionApiV1VersionGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
) -> GetVersionApiV1VersionGetResponseGetVersionApiV1VersionGet | None:
    """API version information

     Return API version metadata.

    Response fields:
    - **version**: Semantic version of the ALDECI API (e.g. ``1.0.0``)
    - **build_date**: Date the current build was produced (``YYYY-MM-DD``)
    - **git_commit**: Short git SHA of the deployed revision
    - **deprecated_endpoints**: Count of currently deprecated API paths
    - **timestamp**: UTC timestamp of this response

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetVersionApiV1VersionGetResponseGetVersionApiV1VersionGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[GetVersionApiV1VersionGetResponseGetVersionApiV1VersionGet]:
    """API version information

     Return API version metadata.

    Response fields:
    - **version**: Semantic version of the ALDECI API (e.g. ``1.0.0``)
    - **build_date**: Date the current build was produced (``YYYY-MM-DD``)
    - **git_commit**: Short git SHA of the deployed revision
    - **deprecated_endpoints**: Count of currently deprecated API paths
    - **timestamp**: UTC timestamp of this response

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetVersionApiV1VersionGetResponseGetVersionApiV1VersionGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
) -> GetVersionApiV1VersionGetResponseGetVersionApiV1VersionGet | None:
    """API version information

     Return API version metadata.

    Response fields:
    - **version**: Semantic version of the ALDECI API (e.g. ``1.0.0``)
    - **build_date**: Date the current build was produced (``YYYY-MM-DD``)
    - **git_commit**: Short git SHA of the deployed revision
    - **deprecated_endpoints**: Count of currently deprecated API paths
    - **timestamp**: UTC timestamp of this response

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetVersionApiV1VersionGetResponseGetVersionApiV1VersionGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
