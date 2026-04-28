from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_stats_api_v1_cloud_stats_get_response_get_stats_api_v1_cloud_stats_get import (
    GetStatsApiV1CloudStatsGetResponseGetStatsApiV1CloudStatsGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str | Unset = "default",
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/cloud/stats",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetStatsApiV1CloudStatsGetResponseGetStatsApiV1CloudStatsGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GetStatsApiV1CloudStatsGetResponseGetStatsApiV1CloudStatsGet.from_dict(response.json())

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
) -> Response[GetStatsApiV1CloudStatsGetResponseGetStatsApiV1CloudStatsGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> Response[GetStatsApiV1CloudStatsGetResponseGetStatsApiV1CloudStatsGet | HTTPValidationError]:
    """Get discovery statistics

     Return aggregated discovery stats by provider, asset type, and region.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetStatsApiV1CloudStatsGetResponseGetStatsApiV1CloudStatsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> GetStatsApiV1CloudStatsGetResponseGetStatsApiV1CloudStatsGet | HTTPValidationError | None:
    """Get discovery statistics

     Return aggregated discovery stats by provider, asset type, and region.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetStatsApiV1CloudStatsGetResponseGetStatsApiV1CloudStatsGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> Response[GetStatsApiV1CloudStatsGetResponseGetStatsApiV1CloudStatsGet | HTTPValidationError]:
    """Get discovery statistics

     Return aggregated discovery stats by provider, asset type, and region.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetStatsApiV1CloudStatsGetResponseGetStatsApiV1CloudStatsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> GetStatsApiV1CloudStatsGetResponseGetStatsApiV1CloudStatsGet | HTTPValidationError | None:
    """Get discovery statistics

     Return aggregated discovery stats by provider, asset type, and region.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetStatsApiV1CloudStatsGetResponseGetStatsApiV1CloudStatsGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
        )
    ).parsed
