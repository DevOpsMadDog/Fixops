from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.core_response import CoreResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    core_id: int,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/trustgraph/cores/{core_id}/stats".format(
            core_id=quote(str(core_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> CoreResponse | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = CoreResponse.from_dict(response.json())

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
) -> Response[CoreResponse | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    core_id: int,
    *,
    client: AuthenticatedClient,
) -> Response[CoreResponse | HTTPValidationError]:
    """Get Core Stats

     Get detailed statistics for a Knowledge Core.

    Args:
        core_id: Knowledge Core ID (1-5)

    Returns:
        Core metadata and statistics

    Args:
        core_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CoreResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        core_id=core_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    core_id: int,
    *,
    client: AuthenticatedClient,
) -> CoreResponse | HTTPValidationError | None:
    """Get Core Stats

     Get detailed statistics for a Knowledge Core.

    Args:
        core_id: Knowledge Core ID (1-5)

    Returns:
        Core metadata and statistics

    Args:
        core_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CoreResponse | HTTPValidationError
    """

    return sync_detailed(
        core_id=core_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    core_id: int,
    *,
    client: AuthenticatedClient,
) -> Response[CoreResponse | HTTPValidationError]:
    """Get Core Stats

     Get detailed statistics for a Knowledge Core.

    Args:
        core_id: Knowledge Core ID (1-5)

    Returns:
        Core metadata and statistics

    Args:
        core_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CoreResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        core_id=core_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    core_id: int,
    *,
    client: AuthenticatedClient,
) -> CoreResponse | HTTPValidationError | None:
    """Get Core Stats

     Get detailed statistics for a Knowledge Core.

    Args:
        core_id: Knowledge Core ID (1-5)

    Returns:
        Core metadata and statistics

    Args:
        core_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CoreResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            core_id=core_id,
            client=client,
        )
    ).parsed
