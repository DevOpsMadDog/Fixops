from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    finding_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_finding_id: None | str | Unset
    if isinstance(finding_id, Unset):
        json_finding_id = UNSET
    else:
        json_finding_id = finding_id
    params["finding_id"] = json_finding_id

    params["limit"] = limit

    params["offset"] = offset

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/servicenow-sync/history",
        "params": params,
    }

    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> HTTPValidationError | None:
    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    finding_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> Response[HTTPValidationError]:
    """Paginated sync history

     Return the sync audit history, newest first.

    Optionally filter to a specific ``finding_id``. Supports pagination via
    ``limit`` and ``offset``.

    Args:
        finding_id (None | str | Unset): Filter by finding ID
        limit (int | Unset): Max records to return Default: 100.
        offset (int | Unset): Number of records to skip Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError]
    """

    kwargs = _get_kwargs(
        finding_id=finding_id,
        limit=limit,
        offset=offset,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    finding_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> HTTPValidationError | None:
    """Paginated sync history

     Return the sync audit history, newest first.

    Optionally filter to a specific ``finding_id``. Supports pagination via
    ``limit`` and ``offset``.

    Args:
        finding_id (None | str | Unset): Filter by finding ID
        limit (int | Unset): Max records to return Default: 100.
        offset (int | Unset): Number of records to skip Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError
    """

    return sync_detailed(
        client=client,
        finding_id=finding_id,
        limit=limit,
        offset=offset,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    finding_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> Response[HTTPValidationError]:
    """Paginated sync history

     Return the sync audit history, newest first.

    Optionally filter to a specific ``finding_id``. Supports pagination via
    ``limit`` and ``offset``.

    Args:
        finding_id (None | str | Unset): Filter by finding ID
        limit (int | Unset): Max records to return Default: 100.
        offset (int | Unset): Number of records to skip Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError]
    """

    kwargs = _get_kwargs(
        finding_id=finding_id,
        limit=limit,
        offset=offset,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    finding_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> HTTPValidationError | None:
    """Paginated sync history

     Return the sync audit history, newest first.

    Optionally filter to a specific ``finding_id``. Supports pagination via
    ``limit`` and ``offset``.

    Args:
        finding_id (None | str | Unset): Filter by finding ID
        limit (int | Unset): Max records to return Default: 100.
        offset (int | Unset): Number of records to skip Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            finding_id=finding_id,
            limit=limit,
            offset=offset,
        )
    ).parsed
