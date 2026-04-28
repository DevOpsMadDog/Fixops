from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.system_logs_recent_api_v1_system_logs_recent_get_response_system_logs_recent_api_v1_system_logs_recent_get import (
    SystemLogsRecentApiV1SystemLogsRecentGetResponseSystemLogsRecentApiV1SystemLogsRecentGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    limit: int | Unset = 100,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/system/logs/recent",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | SystemLogsRecentApiV1SystemLogsRecentGetResponseSystemLogsRecentApiV1SystemLogsRecentGet
    | None
):
    if response.status_code == 200:
        response_200 = (
            SystemLogsRecentApiV1SystemLogsRecentGetResponseSystemLogsRecentApiV1SystemLogsRecentGet.from_dict(
                response.json()
            )
        )

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
) -> Response[
    HTTPValidationError | SystemLogsRecentApiV1SystemLogsRecentGetResponseSystemLogsRecentApiV1SystemLogsRecentGet
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> Response[
    HTTPValidationError | SystemLogsRecentApiV1SystemLogsRecentGetResponseSystemLogsRecentApiV1SystemLogsRecentGet
]:
    """Recent structured request logs

     Return the last N structured request/response log entries from the in-memory ring buffer.

    Fields per entry: request_id, correlation_id, org_id, method, path,
    status_code, duration_ms, req_size, resp_size, level, ts.

    Args:
        limit: Number of entries to return (1-500, default 100).

    Returns:
        JSON with ``logs`` list and ``count``.

    Args:
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SystemLogsRecentApiV1SystemLogsRecentGetResponseSystemLogsRecentApiV1SystemLogsRecentGet]
    """

    kwargs = _get_kwargs(
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> (
    HTTPValidationError
    | SystemLogsRecentApiV1SystemLogsRecentGetResponseSystemLogsRecentApiV1SystemLogsRecentGet
    | None
):
    """Recent structured request logs

     Return the last N structured request/response log entries from the in-memory ring buffer.

    Fields per entry: request_id, correlation_id, org_id, method, path,
    status_code, duration_ms, req_size, resp_size, level, ts.

    Args:
        limit: Number of entries to return (1-500, default 100).

    Returns:
        JSON with ``logs`` list and ``count``.

    Args:
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SystemLogsRecentApiV1SystemLogsRecentGetResponseSystemLogsRecentApiV1SystemLogsRecentGet
    """

    return sync_detailed(
        client=client,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> Response[
    HTTPValidationError | SystemLogsRecentApiV1SystemLogsRecentGetResponseSystemLogsRecentApiV1SystemLogsRecentGet
]:
    """Recent structured request logs

     Return the last N structured request/response log entries from the in-memory ring buffer.

    Fields per entry: request_id, correlation_id, org_id, method, path,
    status_code, duration_ms, req_size, resp_size, level, ts.

    Args:
        limit: Number of entries to return (1-500, default 100).

    Returns:
        JSON with ``logs`` list and ``count``.

    Args:
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SystemLogsRecentApiV1SystemLogsRecentGetResponseSystemLogsRecentApiV1SystemLogsRecentGet]
    """

    kwargs = _get_kwargs(
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> (
    HTTPValidationError
    | SystemLogsRecentApiV1SystemLogsRecentGetResponseSystemLogsRecentApiV1SystemLogsRecentGet
    | None
):
    """Recent structured request logs

     Return the last N structured request/response log entries from the in-memory ring buffer.

    Fields per entry: request_id, correlation_id, org_id, method, path,
    status_code, duration_ms, req_size, resp_size, level, ts.

    Args:
        limit: Number of entries to return (1-500, default 100).

    Returns:
        JSON with ``logs`` list and ``count``.

    Args:
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SystemLogsRecentApiV1SystemLogsRecentGetResponseSystemLogsRecentApiV1SystemLogsRecentGet
    """

    return (
        await asyncio_detailed(
            client=client,
            limit=limit,
        )
    ).parsed
