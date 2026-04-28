from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.system_traces_recent_api_v1_system_traces_recent_get_response_system_traces_recent_api_v1_system_traces_recent_get import (
    SystemTracesRecentApiV1SystemTracesRecentGetResponseSystemTracesRecentApiV1SystemTracesRecentGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    limit: int | Unset = 50,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/system/traces/recent",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | SystemTracesRecentApiV1SystemTracesRecentGetResponseSystemTracesRecentApiV1SystemTracesRecentGet
    | None
):
    if response.status_code == 200:
        response_200 = (
            SystemTracesRecentApiV1SystemTracesRecentGetResponseSystemTracesRecentApiV1SystemTracesRecentGet.from_dict(
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
    HTTPValidationError
    | SystemTracesRecentApiV1SystemTracesRecentGetResponseSystemTracesRecentApiV1SystemTracesRecentGet
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
    limit: int | Unset = 50,
) -> Response[
    HTTPValidationError
    | SystemTracesRecentApiV1SystemTracesRecentGetResponseSystemTracesRecentApiV1SystemTracesRecentGet
]:
    """Recent distributed traces with timing

     Return summaries of the last N completed distributed traces.

    Each entry includes trace_id, operation, service, span_count,
    total_duration_ms, status, org_id, and engine_name (when set by engine calls).
    Useful for diagnosing latency and correlating engine call paths to log entries.

    Args:
        limit (int | Unset): Max traces to return Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SystemTracesRecentApiV1SystemTracesRecentGetResponseSystemTracesRecentApiV1SystemTracesRecentGet]
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
    limit: int | Unset = 50,
) -> (
    HTTPValidationError
    | SystemTracesRecentApiV1SystemTracesRecentGetResponseSystemTracesRecentApiV1SystemTracesRecentGet
    | None
):
    """Recent distributed traces with timing

     Return summaries of the last N completed distributed traces.

    Each entry includes trace_id, operation, service, span_count,
    total_duration_ms, status, org_id, and engine_name (when set by engine calls).
    Useful for diagnosing latency and correlating engine call paths to log entries.

    Args:
        limit (int | Unset): Max traces to return Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SystemTracesRecentApiV1SystemTracesRecentGetResponseSystemTracesRecentApiV1SystemTracesRecentGet
    """

    return sync_detailed(
        client=client,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 50,
) -> Response[
    HTTPValidationError
    | SystemTracesRecentApiV1SystemTracesRecentGetResponseSystemTracesRecentApiV1SystemTracesRecentGet
]:
    """Recent distributed traces with timing

     Return summaries of the last N completed distributed traces.

    Each entry includes trace_id, operation, service, span_count,
    total_duration_ms, status, org_id, and engine_name (when set by engine calls).
    Useful for diagnosing latency and correlating engine call paths to log entries.

    Args:
        limit (int | Unset): Max traces to return Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SystemTracesRecentApiV1SystemTracesRecentGetResponseSystemTracesRecentApiV1SystemTracesRecentGet]
    """

    kwargs = _get_kwargs(
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 50,
) -> (
    HTTPValidationError
    | SystemTracesRecentApiV1SystemTracesRecentGetResponseSystemTracesRecentApiV1SystemTracesRecentGet
    | None
):
    """Recent distributed traces with timing

     Return summaries of the last N completed distributed traces.

    Each entry includes trace_id, operation, service, span_count,
    total_duration_ms, status, org_id, and engine_name (when set by engine calls).
    Useful for diagnosing latency and correlating engine call paths to log entries.

    Args:
        limit (int | Unset): Max traces to return Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SystemTracesRecentApiV1SystemTracesRecentGetResponseSystemTracesRecentApiV1SystemTracesRecentGet
    """

    return (
        await asyncio_detailed(
            client=client,
            limit=limit,
        )
    ).parsed
