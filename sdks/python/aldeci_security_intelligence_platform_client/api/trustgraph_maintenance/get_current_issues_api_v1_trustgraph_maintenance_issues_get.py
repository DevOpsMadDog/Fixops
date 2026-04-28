from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.maintenance_issue_response import MaintenanceIssueResponse
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    severity: None | str | Unset = UNSET,
    issue_type: None | str | Unset = UNSET,
    core_id: int | None | Unset = UNSET,
    limit: int | Unset = 100,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_severity: None | str | Unset
    if isinstance(severity, Unset):
        json_severity = UNSET
    else:
        json_severity = severity
    params["severity"] = json_severity

    json_issue_type: None | str | Unset
    if isinstance(issue_type, Unset):
        json_issue_type = UNSET
    else:
        json_issue_type = issue_type
    params["issue_type"] = json_issue_type

    json_core_id: int | None | Unset
    if isinstance(core_id, Unset):
        json_core_id = UNSET
    else:
        json_core_id = core_id
    params["core_id"] = json_core_id

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/trustgraph/maintenance/issues",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[MaintenanceIssueResponse] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = MaintenanceIssueResponse.from_dict(response_200_item_data)

            response_200.append(response_200_item)

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
) -> Response[HTTPValidationError | list[MaintenanceIssueResponse]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
    issue_type: None | str | Unset = UNSET,
    core_id: int | None | Unset = UNSET,
    limit: int | Unset = 100,
) -> Response[HTTPValidationError | list[MaintenanceIssueResponse]]:
    """Get Current Issues

     Run a maintenance sweep and return the detected issues with optional filters.

    Args:
        severity: Filter to a specific severity level.
        issue_type: Filter to a specific issue type.
        core_id: Filter to issues in a specific Knowledge Core.
        limit: Maximum number of issues to return.

    Returns:
        List of MaintenanceIssue dicts, ordered by severity (critical first).

    Args:
        severity (None | str | Unset): Filter by severity: critical | high | medium | low
        issue_type (None | str | Unset): Filter by issue type: contradiction | orphan | duplicate
            | stale | missing_field | type_mismatch
        core_id (int | None | Unset): Filter by Knowledge Core ID (1-5). 0 = cross-core.
        limit (int | Unset): Maximum issues to return Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[MaintenanceIssueResponse]]
    """

    kwargs = _get_kwargs(
        severity=severity,
        issue_type=issue_type,
        core_id=core_id,
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
    issue_type: None | str | Unset = UNSET,
    core_id: int | None | Unset = UNSET,
    limit: int | Unset = 100,
) -> HTTPValidationError | list[MaintenanceIssueResponse] | None:
    """Get Current Issues

     Run a maintenance sweep and return the detected issues with optional filters.

    Args:
        severity: Filter to a specific severity level.
        issue_type: Filter to a specific issue type.
        core_id: Filter to issues in a specific Knowledge Core.
        limit: Maximum number of issues to return.

    Returns:
        List of MaintenanceIssue dicts, ordered by severity (critical first).

    Args:
        severity (None | str | Unset): Filter by severity: critical | high | medium | low
        issue_type (None | str | Unset): Filter by issue type: contradiction | orphan | duplicate
            | stale | missing_field | type_mismatch
        core_id (int | None | Unset): Filter by Knowledge Core ID (1-5). 0 = cross-core.
        limit (int | Unset): Maximum issues to return Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[MaintenanceIssueResponse]
    """

    return sync_detailed(
        client=client,
        severity=severity,
        issue_type=issue_type,
        core_id=core_id,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
    issue_type: None | str | Unset = UNSET,
    core_id: int | None | Unset = UNSET,
    limit: int | Unset = 100,
) -> Response[HTTPValidationError | list[MaintenanceIssueResponse]]:
    """Get Current Issues

     Run a maintenance sweep and return the detected issues with optional filters.

    Args:
        severity: Filter to a specific severity level.
        issue_type: Filter to a specific issue type.
        core_id: Filter to issues in a specific Knowledge Core.
        limit: Maximum number of issues to return.

    Returns:
        List of MaintenanceIssue dicts, ordered by severity (critical first).

    Args:
        severity (None | str | Unset): Filter by severity: critical | high | medium | low
        issue_type (None | str | Unset): Filter by issue type: contradiction | orphan | duplicate
            | stale | missing_field | type_mismatch
        core_id (int | None | Unset): Filter by Knowledge Core ID (1-5). 0 = cross-core.
        limit (int | Unset): Maximum issues to return Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[MaintenanceIssueResponse]]
    """

    kwargs = _get_kwargs(
        severity=severity,
        issue_type=issue_type,
        core_id=core_id,
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
    issue_type: None | str | Unset = UNSET,
    core_id: int | None | Unset = UNSET,
    limit: int | Unset = 100,
) -> HTTPValidationError | list[MaintenanceIssueResponse] | None:
    """Get Current Issues

     Run a maintenance sweep and return the detected issues with optional filters.

    Args:
        severity: Filter to a specific severity level.
        issue_type: Filter to a specific issue type.
        core_id: Filter to issues in a specific Knowledge Core.
        limit: Maximum number of issues to return.

    Returns:
        List of MaintenanceIssue dicts, ordered by severity (critical first).

    Args:
        severity (None | str | Unset): Filter by severity: critical | high | medium | low
        issue_type (None | str | Unset): Filter by issue type: contradiction | orphan | duplicate
            | stale | missing_field | type_mismatch
        core_id (int | None | Unset): Filter by Knowledge Core ID (1-5). 0 = cross-core.
        limit (int | Unset): Maximum issues to return Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[MaintenanceIssueResponse]
    """

    return (
        await asyncio_detailed(
            client=client,
            severity=severity,
            issue_type=issue_type,
            core_id=core_id,
            limit=limit,
        )
    ).parsed
