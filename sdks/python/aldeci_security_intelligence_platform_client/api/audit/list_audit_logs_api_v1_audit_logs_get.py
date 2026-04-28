from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.paginated_audit_log_response import PaginatedAuditLogResponse
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    event_type: None | str | Unset = UNSET,
    user_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_event_type: None | str | Unset
    if isinstance(event_type, Unset):
        json_event_type = UNSET
    else:
        json_event_type = event_type
    params["event_type"] = json_event_type

    json_user_id: None | str | Unset
    if isinstance(user_id, Unset):
        json_user_id = UNSET
    else:
        json_user_id = user_id
    params["user_id"] = json_user_id

    params["limit"] = limit

    params["offset"] = offset

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/audit/logs",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | PaginatedAuditLogResponse | None:
    if response.status_code == 200:
        response_200 = PaginatedAuditLogResponse.from_dict(response.json())

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
) -> Response[HTTPValidationError | PaginatedAuditLogResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    event_type: None | str | Unset = UNSET,
    user_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | PaginatedAuditLogResponse]:
    """List Audit Logs

     Query audit logs with optional filtering.

    AUTHZ-VULN-09: org_id is applied to filter results to the caller's tenant only.

    Args:
        event_type (None | str | Unset):
        user_id (None | str | Unset):
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | PaginatedAuditLogResponse]
    """

    kwargs = _get_kwargs(
        event_type=event_type,
        user_id=user_id,
        limit=limit,
        offset=offset,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    event_type: None | str | Unset = UNSET,
    user_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | PaginatedAuditLogResponse | None:
    """List Audit Logs

     Query audit logs with optional filtering.

    AUTHZ-VULN-09: org_id is applied to filter results to the caller's tenant only.

    Args:
        event_type (None | str | Unset):
        user_id (None | str | Unset):
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | PaginatedAuditLogResponse
    """

    return sync_detailed(
        client=client,
        event_type=event_type,
        user_id=user_id,
        limit=limit,
        offset=offset,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    event_type: None | str | Unset = UNSET,
    user_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | PaginatedAuditLogResponse]:
    """List Audit Logs

     Query audit logs with optional filtering.

    AUTHZ-VULN-09: org_id is applied to filter results to the caller's tenant only.

    Args:
        event_type (None | str | Unset):
        user_id (None | str | Unset):
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | PaginatedAuditLogResponse]
    """

    kwargs = _get_kwargs(
        event_type=event_type,
        user_id=user_id,
        limit=limit,
        offset=offset,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    event_type: None | str | Unset = UNSET,
    user_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | PaginatedAuditLogResponse | None:
    """List Audit Logs

     Query audit logs with optional filtering.

    AUTHZ-VULN-09: org_id is applied to filter results to the caller's tenant only.

    Args:
        event_type (None | str | Unset):
        user_id (None | str | Unset):
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | PaginatedAuditLogResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            event_type=event_type,
            user_id=user_id,
            limit=limit,
            offset=offset,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
