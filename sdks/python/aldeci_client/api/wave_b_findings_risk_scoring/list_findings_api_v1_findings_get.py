from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_findings_api_v1_findings_get_response_list_findings_api_v1_findings_get import (
    ListFindingsApiV1FindingsGetResponseListFindingsApiV1FindingsGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    status: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    source_tool: None | str | Unset = UNSET,
    limit: int | Unset = 500,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_status: None | str | Unset
    if isinstance(status, Unset):
        json_status = UNSET
    else:
        json_status = status
    params["status"] = json_status

    json_severity: None | str | Unset
    if isinstance(severity, Unset):
        json_severity = UNSET
    else:
        json_severity = severity
    params["severity"] = json_severity

    json_source_tool: None | str | Unset
    if isinstance(source_tool, Unset):
        json_source_tool = UNSET
    else:
        json_source_tool = source_tool
    params["source_tool"] = json_source_tool

    params["limit"] = limit

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/findings",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | ListFindingsApiV1FindingsGetResponseListFindingsApiV1FindingsGet | None:
    if response.status_code == 200:
        response_200 = ListFindingsApiV1FindingsGetResponseListFindingsApiV1FindingsGet.from_dict(response.json())

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
) -> Response[HTTPValidationError | ListFindingsApiV1FindingsGetResponseListFindingsApiV1FindingsGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    source_tool: None | str | Unset = UNSET,
    limit: int | Unset = 500,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | ListFindingsApiV1FindingsGetResponseListFindingsApiV1FindingsGet]:
    """Wave-B-03 — Filterable findings list

     List findings with rich filtering.

    Lifecycle terms (``new``, ``unchanged``, ``resolved``) are mapped to the
    engine's stored ``status`` column.

    Args:
        status (None | str | Unset): Lifecycle status filter (new|unchanged|resolved) or canonical
            engine status (open|in-progress|...)
        severity (None | str | Unset):
        source_tool (None | str | Unset):
        limit (int | Unset):  Default: 500.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListFindingsApiV1FindingsGetResponseListFindingsApiV1FindingsGet]
    """

    kwargs = _get_kwargs(
        status=status,
        severity=severity,
        source_tool=source_tool,
        limit=limit,
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
    status: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    source_tool: None | str | Unset = UNSET,
    limit: int | Unset = 500,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | ListFindingsApiV1FindingsGetResponseListFindingsApiV1FindingsGet | None:
    """Wave-B-03 — Filterable findings list

     List findings with rich filtering.

    Lifecycle terms (``new``, ``unchanged``, ``resolved``) are mapped to the
    engine's stored ``status`` column.

    Args:
        status (None | str | Unset): Lifecycle status filter (new|unchanged|resolved) or canonical
            engine status (open|in-progress|...)
        severity (None | str | Unset):
        source_tool (None | str | Unset):
        limit (int | Unset):  Default: 500.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListFindingsApiV1FindingsGetResponseListFindingsApiV1FindingsGet
    """

    return sync_detailed(
        client=client,
        status=status,
        severity=severity,
        source_tool=source_tool,
        limit=limit,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    source_tool: None | str | Unset = UNSET,
    limit: int | Unset = 500,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | ListFindingsApiV1FindingsGetResponseListFindingsApiV1FindingsGet]:
    """Wave-B-03 — Filterable findings list

     List findings with rich filtering.

    Lifecycle terms (``new``, ``unchanged``, ``resolved``) are mapped to the
    engine's stored ``status`` column.

    Args:
        status (None | str | Unset): Lifecycle status filter (new|unchanged|resolved) or canonical
            engine status (open|in-progress|...)
        severity (None | str | Unset):
        source_tool (None | str | Unset):
        limit (int | Unset):  Default: 500.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListFindingsApiV1FindingsGetResponseListFindingsApiV1FindingsGet]
    """

    kwargs = _get_kwargs(
        status=status,
        severity=severity,
        source_tool=source_tool,
        limit=limit,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    source_tool: None | str | Unset = UNSET,
    limit: int | Unset = 500,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | ListFindingsApiV1FindingsGetResponseListFindingsApiV1FindingsGet | None:
    """Wave-B-03 — Filterable findings list

     List findings with rich filtering.

    Lifecycle terms (``new``, ``unchanged``, ``resolved``) are mapped to the
    engine's stored ``status`` column.

    Args:
        status (None | str | Unset): Lifecycle status filter (new|unchanged|resolved) or canonical
            engine status (open|in-progress|...)
        severity (None | str | Unset):
        source_tool (None | str | Unset):
        limit (int | Unset):  Default: 500.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListFindingsApiV1FindingsGetResponseListFindingsApiV1FindingsGet
    """

    return (
        await asyncio_detailed(
            client=client,
            status=status,
            severity=severity,
            source_tool=source_tool,
            limit=limit,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
