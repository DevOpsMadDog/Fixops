from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.changes_material_api_v1_changes_material_get_response_changes_material_api_v1_changes_material_get import (
    ChangesMaterialApiV1ChangesMaterialGetResponseChangesMaterialApiV1ChangesMaterialGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str | Unset = "default",
    kind: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    json_kind: None | str | Unset
    if isinstance(kind, Unset):
        json_kind = UNSET
    else:
        json_kind = kind
    params["kind"] = json_kind

    json_severity: None | str | Unset
    if isinstance(severity, Unset):
        json_severity = UNSET
    else:
        json_severity = severity
    params["severity"] = json_severity

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/changes/material",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ChangesMaterialApiV1ChangesMaterialGetResponseChangesMaterialApiV1ChangesMaterialGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = ChangesMaterialApiV1ChangesMaterialGetResponseChangesMaterialApiV1ChangesMaterialGet.from_dict(
            response.json()
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
    ChangesMaterialApiV1ChangesMaterialGetResponseChangesMaterialApiV1ChangesMaterialGet | HTTPValidationError
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
    org_id: str | Unset = "default",
    kind: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> Response[
    ChangesMaterialApiV1ChangesMaterialGetResponseChangesMaterialApiV1ChangesMaterialGet | HTTPValidationError
]:
    """List material change events (filter by kind/severity)

     Query the material change ledger with optional filters.

    Args:
        org_id (str | Unset):  Default: 'default'.
        kind (None | str | Unset): dependency|config|secret|crypto|infra|rbac|other
        severity (None | str | Unset): critical|high|medium|low|info
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ChangesMaterialApiV1ChangesMaterialGetResponseChangesMaterialApiV1ChangesMaterialGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        kind=kind,
        severity=severity,
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    kind: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> ChangesMaterialApiV1ChangesMaterialGetResponseChangesMaterialApiV1ChangesMaterialGet | HTTPValidationError | None:
    """List material change events (filter by kind/severity)

     Query the material change ledger with optional filters.

    Args:
        org_id (str | Unset):  Default: 'default'.
        kind (None | str | Unset): dependency|config|secret|crypto|infra|rbac|other
        severity (None | str | Unset): critical|high|medium|low|info
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ChangesMaterialApiV1ChangesMaterialGetResponseChangesMaterialApiV1ChangesMaterialGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        kind=kind,
        severity=severity,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    kind: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> Response[
    ChangesMaterialApiV1ChangesMaterialGetResponseChangesMaterialApiV1ChangesMaterialGet | HTTPValidationError
]:
    """List material change events (filter by kind/severity)

     Query the material change ledger with optional filters.

    Args:
        org_id (str | Unset):  Default: 'default'.
        kind (None | str | Unset): dependency|config|secret|crypto|infra|rbac|other
        severity (None | str | Unset): critical|high|medium|low|info
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ChangesMaterialApiV1ChangesMaterialGetResponseChangesMaterialApiV1ChangesMaterialGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        kind=kind,
        severity=severity,
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    kind: None | str | Unset = UNSET,
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> ChangesMaterialApiV1ChangesMaterialGetResponseChangesMaterialApiV1ChangesMaterialGet | HTTPValidationError | None:
    """List material change events (filter by kind/severity)

     Query the material change ledger with optional filters.

    Args:
        org_id (str | Unset):  Default: 'default'.
        kind (None | str | Unset): dependency|config|secret|crypto|infra|rbac|other
        severity (None | str | Unset): critical|high|medium|low|info
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ChangesMaterialApiV1ChangesMaterialGetResponseChangesMaterialApiV1ChangesMaterialGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            kind=kind,
            severity=severity,
            limit=limit,
        )
    ).parsed
