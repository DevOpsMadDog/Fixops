from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.finding_response import FindingResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    severity: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_severity: None | str | Unset
    if isinstance(severity, Unset):
        json_severity = UNSET
    else:
        json_severity = severity
    params["severity"] = json_severity

    json_status: None | str | Unset
    if isinstance(status, Unset):
        json_status = UNSET
    else:
        json_status = status
    params["status"] = json_status

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
        "url": "/api/v1/analytics/findings",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[FindingResponse] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = FindingResponse.from_dict(response_200_item_data)

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
) -> Response[HTTPValidationError | list[FindingResponse]]:
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
    status: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[FindingResponse]]:
    """Query Findings

     Query findings with filters. Returns real ingested findings.

    Args:
        severity (None | str | Unset):
        status (None | str | Unset):
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[FindingResponse]]
    """

    kwargs = _get_kwargs(
        severity=severity,
        status=status,
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
    severity: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | list[FindingResponse] | None:
    """Query Findings

     Query findings with filters. Returns real ingested findings.

    Args:
        severity (None | str | Unset):
        status (None | str | Unset):
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[FindingResponse]
    """

    return sync_detailed(
        client=client,
        severity=severity,
        status=status,
        limit=limit,
        offset=offset,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    severity: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[FindingResponse]]:
    """Query Findings

     Query findings with filters. Returns real ingested findings.

    Args:
        severity (None | str | Unset):
        status (None | str | Unset):
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[FindingResponse]]
    """

    kwargs = _get_kwargs(
        severity=severity,
        status=status,
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
    severity: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | list[FindingResponse] | None:
    """Query Findings

     Query findings with filters. Returns real ingested findings.

    Args:
        severity (None | str | Unset):
        status (None | str | Unset):
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[FindingResponse]
    """

    return (
        await asyncio_detailed(
            client=client,
            severity=severity,
            status=status,
            limit=limit,
            offset=offset,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
