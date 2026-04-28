from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_audit_log_api_v1_trustgraph_audit_log_get_response_200_item import (
    GetAuditLogApiV1TrustgraphAuditLogGetResponse200Item,
)
from ...models.http_validation_error import HTTPValidationError
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
        "url": "/api/v1/trustgraph/audit/log",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[GetAuditLogApiV1TrustgraphAuditLogGetResponse200Item] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = GetAuditLogApiV1TrustgraphAuditLogGetResponse200Item.from_dict(response_200_item_data)

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
) -> Response[HTTPValidationError | list[GetAuditLogApiV1TrustgraphAuditLogGetResponse200Item]]:
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
) -> Response[HTTPValidationError | list[GetAuditLogApiV1TrustgraphAuditLogGetResponse200Item]]:
    """Get Audit Log

     Get recent tool call audit logs.

    Args:
        limit: Maximum records to return

    Returns:
        List of audit records

    Args:
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetAuditLogApiV1TrustgraphAuditLogGetResponse200Item]]
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
) -> HTTPValidationError | list[GetAuditLogApiV1TrustgraphAuditLogGetResponse200Item] | None:
    """Get Audit Log

     Get recent tool call audit logs.

    Args:
        limit: Maximum records to return

    Returns:
        List of audit records

    Args:
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetAuditLogApiV1TrustgraphAuditLogGetResponse200Item]
    """

    return sync_detailed(
        client=client,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> Response[HTTPValidationError | list[GetAuditLogApiV1TrustgraphAuditLogGetResponse200Item]]:
    """Get Audit Log

     Get recent tool call audit logs.

    Args:
        limit: Maximum records to return

    Returns:
        List of audit records

    Args:
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetAuditLogApiV1TrustgraphAuditLogGetResponse200Item]]
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
) -> HTTPValidationError | list[GetAuditLogApiV1TrustgraphAuditLogGetResponse200Item] | None:
    """Get Audit Log

     Get recent tool call audit logs.

    Args:
        limit: Maximum records to return

    Returns:
        List of audit records

    Args:
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetAuditLogApiV1TrustgraphAuditLogGetResponse200Item]
    """

    return (
        await asyncio_detailed(
            client=client,
            limit=limit,
        )
    ).parsed
