from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.query_audit_api_v1_db_security_query_audit_post_response_query_audit_api_v1_db_security_query_audit_post import (
    QueryAuditApiV1DbSecurityQueryAuditPostResponseQueryAuditApiV1DbSecurityQueryAuditPost,
)
from ...models.query_audit_request import QueryAuditRequest
from ...types import Response


def _get_kwargs(
    *,
    body: QueryAuditRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/db-security/query-audit",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError | QueryAuditApiV1DbSecurityQueryAuditPostResponseQueryAuditApiV1DbSecurityQueryAuditPost | None
):
    if response.status_code == 200:
        response_200 = QueryAuditApiV1DbSecurityQueryAuditPostResponseQueryAuditApiV1DbSecurityQueryAuditPost.from_dict(
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
    HTTPValidationError | QueryAuditApiV1DbSecurityQueryAuditPostResponseQueryAuditApiV1DbSecurityQueryAuditPost
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
    body: QueryAuditRequest,
) -> Response[
    HTTPValidationError | QueryAuditApiV1DbSecurityQueryAuditPostResponseQueryAuditApiV1DbSecurityQueryAuditPost
]:
    """Query Audit

     Analyze query audit logs for suspicious patterns.

    Detects: DROP TABLE, GRANT ALL, bulk SELECT, SQL injection, data exfiltration,
    privilege escalation, and more (14 pattern categories).

    Args:
        body (QueryAuditRequest): Analyze query audit logs for suspicious activity.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | QueryAuditApiV1DbSecurityQueryAuditPostResponseQueryAuditApiV1DbSecurityQueryAuditPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: QueryAuditRequest,
) -> (
    HTTPValidationError | QueryAuditApiV1DbSecurityQueryAuditPostResponseQueryAuditApiV1DbSecurityQueryAuditPost | None
):
    """Query Audit

     Analyze query audit logs for suspicious patterns.

    Detects: DROP TABLE, GRANT ALL, bulk SELECT, SQL injection, data exfiltration,
    privilege escalation, and more (14 pattern categories).

    Args:
        body (QueryAuditRequest): Analyze query audit logs for suspicious activity.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | QueryAuditApiV1DbSecurityQueryAuditPostResponseQueryAuditApiV1DbSecurityQueryAuditPost
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: QueryAuditRequest,
) -> Response[
    HTTPValidationError | QueryAuditApiV1DbSecurityQueryAuditPostResponseQueryAuditApiV1DbSecurityQueryAuditPost
]:
    """Query Audit

     Analyze query audit logs for suspicious patterns.

    Detects: DROP TABLE, GRANT ALL, bulk SELECT, SQL injection, data exfiltration,
    privilege escalation, and more (14 pattern categories).

    Args:
        body (QueryAuditRequest): Analyze query audit logs for suspicious activity.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | QueryAuditApiV1DbSecurityQueryAuditPostResponseQueryAuditApiV1DbSecurityQueryAuditPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: QueryAuditRequest,
) -> (
    HTTPValidationError | QueryAuditApiV1DbSecurityQueryAuditPostResponseQueryAuditApiV1DbSecurityQueryAuditPost | None
):
    """Query Audit

     Analyze query audit logs for suspicious patterns.

    Detects: DROP TABLE, GRANT ALL, bulk SELECT, SQL injection, data exfiltration,
    privilege escalation, and more (14 pattern categories).

    Args:
        body (QueryAuditRequest): Analyze query audit logs for suspicious activity.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | QueryAuditApiV1DbSecurityQueryAuditPostResponseQueryAuditApiV1DbSecurityQueryAuditPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
