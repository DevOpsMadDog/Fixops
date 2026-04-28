from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.privilege_audit_api_v1_db_security_privilege_audit_post_response_privilege_audit_api_v1_db_security_privilege_audit_post import (
    PrivilegeAuditApiV1DbSecurityPrivilegeAuditPostResponsePrivilegeAuditApiV1DbSecurityPrivilegeAuditPost,
)
from ...models.privilege_audit_request import PrivilegeAuditRequest
from ...types import Response


def _get_kwargs(
    *,
    body: PrivilegeAuditRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/db-security/privilege-audit",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | PrivilegeAuditApiV1DbSecurityPrivilegeAuditPostResponsePrivilegeAuditApiV1DbSecurityPrivilegeAuditPost
    | None
):
    if response.status_code == 200:
        response_200 = PrivilegeAuditApiV1DbSecurityPrivilegeAuditPostResponsePrivilegeAuditApiV1DbSecurityPrivilegeAuditPost.from_dict(
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
    HTTPValidationError
    | PrivilegeAuditApiV1DbSecurityPrivilegeAuditPostResponsePrivilegeAuditApiV1DbSecurityPrivilegeAuditPost
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
    body: PrivilegeAuditRequest,
) -> Response[
    HTTPValidationError
    | PrivilegeAuditApiV1DbSecurityPrivilegeAuditPostResponsePrivilegeAuditApiV1DbSecurityPrivilegeAuditPost
]:
    """Privilege Audit

     Audit database user privileges for over-provisioning, default passwords, shared accounts.

    Returns per-user risk scores and privilege details.

    Args:
        body (PrivilegeAuditRequest): Run a privilege audit for a specific database.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | PrivilegeAuditApiV1DbSecurityPrivilegeAuditPostResponsePrivilegeAuditApiV1DbSecurityPrivilegeAuditPost]
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
    body: PrivilegeAuditRequest,
) -> (
    HTTPValidationError
    | PrivilegeAuditApiV1DbSecurityPrivilegeAuditPostResponsePrivilegeAuditApiV1DbSecurityPrivilegeAuditPost
    | None
):
    """Privilege Audit

     Audit database user privileges for over-provisioning, default passwords, shared accounts.

    Returns per-user risk scores and privilege details.

    Args:
        body (PrivilegeAuditRequest): Run a privilege audit for a specific database.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | PrivilegeAuditApiV1DbSecurityPrivilegeAuditPostResponsePrivilegeAuditApiV1DbSecurityPrivilegeAuditPost
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: PrivilegeAuditRequest,
) -> Response[
    HTTPValidationError
    | PrivilegeAuditApiV1DbSecurityPrivilegeAuditPostResponsePrivilegeAuditApiV1DbSecurityPrivilegeAuditPost
]:
    """Privilege Audit

     Audit database user privileges for over-provisioning, default passwords, shared accounts.

    Returns per-user risk scores and privilege details.

    Args:
        body (PrivilegeAuditRequest): Run a privilege audit for a specific database.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | PrivilegeAuditApiV1DbSecurityPrivilegeAuditPostResponsePrivilegeAuditApiV1DbSecurityPrivilegeAuditPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: PrivilegeAuditRequest,
) -> (
    HTTPValidationError
    | PrivilegeAuditApiV1DbSecurityPrivilegeAuditPostResponsePrivilegeAuditApiV1DbSecurityPrivilegeAuditPost
    | None
):
    """Privilege Audit

     Audit database user privileges for over-provisioning, default passwords, shared accounts.

    Returns per-user risk scores and privilege details.

    Args:
        body (PrivilegeAuditRequest): Run a privilege audit for a specific database.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | PrivilegeAuditApiV1DbSecurityPrivilegeAuditPostResponsePrivilegeAuditApiV1DbSecurityPrivilegeAuditPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
