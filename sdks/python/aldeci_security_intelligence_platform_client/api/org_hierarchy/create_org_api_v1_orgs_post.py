from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.create_org_api_v1_orgs_post_response_create_org_api_v1_orgs_post import (
    CreateOrgApiV1OrgsPostResponseCreateOrgApiV1OrgsPost,
)
from ...models.http_validation_error import HTTPValidationError
from ...models.org_create import OrgCreate
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: OrgCreate,
    org_id: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/orgs",
        "params": params,
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> CreateOrgApiV1OrgsPostResponseCreateOrgApiV1OrgsPost | HTTPValidationError | None:
    if response.status_code == 201:
        response_201 = CreateOrgApiV1OrgsPostResponseCreateOrgApiV1OrgsPost.from_dict(response.json())

        return response_201

    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[CreateOrgApiV1OrgsPostResponseCreateOrgApiV1OrgsPost | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: OrgCreate,
    org_id: str,
) -> Response[CreateOrgApiV1OrgsPostResponseCreateOrgApiV1OrgsPost | HTTPValidationError]:
    """Create Org

     Create an organisation node.

    Args:
        org_id (str): Tenant ID
        body (OrgCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateOrgApiV1OrgsPostResponseCreateOrgApiV1OrgsPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: OrgCreate,
    org_id: str,
) -> CreateOrgApiV1OrgsPostResponseCreateOrgApiV1OrgsPost | HTTPValidationError | None:
    """Create Org

     Create an organisation node.

    Args:
        org_id (str): Tenant ID
        body (OrgCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateOrgApiV1OrgsPostResponseCreateOrgApiV1OrgsPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: OrgCreate,
    org_id: str,
) -> Response[CreateOrgApiV1OrgsPostResponseCreateOrgApiV1OrgsPost | HTTPValidationError]:
    """Create Org

     Create an organisation node.

    Args:
        org_id (str): Tenant ID
        body (OrgCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateOrgApiV1OrgsPostResponseCreateOrgApiV1OrgsPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: OrgCreate,
    org_id: str,
) -> CreateOrgApiV1OrgsPostResponseCreateOrgApiV1OrgsPost | HTTPValidationError | None:
    """Create Org

     Create an organisation node.

    Args:
        org_id (str): Tenant ID
        body (OrgCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateOrgApiV1OrgsPostResponseCreateOrgApiV1OrgsPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            org_id=org_id,
        )
    ).parsed
