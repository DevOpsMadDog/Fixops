from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.register_cmdb_api_v1_cloud_cmdb_register_post_response_register_cmdb_api_v1_cloud_cmdb_register_post import (
    RegisterCmdbApiV1CloudCmdbRegisterPostResponseRegisterCmdbApiV1CloudCmdbRegisterPost,
)
from ...models.register_cmdb_request import RegisterCMDBRequest
from ...types import Response


def _get_kwargs(
    *,
    body: RegisterCMDBRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/cloud/cmdb/register",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | RegisterCmdbApiV1CloudCmdbRegisterPostResponseRegisterCmdbApiV1CloudCmdbRegisterPost | None:
    if response.status_code == 200:
        response_200 = RegisterCmdbApiV1CloudCmdbRegisterPostResponseRegisterCmdbApiV1CloudCmdbRegisterPost.from_dict(
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
    HTTPValidationError | RegisterCmdbApiV1CloudCmdbRegisterPostResponseRegisterCmdbApiV1CloudCmdbRegisterPost
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
    body: RegisterCMDBRequest,
) -> Response[
    HTTPValidationError | RegisterCmdbApiV1CloudCmdbRegisterPostResponseRegisterCmdbApiV1CloudCmdbRegisterPost
]:
    """Register asset as managed in CMDB

     Mark a cloud resource as known/managed so it no longer appears as unmanaged.

    Args:
        body (RegisterCMDBRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RegisterCmdbApiV1CloudCmdbRegisterPostResponseRegisterCmdbApiV1CloudCmdbRegisterPost]
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
    body: RegisterCMDBRequest,
) -> HTTPValidationError | RegisterCmdbApiV1CloudCmdbRegisterPostResponseRegisterCmdbApiV1CloudCmdbRegisterPost | None:
    """Register asset as managed in CMDB

     Mark a cloud resource as known/managed so it no longer appears as unmanaged.

    Args:
        body (RegisterCMDBRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RegisterCmdbApiV1CloudCmdbRegisterPostResponseRegisterCmdbApiV1CloudCmdbRegisterPost
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: RegisterCMDBRequest,
) -> Response[
    HTTPValidationError | RegisterCmdbApiV1CloudCmdbRegisterPostResponseRegisterCmdbApiV1CloudCmdbRegisterPost
]:
    """Register asset as managed in CMDB

     Mark a cloud resource as known/managed so it no longer appears as unmanaged.

    Args:
        body (RegisterCMDBRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RegisterCmdbApiV1CloudCmdbRegisterPostResponseRegisterCmdbApiV1CloudCmdbRegisterPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: RegisterCMDBRequest,
) -> HTTPValidationError | RegisterCmdbApiV1CloudCmdbRegisterPostResponseRegisterCmdbApiV1CloudCmdbRegisterPost | None:
    """Register asset as managed in CMDB

     Mark a cloud resource as known/managed so it no longer appears as unmanaged.

    Args:
        body (RegisterCMDBRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RegisterCmdbApiV1CloudCmdbRegisterPostResponseRegisterCmdbApiV1CloudCmdbRegisterPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
