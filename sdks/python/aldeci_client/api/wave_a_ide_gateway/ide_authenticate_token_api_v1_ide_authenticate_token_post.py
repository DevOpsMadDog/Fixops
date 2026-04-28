from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.ide_authenticate_token_api_v1_ide_authenticate_token_post_response_ide_authenticate_token_api_v1_ide_authenticate_token_post import (
    IdeAuthenticateTokenApiV1IdeAuthenticateTokenPostResponseIdeAuthenticateTokenApiV1IdeAuthenticateTokenPost,
)
from ...models.ide_authenticate_token_request import IDEAuthenticateTokenRequest
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: IDEAuthenticateTokenRequest,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/ide/authenticate-token",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | IdeAuthenticateTokenApiV1IdeAuthenticateTokenPostResponseIdeAuthenticateTokenApiV1IdeAuthenticateTokenPost
    | None
):
    if response.status_code == 200:
        response_200 = IdeAuthenticateTokenApiV1IdeAuthenticateTokenPostResponseIdeAuthenticateTokenApiV1IdeAuthenticateTokenPost.from_dict(
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
    | IdeAuthenticateTokenApiV1IdeAuthenticateTokenPostResponseIdeAuthenticateTokenApiV1IdeAuthenticateTokenPost
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
    body: IDEAuthenticateTokenRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | IdeAuthenticateTokenApiV1IdeAuthenticateTokenPostResponseIdeAuthenticateTokenApiV1IdeAuthenticateTokenPost
]:
    """Validate an IDE-supplied token and return scoped session info

     Validate an IDE token and return session info.

    Honors three lookup paths in order:
      1. JWT decode via core.api_key_manager / FIXOPS_JWT_SECRET
      2. api_key_manager.validate_key by raw key
      3. Fallback failure with 401

    Args:
        x_org_id (None | str | Unset):
        body (IDEAuthenticateTokenRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | IdeAuthenticateTokenApiV1IdeAuthenticateTokenPostResponseIdeAuthenticateTokenApiV1IdeAuthenticateTokenPost]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: IDEAuthenticateTokenRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | IdeAuthenticateTokenApiV1IdeAuthenticateTokenPostResponseIdeAuthenticateTokenApiV1IdeAuthenticateTokenPost
    | None
):
    """Validate an IDE-supplied token and return scoped session info

     Validate an IDE token and return session info.

    Honors three lookup paths in order:
      1. JWT decode via core.api_key_manager / FIXOPS_JWT_SECRET
      2. api_key_manager.validate_key by raw key
      3. Fallback failure with 401

    Args:
        x_org_id (None | str | Unset):
        body (IDEAuthenticateTokenRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | IdeAuthenticateTokenApiV1IdeAuthenticateTokenPostResponseIdeAuthenticateTokenApiV1IdeAuthenticateTokenPost
    """

    return sync_detailed(
        client=client,
        body=body,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: IDEAuthenticateTokenRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | IdeAuthenticateTokenApiV1IdeAuthenticateTokenPostResponseIdeAuthenticateTokenApiV1IdeAuthenticateTokenPost
]:
    """Validate an IDE-supplied token and return scoped session info

     Validate an IDE token and return session info.

    Honors three lookup paths in order:
      1. JWT decode via core.api_key_manager / FIXOPS_JWT_SECRET
      2. api_key_manager.validate_key by raw key
      3. Fallback failure with 401

    Args:
        x_org_id (None | str | Unset):
        body (IDEAuthenticateTokenRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | IdeAuthenticateTokenApiV1IdeAuthenticateTokenPostResponseIdeAuthenticateTokenApiV1IdeAuthenticateTokenPost]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: IDEAuthenticateTokenRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | IdeAuthenticateTokenApiV1IdeAuthenticateTokenPostResponseIdeAuthenticateTokenApiV1IdeAuthenticateTokenPost
    | None
):
    """Validate an IDE-supplied token and return scoped session info

     Validate an IDE token and return session info.

    Honors three lookup paths in order:
      1. JWT decode via core.api_key_manager / FIXOPS_JWT_SECRET
      2. api_key_manager.validate_key by raw key
      3. Fallback failure with 401

    Args:
        x_org_id (None | str | Unset):
        body (IDEAuthenticateTokenRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | IdeAuthenticateTokenApiV1IdeAuthenticateTokenPostResponseIdeAuthenticateTokenApiV1IdeAuthenticateTokenPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            x_org_id=x_org_id,
        )
    ).parsed
