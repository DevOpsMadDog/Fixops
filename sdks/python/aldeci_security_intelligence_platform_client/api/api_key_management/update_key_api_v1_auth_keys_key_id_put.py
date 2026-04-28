from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.api_key_response import APIKeyResponse
from ...models.http_validation_error import HTTPValidationError
from ...models.update_key_request import UpdateKeyRequest
from ...types import Response


def _get_kwargs(
    key_id: str,
    *,
    body: UpdateKeyRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/auth/keys/{key_id}".format(
            key_id=quote(str(key_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> APIKeyResponse | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = APIKeyResponse.from_dict(response.json())

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
) -> Response[APIKeyResponse | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    key_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateKeyRequest,
) -> Response[APIKeyResponse | HTTPValidationError]:
    """Update Key

     Update mutable key metadata: name, description, scopes, rate_limit.

    Args:
        key_id (str):
        body (UpdateKeyRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[APIKeyResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        key_id=key_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    key_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateKeyRequest,
) -> APIKeyResponse | HTTPValidationError | None:
    """Update Key

     Update mutable key metadata: name, description, scopes, rate_limit.

    Args:
        key_id (str):
        body (UpdateKeyRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        APIKeyResponse | HTTPValidationError
    """

    return sync_detailed(
        key_id=key_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    key_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateKeyRequest,
) -> Response[APIKeyResponse | HTTPValidationError]:
    """Update Key

     Update mutable key metadata: name, description, scopes, rate_limit.

    Args:
        key_id (str):
        body (UpdateKeyRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[APIKeyResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        key_id=key_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    key_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateKeyRequest,
) -> APIKeyResponse | HTTPValidationError | None:
    """Update Key

     Update mutable key metadata: name, description, scopes, rate_limit.

    Args:
        key_id (str):
        body (UpdateKeyRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        APIKeyResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            key_id=key_id,
            client=client,
            body=body,
        )
    ).parsed
