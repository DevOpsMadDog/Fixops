from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.create_key_response import CreateKeyResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    key_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/auth/keys/{key_id}/rotate".format(
            key_id=quote(str(key_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> CreateKeyResponse | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = CreateKeyResponse.from_dict(response.json())

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
) -> Response[CreateKeyResponse | HTTPValidationError]:
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
) -> Response[CreateKeyResponse | HTTPValidationError]:
    """Rotate Key

     Rotate a key — deactivates old, returns new key (plaintext shown once).

    Args:
        key_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateKeyResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        key_id=key_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    key_id: str,
    *,
    client: AuthenticatedClient,
) -> CreateKeyResponse | HTTPValidationError | None:
    """Rotate Key

     Rotate a key — deactivates old, returns new key (plaintext shown once).

    Args:
        key_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateKeyResponse | HTTPValidationError
    """

    return sync_detailed(
        key_id=key_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    key_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[CreateKeyResponse | HTTPValidationError]:
    """Rotate Key

     Rotate a key — deactivates old, returns new key (plaintext shown once).

    Args:
        key_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateKeyResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        key_id=key_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    key_id: str,
    *,
    client: AuthenticatedClient,
) -> CreateKeyResponse | HTTPValidationError | None:
    """Rotate Key

     Rotate a key — deactivates old, returns new key (plaintext shown once).

    Args:
        key_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateKeyResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            key_id=key_id,
            client=client,
        )
    ).parsed
