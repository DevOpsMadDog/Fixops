from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: None | str | Unset = UNSET,
    active_only: bool | Unset = True,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params["active_only"] = active_only

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/auth/disposable-tokens",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = response.json()
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
) -> Response[Any | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    active_only: bool | Unset = True,
) -> Response[Any | HTTPValidationError]:
    """List Disposable Tokens Endpoint

     List disposable tokens (never returns raw_token/hash). Defaults to caller's org.

    Args:
        org_id (None | str | Unset):
        active_only (bool | Unset):  Default: True.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        active_only=active_only,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    active_only: bool | Unset = True,
) -> Any | HTTPValidationError | None:
    """List Disposable Tokens Endpoint

     List disposable tokens (never returns raw_token/hash). Defaults to caller's org.

    Args:
        org_id (None | str | Unset):
        active_only (bool | Unset):  Default: True.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        active_only=active_only,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    active_only: bool | Unset = True,
) -> Response[Any | HTTPValidationError]:
    """List Disposable Tokens Endpoint

     List disposable tokens (never returns raw_token/hash). Defaults to caller's org.

    Args:
        org_id (None | str | Unset):
        active_only (bool | Unset):  Default: True.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        active_only=active_only,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    active_only: bool | Unset = True,
) -> Any | HTTPValidationError | None:
    """List Disposable Tokens Endpoint

     List disposable tokens (never returns raw_token/hash). Defaults to caller's org.

    Args:
        org_id (None | str | Unset):
        active_only (bool | Unset):  Default: True.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            active_only=active_only,
        )
    ).parsed
