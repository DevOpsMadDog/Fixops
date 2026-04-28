from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_waivers_api_v1_waivers_get_response_list_waivers_api_v1_waivers_get import (
    ListWaiversApiV1WaiversGetResponseListWaiversApiV1WaiversGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    auto: bool | Unset = False,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["auto"] = auto

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/waivers",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | ListWaiversApiV1WaiversGetResponseListWaiversApiV1WaiversGet | None:
    if response.status_code == 200:
        response_200 = ListWaiversApiV1WaiversGetResponseListWaiversApiV1WaiversGet.from_dict(response.json())

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
) -> Response[HTTPValidationError | ListWaiversApiV1WaiversGetResponseListWaiversApiV1WaiversGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    auto: bool | Unset = False,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | ListWaiversApiV1WaiversGetResponseListWaiversApiV1WaiversGet]:
    """List Waivers

     List waivers, optionally filtered to auto-applied ones. (Multica 49049e61)

    Args:
        auto (bool | Unset):  Default: False.
        limit (int | Unset):  Default: 100.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListWaiversApiV1WaiversGetResponseListWaiversApiV1WaiversGet]
    """

    kwargs = _get_kwargs(
        auto=auto,
        limit=limit,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    auto: bool | Unset = False,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | ListWaiversApiV1WaiversGetResponseListWaiversApiV1WaiversGet | None:
    """List Waivers

     List waivers, optionally filtered to auto-applied ones. (Multica 49049e61)

    Args:
        auto (bool | Unset):  Default: False.
        limit (int | Unset):  Default: 100.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListWaiversApiV1WaiversGetResponseListWaiversApiV1WaiversGet
    """

    return sync_detailed(
        client=client,
        auto=auto,
        limit=limit,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    auto: bool | Unset = False,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | ListWaiversApiV1WaiversGetResponseListWaiversApiV1WaiversGet]:
    """List Waivers

     List waivers, optionally filtered to auto-applied ones. (Multica 49049e61)

    Args:
        auto (bool | Unset):  Default: False.
        limit (int | Unset):  Default: 100.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListWaiversApiV1WaiversGetResponseListWaiversApiV1WaiversGet]
    """

    kwargs = _get_kwargs(
        auto=auto,
        limit=limit,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    auto: bool | Unset = False,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | ListWaiversApiV1WaiversGetResponseListWaiversApiV1WaiversGet | None:
    """List Waivers

     List waivers, optionally filtered to auto-applied ones. (Multica 49049e61)

    Args:
        auto (bool | Unset):  Default: False.
        limit (int | Unset):  Default: 100.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListWaiversApiV1WaiversGetResponseListWaiversApiV1WaiversGet
    """

    return (
        await asyncio_detailed(
            client=client,
            auto=auto,
            limit=limit,
            x_org_id=x_org_id,
        )
    ).parsed
