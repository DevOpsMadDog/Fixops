from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_change_api_v1_changes_change_id_get_response_get_change_api_v1_changes_change_id_get import (
    GetChangeApiV1ChangesChangeIdGetResponseGetChangeApiV1ChangesChangeIdGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    change_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/changes/{change_id}".format(
            change_id=quote(str(change_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetChangeApiV1ChangesChangeIdGetResponseGetChangeApiV1ChangesChangeIdGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GetChangeApiV1ChangesChangeIdGetResponseGetChangeApiV1ChangesChangeIdGet.from_dict(
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
) -> Response[GetChangeApiV1ChangesChangeIdGetResponseGetChangeApiV1ChangesChangeIdGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    change_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[GetChangeApiV1ChangesChangeIdGetResponseGetChangeApiV1ChangesChangeIdGet | HTTPValidationError]:
    """Get Change

     Get a specific change request by ID.

    Args:
        change_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetChangeApiV1ChangesChangeIdGetResponseGetChangeApiV1ChangesChangeIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        change_id=change_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    change_id: str,
    *,
    client: AuthenticatedClient,
) -> GetChangeApiV1ChangesChangeIdGetResponseGetChangeApiV1ChangesChangeIdGet | HTTPValidationError | None:
    """Get Change

     Get a specific change request by ID.

    Args:
        change_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetChangeApiV1ChangesChangeIdGetResponseGetChangeApiV1ChangesChangeIdGet | HTTPValidationError
    """

    return sync_detailed(
        change_id=change_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    change_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[GetChangeApiV1ChangesChangeIdGetResponseGetChangeApiV1ChangesChangeIdGet | HTTPValidationError]:
    """Get Change

     Get a specific change request by ID.

    Args:
        change_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetChangeApiV1ChangesChangeIdGetResponseGetChangeApiV1ChangesChangeIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        change_id=change_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    change_id: str,
    *,
    client: AuthenticatedClient,
) -> GetChangeApiV1ChangesChangeIdGetResponseGetChangeApiV1ChangesChangeIdGet | HTTPValidationError | None:
    """Get Change

     Get a specific change request by ID.

    Args:
        change_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetChangeApiV1ChangesChangeIdGetResponseGetChangeApiV1ChangesChangeIdGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            change_id=change_id,
            client=client,
        )
    ).parsed
