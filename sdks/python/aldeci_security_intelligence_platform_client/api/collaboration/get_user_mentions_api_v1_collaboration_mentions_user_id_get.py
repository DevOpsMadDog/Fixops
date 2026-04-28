from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_user_mentions_api_v1_collaboration_mentions_user_id_get_response_get_user_mentions_api_v1_collaboration_mentions_user_id_get import (
    GetUserMentionsApiV1CollaborationMentionsUserIdGetResponseGetUserMentionsApiV1CollaborationMentionsUserIdGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    user_id: str,
    *,
    unacknowledged_only: bool | Unset = False,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["unacknowledged_only"] = unacknowledged_only

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/collaboration/mentions/{user_id}".format(
            user_id=quote(str(user_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetUserMentionsApiV1CollaborationMentionsUserIdGetResponseGetUserMentionsApiV1CollaborationMentionsUserIdGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetUserMentionsApiV1CollaborationMentionsUserIdGetResponseGetUserMentionsApiV1CollaborationMentionsUserIdGet.from_dict(
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
    GetUserMentionsApiV1CollaborationMentionsUserIdGetResponseGetUserMentionsApiV1CollaborationMentionsUserIdGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    user_id: str,
    *,
    client: AuthenticatedClient,
    unacknowledged_only: bool | Unset = False,
) -> Response[
    GetUserMentionsApiV1CollaborationMentionsUserIdGetResponseGetUserMentionsApiV1CollaborationMentionsUserIdGet
    | HTTPValidationError
]:
    """Get User Mentions

     Get mentions for a user.

    Args:
        user_id (str):
        unacknowledged_only (bool | Unset):  Default: False.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetUserMentionsApiV1CollaborationMentionsUserIdGetResponseGetUserMentionsApiV1CollaborationMentionsUserIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        user_id=user_id,
        unacknowledged_only=unacknowledged_only,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    user_id: str,
    *,
    client: AuthenticatedClient,
    unacknowledged_only: bool | Unset = False,
) -> (
    GetUserMentionsApiV1CollaborationMentionsUserIdGetResponseGetUserMentionsApiV1CollaborationMentionsUserIdGet
    | HTTPValidationError
    | None
):
    """Get User Mentions

     Get mentions for a user.

    Args:
        user_id (str):
        unacknowledged_only (bool | Unset):  Default: False.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetUserMentionsApiV1CollaborationMentionsUserIdGetResponseGetUserMentionsApiV1CollaborationMentionsUserIdGet | HTTPValidationError
    """

    return sync_detailed(
        user_id=user_id,
        client=client,
        unacknowledged_only=unacknowledged_only,
    ).parsed


async def asyncio_detailed(
    user_id: str,
    *,
    client: AuthenticatedClient,
    unacknowledged_only: bool | Unset = False,
) -> Response[
    GetUserMentionsApiV1CollaborationMentionsUserIdGetResponseGetUserMentionsApiV1CollaborationMentionsUserIdGet
    | HTTPValidationError
]:
    """Get User Mentions

     Get mentions for a user.

    Args:
        user_id (str):
        unacknowledged_only (bool | Unset):  Default: False.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetUserMentionsApiV1CollaborationMentionsUserIdGetResponseGetUserMentionsApiV1CollaborationMentionsUserIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        user_id=user_id,
        unacknowledged_only=unacknowledged_only,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    user_id: str,
    *,
    client: AuthenticatedClient,
    unacknowledged_only: bool | Unset = False,
) -> (
    GetUserMentionsApiV1CollaborationMentionsUserIdGetResponseGetUserMentionsApiV1CollaborationMentionsUserIdGet
    | HTTPValidationError
    | None
):
    """Get User Mentions

     Get mentions for a user.

    Args:
        user_id (str):
        unacknowledged_only (bool | Unset):  Default: False.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetUserMentionsApiV1CollaborationMentionsUserIdGetResponseGetUserMentionsApiV1CollaborationMentionsUserIdGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            user_id=user_id,
            client=client,
            unacknowledged_only=unacknowledged_only,
        )
    ).parsed
