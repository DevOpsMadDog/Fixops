from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_watched_entities_api_v1_collaboration_watchers_user_user_id_get_response_get_watched_entities_api_v1_collaboration_watchers_user_user_id_get import (
    GetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGetResponseGetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    user_id: str,
    *,
    entity_type: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_entity_type: None | str | Unset
    if isinstance(entity_type, Unset):
        json_entity_type = UNSET
    else:
        json_entity_type = entity_type
    params["entity_type"] = json_entity_type

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/collaboration/watchers/user/{user_id}".format(
            user_id=quote(str(user_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGetResponseGetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGetResponseGetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGet.from_dict(
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
    GetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGetResponseGetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGet
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
    entity_type: None | str | Unset = UNSET,
) -> Response[
    GetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGetResponseGetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGet
    | HTTPValidationError
]:
    """Get Watched Entities

     Get entities watched by a user.

    Args:
        user_id (str):
        entity_type (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGetResponseGetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        user_id=user_id,
        entity_type=entity_type,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    user_id: str,
    *,
    client: AuthenticatedClient,
    entity_type: None | str | Unset = UNSET,
) -> (
    GetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGetResponseGetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGet
    | HTTPValidationError
    | None
):
    """Get Watched Entities

     Get entities watched by a user.

    Args:
        user_id (str):
        entity_type (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGetResponseGetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGet | HTTPValidationError
    """

    return sync_detailed(
        user_id=user_id,
        client=client,
        entity_type=entity_type,
    ).parsed


async def asyncio_detailed(
    user_id: str,
    *,
    client: AuthenticatedClient,
    entity_type: None | str | Unset = UNSET,
) -> Response[
    GetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGetResponseGetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGet
    | HTTPValidationError
]:
    """Get Watched Entities

     Get entities watched by a user.

    Args:
        user_id (str):
        entity_type (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGetResponseGetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        user_id=user_id,
        entity_type=entity_type,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    user_id: str,
    *,
    client: AuthenticatedClient,
    entity_type: None | str | Unset = UNSET,
) -> (
    GetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGetResponseGetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGet
    | HTTPValidationError
    | None
):
    """Get Watched Entities

     Get entities watched by a user.

    Args:
        user_id (str):
        entity_type (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGetResponseGetWatchedEntitiesApiV1CollaborationWatchersUserUserIdGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            user_id=user_id,
            client=client,
            entity_type=entity_type,
        )
    ).parsed
