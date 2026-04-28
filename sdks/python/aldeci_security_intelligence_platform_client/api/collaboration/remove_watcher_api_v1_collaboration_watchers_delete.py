from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.remove_watcher_api_v1_collaboration_watchers_delete_response_remove_watcher_api_v1_collaboration_watchers_delete import (
    RemoveWatcherApiV1CollaborationWatchersDeleteResponseRemoveWatcherApiV1CollaborationWatchersDelete,
)
from ...types import UNSET, Response


def _get_kwargs(
    *,
    entity_type: str,
    entity_id: str,
    user_id: str,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["entity_type"] = entity_type

    params["entity_id"] = entity_id

    params["user_id"] = user_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/collaboration/watchers",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | RemoveWatcherApiV1CollaborationWatchersDeleteResponseRemoveWatcherApiV1CollaborationWatchersDelete
    | None
):
    if response.status_code == 200:
        response_200 = RemoveWatcherApiV1CollaborationWatchersDeleteResponseRemoveWatcherApiV1CollaborationWatchersDelete.from_dict(
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
    | RemoveWatcherApiV1CollaborationWatchersDeleteResponseRemoveWatcherApiV1CollaborationWatchersDelete
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
    entity_type: str,
    entity_id: str,
    user_id: str,
) -> Response[
    HTTPValidationError
    | RemoveWatcherApiV1CollaborationWatchersDeleteResponseRemoveWatcherApiV1CollaborationWatchersDelete
]:
    """Remove Watcher

     Remove a watcher from an entity.

    Args:
        entity_type (str):
        entity_id (str):
        user_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RemoveWatcherApiV1CollaborationWatchersDeleteResponseRemoveWatcherApiV1CollaborationWatchersDelete]
    """

    kwargs = _get_kwargs(
        entity_type=entity_type,
        entity_id=entity_id,
        user_id=user_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    entity_type: str,
    entity_id: str,
    user_id: str,
) -> (
    HTTPValidationError
    | RemoveWatcherApiV1CollaborationWatchersDeleteResponseRemoveWatcherApiV1CollaborationWatchersDelete
    | None
):
    """Remove Watcher

     Remove a watcher from an entity.

    Args:
        entity_type (str):
        entity_id (str):
        user_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RemoveWatcherApiV1CollaborationWatchersDeleteResponseRemoveWatcherApiV1CollaborationWatchersDelete
    """

    return sync_detailed(
        client=client,
        entity_type=entity_type,
        entity_id=entity_id,
        user_id=user_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    entity_type: str,
    entity_id: str,
    user_id: str,
) -> Response[
    HTTPValidationError
    | RemoveWatcherApiV1CollaborationWatchersDeleteResponseRemoveWatcherApiV1CollaborationWatchersDelete
]:
    """Remove Watcher

     Remove a watcher from an entity.

    Args:
        entity_type (str):
        entity_id (str):
        user_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RemoveWatcherApiV1CollaborationWatchersDeleteResponseRemoveWatcherApiV1CollaborationWatchersDelete]
    """

    kwargs = _get_kwargs(
        entity_type=entity_type,
        entity_id=entity_id,
        user_id=user_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    entity_type: str,
    entity_id: str,
    user_id: str,
) -> (
    HTTPValidationError
    | RemoveWatcherApiV1CollaborationWatchersDeleteResponseRemoveWatcherApiV1CollaborationWatchersDelete
    | None
):
    """Remove Watcher

     Remove a watcher from an entity.

    Args:
        entity_type (str):
        entity_id (str):
        user_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RemoveWatcherApiV1CollaborationWatchersDeleteResponseRemoveWatcherApiV1CollaborationWatchersDelete
    """

    return (
        await asyncio_detailed(
            client=client,
            entity_type=entity_type,
            entity_id=entity_id,
            user_id=user_id,
        )
    ).parsed
