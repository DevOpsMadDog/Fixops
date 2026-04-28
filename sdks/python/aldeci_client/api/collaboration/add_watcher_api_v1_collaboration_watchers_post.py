from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.add_watcher_api_v1_collaboration_watchers_post_response_add_watcher_api_v1_collaboration_watchers_post import (
    AddWatcherApiV1CollaborationWatchersPostResponseAddWatcherApiV1CollaborationWatchersPost,
)
from ...models.add_watcher_request import AddWatcherRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    *,
    body: AddWatcherRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/collaboration/watchers",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    AddWatcherApiV1CollaborationWatchersPostResponseAddWatcherApiV1CollaborationWatchersPost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            AddWatcherApiV1CollaborationWatchersPostResponseAddWatcherApiV1CollaborationWatchersPost.from_dict(
                response.json()
            )
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
    AddWatcherApiV1CollaborationWatchersPostResponseAddWatcherApiV1CollaborationWatchersPost | HTTPValidationError
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
    body: AddWatcherRequest,
) -> Response[
    AddWatcherApiV1CollaborationWatchersPostResponseAddWatcherApiV1CollaborationWatchersPost | HTTPValidationError
]:
    """Add Watcher

     Add a watcher to an entity.

    Args:
        body (AddWatcherRequest): Request to add a watcher.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AddWatcherApiV1CollaborationWatchersPostResponseAddWatcherApiV1CollaborationWatchersPost | HTTPValidationError]
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
    body: AddWatcherRequest,
) -> (
    AddWatcherApiV1CollaborationWatchersPostResponseAddWatcherApiV1CollaborationWatchersPost
    | HTTPValidationError
    | None
):
    """Add Watcher

     Add a watcher to an entity.

    Args:
        body (AddWatcherRequest): Request to add a watcher.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AddWatcherApiV1CollaborationWatchersPostResponseAddWatcherApiV1CollaborationWatchersPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: AddWatcherRequest,
) -> Response[
    AddWatcherApiV1CollaborationWatchersPostResponseAddWatcherApiV1CollaborationWatchersPost | HTTPValidationError
]:
    """Add Watcher

     Add a watcher to an entity.

    Args:
        body (AddWatcherRequest): Request to add a watcher.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AddWatcherApiV1CollaborationWatchersPostResponseAddWatcherApiV1CollaborationWatchersPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: AddWatcherRequest,
) -> (
    AddWatcherApiV1CollaborationWatchersPostResponseAddWatcherApiV1CollaborationWatchersPost
    | HTTPValidationError
    | None
):
    """Add Watcher

     Add a watcher to an entity.

    Args:
        body (AddWatcherRequest): Request to add a watcher.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AddWatcherApiV1CollaborationWatchersPostResponseAddWatcherApiV1CollaborationWatchersPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
