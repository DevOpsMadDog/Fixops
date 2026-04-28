from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_comments_api_v1_collaboration_comments_get_response_get_comments_api_v1_collaboration_comments_get import (
    GetCommentsApiV1CollaborationCommentsGetResponseGetCommentsApiV1CollaborationCommentsGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    entity_type: None | str | Unset = UNSET,
    entity_id: None | str | Unset = UNSET,
    include_internal: bool | Unset = True,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_entity_type: None | str | Unset
    if isinstance(entity_type, Unset):
        json_entity_type = UNSET
    else:
        json_entity_type = entity_type
    params["entity_type"] = json_entity_type

    json_entity_id: None | str | Unset
    if isinstance(entity_id, Unset):
        json_entity_id = UNSET
    else:
        json_entity_id = entity_id
    params["entity_id"] = json_entity_id

    params["include_internal"] = include_internal

    params["limit"] = limit

    params["offset"] = offset

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/collaboration/comments",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetCommentsApiV1CollaborationCommentsGetResponseGetCommentsApiV1CollaborationCommentsGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            GetCommentsApiV1CollaborationCommentsGetResponseGetCommentsApiV1CollaborationCommentsGet.from_dict(
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
    GetCommentsApiV1CollaborationCommentsGetResponseGetCommentsApiV1CollaborationCommentsGet | HTTPValidationError
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
    entity_type: None | str | Unset = UNSET,
    entity_id: None | str | Unset = UNSET,
    include_internal: bool | Unset = True,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> Response[
    GetCommentsApiV1CollaborationCommentsGetResponseGetCommentsApiV1CollaborationCommentsGet | HTTPValidationError
]:
    """Get Comments

     Get comments for an entity. If entity_type/entity_id omitted, returns recent comments.

    Args:
        entity_type (None | str | Unset):
        entity_id (None | str | Unset):
        include_internal (bool | Unset):  Default: True.
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetCommentsApiV1CollaborationCommentsGetResponseGetCommentsApiV1CollaborationCommentsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        entity_type=entity_type,
        entity_id=entity_id,
        include_internal=include_internal,
        limit=limit,
        offset=offset,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    entity_type: None | str | Unset = UNSET,
    entity_id: None | str | Unset = UNSET,
    include_internal: bool | Unset = True,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> (
    GetCommentsApiV1CollaborationCommentsGetResponseGetCommentsApiV1CollaborationCommentsGet
    | HTTPValidationError
    | None
):
    """Get Comments

     Get comments for an entity. If entity_type/entity_id omitted, returns recent comments.

    Args:
        entity_type (None | str | Unset):
        entity_id (None | str | Unset):
        include_internal (bool | Unset):  Default: True.
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetCommentsApiV1CollaborationCommentsGetResponseGetCommentsApiV1CollaborationCommentsGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        entity_type=entity_type,
        entity_id=entity_id,
        include_internal=include_internal,
        limit=limit,
        offset=offset,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    entity_type: None | str | Unset = UNSET,
    entity_id: None | str | Unset = UNSET,
    include_internal: bool | Unset = True,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> Response[
    GetCommentsApiV1CollaborationCommentsGetResponseGetCommentsApiV1CollaborationCommentsGet | HTTPValidationError
]:
    """Get Comments

     Get comments for an entity. If entity_type/entity_id omitted, returns recent comments.

    Args:
        entity_type (None | str | Unset):
        entity_id (None | str | Unset):
        include_internal (bool | Unset):  Default: True.
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetCommentsApiV1CollaborationCommentsGetResponseGetCommentsApiV1CollaborationCommentsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        entity_type=entity_type,
        entity_id=entity_id,
        include_internal=include_internal,
        limit=limit,
        offset=offset,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    entity_type: None | str | Unset = UNSET,
    entity_id: None | str | Unset = UNSET,
    include_internal: bool | Unset = True,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> (
    GetCommentsApiV1CollaborationCommentsGetResponseGetCommentsApiV1CollaborationCommentsGet
    | HTTPValidationError
    | None
):
    """Get Comments

     Get comments for an entity. If entity_type/entity_id omitted, returns recent comments.

    Args:
        entity_type (None | str | Unset):
        entity_id (None | str | Unset):
        include_internal (bool | Unset):  Default: True.
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetCommentsApiV1CollaborationCommentsGetResponseGetCommentsApiV1CollaborationCommentsGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            entity_type=entity_type,
            entity_id=entity_id,
            include_internal=include_internal,
            limit=limit,
            offset=offset,
        )
    ).parsed
