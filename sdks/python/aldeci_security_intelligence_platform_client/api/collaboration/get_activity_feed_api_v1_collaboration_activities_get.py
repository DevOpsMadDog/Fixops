from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_activity_feed_api_v1_collaboration_activities_get_response_get_activity_feed_api_v1_collaboration_activities_get import (
    GetActivityFeedApiV1CollaborationActivitiesGetResponseGetActivityFeedApiV1CollaborationActivitiesGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str,
    entity_type: None | str | Unset = UNSET,
    entity_id: None | str | Unset = UNSET,
    activity_types: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

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

    json_activity_types: None | str | Unset
    if isinstance(activity_types, Unset):
        json_activity_types = UNSET
    else:
        json_activity_types = activity_types
    params["activity_types"] = json_activity_types

    params["limit"] = limit

    params["offset"] = offset

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/collaboration/activities",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetActivityFeedApiV1CollaborationActivitiesGetResponseGetActivityFeedApiV1CollaborationActivitiesGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetActivityFeedApiV1CollaborationActivitiesGetResponseGetActivityFeedApiV1CollaborationActivitiesGet.from_dict(
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
    GetActivityFeedApiV1CollaborationActivitiesGetResponseGetActivityFeedApiV1CollaborationActivitiesGet
    | HTTPValidationError
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
    org_id: str,
    entity_type: None | str | Unset = UNSET,
    entity_id: None | str | Unset = UNSET,
    activity_types: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
) -> Response[
    GetActivityFeedApiV1CollaborationActivitiesGetResponseGetActivityFeedApiV1CollaborationActivitiesGet
    | HTTPValidationError
]:
    """Get Activity Feed

     Get activity feed with optional filters.

    Args:
        org_id (str):
        entity_type (None | str | Unset):
        entity_id (None | str | Unset):
        activity_types (None | str | Unset):
        limit (int | Unset):  Default: 50.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetActivityFeedApiV1CollaborationActivitiesGetResponseGetActivityFeedApiV1CollaborationActivitiesGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        entity_type=entity_type,
        entity_id=entity_id,
        activity_types=activity_types,
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
    org_id: str,
    entity_type: None | str | Unset = UNSET,
    entity_id: None | str | Unset = UNSET,
    activity_types: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
) -> (
    GetActivityFeedApiV1CollaborationActivitiesGetResponseGetActivityFeedApiV1CollaborationActivitiesGet
    | HTTPValidationError
    | None
):
    """Get Activity Feed

     Get activity feed with optional filters.

    Args:
        org_id (str):
        entity_type (None | str | Unset):
        entity_id (None | str | Unset):
        activity_types (None | str | Unset):
        limit (int | Unset):  Default: 50.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetActivityFeedApiV1CollaborationActivitiesGetResponseGetActivityFeedApiV1CollaborationActivitiesGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        entity_type=entity_type,
        entity_id=entity_id,
        activity_types=activity_types,
        limit=limit,
        offset=offset,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str,
    entity_type: None | str | Unset = UNSET,
    entity_id: None | str | Unset = UNSET,
    activity_types: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
) -> Response[
    GetActivityFeedApiV1CollaborationActivitiesGetResponseGetActivityFeedApiV1CollaborationActivitiesGet
    | HTTPValidationError
]:
    """Get Activity Feed

     Get activity feed with optional filters.

    Args:
        org_id (str):
        entity_type (None | str | Unset):
        entity_id (None | str | Unset):
        activity_types (None | str | Unset):
        limit (int | Unset):  Default: 50.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetActivityFeedApiV1CollaborationActivitiesGetResponseGetActivityFeedApiV1CollaborationActivitiesGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        entity_type=entity_type,
        entity_id=entity_id,
        activity_types=activity_types,
        limit=limit,
        offset=offset,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str,
    entity_type: None | str | Unset = UNSET,
    entity_id: None | str | Unset = UNSET,
    activity_types: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
) -> (
    GetActivityFeedApiV1CollaborationActivitiesGetResponseGetActivityFeedApiV1CollaborationActivitiesGet
    | HTTPValidationError
    | None
):
    """Get Activity Feed

     Get activity feed with optional filters.

    Args:
        org_id (str):
        entity_type (None | str | Unset):
        entity_id (None | str | Unset):
        activity_types (None | str | Unset):
        limit (int | Unset):  Default: 50.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetActivityFeedApiV1CollaborationActivitiesGetResponseGetActivityFeedApiV1CollaborationActivitiesGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            entity_type=entity_type,
            entity_id=entity_id,
            activity_types=activity_types,
            limit=limit,
            offset=offset,
        )
    ).parsed
