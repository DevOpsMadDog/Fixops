from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.event_channel import EventChannel
from ...models.get_recent_api_v1_stream_recent_channel_get_response_get_recent_api_v1_stream_recent_channel_get import (
    GetRecentApiV1StreamRecentChannelGetResponseGetRecentApiV1StreamRecentChannelGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    channel: EventChannel,
    *,
    limit: int | Unset = 20,
    org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["limit"] = limit

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/stream/recent/{channel}".format(
            channel=quote(str(channel), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetRecentApiV1StreamRecentChannelGetResponseGetRecentApiV1StreamRecentChannelGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GetRecentApiV1StreamRecentChannelGetResponseGetRecentApiV1StreamRecentChannelGet.from_dict(
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
) -> Response[GetRecentApiV1StreamRecentChannelGetResponseGetRecentApiV1StreamRecentChannelGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    channel: EventChannel,
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 20,
    org_id: None | str | Unset = UNSET,
) -> Response[GetRecentApiV1StreamRecentChannelGetResponseGetRecentApiV1StreamRecentChannelGet | HTTPValidationError]:
    """Get recent events for a channel

     Return the last *limit* events from *channel*, newest first.

    Useful for dashboard initial load before subscribing to SSE/WS.

    Args:
        channel (EventChannel): Logical event channels for dashboard routing.
        limit (int | Unset):  Default: 20.
        org_id (None | str | Unset): Filter to this org

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetRecentApiV1StreamRecentChannelGetResponseGetRecentApiV1StreamRecentChannelGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        channel=channel,
        limit=limit,
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    channel: EventChannel,
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 20,
    org_id: None | str | Unset = UNSET,
) -> GetRecentApiV1StreamRecentChannelGetResponseGetRecentApiV1StreamRecentChannelGet | HTTPValidationError | None:
    """Get recent events for a channel

     Return the last *limit* events from *channel*, newest first.

    Useful for dashboard initial load before subscribing to SSE/WS.

    Args:
        channel (EventChannel): Logical event channels for dashboard routing.
        limit (int | Unset):  Default: 20.
        org_id (None | str | Unset): Filter to this org

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetRecentApiV1StreamRecentChannelGetResponseGetRecentApiV1StreamRecentChannelGet | HTTPValidationError
    """

    return sync_detailed(
        channel=channel,
        client=client,
        limit=limit,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    channel: EventChannel,
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 20,
    org_id: None | str | Unset = UNSET,
) -> Response[GetRecentApiV1StreamRecentChannelGetResponseGetRecentApiV1StreamRecentChannelGet | HTTPValidationError]:
    """Get recent events for a channel

     Return the last *limit* events from *channel*, newest first.

    Useful for dashboard initial load before subscribing to SSE/WS.

    Args:
        channel (EventChannel): Logical event channels for dashboard routing.
        limit (int | Unset):  Default: 20.
        org_id (None | str | Unset): Filter to this org

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetRecentApiV1StreamRecentChannelGetResponseGetRecentApiV1StreamRecentChannelGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        channel=channel,
        limit=limit,
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    channel: EventChannel,
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 20,
    org_id: None | str | Unset = UNSET,
) -> GetRecentApiV1StreamRecentChannelGetResponseGetRecentApiV1StreamRecentChannelGet | HTTPValidationError | None:
    """Get recent events for a channel

     Return the last *limit* events from *channel*, newest first.

    Useful for dashboard initial load before subscribing to SSE/WS.

    Args:
        channel (EventChannel): Logical event channels for dashboard routing.
        limit (int | Unset):  Default: 20.
        org_id (None | str | Unset): Filter to this org

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetRecentApiV1StreamRecentChannelGetResponseGetRecentApiV1StreamRecentChannelGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            channel=channel,
            client=client,
            limit=limit,
            org_id=org_id,
        )
    ).parsed
