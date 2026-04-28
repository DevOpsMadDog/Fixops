from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.event_channel import EventChannel
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    channel: EventChannel,
    *,
    org_id: None | str | Unset = UNSET,
    replay: bool | Unset = True,
    api_key: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params["replay"] = replay

    json_api_key: None | str | Unset
    if isinstance(api_key, Unset):
        json_api_key = UNSET
    else:
        json_api_key = api_key
    params["api_key"] = json_api_key

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/stream/sse/{channel}".format(
            channel=quote(str(channel), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = cast(Any, None)
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
    channel: EventChannel,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    replay: bool | Unset = True,
    api_key: None | str | Unset = UNSET,
) -> Response[Any | HTTPValidationError]:
    r"""Server-Sent Events stream for a channel

     Stream events for *channel* as Server-Sent Events.

    The client receives:
    - An initial burst of up to 10 recent events (if replay=true)
    - A ``ping`` heartbeat comment every 15 seconds
    - New events as they are published

    SSE format::

        id: <uuid>
        event: <event_type>
        data: {\"id\": \"…\", \"event_type\": \"…\", \"data\": {…}, …}

    Args:
        channel (EventChannel): Logical event channels for dashboard routing.
        org_id (None | str | Unset): Filter to this org
        replay (bool | Unset): Replay last 10 events on connect Default: True.
        api_key (None | str | Unset): Optional API key

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        channel=channel,
        org_id=org_id,
        replay=replay,
        api_key=api_key,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    channel: EventChannel,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    replay: bool | Unset = True,
    api_key: None | str | Unset = UNSET,
) -> Any | HTTPValidationError | None:
    r"""Server-Sent Events stream for a channel

     Stream events for *channel* as Server-Sent Events.

    The client receives:
    - An initial burst of up to 10 recent events (if replay=true)
    - A ``ping`` heartbeat comment every 15 seconds
    - New events as they are published

    SSE format::

        id: <uuid>
        event: <event_type>
        data: {\"id\": \"…\", \"event_type\": \"…\", \"data\": {…}, …}

    Args:
        channel (EventChannel): Logical event channels for dashboard routing.
        org_id (None | str | Unset): Filter to this org
        replay (bool | Unset): Replay last 10 events on connect Default: True.
        api_key (None | str | Unset): Optional API key

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return sync_detailed(
        channel=channel,
        client=client,
        org_id=org_id,
        replay=replay,
        api_key=api_key,
    ).parsed


async def asyncio_detailed(
    channel: EventChannel,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    replay: bool | Unset = True,
    api_key: None | str | Unset = UNSET,
) -> Response[Any | HTTPValidationError]:
    r"""Server-Sent Events stream for a channel

     Stream events for *channel* as Server-Sent Events.

    The client receives:
    - An initial burst of up to 10 recent events (if replay=true)
    - A ``ping`` heartbeat comment every 15 seconds
    - New events as they are published

    SSE format::

        id: <uuid>
        event: <event_type>
        data: {\"id\": \"…\", \"event_type\": \"…\", \"data\": {…}, …}

    Args:
        channel (EventChannel): Logical event channels for dashboard routing.
        org_id (None | str | Unset): Filter to this org
        replay (bool | Unset): Replay last 10 events on connect Default: True.
        api_key (None | str | Unset): Optional API key

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        channel=channel,
        org_id=org_id,
        replay=replay,
        api_key=api_key,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    channel: EventChannel,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    replay: bool | Unset = True,
    api_key: None | str | Unset = UNSET,
) -> Any | HTTPValidationError | None:
    r"""Server-Sent Events stream for a channel

     Stream events for *channel* as Server-Sent Events.

    The client receives:
    - An initial burst of up to 10 recent events (if replay=true)
    - A ``ping`` heartbeat comment every 15 seconds
    - New events as they are published

    SSE format::

        id: <uuid>
        event: <event_type>
        data: {\"id\": \"…\", \"event_type\": \"…\", \"data\": {…}, …}

    Args:
        channel (EventChannel): Logical event channels for dashboard routing.
        org_id (None | str | Unset): Filter to this org
        replay (bool | Unset): Replay last 10 events on connect Default: True.
        api_key (None | str | Unset): Optional API key

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            channel=channel,
            client=client,
            org_id=org_id,
            replay=replay,
            api_key=api_key,
        )
    ).parsed
