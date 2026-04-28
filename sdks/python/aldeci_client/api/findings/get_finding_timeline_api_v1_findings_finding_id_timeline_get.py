from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.timeline_event import TimelineEvent
from ...types import Response


def _get_kwargs(
    finding_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/findings/{finding_id}/timeline".format(
            finding_id=quote(str(finding_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[TimelineEvent] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = TimelineEvent.from_dict(response_200_item_data)

            response_200.append(response_200_item)

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
) -> Response[HTTPValidationError | list[TimelineEvent]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    finding_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[HTTPValidationError | list[TimelineEvent]]:
    """Get Finding Timeline

     Get complete timeline of all actions on finding.

    Args:
        finding_id: Finding identifier

    Returns:
        List of timeline events in chronological order

    Raises:
        HTTPException: 404 if finding not found

    Args:
        finding_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[TimelineEvent]]
    """

    kwargs = _get_kwargs(
        finding_id=finding_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    finding_id: str,
    *,
    client: AuthenticatedClient,
) -> HTTPValidationError | list[TimelineEvent] | None:
    """Get Finding Timeline

     Get complete timeline of all actions on finding.

    Args:
        finding_id: Finding identifier

    Returns:
        List of timeline events in chronological order

    Raises:
        HTTPException: 404 if finding not found

    Args:
        finding_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[TimelineEvent]
    """

    return sync_detailed(
        finding_id=finding_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    finding_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[HTTPValidationError | list[TimelineEvent]]:
    """Get Finding Timeline

     Get complete timeline of all actions on finding.

    Args:
        finding_id: Finding identifier

    Returns:
        List of timeline events in chronological order

    Raises:
        HTTPException: 404 if finding not found

    Args:
        finding_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[TimelineEvent]]
    """

    kwargs = _get_kwargs(
        finding_id=finding_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    finding_id: str,
    *,
    client: AuthenticatedClient,
) -> HTTPValidationError | list[TimelineEvent] | None:
    """Get Finding Timeline

     Get complete timeline of all actions on finding.

    Args:
        finding_id: Finding identifier

    Returns:
        List of timeline events in chronological order

    Raises:
        HTTPException: 404 if finding not found

    Args:
        finding_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[TimelineEvent]
    """

    return (
        await asyncio_detailed(
            finding_id=finding_id,
            client=client,
        )
    ).parsed
