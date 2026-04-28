from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.entity_response import EntityResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    entity_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/trustgraph/entities/{entity_id}".format(
            entity_id=quote(str(entity_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> EntityResponse | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = EntityResponse.from_dict(response.json())

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
) -> Response[EntityResponse | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    entity_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[EntityResponse | HTTPValidationError]:
    """Get Entity

     Get entity details by ID.

    Args:
        entity_id: Entity ID to retrieve

    Returns:
        Entity with relationships

    Args:
        entity_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EntityResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        entity_id=entity_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    entity_id: str,
    *,
    client: AuthenticatedClient,
) -> EntityResponse | HTTPValidationError | None:
    """Get Entity

     Get entity details by ID.

    Args:
        entity_id: Entity ID to retrieve

    Returns:
        Entity with relationships

    Args:
        entity_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EntityResponse | HTTPValidationError
    """

    return sync_detailed(
        entity_id=entity_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    entity_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[EntityResponse | HTTPValidationError]:
    """Get Entity

     Get entity details by ID.

    Args:
        entity_id: Entity ID to retrieve

    Returns:
        Entity with relationships

    Args:
        entity_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EntityResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        entity_id=entity_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    entity_id: str,
    *,
    client: AuthenticatedClient,
) -> EntityResponse | HTTPValidationError | None:
    """Get Entity

     Get entity details by ID.

    Args:
        entity_id: Entity ID to retrieve

    Returns:
        Entity with relationships

    Args:
        entity_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EntityResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            entity_id=entity_id,
            client=client,
        )
    ).parsed
