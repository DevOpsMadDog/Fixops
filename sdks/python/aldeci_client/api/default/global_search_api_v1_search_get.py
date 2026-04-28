from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.global_search_api_v1_search_get_response_global_search_api_v1_search_get import (
    GlobalSearchApiV1SearchGetResponseGlobalSearchApiV1SearchGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    q: str | Unset = "",
    entity_types: None | str | Unset = UNSET,
    limit: int | Unset = 50,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["q"] = q

    json_entity_types: None | str | Unset
    if isinstance(entity_types, Unset):
        json_entity_types = UNSET
    else:
        json_entity_types = entity_types
    params["entity_types"] = json_entity_types

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/search",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GlobalSearchApiV1SearchGetResponseGlobalSearchApiV1SearchGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GlobalSearchApiV1SearchGetResponseGlobalSearchApiV1SearchGet.from_dict(response.json())

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
) -> Response[GlobalSearchApiV1SearchGetResponseGlobalSearchApiV1SearchGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    q: str | Unset = "",
    entity_types: None | str | Unset = UNSET,
    limit: int | Unset = 50,
) -> Response[GlobalSearchApiV1SearchGetResponseGlobalSearchApiV1SearchGet | HTTPValidationError]:
    """Global Search

     Cross-entity global search across findings, assets, evidence, and tickets.

    Returns unified results sorted by relevance with type annotations so the
    UI can render heterogeneous result cards in a single list.

    Args:
        q (str | Unset): Search query Default: ''.
        entity_types (None | str | Unset): Comma-separated entity types to search:
            findings,assets,evidence,tickets. Default: all.
        limit (int | Unset): Max results per entity type Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GlobalSearchApiV1SearchGetResponseGlobalSearchApiV1SearchGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        q=q,
        entity_types=entity_types,
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    q: str | Unset = "",
    entity_types: None | str | Unset = UNSET,
    limit: int | Unset = 50,
) -> GlobalSearchApiV1SearchGetResponseGlobalSearchApiV1SearchGet | HTTPValidationError | None:
    """Global Search

     Cross-entity global search across findings, assets, evidence, and tickets.

    Returns unified results sorted by relevance with type annotations so the
    UI can render heterogeneous result cards in a single list.

    Args:
        q (str | Unset): Search query Default: ''.
        entity_types (None | str | Unset): Comma-separated entity types to search:
            findings,assets,evidence,tickets. Default: all.
        limit (int | Unset): Max results per entity type Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GlobalSearchApiV1SearchGetResponseGlobalSearchApiV1SearchGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        q=q,
        entity_types=entity_types,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    q: str | Unset = "",
    entity_types: None | str | Unset = UNSET,
    limit: int | Unset = 50,
) -> Response[GlobalSearchApiV1SearchGetResponseGlobalSearchApiV1SearchGet | HTTPValidationError]:
    """Global Search

     Cross-entity global search across findings, assets, evidence, and tickets.

    Returns unified results sorted by relevance with type annotations so the
    UI can render heterogeneous result cards in a single list.

    Args:
        q (str | Unset): Search query Default: ''.
        entity_types (None | str | Unset): Comma-separated entity types to search:
            findings,assets,evidence,tickets. Default: all.
        limit (int | Unset): Max results per entity type Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GlobalSearchApiV1SearchGetResponseGlobalSearchApiV1SearchGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        q=q,
        entity_types=entity_types,
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    q: str | Unset = "",
    entity_types: None | str | Unset = UNSET,
    limit: int | Unset = 50,
) -> GlobalSearchApiV1SearchGetResponseGlobalSearchApiV1SearchGet | HTTPValidationError | None:
    """Global Search

     Cross-entity global search across findings, assets, evidence, and tickets.

    Returns unified results sorted by relevance with type annotations so the
    UI can render heterogeneous result cards in a single list.

    Args:
        q (str | Unset): Search query Default: ''.
        entity_types (None | str | Unset): Comma-separated entity types to search:
            findings,assets,evidence,tickets. Default: all.
        limit (int | Unset): Max results per entity type Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GlobalSearchApiV1SearchGetResponseGlobalSearchApiV1SearchGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            q=q,
            entity_types=entity_types,
            limit=limit,
        )
    ).parsed
