from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.search_components_api_v1_dtrack_components_search_get_response_search_components_api_v1_dtrack_components_search_get import (
    SearchComponentsApiV1DtrackComponentsSearchGetResponseSearchComponentsApiV1DtrackComponentsSearchGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    query: str,
    page: int | Unset = 1,
    page_size: int | Unset = 100,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["query"] = query

    params["page"] = page

    params["page_size"] = page_size

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/dtrack/components/search",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | SearchComponentsApiV1DtrackComponentsSearchGetResponseSearchComponentsApiV1DtrackComponentsSearchGet
    | None
):
    if response.status_code == 200:
        response_200 = SearchComponentsApiV1DtrackComponentsSearchGetResponseSearchComponentsApiV1DtrackComponentsSearchGet.from_dict(
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
    | SearchComponentsApiV1DtrackComponentsSearchGetResponseSearchComponentsApiV1DtrackComponentsSearchGet
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
    query: str,
    page: int | Unset = 1,
    page_size: int | Unset = 100,
) -> Response[
    HTTPValidationError
    | SearchComponentsApiV1DtrackComponentsSearchGetResponseSearchComponentsApiV1DtrackComponentsSearchGet
]:
    """Search Components

     Search components across entire portfolio. Use for impact analysis
    (e.g., 'which applications use log4j?').

    Args:
        query (str): Component name to search (e.g. 'log4j')
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SearchComponentsApiV1DtrackComponentsSearchGetResponseSearchComponentsApiV1DtrackComponentsSearchGet]
    """

    kwargs = _get_kwargs(
        query=query,
        page=page,
        page_size=page_size,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    query: str,
    page: int | Unset = 1,
    page_size: int | Unset = 100,
) -> (
    HTTPValidationError
    | SearchComponentsApiV1DtrackComponentsSearchGetResponseSearchComponentsApiV1DtrackComponentsSearchGet
    | None
):
    """Search Components

     Search components across entire portfolio. Use for impact analysis
    (e.g., 'which applications use log4j?').

    Args:
        query (str): Component name to search (e.g. 'log4j')
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SearchComponentsApiV1DtrackComponentsSearchGetResponseSearchComponentsApiV1DtrackComponentsSearchGet
    """

    return sync_detailed(
        client=client,
        query=query,
        page=page,
        page_size=page_size,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    query: str,
    page: int | Unset = 1,
    page_size: int | Unset = 100,
) -> Response[
    HTTPValidationError
    | SearchComponentsApiV1DtrackComponentsSearchGetResponseSearchComponentsApiV1DtrackComponentsSearchGet
]:
    """Search Components

     Search components across entire portfolio. Use for impact analysis
    (e.g., 'which applications use log4j?').

    Args:
        query (str): Component name to search (e.g. 'log4j')
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SearchComponentsApiV1DtrackComponentsSearchGetResponseSearchComponentsApiV1DtrackComponentsSearchGet]
    """

    kwargs = _get_kwargs(
        query=query,
        page=page,
        page_size=page_size,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    query: str,
    page: int | Unset = 1,
    page_size: int | Unset = 100,
) -> (
    HTTPValidationError
    | SearchComponentsApiV1DtrackComponentsSearchGetResponseSearchComponentsApiV1DtrackComponentsSearchGet
    | None
):
    """Search Components

     Search components across entire portfolio. Use for impact analysis
    (e.g., 'which applications use log4j?').

    Args:
        query (str): Component name to search (e.g. 'log4j')
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SearchComponentsApiV1DtrackComponentsSearchGetResponseSearchComponentsApiV1DtrackComponentsSearchGet
    """

    return (
        await asyncio_detailed(
            client=client,
            query=query,
            page=page,
            page_size=page_size,
        )
    ).parsed
