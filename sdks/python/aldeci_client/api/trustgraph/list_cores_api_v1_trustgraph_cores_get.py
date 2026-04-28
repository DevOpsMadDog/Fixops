from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.list_cores_api_v1_trustgraph_cores_get_response_list_cores_api_v1_trustgraph_cores_get import (
    ListCoresApiV1TrustgraphCoresGetResponseListCoresApiV1TrustgraphCoresGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/trustgraph/cores",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ListCoresApiV1TrustgraphCoresGetResponseListCoresApiV1TrustgraphCoresGet | None:
    if response.status_code == 200:
        response_200 = ListCoresApiV1TrustgraphCoresGetResponseListCoresApiV1TrustgraphCoresGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ListCoresApiV1TrustgraphCoresGetResponseListCoresApiV1TrustgraphCoresGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[ListCoresApiV1TrustgraphCoresGetResponseListCoresApiV1TrustgraphCoresGet]:
    """List Cores

     List all Knowledge Cores with summary statistics.

    Returns:
        List of cores with metadata and stats

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ListCoresApiV1TrustgraphCoresGetResponseListCoresApiV1TrustgraphCoresGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> ListCoresApiV1TrustgraphCoresGetResponseListCoresApiV1TrustgraphCoresGet | None:
    """List Cores

     List all Knowledge Cores with summary statistics.

    Returns:
        List of cores with metadata and stats

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ListCoresApiV1TrustgraphCoresGetResponseListCoresApiV1TrustgraphCoresGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[ListCoresApiV1TrustgraphCoresGetResponseListCoresApiV1TrustgraphCoresGet]:
    """List Cores

     List all Knowledge Cores with summary statistics.

    Returns:
        List of cores with metadata and stats

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ListCoresApiV1TrustgraphCoresGetResponseListCoresApiV1TrustgraphCoresGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> ListCoresApiV1TrustgraphCoresGetResponseListCoresApiV1TrustgraphCoresGet | None:
    """List Cores

     List all Knowledge Cores with summary statistics.

    Returns:
        List of cores with metadata and stats

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ListCoresApiV1TrustgraphCoresGetResponseListCoresApiV1TrustgraphCoresGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
