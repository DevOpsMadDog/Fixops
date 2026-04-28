from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.graph_affected_nodes_api_v1_graph_affected_nodes_get_response_graph_affected_nodes_api_v1_graph_affected_nodes_get import (
    GraphAffectedNodesApiV1GraphAffectedNodesGetResponseGraphAffectedNodesApiV1GraphAffectedNodesGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    since: str,
    node_kinds: None | str | Unset = UNSET,
    limit: int | Unset = 500,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["since"] = since

    json_node_kinds: None | str | Unset
    if isinstance(node_kinds, Unset):
        json_node_kinds = UNSET
    else:
        json_node_kinds = node_kinds
    params["node_kinds"] = json_node_kinds

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/graph/affected-nodes",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GraphAffectedNodesApiV1GraphAffectedNodesGetResponseGraphAffectedNodesApiV1GraphAffectedNodesGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            GraphAffectedNodesApiV1GraphAffectedNodesGetResponseGraphAffectedNodesApiV1GraphAffectedNodesGet.from_dict(
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
    GraphAffectedNodesApiV1GraphAffectedNodesGetResponseGraphAffectedNodesApiV1GraphAffectedNodesGet
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
    since: str,
    node_kinds: None | str | Unset = UNSET,
    limit: int | Unset = 500,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GraphAffectedNodesApiV1GraphAffectedNodesGetResponseGraphAffectedNodesApiV1GraphAffectedNodesGet
    | HTTPValidationError
]:
    """List graph nodes whose state changed since a given timestamp

     Return graph nodes added/modified after the supplied threshold.

    Sources, in priority:
      1. ``core.cloud_graph.CloudGraphEngine`` (live tenant graph)
      2. ``architecture_reports`` persistent_store snapshots (delta of new nodes)

    Both sources fall through gracefully — if neither has data we return an
    empty list with `available=False` so the UI can render an EmptyState.

    Args:
        since (str): ISO-8601 timestamp or relative duration (e.g. 4h, 2d)
        node_kinds (None | str | Unset): Comma-separated kinds filter: service,layer,database,api
        limit (int | Unset):  Default: 500.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GraphAffectedNodesApiV1GraphAffectedNodesGetResponseGraphAffectedNodesApiV1GraphAffectedNodesGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        since=since,
        node_kinds=node_kinds,
        limit=limit,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    since: str,
    node_kinds: None | str | Unset = UNSET,
    limit: int | Unset = 500,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GraphAffectedNodesApiV1GraphAffectedNodesGetResponseGraphAffectedNodesApiV1GraphAffectedNodesGet
    | HTTPValidationError
    | None
):
    """List graph nodes whose state changed since a given timestamp

     Return graph nodes added/modified after the supplied threshold.

    Sources, in priority:
      1. ``core.cloud_graph.CloudGraphEngine`` (live tenant graph)
      2. ``architecture_reports`` persistent_store snapshots (delta of new nodes)

    Both sources fall through gracefully — if neither has data we return an
    empty list with `available=False` so the UI can render an EmptyState.

    Args:
        since (str): ISO-8601 timestamp or relative duration (e.g. 4h, 2d)
        node_kinds (None | str | Unset): Comma-separated kinds filter: service,layer,database,api
        limit (int | Unset):  Default: 500.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GraphAffectedNodesApiV1GraphAffectedNodesGetResponseGraphAffectedNodesApiV1GraphAffectedNodesGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        since=since,
        node_kinds=node_kinds,
        limit=limit,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    since: str,
    node_kinds: None | str | Unset = UNSET,
    limit: int | Unset = 500,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GraphAffectedNodesApiV1GraphAffectedNodesGetResponseGraphAffectedNodesApiV1GraphAffectedNodesGet
    | HTTPValidationError
]:
    """List graph nodes whose state changed since a given timestamp

     Return graph nodes added/modified after the supplied threshold.

    Sources, in priority:
      1. ``core.cloud_graph.CloudGraphEngine`` (live tenant graph)
      2. ``architecture_reports`` persistent_store snapshots (delta of new nodes)

    Both sources fall through gracefully — if neither has data we return an
    empty list with `available=False` so the UI can render an EmptyState.

    Args:
        since (str): ISO-8601 timestamp or relative duration (e.g. 4h, 2d)
        node_kinds (None | str | Unset): Comma-separated kinds filter: service,layer,database,api
        limit (int | Unset):  Default: 500.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GraphAffectedNodesApiV1GraphAffectedNodesGetResponseGraphAffectedNodesApiV1GraphAffectedNodesGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        since=since,
        node_kinds=node_kinds,
        limit=limit,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    since: str,
    node_kinds: None | str | Unset = UNSET,
    limit: int | Unset = 500,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GraphAffectedNodesApiV1GraphAffectedNodesGetResponseGraphAffectedNodesApiV1GraphAffectedNodesGet
    | HTTPValidationError
    | None
):
    """List graph nodes whose state changed since a given timestamp

     Return graph nodes added/modified after the supplied threshold.

    Sources, in priority:
      1. ``core.cloud_graph.CloudGraphEngine`` (live tenant graph)
      2. ``architecture_reports`` persistent_store snapshots (delta of new nodes)

    Both sources fall through gracefully — if neither has data we return an
    empty list with `available=False` so the UI can render an EmptyState.

    Args:
        since (str): ISO-8601 timestamp or relative duration (e.g. 4h, 2d)
        node_kinds (None | str | Unset): Comma-separated kinds filter: service,layer,database,api
        limit (int | Unset):  Default: 500.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GraphAffectedNodesApiV1GraphAffectedNodesGetResponseGraphAffectedNodesApiV1GraphAffectedNodesGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            since=since,
            node_kinds=node_kinds,
            limit=limit,
            x_org_id=x_org_id,
        )
    ).parsed
