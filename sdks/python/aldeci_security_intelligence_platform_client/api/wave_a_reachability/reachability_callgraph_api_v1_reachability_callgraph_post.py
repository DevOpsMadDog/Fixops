from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.call_graph_request import CallGraphRequest
from ...models.http_validation_error import HTTPValidationError
from ...models.reachability_callgraph_api_v1_reachability_callgraph_post_response_reachability_callgraph_api_v1_reachability_callgraph_post import (
    ReachabilityCallgraphApiV1ReachabilityCallgraphPostResponseReachabilityCallgraphApiV1ReachabilityCallgraphPost,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: CallGraphRequest,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/reachability/callgraph",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | ReachabilityCallgraphApiV1ReachabilityCallgraphPostResponseReachabilityCallgraphApiV1ReachabilityCallgraphPost
    | None
):
    if response.status_code == 201:
        response_201 = ReachabilityCallgraphApiV1ReachabilityCallgraphPostResponseReachabilityCallgraphApiV1ReachabilityCallgraphPost.from_dict(
            response.json()
        )

        return response_201

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
    | ReachabilityCallgraphApiV1ReachabilityCallgraphPostResponseReachabilityCallgraphApiV1ReachabilityCallgraphPost
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
    body: CallGraphRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | ReachabilityCallgraphApiV1ReachabilityCallgraphPostResponseReachabilityCallgraphApiV1ReachabilityCallgraphPost
]:
    """Build a callgraph for a repo

     Build a callgraph for a repo using the function_reachability_engine.

    For Python repos with a local ``repo_path`` provided we delegate to the
    engine's AST parser. For non-Python or remote repos, returns 501.

    Args:
        x_org_id (None | str | Unset):
        body (CallGraphRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ReachabilityCallgraphApiV1ReachabilityCallgraphPostResponseReachabilityCallgraphApiV1ReachabilityCallgraphPost]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: CallGraphRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | ReachabilityCallgraphApiV1ReachabilityCallgraphPostResponseReachabilityCallgraphApiV1ReachabilityCallgraphPost
    | None
):
    """Build a callgraph for a repo

     Build a callgraph for a repo using the function_reachability_engine.

    For Python repos with a local ``repo_path`` provided we delegate to the
    engine's AST parser. For non-Python or remote repos, returns 501.

    Args:
        x_org_id (None | str | Unset):
        body (CallGraphRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ReachabilityCallgraphApiV1ReachabilityCallgraphPostResponseReachabilityCallgraphApiV1ReachabilityCallgraphPost
    """

    return sync_detailed(
        client=client,
        body=body,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: CallGraphRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | ReachabilityCallgraphApiV1ReachabilityCallgraphPostResponseReachabilityCallgraphApiV1ReachabilityCallgraphPost
]:
    """Build a callgraph for a repo

     Build a callgraph for a repo using the function_reachability_engine.

    For Python repos with a local ``repo_path`` provided we delegate to the
    engine's AST parser. For non-Python or remote repos, returns 501.

    Args:
        x_org_id (None | str | Unset):
        body (CallGraphRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ReachabilityCallgraphApiV1ReachabilityCallgraphPostResponseReachabilityCallgraphApiV1ReachabilityCallgraphPost]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: CallGraphRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | ReachabilityCallgraphApiV1ReachabilityCallgraphPostResponseReachabilityCallgraphApiV1ReachabilityCallgraphPost
    | None
):
    """Build a callgraph for a repo

     Build a callgraph for a repo using the function_reachability_engine.

    For Python repos with a local ``repo_path`` provided we delegate to the
    engine's AST parser. For non-Python or remote repos, returns 501.

    Args:
        x_org_id (None | str | Unset):
        body (CallGraphRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ReachabilityCallgraphApiV1ReachabilityCallgraphPostResponseReachabilityCallgraphApiV1ReachabilityCallgraphPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            x_org_id=x_org_id,
        )
    ).parsed
