from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.graph_diff_by_ids_api_v1_graph_diff_baseline_id_current_id_get_response_graph_diff_by_ids_api_v1_graph_diff_baseline_id_current_id_get import (
    GraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGetResponseGraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    baseline_id: str,
    current_id: str,
    *,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/graph/diff/{baseline_id}/{current_id}".format(
            baseline_id=quote(str(baseline_id), safe=""),
            current_id=quote(str(current_id), safe=""),
        ),
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGetResponseGraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGetResponseGraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet.from_dict(
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
    GraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGetResponseGraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    baseline_id: str,
    current_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGetResponseGraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet
    | HTTPValidationError
]:
    """Diff two architecture/graph snapshots by their IDs

     Diff two architecture-detect snapshots by ID.

    Looks both snapshots up in the ``architecture_reports`` persistent store and
    returns added/removed entities across layers, services, databases and APIs.

    Wires to ``core.architecture_diff_engine.ArchitectureDiffEngine`` if it
    exists; falls back to a deterministic set diff otherwise.

    Args:
        baseline_id (str):
        current_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGetResponseGraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        baseline_id=baseline_id,
        current_id=current_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    baseline_id: str,
    current_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGetResponseGraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet
    | HTTPValidationError
    | None
):
    """Diff two architecture/graph snapshots by their IDs

     Diff two architecture-detect snapshots by ID.

    Looks both snapshots up in the ``architecture_reports`` persistent store and
    returns added/removed entities across layers, services, databases and APIs.

    Wires to ``core.architecture_diff_engine.ArchitectureDiffEngine`` if it
    exists; falls back to a deterministic set diff otherwise.

    Args:
        baseline_id (str):
        current_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGetResponseGraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet | HTTPValidationError
    """

    return sync_detailed(
        baseline_id=baseline_id,
        current_id=current_id,
        client=client,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    baseline_id: str,
    current_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGetResponseGraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet
    | HTTPValidationError
]:
    """Diff two architecture/graph snapshots by their IDs

     Diff two architecture-detect snapshots by ID.

    Looks both snapshots up in the ``architecture_reports`` persistent store and
    returns added/removed entities across layers, services, databases and APIs.

    Wires to ``core.architecture_diff_engine.ArchitectureDiffEngine`` if it
    exists; falls back to a deterministic set diff otherwise.

    Args:
        baseline_id (str):
        current_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGetResponseGraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        baseline_id=baseline_id,
        current_id=current_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    baseline_id: str,
    current_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGetResponseGraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet
    | HTTPValidationError
    | None
):
    """Diff two architecture/graph snapshots by their IDs

     Diff two architecture-detect snapshots by ID.

    Looks both snapshots up in the ``architecture_reports`` persistent store and
    returns added/removed entities across layers, services, databases and APIs.

    Wires to ``core.architecture_diff_engine.ArchitectureDiffEngine`` if it
    exists; falls back to a deterministic set diff otherwise.

    Args:
        baseline_id (str):
        current_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGetResponseGraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            baseline_id=baseline_id,
            current_id=current_id,
            client=client,
            x_org_id=x_org_id,
        )
    ).parsed
