from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.graph_diff_api_v1_graph_diff_get_response_graph_diff_api_v1_graph_diff_get import (
    GraphDiffApiV1GraphDiffGetResponseGraphDiffApiV1GraphDiffGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    pr_id: None | str | Unset = UNSET,
    base_report_id: None | str | Unset = UNSET,
    head_report_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_pr_id: None | str | Unset
    if isinstance(pr_id, Unset):
        json_pr_id = UNSET
    else:
        json_pr_id = pr_id
    params["prId"] = json_pr_id

    json_base_report_id: None | str | Unset
    if isinstance(base_report_id, Unset):
        json_base_report_id = UNSET
    else:
        json_base_report_id = base_report_id
    params["base_report_id"] = json_base_report_id

    json_head_report_id: None | str | Unset
    if isinstance(head_report_id, Unset):
        json_head_report_id = UNSET
    else:
        json_head_report_id = head_report_id
    params["head_report_id"] = json_head_report_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/graph/diff",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GraphDiffApiV1GraphDiffGetResponseGraphDiffApiV1GraphDiffGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GraphDiffApiV1GraphDiffGetResponseGraphDiffApiV1GraphDiffGet.from_dict(response.json())

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
) -> Response[GraphDiffApiV1GraphDiffGetResponseGraphDiffApiV1GraphDiffGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    pr_id: None | str | Unset = UNSET,
    base_report_id: None | str | Unset = UNSET,
    head_report_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[GraphDiffApiV1GraphDiffGetResponseGraphDiffApiV1GraphDiffGet | HTTPValidationError]:
    """Diff architecture graph between two snapshots / a PR

     Compare two architecture snapshots and return added/removed entities.

    Snapshots are looked up by ``base_report_id`` / ``head_report_id`` query
    params, or by PR id if the snapshots are tagged with ``pr_id``.

    Args:
        pr_id (None | str | Unset):
        base_report_id (None | str | Unset):
        head_report_id (None | str | Unset):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GraphDiffApiV1GraphDiffGetResponseGraphDiffApiV1GraphDiffGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        pr_id=pr_id,
        base_report_id=base_report_id,
        head_report_id=head_report_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    pr_id: None | str | Unset = UNSET,
    base_report_id: None | str | Unset = UNSET,
    head_report_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> GraphDiffApiV1GraphDiffGetResponseGraphDiffApiV1GraphDiffGet | HTTPValidationError | None:
    """Diff architecture graph between two snapshots / a PR

     Compare two architecture snapshots and return added/removed entities.

    Snapshots are looked up by ``base_report_id`` / ``head_report_id`` query
    params, or by PR id if the snapshots are tagged with ``pr_id``.

    Args:
        pr_id (None | str | Unset):
        base_report_id (None | str | Unset):
        head_report_id (None | str | Unset):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GraphDiffApiV1GraphDiffGetResponseGraphDiffApiV1GraphDiffGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        pr_id=pr_id,
        base_report_id=base_report_id,
        head_report_id=head_report_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    pr_id: None | str | Unset = UNSET,
    base_report_id: None | str | Unset = UNSET,
    head_report_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[GraphDiffApiV1GraphDiffGetResponseGraphDiffApiV1GraphDiffGet | HTTPValidationError]:
    """Diff architecture graph between two snapshots / a PR

     Compare two architecture snapshots and return added/removed entities.

    Snapshots are looked up by ``base_report_id`` / ``head_report_id`` query
    params, or by PR id if the snapshots are tagged with ``pr_id``.

    Args:
        pr_id (None | str | Unset):
        base_report_id (None | str | Unset):
        head_report_id (None | str | Unset):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GraphDiffApiV1GraphDiffGetResponseGraphDiffApiV1GraphDiffGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        pr_id=pr_id,
        base_report_id=base_report_id,
        head_report_id=head_report_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    pr_id: None | str | Unset = UNSET,
    base_report_id: None | str | Unset = UNSET,
    head_report_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> GraphDiffApiV1GraphDiffGetResponseGraphDiffApiV1GraphDiffGet | HTTPValidationError | None:
    """Diff architecture graph between two snapshots / a PR

     Compare two architecture snapshots and return added/removed entities.

    Snapshots are looked up by ``base_report_id`` / ``head_report_id`` query
    params, or by PR id if the snapshots are tagged with ``pr_id``.

    Args:
        pr_id (None | str | Unset):
        base_report_id (None | str | Unset):
        head_report_id (None | str | Unset):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GraphDiffApiV1GraphDiffGetResponseGraphDiffApiV1GraphDiffGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            pr_id=pr_id,
            base_report_id=base_report_id,
            head_report_id=head_report_id,
            x_org_id=x_org_id,
        )
    ).parsed
