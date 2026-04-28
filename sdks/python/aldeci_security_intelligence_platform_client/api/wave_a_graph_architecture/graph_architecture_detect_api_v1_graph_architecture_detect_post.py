from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.architecture_detect_request import ArchitectureDetectRequest
from ...models.graph_architecture_detect_api_v1_graph_architecture_detect_post_response_graph_architecture_detect_api_v1_graph_architecture_detect_post import (
    GraphArchitectureDetectApiV1GraphArchitectureDetectPostResponseGraphArchitectureDetectApiV1GraphArchitectureDetectPost,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: ArchitectureDetectRequest,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/graph/architecture-detect",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GraphArchitectureDetectApiV1GraphArchitectureDetectPostResponseGraphArchitectureDetectApiV1GraphArchitectureDetectPost
    | HTTPValidationError
    | None
):
    if response.status_code == 201:
        response_201 = GraphArchitectureDetectApiV1GraphArchitectureDetectPostResponseGraphArchitectureDetectApiV1GraphArchitectureDetectPost.from_dict(
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
    GraphArchitectureDetectApiV1GraphArchitectureDetectPostResponseGraphArchitectureDetectApiV1GraphArchitectureDetectPost
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
    body: ArchitectureDetectRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GraphArchitectureDetectApiV1GraphArchitectureDetectPostResponseGraphArchitectureDetectApiV1GraphArchitectureDetectPost
    | HTTPValidationError
]:
    """Detect architecture (layers/services/databases/APIs) from a repo

     Run architecture detection over a repository and persist the snapshot.

    Wires to existing helpers when available:
      * ``core.security_architecture_review_engine`` — high-level review
      * Filesystem walk for layer / database / API detection (deterministic)

    Returns: report_id, layer count, service count, database count, API count.

    Args:
        x_org_id (None | str | Unset):
        body (ArchitectureDetectRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GraphArchitectureDetectApiV1GraphArchitectureDetectPostResponseGraphArchitectureDetectApiV1GraphArchitectureDetectPost | HTTPValidationError]
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
    body: ArchitectureDetectRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GraphArchitectureDetectApiV1GraphArchitectureDetectPostResponseGraphArchitectureDetectApiV1GraphArchitectureDetectPost
    | HTTPValidationError
    | None
):
    """Detect architecture (layers/services/databases/APIs) from a repo

     Run architecture detection over a repository and persist the snapshot.

    Wires to existing helpers when available:
      * ``core.security_architecture_review_engine`` — high-level review
      * Filesystem walk for layer / database / API detection (deterministic)

    Returns: report_id, layer count, service count, database count, API count.

    Args:
        x_org_id (None | str | Unset):
        body (ArchitectureDetectRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GraphArchitectureDetectApiV1GraphArchitectureDetectPostResponseGraphArchitectureDetectApiV1GraphArchitectureDetectPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ArchitectureDetectRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GraphArchitectureDetectApiV1GraphArchitectureDetectPostResponseGraphArchitectureDetectApiV1GraphArchitectureDetectPost
    | HTTPValidationError
]:
    """Detect architecture (layers/services/databases/APIs) from a repo

     Run architecture detection over a repository and persist the snapshot.

    Wires to existing helpers when available:
      * ``core.security_architecture_review_engine`` — high-level review
      * Filesystem walk for layer / database / API detection (deterministic)

    Returns: report_id, layer count, service count, database count, API count.

    Args:
        x_org_id (None | str | Unset):
        body (ArchitectureDetectRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GraphArchitectureDetectApiV1GraphArchitectureDetectPostResponseGraphArchitectureDetectApiV1GraphArchitectureDetectPost | HTTPValidationError]
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
    body: ArchitectureDetectRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GraphArchitectureDetectApiV1GraphArchitectureDetectPostResponseGraphArchitectureDetectApiV1GraphArchitectureDetectPost
    | HTTPValidationError
    | None
):
    """Detect architecture (layers/services/databases/APIs) from a repo

     Run architecture detection over a repository and persist the snapshot.

    Wires to existing helpers when available:
      * ``core.security_architecture_review_engine`` — high-level review
      * Filesystem walk for layer / database / API detection (deterministic)

    Returns: report_id, layer count, service count, database count, API count.

    Args:
        x_org_id (None | str | Unset):
        body (ArchitectureDetectRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GraphArchitectureDetectApiV1GraphArchitectureDetectPostResponseGraphArchitectureDetectApiV1GraphArchitectureDetectPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            x_org_id=x_org_id,
        )
    ).parsed
