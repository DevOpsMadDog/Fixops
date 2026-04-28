from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.graph_databases_api_v1_graph_databases_repo_id_get_response_graph_databases_api_v1_graph_databases_repo_id_get import (
    GraphDatabasesApiV1GraphDatabasesRepoIdGetResponseGraphDatabasesApiV1GraphDatabasesRepoIdGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    repo_id: str,
    *,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/graph/databases/{repo_id}".format(
            repo_id=quote(str(repo_id), safe=""),
        ),
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GraphDatabasesApiV1GraphDatabasesRepoIdGetResponseGraphDatabasesApiV1GraphDatabasesRepoIdGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            GraphDatabasesApiV1GraphDatabasesRepoIdGetResponseGraphDatabasesApiV1GraphDatabasesRepoIdGet.from_dict(
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
    GraphDatabasesApiV1GraphDatabasesRepoIdGetResponseGraphDatabasesApiV1GraphDatabasesRepoIdGet | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    repo_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GraphDatabasesApiV1GraphDatabasesRepoIdGetResponseGraphDatabasesApiV1GraphDatabasesRepoIdGet | HTTPValidationError
]:
    """List databases referenced by a repository

     Return databases discovered by /architecture-detect for the given repo.

    Args:
        repo_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GraphDatabasesApiV1GraphDatabasesRepoIdGetResponseGraphDatabasesApiV1GraphDatabasesRepoIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        repo_id=repo_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    repo_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GraphDatabasesApiV1GraphDatabasesRepoIdGetResponseGraphDatabasesApiV1GraphDatabasesRepoIdGet
    | HTTPValidationError
    | None
):
    """List databases referenced by a repository

     Return databases discovered by /architecture-detect for the given repo.

    Args:
        repo_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GraphDatabasesApiV1GraphDatabasesRepoIdGetResponseGraphDatabasesApiV1GraphDatabasesRepoIdGet | HTTPValidationError
    """

    return sync_detailed(
        repo_id=repo_id,
        client=client,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    repo_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GraphDatabasesApiV1GraphDatabasesRepoIdGetResponseGraphDatabasesApiV1GraphDatabasesRepoIdGet | HTTPValidationError
]:
    """List databases referenced by a repository

     Return databases discovered by /architecture-detect for the given repo.

    Args:
        repo_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GraphDatabasesApiV1GraphDatabasesRepoIdGetResponseGraphDatabasesApiV1GraphDatabasesRepoIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        repo_id=repo_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    repo_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GraphDatabasesApiV1GraphDatabasesRepoIdGetResponseGraphDatabasesApiV1GraphDatabasesRepoIdGet
    | HTTPValidationError
    | None
):
    """List databases referenced by a repository

     Return databases discovered by /architecture-detect for the given repo.

    Args:
        repo_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GraphDatabasesApiV1GraphDatabasesRepoIdGetResponseGraphDatabasesApiV1GraphDatabasesRepoIdGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            repo_id=repo_id,
            client=client,
            x_org_id=x_org_id,
        )
    ).parsed
