from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.dca_entities_api_v1_dca_entities_repo_get_response_dca_entities_api_v1_dca_entities_repo_get import (
    DcaEntitiesApiV1DcaEntitiesRepoGetResponseDcaEntitiesApiV1DcaEntitiesRepoGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    repo: str,
    *,
    kind: None | str | Unset = UNSET,
    limit: int | Unset = 200,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_kind: None | str | Unset
    if isinstance(kind, Unset):
        json_kind = UNSET
    else:
        json_kind = kind
    params["kind"] = json_kind

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/dca/entities/{repo}".format(
            repo=quote(str(repo), safe=""),
        ),
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> DcaEntitiesApiV1DcaEntitiesRepoGetResponseDcaEntitiesApiV1DcaEntitiesRepoGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = DcaEntitiesApiV1DcaEntitiesRepoGetResponseDcaEntitiesApiV1DcaEntitiesRepoGet.from_dict(
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
) -> Response[DcaEntitiesApiV1DcaEntitiesRepoGetResponseDcaEntitiesApiV1DcaEntitiesRepoGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    repo: str,
    *,
    client: AuthenticatedClient,
    kind: None | str | Unset = UNSET,
    limit: int | Unset = 200,
    x_org_id: None | str | Unset = UNSET,
) -> Response[DcaEntitiesApiV1DcaEntitiesRepoGetResponseDcaEntitiesApiV1DcaEntitiesRepoGet | HTTPValidationError]:
    """List parsed entities (functions, classes) for a repo

     Return entities recorded for a repo.

    Pulls from the ``function_reachability_engine`` SQLite tables when the
    parser populated them; otherwise returns the entity_counts persisted by
    /parse-repo.

    Args:
        repo (str):
        kind (None | str | Unset): function|class|module
        limit (int | Unset):  Default: 200.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DcaEntitiesApiV1DcaEntitiesRepoGetResponseDcaEntitiesApiV1DcaEntitiesRepoGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        repo=repo,
        kind=kind,
        limit=limit,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    repo: str,
    *,
    client: AuthenticatedClient,
    kind: None | str | Unset = UNSET,
    limit: int | Unset = 200,
    x_org_id: None | str | Unset = UNSET,
) -> DcaEntitiesApiV1DcaEntitiesRepoGetResponseDcaEntitiesApiV1DcaEntitiesRepoGet | HTTPValidationError | None:
    """List parsed entities (functions, classes) for a repo

     Return entities recorded for a repo.

    Pulls from the ``function_reachability_engine`` SQLite tables when the
    parser populated them; otherwise returns the entity_counts persisted by
    /parse-repo.

    Args:
        repo (str):
        kind (None | str | Unset): function|class|module
        limit (int | Unset):  Default: 200.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DcaEntitiesApiV1DcaEntitiesRepoGetResponseDcaEntitiesApiV1DcaEntitiesRepoGet | HTTPValidationError
    """

    return sync_detailed(
        repo=repo,
        client=client,
        kind=kind,
        limit=limit,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    repo: str,
    *,
    client: AuthenticatedClient,
    kind: None | str | Unset = UNSET,
    limit: int | Unset = 200,
    x_org_id: None | str | Unset = UNSET,
) -> Response[DcaEntitiesApiV1DcaEntitiesRepoGetResponseDcaEntitiesApiV1DcaEntitiesRepoGet | HTTPValidationError]:
    """List parsed entities (functions, classes) for a repo

     Return entities recorded for a repo.

    Pulls from the ``function_reachability_engine`` SQLite tables when the
    parser populated them; otherwise returns the entity_counts persisted by
    /parse-repo.

    Args:
        repo (str):
        kind (None | str | Unset): function|class|module
        limit (int | Unset):  Default: 200.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DcaEntitiesApiV1DcaEntitiesRepoGetResponseDcaEntitiesApiV1DcaEntitiesRepoGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        repo=repo,
        kind=kind,
        limit=limit,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    repo: str,
    *,
    client: AuthenticatedClient,
    kind: None | str | Unset = UNSET,
    limit: int | Unset = 200,
    x_org_id: None | str | Unset = UNSET,
) -> DcaEntitiesApiV1DcaEntitiesRepoGetResponseDcaEntitiesApiV1DcaEntitiesRepoGet | HTTPValidationError | None:
    """List parsed entities (functions, classes) for a repo

     Return entities recorded for a repo.

    Pulls from the ``function_reachability_engine`` SQLite tables when the
    parser populated them; otherwise returns the entity_counts persisted by
    /parse-repo.

    Args:
        repo (str):
        kind (None | str | Unset): function|class|module
        limit (int | Unset):  Default: 200.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DcaEntitiesApiV1DcaEntitiesRepoGetResponseDcaEntitiesApiV1DcaEntitiesRepoGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            repo=repo,
            client=client,
            kind=kind,
            limit=limit,
            x_org_id=x_org_id,
        )
    ).parsed
