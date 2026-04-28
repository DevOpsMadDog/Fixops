from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.ide_user_snapshot_api_v1_ide_user_snapshot_get_response_ide_user_snapshot_api_v1_ide_user_snapshot_get import (
    IdeUserSnapshotApiV1IdeUserSnapshotGetResponseIdeUserSnapshotApiV1IdeUserSnapshotGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    user_id: str | Unset = "self",
    repo: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
    x_user_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    if not isinstance(x_user_id, Unset):
        headers["X-User-ID"] = x_user_id

    params: dict[str, Any] = {}

    params["user_id"] = user_id

    json_repo: None | str | Unset
    if isinstance(repo, Unset):
        json_repo = UNSET
    else:
        json_repo = repo
    params["repo"] = json_repo

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/ide/user-snapshot",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | IdeUserSnapshotApiV1IdeUserSnapshotGetResponseIdeUserSnapshotApiV1IdeUserSnapshotGet | None:
    if response.status_code == 200:
        response_200 = IdeUserSnapshotApiV1IdeUserSnapshotGetResponseIdeUserSnapshotApiV1IdeUserSnapshotGet.from_dict(
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
    HTTPValidationError | IdeUserSnapshotApiV1IdeUserSnapshotGetResponseIdeUserSnapshotApiV1IdeUserSnapshotGet
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
    user_id: str | Unset = "self",
    repo: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
    x_user_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError | IdeUserSnapshotApiV1IdeUserSnapshotGetResponseIdeUserSnapshotApiV1IdeUserSnapshotGet
]:
    """Snapshot of a user's IDE state — recent findings, open files, scopes

     Return per-user IDE snapshot: recent files, scopes, finding counts.

    Args:
        user_id (str | Unset):  Default: 'self'.
        repo (None | str | Unset):
        x_org_id (None | str | Unset):
        x_user_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | IdeUserSnapshotApiV1IdeUserSnapshotGetResponseIdeUserSnapshotApiV1IdeUserSnapshotGet]
    """

    kwargs = _get_kwargs(
        user_id=user_id,
        repo=repo,
        x_org_id=x_org_id,
        x_user_id=x_user_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    user_id: str | Unset = "self",
    repo: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
    x_user_id: None | str | Unset = UNSET,
) -> HTTPValidationError | IdeUserSnapshotApiV1IdeUserSnapshotGetResponseIdeUserSnapshotApiV1IdeUserSnapshotGet | None:
    """Snapshot of a user's IDE state — recent findings, open files, scopes

     Return per-user IDE snapshot: recent files, scopes, finding counts.

    Args:
        user_id (str | Unset):  Default: 'self'.
        repo (None | str | Unset):
        x_org_id (None | str | Unset):
        x_user_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | IdeUserSnapshotApiV1IdeUserSnapshotGetResponseIdeUserSnapshotApiV1IdeUserSnapshotGet
    """

    return sync_detailed(
        client=client,
        user_id=user_id,
        repo=repo,
        x_org_id=x_org_id,
        x_user_id=x_user_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    user_id: str | Unset = "self",
    repo: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
    x_user_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError | IdeUserSnapshotApiV1IdeUserSnapshotGetResponseIdeUserSnapshotApiV1IdeUserSnapshotGet
]:
    """Snapshot of a user's IDE state — recent findings, open files, scopes

     Return per-user IDE snapshot: recent files, scopes, finding counts.

    Args:
        user_id (str | Unset):  Default: 'self'.
        repo (None | str | Unset):
        x_org_id (None | str | Unset):
        x_user_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | IdeUserSnapshotApiV1IdeUserSnapshotGetResponseIdeUserSnapshotApiV1IdeUserSnapshotGet]
    """

    kwargs = _get_kwargs(
        user_id=user_id,
        repo=repo,
        x_org_id=x_org_id,
        x_user_id=x_user_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    user_id: str | Unset = "self",
    repo: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
    x_user_id: None | str | Unset = UNSET,
) -> HTTPValidationError | IdeUserSnapshotApiV1IdeUserSnapshotGetResponseIdeUserSnapshotApiV1IdeUserSnapshotGet | None:
    """Snapshot of a user's IDE state — recent findings, open files, scopes

     Return per-user IDE snapshot: recent files, scopes, finding counts.

    Args:
        user_id (str | Unset):  Default: 'self'.
        repo (None | str | Unset):
        x_org_id (None | str | Unset):
        x_user_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | IdeUserSnapshotApiV1IdeUserSnapshotGetResponseIdeUserSnapshotApiV1IdeUserSnapshotGet
    """

    return (
        await asyncio_detailed(
            client=client,
            user_id=user_id,
            repo=repo,
            x_org_id=x_org_id,
            x_user_id=x_user_id,
        )
    ).parsed
