from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.rollback_change_api_v1_changes_change_id_rollback_post_response_rollback_change_api_v1_changes_change_id_rollback_post import (
    RollbackChangeApiV1ChangesChangeIdRollbackPostResponseRollbackChangeApiV1ChangesChangeIdRollbackPost,
)
from ...models.rollback_request import RollbackRequest
from ...types import Response


def _get_kwargs(
    change_id: str,
    *,
    body: RollbackRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/changes/{change_id}/rollback".format(
            change_id=quote(str(change_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | RollbackChangeApiV1ChangesChangeIdRollbackPostResponseRollbackChangeApiV1ChangesChangeIdRollbackPost
    | None
):
    if response.status_code == 200:
        response_200 = RollbackChangeApiV1ChangesChangeIdRollbackPostResponseRollbackChangeApiV1ChangesChangeIdRollbackPost.from_dict(
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
    | RollbackChangeApiV1ChangesChangeIdRollbackPostResponseRollbackChangeApiV1ChangesChangeIdRollbackPost
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    change_id: str,
    *,
    client: AuthenticatedClient,
    body: RollbackRequest,
) -> Response[
    HTTPValidationError
    | RollbackChangeApiV1ChangesChangeIdRollbackPostResponseRollbackChangeApiV1ChangesChangeIdRollbackPost
]:
    """Rollback Change

     Execute rollback for a change that is IMPLEMENTING or COMPLETED.

    Args:
        change_id (str):
        body (RollbackRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RollbackChangeApiV1ChangesChangeIdRollbackPostResponseRollbackChangeApiV1ChangesChangeIdRollbackPost]
    """

    kwargs = _get_kwargs(
        change_id=change_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    change_id: str,
    *,
    client: AuthenticatedClient,
    body: RollbackRequest,
) -> (
    HTTPValidationError
    | RollbackChangeApiV1ChangesChangeIdRollbackPostResponseRollbackChangeApiV1ChangesChangeIdRollbackPost
    | None
):
    """Rollback Change

     Execute rollback for a change that is IMPLEMENTING or COMPLETED.

    Args:
        change_id (str):
        body (RollbackRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RollbackChangeApiV1ChangesChangeIdRollbackPostResponseRollbackChangeApiV1ChangesChangeIdRollbackPost
    """

    return sync_detailed(
        change_id=change_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    change_id: str,
    *,
    client: AuthenticatedClient,
    body: RollbackRequest,
) -> Response[
    HTTPValidationError
    | RollbackChangeApiV1ChangesChangeIdRollbackPostResponseRollbackChangeApiV1ChangesChangeIdRollbackPost
]:
    """Rollback Change

     Execute rollback for a change that is IMPLEMENTING or COMPLETED.

    Args:
        change_id (str):
        body (RollbackRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RollbackChangeApiV1ChangesChangeIdRollbackPostResponseRollbackChangeApiV1ChangesChangeIdRollbackPost]
    """

    kwargs = _get_kwargs(
        change_id=change_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    change_id: str,
    *,
    client: AuthenticatedClient,
    body: RollbackRequest,
) -> (
    HTTPValidationError
    | RollbackChangeApiV1ChangesChangeIdRollbackPostResponseRollbackChangeApiV1ChangesChangeIdRollbackPost
    | None
):
    """Rollback Change

     Execute rollback for a change that is IMPLEMENTING or COMPLETED.

    Args:
        change_id (str):
        body (RollbackRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RollbackChangeApiV1ChangesChangeIdRollbackPostResponseRollbackChangeApiV1ChangesChangeIdRollbackPost
    """

    return (
        await asyncio_detailed(
            change_id=change_id,
            client=client,
            body=body,
        )
    ).parsed
