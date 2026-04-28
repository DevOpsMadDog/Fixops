from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.add_comment_api_v1_collaboration_comments_post_response_add_comment_api_v1_collaboration_comments_post import (
    AddCommentApiV1CollaborationCommentsPostResponseAddCommentApiV1CollaborationCommentsPost,
)
from ...models.add_comment_request import AddCommentRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    *,
    body: AddCommentRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/collaboration/comments",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    AddCommentApiV1CollaborationCommentsPostResponseAddCommentApiV1CollaborationCommentsPost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            AddCommentApiV1CollaborationCommentsPostResponseAddCommentApiV1CollaborationCommentsPost.from_dict(
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
    AddCommentApiV1CollaborationCommentsPostResponseAddCommentApiV1CollaborationCommentsPost | HTTPValidationError
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
    body: AddCommentRequest,
) -> Response[
    AddCommentApiV1CollaborationCommentsPostResponseAddCommentApiV1CollaborationCommentsPost | HTTPValidationError
]:
    """Add Comment

     Add a comment to an entity.

    Args:
        body (AddCommentRequest): Request to add a comment.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AddCommentApiV1CollaborationCommentsPostResponseAddCommentApiV1CollaborationCommentsPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: AddCommentRequest,
) -> (
    AddCommentApiV1CollaborationCommentsPostResponseAddCommentApiV1CollaborationCommentsPost
    | HTTPValidationError
    | None
):
    """Add Comment

     Add a comment to an entity.

    Args:
        body (AddCommentRequest): Request to add a comment.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AddCommentApiV1CollaborationCommentsPostResponseAddCommentApiV1CollaborationCommentsPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: AddCommentRequest,
) -> Response[
    AddCommentApiV1CollaborationCommentsPostResponseAddCommentApiV1CollaborationCommentsPost | HTTPValidationError
]:
    """Add Comment

     Add a comment to an entity.

    Args:
        body (AddCommentRequest): Request to add a comment.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AddCommentApiV1CollaborationCommentsPostResponseAddCommentApiV1CollaborationCommentsPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: AddCommentRequest,
) -> (
    AddCommentApiV1CollaborationCommentsPostResponseAddCommentApiV1CollaborationCommentsPost
    | HTTPValidationError
    | None
):
    """Add Comment

     Add a comment to an entity.

    Args:
        body (AddCommentRequest): Request to add a comment.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AddCommentApiV1CollaborationCommentsPostResponseAddCommentApiV1CollaborationCommentsPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
