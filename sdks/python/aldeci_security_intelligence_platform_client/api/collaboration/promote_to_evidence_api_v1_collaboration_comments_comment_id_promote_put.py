from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.promote_to_evidence_api_v1_collaboration_comments_comment_id_promote_put_response_promote_to_evidence_api_v1_collaboration_comments_comment_id_promote_put import (
    PromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePutResponsePromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePut,
)
from ...types import UNSET, Response


def _get_kwargs(
    comment_id: str,
    *,
    promoted_by: str,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["promoted_by"] = promoted_by

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/collaboration/comments/{comment_id}/promote".format(
            comment_id=quote(str(comment_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | PromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePutResponsePromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePut
    | None
):
    if response.status_code == 200:
        response_200 = PromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePutResponsePromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePut.from_dict(
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
    | PromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePutResponsePromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePut
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    comment_id: str,
    *,
    client: AuthenticatedClient,
    promoted_by: str,
) -> Response[
    HTTPValidationError
    | PromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePutResponsePromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePut
]:
    """Promote To Evidence

     Promote a comment to evidence for compliance.

    Args:
        comment_id (str):
        promoted_by (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | PromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePutResponsePromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePut]
    """

    kwargs = _get_kwargs(
        comment_id=comment_id,
        promoted_by=promoted_by,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    comment_id: str,
    *,
    client: AuthenticatedClient,
    promoted_by: str,
) -> (
    HTTPValidationError
    | PromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePutResponsePromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePut
    | None
):
    """Promote To Evidence

     Promote a comment to evidence for compliance.

    Args:
        comment_id (str):
        promoted_by (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | PromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePutResponsePromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePut
    """

    return sync_detailed(
        comment_id=comment_id,
        client=client,
        promoted_by=promoted_by,
    ).parsed


async def asyncio_detailed(
    comment_id: str,
    *,
    client: AuthenticatedClient,
    promoted_by: str,
) -> Response[
    HTTPValidationError
    | PromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePutResponsePromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePut
]:
    """Promote To Evidence

     Promote a comment to evidence for compliance.

    Args:
        comment_id (str):
        promoted_by (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | PromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePutResponsePromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePut]
    """

    kwargs = _get_kwargs(
        comment_id=comment_id,
        promoted_by=promoted_by,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    comment_id: str,
    *,
    client: AuthenticatedClient,
    promoted_by: str,
) -> (
    HTTPValidationError
    | PromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePutResponsePromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePut
    | None
):
    """Promote To Evidence

     Promote a comment to evidence for compliance.

    Args:
        comment_id (str):
        promoted_by (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | PromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePutResponsePromoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePut
    """

    return (
        await asyncio_detailed(
            comment_id=comment_id,
            client=client,
            promoted_by=promoted_by,
        )
    ).parsed
