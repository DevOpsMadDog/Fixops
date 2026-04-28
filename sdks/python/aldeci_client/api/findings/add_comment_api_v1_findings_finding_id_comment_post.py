from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.comment_response import CommentResponse
from ...models.finding_comment import FindingComment
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    finding_id: str,
    *,
    body: FindingComment,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/findings/{finding_id}/comment".format(
            finding_id=quote(str(finding_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> CommentResponse | HTTPValidationError | None:
    if response.status_code == 201:
        response_201 = CommentResponse.from_dict(response.json())

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
) -> Response[CommentResponse | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    finding_id: str,
    *,
    client: AuthenticatedClient,
    body: FindingComment,
) -> Response[CommentResponse | HTTPValidationError]:
    """Add Comment

     Add comment to finding.

    Args:
        finding_id: Finding identifier
        comment: FindingComment with text

    Returns:
        CommentResponse with comment details

    Raises:
        HTTPException: 404 if finding not found

    Args:
        finding_id (str):
        body (FindingComment): Comment on a finding.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CommentResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        finding_id=finding_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    finding_id: str,
    *,
    client: AuthenticatedClient,
    body: FindingComment,
) -> CommentResponse | HTTPValidationError | None:
    """Add Comment

     Add comment to finding.

    Args:
        finding_id: Finding identifier
        comment: FindingComment with text

    Returns:
        CommentResponse with comment details

    Raises:
        HTTPException: 404 if finding not found

    Args:
        finding_id (str):
        body (FindingComment): Comment on a finding.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CommentResponse | HTTPValidationError
    """

    return sync_detailed(
        finding_id=finding_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    finding_id: str,
    *,
    client: AuthenticatedClient,
    body: FindingComment,
) -> Response[CommentResponse | HTTPValidationError]:
    """Add Comment

     Add comment to finding.

    Args:
        finding_id: Finding identifier
        comment: FindingComment with text

    Returns:
        CommentResponse with comment details

    Raises:
        HTTPException: 404 if finding not found

    Args:
        finding_id (str):
        body (FindingComment): Comment on a finding.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CommentResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        finding_id=finding_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    finding_id: str,
    *,
    client: AuthenticatedClient,
    body: FindingComment,
) -> CommentResponse | HTTPValidationError | None:
    """Add Comment

     Add comment to finding.

    Args:
        finding_id: Finding identifier
        comment: FindingComment with text

    Returns:
        CommentResponse with comment details

    Raises:
        HTTPException: 404 if finding not found

    Args:
        finding_id (str):
        body (FindingComment): Comment on a finding.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CommentResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            finding_id=finding_id,
            client=client,
            body=body,
        )
    ).parsed
