from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.add_approval_api_v1_changes_change_id_approve_post_response_add_approval_api_v1_changes_change_id_approve_post import (
    AddApprovalApiV1ChangesChangeIdApprovePostResponseAddApprovalApiV1ChangesChangeIdApprovePost,
)
from ...models.add_approval_request import AddApprovalRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    change_id: str,
    *,
    body: AddApprovalRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/changes/{change_id}/approve".format(
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
    AddApprovalApiV1ChangesChangeIdApprovePostResponseAddApprovalApiV1ChangesChangeIdApprovePost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            AddApprovalApiV1ChangesChangeIdApprovePostResponseAddApprovalApiV1ChangesChangeIdApprovePost.from_dict(
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
    AddApprovalApiV1ChangesChangeIdApprovePostResponseAddApprovalApiV1ChangesChangeIdApprovePost | HTTPValidationError
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
    body: AddApprovalRequest,
) -> Response[
    AddApprovalApiV1ChangesChangeIdApprovePostResponseAddApprovalApiV1ChangesChangeIdApprovePost | HTTPValidationError
]:
    """Add Approval

     Add a CAB member approval, rejection, or conditional approval.

    Args:
        change_id (str):
        body (AddApprovalRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AddApprovalApiV1ChangesChangeIdApprovePostResponseAddApprovalApiV1ChangesChangeIdApprovePost | HTTPValidationError]
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
    body: AddApprovalRequest,
) -> (
    AddApprovalApiV1ChangesChangeIdApprovePostResponseAddApprovalApiV1ChangesChangeIdApprovePost
    | HTTPValidationError
    | None
):
    """Add Approval

     Add a CAB member approval, rejection, or conditional approval.

    Args:
        change_id (str):
        body (AddApprovalRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AddApprovalApiV1ChangesChangeIdApprovePostResponseAddApprovalApiV1ChangesChangeIdApprovePost | HTTPValidationError
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
    body: AddApprovalRequest,
) -> Response[
    AddApprovalApiV1ChangesChangeIdApprovePostResponseAddApprovalApiV1ChangesChangeIdApprovePost | HTTPValidationError
]:
    """Add Approval

     Add a CAB member approval, rejection, or conditional approval.

    Args:
        change_id (str):
        body (AddApprovalRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AddApprovalApiV1ChangesChangeIdApprovePostResponseAddApprovalApiV1ChangesChangeIdApprovePost | HTTPValidationError]
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
    body: AddApprovalRequest,
) -> (
    AddApprovalApiV1ChangesChangeIdApprovePostResponseAddApprovalApiV1ChangesChangeIdApprovePost
    | HTTPValidationError
    | None
):
    """Add Approval

     Add a CAB member approval, rejection, or conditional approval.

    Args:
        change_id (str):
        body (AddApprovalRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AddApprovalApiV1ChangesChangeIdApprovePostResponseAddApprovalApiV1ChangesChangeIdApprovePost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            change_id=change_id,
            client=client,
            body=body,
        )
    ).parsed
