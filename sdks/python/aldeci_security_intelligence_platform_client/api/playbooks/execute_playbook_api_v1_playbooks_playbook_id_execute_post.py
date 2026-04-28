from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.execute_playbook_api_v1_playbooks_playbook_id_execute_post_response_execute_playbook_api_v1_playbooks_playbook_id_execute_post import (
    ExecutePlaybookApiV1PlaybooksPlaybookIdExecutePostResponseExecutePlaybookApiV1PlaybooksPlaybookIdExecutePost,
)
from ...models.http_validation_error import HTTPValidationError
from ...models.playbook_execute_request import PlaybookExecuteRequest
from ...types import Response


def _get_kwargs(
    playbook_id: str,
    *,
    body: PlaybookExecuteRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/playbooks/{playbook_id}/execute".format(
            playbook_id=quote(str(playbook_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    ExecutePlaybookApiV1PlaybooksPlaybookIdExecutePostResponseExecutePlaybookApiV1PlaybooksPlaybookIdExecutePost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = ExecutePlaybookApiV1PlaybooksPlaybookIdExecutePostResponseExecutePlaybookApiV1PlaybooksPlaybookIdExecutePost.from_dict(
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
    ExecutePlaybookApiV1PlaybooksPlaybookIdExecutePostResponseExecutePlaybookApiV1PlaybooksPlaybookIdExecutePost
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    playbook_id: str,
    *,
    client: AuthenticatedClient,
    body: PlaybookExecuteRequest,
) -> Response[
    ExecutePlaybookApiV1PlaybooksPlaybookIdExecutePostResponseExecutePlaybookApiV1PlaybooksPlaybookIdExecutePost
    | HTTPValidationError
]:
    """Execute playbook

     Trigger execution of a playbook with optional context.

    Args:
        playbook_id (str):
        body (PlaybookExecuteRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ExecutePlaybookApiV1PlaybooksPlaybookIdExecutePostResponseExecutePlaybookApiV1PlaybooksPlaybookIdExecutePost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        playbook_id=playbook_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    playbook_id: str,
    *,
    client: AuthenticatedClient,
    body: PlaybookExecuteRequest,
) -> (
    ExecutePlaybookApiV1PlaybooksPlaybookIdExecutePostResponseExecutePlaybookApiV1PlaybooksPlaybookIdExecutePost
    | HTTPValidationError
    | None
):
    """Execute playbook

     Trigger execution of a playbook with optional context.

    Args:
        playbook_id (str):
        body (PlaybookExecuteRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ExecutePlaybookApiV1PlaybooksPlaybookIdExecutePostResponseExecutePlaybookApiV1PlaybooksPlaybookIdExecutePost | HTTPValidationError
    """

    return sync_detailed(
        playbook_id=playbook_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    playbook_id: str,
    *,
    client: AuthenticatedClient,
    body: PlaybookExecuteRequest,
) -> Response[
    ExecutePlaybookApiV1PlaybooksPlaybookIdExecutePostResponseExecutePlaybookApiV1PlaybooksPlaybookIdExecutePost
    | HTTPValidationError
]:
    """Execute playbook

     Trigger execution of a playbook with optional context.

    Args:
        playbook_id (str):
        body (PlaybookExecuteRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ExecutePlaybookApiV1PlaybooksPlaybookIdExecutePostResponseExecutePlaybookApiV1PlaybooksPlaybookIdExecutePost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        playbook_id=playbook_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    playbook_id: str,
    *,
    client: AuthenticatedClient,
    body: PlaybookExecuteRequest,
) -> (
    ExecutePlaybookApiV1PlaybooksPlaybookIdExecutePostResponseExecutePlaybookApiV1PlaybooksPlaybookIdExecutePost
    | HTTPValidationError
    | None
):
    """Execute playbook

     Trigger execution of a playbook with optional context.

    Args:
        playbook_id (str):
        body (PlaybookExecuteRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ExecutePlaybookApiV1PlaybooksPlaybookIdExecutePostResponseExecutePlaybookApiV1PlaybooksPlaybookIdExecutePost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            playbook_id=playbook_id,
            client=client,
            body=body,
        )
    ).parsed
