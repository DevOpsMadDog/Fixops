from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.acknowledge_mention_api_v1_collaboration_mentions_mention_id_acknowledge_put_response_acknowledge_mention_api_v1_collaboration_mentions_mention_id_acknowledge_put import (
    AcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePutResponseAcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePut,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    mention_id: int,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/collaboration/mentions/{mention_id}/acknowledge".format(
            mention_id=quote(str(mention_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    AcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePutResponseAcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePut
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = AcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePutResponseAcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePut.from_dict(
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
    AcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePutResponseAcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePut
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    mention_id: int,
    *,
    client: AuthenticatedClient,
) -> Response[
    AcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePutResponseAcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePut
    | HTTPValidationError
]:
    """Acknowledge Mention

     Acknowledge a mention.

    Args:
        mention_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePutResponseAcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePut | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        mention_id=mention_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    mention_id: int,
    *,
    client: AuthenticatedClient,
) -> (
    AcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePutResponseAcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePut
    | HTTPValidationError
    | None
):
    """Acknowledge Mention

     Acknowledge a mention.

    Args:
        mention_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePutResponseAcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePut | HTTPValidationError
    """

    return sync_detailed(
        mention_id=mention_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    mention_id: int,
    *,
    client: AuthenticatedClient,
) -> Response[
    AcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePutResponseAcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePut
    | HTTPValidationError
]:
    """Acknowledge Mention

     Acknowledge a mention.

    Args:
        mention_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePutResponseAcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePut | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        mention_id=mention_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    mention_id: int,
    *,
    client: AuthenticatedClient,
) -> (
    AcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePutResponseAcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePut
    | HTTPValidationError
    | None
):
    """Acknowledge Mention

     Acknowledge a mention.

    Args:
        mention_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePutResponseAcknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePut | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            mention_id=mention_id,
            client=client,
        )
    ).parsed
