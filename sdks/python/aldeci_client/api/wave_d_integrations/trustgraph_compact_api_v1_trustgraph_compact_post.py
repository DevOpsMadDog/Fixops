from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.trust_graph_compact_request import TrustGraphCompactRequest
from ...models.trustgraph_compact_api_v1_trustgraph_compact_post_response_trustgraph_compact_api_v1_trustgraph_compact_post import (
    TrustgraphCompactApiV1TrustgraphCompactPostResponseTrustgraphCompactApiV1TrustgraphCompactPost,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: TrustGraphCompactRequest,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/trustgraph/compact",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | TrustgraphCompactApiV1TrustgraphCompactPostResponseTrustgraphCompactApiV1TrustgraphCompactPost
    | None
):
    if response.status_code == 200:
        response_200 = (
            TrustgraphCompactApiV1TrustgraphCompactPostResponseTrustgraphCompactApiV1TrustgraphCompactPost.from_dict(
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
    HTTPValidationError | TrustgraphCompactApiV1TrustgraphCompactPostResponseTrustgraphCompactApiV1TrustgraphCompactPost
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
    body: TrustGraphCompactRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError | TrustgraphCompactApiV1TrustgraphCompactPostResponseTrustgraphCompactApiV1TrustgraphCompactPost
]:
    """Trustgraph Compact

     Run TrustGraph compaction. (Multica d532f156)

    Args:
        x_org_id (None | str | Unset):
        body (TrustGraphCompactRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TrustgraphCompactApiV1TrustgraphCompactPostResponseTrustgraphCompactApiV1TrustgraphCompactPost]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: TrustGraphCompactRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | TrustgraphCompactApiV1TrustgraphCompactPostResponseTrustgraphCompactApiV1TrustgraphCompactPost
    | None
):
    """Trustgraph Compact

     Run TrustGraph compaction. (Multica d532f156)

    Args:
        x_org_id (None | str | Unset):
        body (TrustGraphCompactRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TrustgraphCompactApiV1TrustgraphCompactPostResponseTrustgraphCompactApiV1TrustgraphCompactPost
    """

    return sync_detailed(
        client=client,
        body=body,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: TrustGraphCompactRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError | TrustgraphCompactApiV1TrustgraphCompactPostResponseTrustgraphCompactApiV1TrustgraphCompactPost
]:
    """Trustgraph Compact

     Run TrustGraph compaction. (Multica d532f156)

    Args:
        x_org_id (None | str | Unset):
        body (TrustGraphCompactRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TrustgraphCompactApiV1TrustgraphCompactPostResponseTrustgraphCompactApiV1TrustgraphCompactPost]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: TrustGraphCompactRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | TrustgraphCompactApiV1TrustgraphCompactPostResponseTrustgraphCompactApiV1TrustgraphCompactPost
    | None
):
    """Trustgraph Compact

     Run TrustGraph compaction. (Multica d532f156)

    Args:
        x_org_id (None | str | Unset):
        body (TrustGraphCompactRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TrustgraphCompactApiV1TrustgraphCompactPostResponseTrustgraphCompactApiV1TrustgraphCompactPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            x_org_id=x_org_id,
        )
    ).parsed
