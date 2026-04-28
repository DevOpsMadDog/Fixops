from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.copilot_graph_nl_query_api_v1_copilot_graph_nl_query_post_response_copilot_graph_nl_query_api_v1_copilot_graph_nl_query_post import (
    CopilotGraphNlQueryApiV1CopilotGraphNlQueryPostResponseCopilotGraphNlQueryApiV1CopilotGraphNlQueryPost,
)
from ...models.copilot_graph_nl_request import CopilotGraphNLRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: CopilotGraphNLRequest,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/copilot/graph-nl-query",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    CopilotGraphNlQueryApiV1CopilotGraphNlQueryPostResponseCopilotGraphNlQueryApiV1CopilotGraphNlQueryPost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = CopilotGraphNlQueryApiV1CopilotGraphNlQueryPostResponseCopilotGraphNlQueryApiV1CopilotGraphNlQueryPost.from_dict(
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
    CopilotGraphNlQueryApiV1CopilotGraphNlQueryPostResponseCopilotGraphNlQueryApiV1CopilotGraphNlQueryPost
    | HTTPValidationError
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
    body: CopilotGraphNLRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    CopilotGraphNlQueryApiV1CopilotGraphNlQueryPostResponseCopilotGraphNlQueryApiV1CopilotGraphNlQueryPost
    | HTTPValidationError
]:
    """Copilot Graph Nl Query

     Run a natural-language query against the TrustGraph. (Multica 0817d38c)

    Args:
        x_org_id (None | str | Unset):
        body (CopilotGraphNLRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CopilotGraphNlQueryApiV1CopilotGraphNlQueryPostResponseCopilotGraphNlQueryApiV1CopilotGraphNlQueryPost | HTTPValidationError]
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
    body: CopilotGraphNLRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    CopilotGraphNlQueryApiV1CopilotGraphNlQueryPostResponseCopilotGraphNlQueryApiV1CopilotGraphNlQueryPost
    | HTTPValidationError
    | None
):
    """Copilot Graph Nl Query

     Run a natural-language query against the TrustGraph. (Multica 0817d38c)

    Args:
        x_org_id (None | str | Unset):
        body (CopilotGraphNLRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CopilotGraphNlQueryApiV1CopilotGraphNlQueryPostResponseCopilotGraphNlQueryApiV1CopilotGraphNlQueryPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: CopilotGraphNLRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    CopilotGraphNlQueryApiV1CopilotGraphNlQueryPostResponseCopilotGraphNlQueryApiV1CopilotGraphNlQueryPost
    | HTTPValidationError
]:
    """Copilot Graph Nl Query

     Run a natural-language query against the TrustGraph. (Multica 0817d38c)

    Args:
        x_org_id (None | str | Unset):
        body (CopilotGraphNLRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CopilotGraphNlQueryApiV1CopilotGraphNlQueryPostResponseCopilotGraphNlQueryApiV1CopilotGraphNlQueryPost | HTTPValidationError]
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
    body: CopilotGraphNLRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    CopilotGraphNlQueryApiV1CopilotGraphNlQueryPostResponseCopilotGraphNlQueryApiV1CopilotGraphNlQueryPost
    | HTTPValidationError
    | None
):
    """Copilot Graph Nl Query

     Run a natural-language query against the TrustGraph. (Multica 0817d38c)

    Args:
        x_org_id (None | str | Unset):
        body (CopilotGraphNLRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CopilotGraphNlQueryApiV1CopilotGraphNlQueryPostResponseCopilotGraphNlQueryApiV1CopilotGraphNlQueryPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            x_org_id=x_org_id,
        )
    ).parsed
