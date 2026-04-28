from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.consensus_request import ConsensusRequest
from ...models.http_validation_error import HTTPValidationError
from ...models.multi_agent_consensus_api_v1_ai_orchestrator_consensus_post_response_multi_agent_consensus_api_v1_ai_orchestrator_consensus_post import (
    MultiAgentConsensusApiV1AiOrchestratorConsensusPostResponseMultiAgentConsensusApiV1AiOrchestratorConsensusPost,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: ConsensusRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/ai-orchestrator/consensus",
        "params": params,
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | MultiAgentConsensusApiV1AiOrchestratorConsensusPostResponseMultiAgentConsensusApiV1AiOrchestratorConsensusPost
    | None
):
    if response.status_code == 200:
        response_200 = MultiAgentConsensusApiV1AiOrchestratorConsensusPostResponseMultiAgentConsensusApiV1AiOrchestratorConsensusPost.from_dict(
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
    | MultiAgentConsensusApiV1AiOrchestratorConsensusPostResponseMultiAgentConsensusApiV1AiOrchestratorConsensusPost
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
    body: ConsensusRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | MultiAgentConsensusApiV1AiOrchestratorConsensusPostResponseMultiAgentConsensusApiV1AiOrchestratorConsensusPost
]:
    """Multi-agent consensus on a security decision

     Query multiple agent roles and return a consensus decision.

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (ConsensusRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | MultiAgentConsensusApiV1AiOrchestratorConsensusPostResponseMultiAgentConsensusApiV1AiOrchestratorConsensusPost]
    """

    kwargs = _get_kwargs(
        body=body,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: ConsensusRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | MultiAgentConsensusApiV1AiOrchestratorConsensusPostResponseMultiAgentConsensusApiV1AiOrchestratorConsensusPost
    | None
):
    """Multi-agent consensus on a security decision

     Query multiple agent roles and return a consensus decision.

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (ConsensusRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | MultiAgentConsensusApiV1AiOrchestratorConsensusPostResponseMultiAgentConsensusApiV1AiOrchestratorConsensusPost
    """

    return sync_detailed(
        client=client,
        body=body,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ConsensusRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | MultiAgentConsensusApiV1AiOrchestratorConsensusPostResponseMultiAgentConsensusApiV1AiOrchestratorConsensusPost
]:
    """Multi-agent consensus on a security decision

     Query multiple agent roles and return a consensus decision.

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (ConsensusRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | MultiAgentConsensusApiV1AiOrchestratorConsensusPostResponseMultiAgentConsensusApiV1AiOrchestratorConsensusPost]
    """

    kwargs = _get_kwargs(
        body=body,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ConsensusRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | MultiAgentConsensusApiV1AiOrchestratorConsensusPostResponseMultiAgentConsensusApiV1AiOrchestratorConsensusPost
    | None
):
    """Multi-agent consensus on a security decision

     Query multiple agent roles and return a consensus decision.

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (ConsensusRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | MultiAgentConsensusApiV1AiOrchestratorConsensusPostResponseMultiAgentConsensusApiV1AiOrchestratorConsensusPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
