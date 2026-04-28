from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.preflight_estimate_api_v1_ai_orchestrator_preflight_estimate_post_response_preflight_estimate_api_v1_ai_orchestrator_preflight_estimate_post import (
    PreflightEstimateApiV1AiOrchestratorPreflightEstimatePostResponsePreflightEstimateApiV1AiOrchestratorPreflightEstimatePost,
)
from ...models.preflight_request import PreflightRequest
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: PreflightRequest,
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
        "url": "/api/v1/ai-orchestrator/preflight-estimate",
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
    | PreflightEstimateApiV1AiOrchestratorPreflightEstimatePostResponsePreflightEstimateApiV1AiOrchestratorPreflightEstimatePost
    | None
):
    if response.status_code == 200:
        response_200 = PreflightEstimateApiV1AiOrchestratorPreflightEstimatePostResponsePreflightEstimateApiV1AiOrchestratorPreflightEstimatePost.from_dict(
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
    | PreflightEstimateApiV1AiOrchestratorPreflightEstimatePostResponsePreflightEstimateApiV1AiOrchestratorPreflightEstimatePost
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
    body: PreflightRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | PreflightEstimateApiV1AiOrchestratorPreflightEstimatePostResponsePreflightEstimateApiV1AiOrchestratorPreflightEstimatePost
]:
    """GAP-061: Pre-flight LLM cost estimate for a set of rules

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (PreflightRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | PreflightEstimateApiV1AiOrchestratorPreflightEstimatePostResponsePreflightEstimateApiV1AiOrchestratorPreflightEstimatePost]
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
    body: PreflightRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | PreflightEstimateApiV1AiOrchestratorPreflightEstimatePostResponsePreflightEstimateApiV1AiOrchestratorPreflightEstimatePost
    | None
):
    """GAP-061: Pre-flight LLM cost estimate for a set of rules

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (PreflightRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | PreflightEstimateApiV1AiOrchestratorPreflightEstimatePostResponsePreflightEstimateApiV1AiOrchestratorPreflightEstimatePost
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
    body: PreflightRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | PreflightEstimateApiV1AiOrchestratorPreflightEstimatePostResponsePreflightEstimateApiV1AiOrchestratorPreflightEstimatePost
]:
    """GAP-061: Pre-flight LLM cost estimate for a set of rules

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (PreflightRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | PreflightEstimateApiV1AiOrchestratorPreflightEstimatePostResponsePreflightEstimateApiV1AiOrchestratorPreflightEstimatePost]
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
    body: PreflightRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | PreflightEstimateApiV1AiOrchestratorPreflightEstimatePostResponsePreflightEstimateApiV1AiOrchestratorPreflightEstimatePost
    | None
):
    """GAP-061: Pre-flight LLM cost estimate for a set of rules

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (PreflightRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | PreflightEstimateApiV1AiOrchestratorPreflightEstimatePostResponsePreflightEstimateApiV1AiOrchestratorPreflightEstimatePost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
