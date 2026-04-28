from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enhanced_decision_request import EnhancedDecisionRequest
from ...models.http_validation_error import HTTPValidationError
from ...models.run_enhanced_analysis_api_v1_enhanced_analysis_post_response_run_enhanced_analysis_api_v1_enhanced_analysis_post import (
    RunEnhancedAnalysisApiV1EnhancedAnalysisPostResponseRunEnhancedAnalysisApiV1EnhancedAnalysisPost,
)
from ...types import Response


def _get_kwargs(
    *,
    body: EnhancedDecisionRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/enhanced/analysis",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | RunEnhancedAnalysisApiV1EnhancedAnalysisPostResponseRunEnhancedAnalysisApiV1EnhancedAnalysisPost
    | None
):
    if response.status_code == 200:
        response_200 = (
            RunEnhancedAnalysisApiV1EnhancedAnalysisPostResponseRunEnhancedAnalysisApiV1EnhancedAnalysisPost.from_dict(
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
    HTTPValidationError
    | RunEnhancedAnalysisApiV1EnhancedAnalysisPostResponseRunEnhancedAnalysisApiV1EnhancedAnalysisPost
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
    body: EnhancedDecisionRequest,
) -> Response[
    HTTPValidationError
    | RunEnhancedAnalysisApiV1EnhancedAnalysisPostResponseRunEnhancedAnalysisApiV1EnhancedAnalysisPost
]:
    """Run Enhanced Analysis

     Return multi-LLM consensus analysis for the supplied findings payload.

    Args:
        body (EnhancedDecisionRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RunEnhancedAnalysisApiV1EnhancedAnalysisPostResponseRunEnhancedAnalysisApiV1EnhancedAnalysisPost]
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
    body: EnhancedDecisionRequest,
) -> (
    HTTPValidationError
    | RunEnhancedAnalysisApiV1EnhancedAnalysisPostResponseRunEnhancedAnalysisApiV1EnhancedAnalysisPost
    | None
):
    """Run Enhanced Analysis

     Return multi-LLM consensus analysis for the supplied findings payload.

    Args:
        body (EnhancedDecisionRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RunEnhancedAnalysisApiV1EnhancedAnalysisPostResponseRunEnhancedAnalysisApiV1EnhancedAnalysisPost
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnhancedDecisionRequest,
) -> Response[
    HTTPValidationError
    | RunEnhancedAnalysisApiV1EnhancedAnalysisPostResponseRunEnhancedAnalysisApiV1EnhancedAnalysisPost
]:
    """Run Enhanced Analysis

     Return multi-LLM consensus analysis for the supplied findings payload.

    Args:
        body (EnhancedDecisionRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RunEnhancedAnalysisApiV1EnhancedAnalysisPostResponseRunEnhancedAnalysisApiV1EnhancedAnalysisPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnhancedDecisionRequest,
) -> (
    HTTPValidationError
    | RunEnhancedAnalysisApiV1EnhancedAnalysisPostResponseRunEnhancedAnalysisApiV1EnhancedAnalysisPost
    | None
):
    """Run Enhanced Analysis

     Return multi-LLM consensus analysis for the supplied findings payload.

    Args:
        body (EnhancedDecisionRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RunEnhancedAnalysisApiV1EnhancedAnalysisPostResponseRunEnhancedAnalysisApiV1EnhancedAnalysisPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
