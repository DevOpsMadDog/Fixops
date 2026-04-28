from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.evaluate_at_stage_api_v1_evaluate_post_response_evaluate_at_stage_api_v1_evaluate_post import (
    EvaluateAtStageApiV1EvaluatePostResponseEvaluateAtStageApiV1EvaluatePost,
)
from ...models.http_validation_error import HTTPValidationError
from ...models.stage_evaluate_request import StageEvaluateRequest
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: StageEvaluateRequest,
    stage: str,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["stage"] = stage

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/evaluate",
        "params": params,
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> EvaluateAtStageApiV1EvaluatePostResponseEvaluateAtStageApiV1EvaluatePost | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = EvaluateAtStageApiV1EvaluatePostResponseEvaluateAtStageApiV1EvaluatePost.from_dict(
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
) -> Response[EvaluateAtStageApiV1EvaluatePostResponseEvaluateAtStageApiV1EvaluatePost | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: StageEvaluateRequest,
    stage: str,
    x_org_id: None | str | Unset = UNSET,
) -> Response[EvaluateAtStageApiV1EvaluatePostResponseEvaluateAtStageApiV1EvaluatePost | HTTPValidationError]:
    """Evaluate At Stage

     Evaluate a context against stage-aware policies. (Multica a0585e59)

    Args:
        stage (str):
        x_org_id (None | str | Unset):
        body (StageEvaluateRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EvaluateAtStageApiV1EvaluatePostResponseEvaluateAtStageApiV1EvaluatePost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        stage=stage,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: StageEvaluateRequest,
    stage: str,
    x_org_id: None | str | Unset = UNSET,
) -> EvaluateAtStageApiV1EvaluatePostResponseEvaluateAtStageApiV1EvaluatePost | HTTPValidationError | None:
    """Evaluate At Stage

     Evaluate a context against stage-aware policies. (Multica a0585e59)

    Args:
        stage (str):
        x_org_id (None | str | Unset):
        body (StageEvaluateRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EvaluateAtStageApiV1EvaluatePostResponseEvaluateAtStageApiV1EvaluatePost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
        stage=stage,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: StageEvaluateRequest,
    stage: str,
    x_org_id: None | str | Unset = UNSET,
) -> Response[EvaluateAtStageApiV1EvaluatePostResponseEvaluateAtStageApiV1EvaluatePost | HTTPValidationError]:
    """Evaluate At Stage

     Evaluate a context against stage-aware policies. (Multica a0585e59)

    Args:
        stage (str):
        x_org_id (None | str | Unset):
        body (StageEvaluateRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EvaluateAtStageApiV1EvaluatePostResponseEvaluateAtStageApiV1EvaluatePost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        stage=stage,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: StageEvaluateRequest,
    stage: str,
    x_org_id: None | str | Unset = UNSET,
) -> EvaluateAtStageApiV1EvaluatePostResponseEvaluateAtStageApiV1EvaluatePost | HTTPValidationError | None:
    """Evaluate At Stage

     Evaluate a context against stage-aware policies. (Multica a0585e59)

    Args:
        stage (str):
        x_org_id (None | str | Unset):
        body (StageEvaluateRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EvaluateAtStageApiV1EvaluatePostResponseEvaluateAtStageApiV1EvaluatePost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            stage=stage,
            x_org_id=x_org_id,
        )
    ).parsed
