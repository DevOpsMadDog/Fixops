from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.evaluate_batch_api_v1_policy_engine_evaluate_batch_post_response_evaluate_batch_api_v1_policy_engine_evaluate_batch_post import (
    EvaluateBatchApiV1PolicyEngineEvaluateBatchPostResponseEvaluateBatchApiV1PolicyEngineEvaluateBatchPost,
)
from ...models.evaluate_batch_request import EvaluateBatchRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: EvaluateBatchRequest,
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
        "url": "/api/v1/policy-engine/evaluate/batch",
        "params": params,
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    EvaluateBatchApiV1PolicyEngineEvaluateBatchPostResponseEvaluateBatchApiV1PolicyEngineEvaluateBatchPost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = EvaluateBatchApiV1PolicyEngineEvaluateBatchPostResponseEvaluateBatchApiV1PolicyEngineEvaluateBatchPost.from_dict(
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
    EvaluateBatchApiV1PolicyEngineEvaluateBatchPostResponseEvaluateBatchApiV1PolicyEngineEvaluateBatchPost
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
    body: EvaluateBatchRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    EvaluateBatchApiV1PolicyEngineEvaluateBatchPostResponseEvaluateBatchApiV1PolicyEngineEvaluateBatchPost
    | HTTPValidationError
]:
    """Evaluate Batch

     Evaluate a list of inputs against policies. Returns one result per input.

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (EvaluateBatchRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EvaluateBatchApiV1PolicyEngineEvaluateBatchPostResponseEvaluateBatchApiV1PolicyEngineEvaluateBatchPost | HTTPValidationError]
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
    body: EvaluateBatchRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    EvaluateBatchApiV1PolicyEngineEvaluateBatchPostResponseEvaluateBatchApiV1PolicyEngineEvaluateBatchPost
    | HTTPValidationError
    | None
):
    """Evaluate Batch

     Evaluate a list of inputs against policies. Returns one result per input.

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (EvaluateBatchRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EvaluateBatchApiV1PolicyEngineEvaluateBatchPostResponseEvaluateBatchApiV1PolicyEngineEvaluateBatchPost | HTTPValidationError
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
    body: EvaluateBatchRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    EvaluateBatchApiV1PolicyEngineEvaluateBatchPostResponseEvaluateBatchApiV1PolicyEngineEvaluateBatchPost
    | HTTPValidationError
]:
    """Evaluate Batch

     Evaluate a list of inputs against policies. Returns one result per input.

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (EvaluateBatchRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EvaluateBatchApiV1PolicyEngineEvaluateBatchPostResponseEvaluateBatchApiV1PolicyEngineEvaluateBatchPost | HTTPValidationError]
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
    body: EvaluateBatchRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    EvaluateBatchApiV1PolicyEngineEvaluateBatchPostResponseEvaluateBatchApiV1PolicyEngineEvaluateBatchPost
    | HTTPValidationError
    | None
):
    """Evaluate Batch

     Evaluate a list of inputs against policies. Returns one result per input.

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (EvaluateBatchRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EvaluateBatchApiV1PolicyEngineEvaluateBatchPostResponseEvaluateBatchApiV1PolicyEngineEvaluateBatchPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
