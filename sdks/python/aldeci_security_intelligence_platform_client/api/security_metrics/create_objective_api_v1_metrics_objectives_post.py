from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.create_objective_api_v1_metrics_objectives_post_response_create_objective_api_v1_metrics_objectives_post import (
    CreateObjectiveApiV1MetricsObjectivesPostResponseCreateObjectiveApiV1MetricsObjectivesPost,
)
from ...models.http_validation_error import HTTPValidationError
from ...models.objective_create import ObjectiveCreate
from ...types import Response


def _get_kwargs(
    *,
    body: ObjectiveCreate,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/metrics/objectives",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    CreateObjectiveApiV1MetricsObjectivesPostResponseCreateObjectiveApiV1MetricsObjectivesPost
    | HTTPValidationError
    | None
):
    if response.status_code == 201:
        response_201 = (
            CreateObjectiveApiV1MetricsObjectivesPostResponseCreateObjectiveApiV1MetricsObjectivesPost.from_dict(
                response.json()
            )
        )

        return response_201

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
    CreateObjectiveApiV1MetricsObjectivesPostResponseCreateObjectiveApiV1MetricsObjectivesPost | HTTPValidationError
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
    body: ObjectiveCreate,
) -> Response[
    CreateObjectiveApiV1MetricsObjectivesPostResponseCreateObjectiveApiV1MetricsObjectivesPost | HTTPValidationError
]:
    """Create an OKR objective

    Args:
        body (ObjectiveCreate): Request body for creating an OKR objective.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateObjectiveApiV1MetricsObjectivesPostResponseCreateObjectiveApiV1MetricsObjectivesPost | HTTPValidationError]
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
    body: ObjectiveCreate,
) -> (
    CreateObjectiveApiV1MetricsObjectivesPostResponseCreateObjectiveApiV1MetricsObjectivesPost
    | HTTPValidationError
    | None
):
    """Create an OKR objective

    Args:
        body (ObjectiveCreate): Request body for creating an OKR objective.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateObjectiveApiV1MetricsObjectivesPostResponseCreateObjectiveApiV1MetricsObjectivesPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ObjectiveCreate,
) -> Response[
    CreateObjectiveApiV1MetricsObjectivesPostResponseCreateObjectiveApiV1MetricsObjectivesPost | HTTPValidationError
]:
    """Create an OKR objective

    Args:
        body (ObjectiveCreate): Request body for creating an OKR objective.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateObjectiveApiV1MetricsObjectivesPostResponseCreateObjectiveApiV1MetricsObjectivesPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ObjectiveCreate,
) -> (
    CreateObjectiveApiV1MetricsObjectivesPostResponseCreateObjectiveApiV1MetricsObjectivesPost
    | HTTPValidationError
    | None
):
    """Create an OKR objective

    Args:
        body (ObjectiveCreate): Request body for creating an OKR objective.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateObjectiveApiV1MetricsObjectivesPostResponseCreateObjectiveApiV1MetricsObjectivesPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
