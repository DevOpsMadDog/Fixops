from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.exercise_summary_response import ExerciseSummaryResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    status: None | str | Unset = UNSET,
    category: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_status: None | str | Unset
    if isinstance(status, Unset):
        json_status = UNSET
    else:
        json_status = status
    params["status"] = json_status

    json_category: None | str | Unset
    if isinstance(category, Unset):
        json_category = UNSET
    else:
        json_category = category
    params["category"] = json_category

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/purple-team/exercises",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[ExerciseSummaryResponse] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = ExerciseSummaryResponse.from_dict(response_200_item_data)

            response_200.append(response_200_item)

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
) -> Response[HTTPValidationError | list[ExerciseSummaryResponse]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    category: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[ExerciseSummaryResponse]]:
    """List all exercises

    Args:
        status (None | str | Unset): Filter by status
        category (None | str | Unset): Filter by scenario category

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ExerciseSummaryResponse]]
    """

    kwargs = _get_kwargs(
        status=status,
        category=category,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    category: None | str | Unset = UNSET,
) -> HTTPValidationError | list[ExerciseSummaryResponse] | None:
    """List all exercises

    Args:
        status (None | str | Unset): Filter by status
        category (None | str | Unset): Filter by scenario category

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ExerciseSummaryResponse]
    """

    return sync_detailed(
        client=client,
        status=status,
        category=category,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    category: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[ExerciseSummaryResponse]]:
    """List all exercises

    Args:
        status (None | str | Unset): Filter by status
        category (None | str | Unset): Filter by scenario category

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ExerciseSummaryResponse]]
    """

    kwargs = _get_kwargs(
        status=status,
        category=category,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    category: None | str | Unset = UNSET,
) -> HTTPValidationError | list[ExerciseSummaryResponse] | None:
    """List all exercises

    Args:
        status (None | str | Unset): Filter by status
        category (None | str | Unset): Filter by scenario category

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ExerciseSummaryResponse]
    """

    return (
        await asyncio_detailed(
            client=client,
            status=status,
            category=category,
        )
    ).parsed
