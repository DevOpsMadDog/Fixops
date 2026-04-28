from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_jobs_api_v1_bulk_jobs_get_response_list_jobs_api_v1_bulk_jobs_get import (
    ListJobsApiV1BulkJobsGetResponseListJobsApiV1BulkJobsGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    status: None | str | Unset = UNSET,
    action_type: None | str | Unset = UNSET,
    limit: int | Unset = 20,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_status: None | str | Unset
    if isinstance(status, Unset):
        json_status = UNSET
    else:
        json_status = status
    params["status"] = json_status

    json_action_type: None | str | Unset
    if isinstance(action_type, Unset):
        json_action_type = UNSET
    else:
        json_action_type = action_type
    params["action_type"] = json_action_type

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/bulk/jobs",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | ListJobsApiV1BulkJobsGetResponseListJobsApiV1BulkJobsGet | None:
    if response.status_code == 200:
        response_200 = ListJobsApiV1BulkJobsGetResponseListJobsApiV1BulkJobsGet.from_dict(response.json())

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
) -> Response[HTTPValidationError | ListJobsApiV1BulkJobsGetResponseListJobsApiV1BulkJobsGet]:
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
    action_type: None | str | Unset = UNSET,
    limit: int | Unset = 20,
) -> Response[HTTPValidationError | ListJobsApiV1BulkJobsGetResponseListJobsApiV1BulkJobsGet]:
    """List Jobs

     List bulk jobs with optional filters.

    Args:
        status (None | str | Unset):
        action_type (None | str | Unset):
        limit (int | Unset):  Default: 20.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListJobsApiV1BulkJobsGetResponseListJobsApiV1BulkJobsGet]
    """

    kwargs = _get_kwargs(
        status=status,
        action_type=action_type,
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    action_type: None | str | Unset = UNSET,
    limit: int | Unset = 20,
) -> HTTPValidationError | ListJobsApiV1BulkJobsGetResponseListJobsApiV1BulkJobsGet | None:
    """List Jobs

     List bulk jobs with optional filters.

    Args:
        status (None | str | Unset):
        action_type (None | str | Unset):
        limit (int | Unset):  Default: 20.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListJobsApiV1BulkJobsGetResponseListJobsApiV1BulkJobsGet
    """

    return sync_detailed(
        client=client,
        status=status,
        action_type=action_type,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    action_type: None | str | Unset = UNSET,
    limit: int | Unset = 20,
) -> Response[HTTPValidationError | ListJobsApiV1BulkJobsGetResponseListJobsApiV1BulkJobsGet]:
    """List Jobs

     List bulk jobs with optional filters.

    Args:
        status (None | str | Unset):
        action_type (None | str | Unset):
        limit (int | Unset):  Default: 20.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListJobsApiV1BulkJobsGetResponseListJobsApiV1BulkJobsGet]
    """

    kwargs = _get_kwargs(
        status=status,
        action_type=action_type,
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    action_type: None | str | Unset = UNSET,
    limit: int | Unset = 20,
) -> HTTPValidationError | ListJobsApiV1BulkJobsGetResponseListJobsApiV1BulkJobsGet | None:
    """List Jobs

     List bulk jobs with optional filters.

    Args:
        status (None | str | Unset):
        action_type (None | str | Unset):
        limit (int | Unset):  Default: 20.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListJobsApiV1BulkJobsGetResponseListJobsApiV1BulkJobsGet
    """

    return (
        await asyncio_detailed(
            client=client,
            status=status,
            action_type=action_type,
            limit=limit,
        )
    ).parsed
