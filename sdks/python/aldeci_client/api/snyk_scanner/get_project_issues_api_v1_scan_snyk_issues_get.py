from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_project_issues_api_v1_scan_snyk_issues_get_response_200_item import (
    GetProjectIssuesApiV1ScanSnykIssuesGetResponse200Item,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response


def _get_kwargs(
    *,
    project_id: str,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["project_id"] = project_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/scan/snyk/issues",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[GetProjectIssuesApiV1ScanSnykIssuesGetResponse200Item] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = GetProjectIssuesApiV1ScanSnykIssuesGetResponse200Item.from_dict(response_200_item_data)

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
) -> Response[HTTPValidationError | list[GetProjectIssuesApiV1ScanSnykIssuesGetResponse200Item]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    project_id: str,
) -> Response[HTTPValidationError | list[GetProjectIssuesApiV1ScanSnykIssuesGetResponse200Item]]:
    """Get issues for a Snyk project

     Get all open issues for a specific Snyk project.

    Returns mock issue data when SNYK_API_TOKEN is not configured.

    Args:
        project_id (str): Snyk project UUID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetProjectIssuesApiV1ScanSnykIssuesGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        project_id=project_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    project_id: str,
) -> HTTPValidationError | list[GetProjectIssuesApiV1ScanSnykIssuesGetResponse200Item] | None:
    """Get issues for a Snyk project

     Get all open issues for a specific Snyk project.

    Returns mock issue data when SNYK_API_TOKEN is not configured.

    Args:
        project_id (str): Snyk project UUID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetProjectIssuesApiV1ScanSnykIssuesGetResponse200Item]
    """

    return sync_detailed(
        client=client,
        project_id=project_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    project_id: str,
) -> Response[HTTPValidationError | list[GetProjectIssuesApiV1ScanSnykIssuesGetResponse200Item]]:
    """Get issues for a Snyk project

     Get all open issues for a specific Snyk project.

    Returns mock issue data when SNYK_API_TOKEN is not configured.

    Args:
        project_id (str): Snyk project UUID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[GetProjectIssuesApiV1ScanSnykIssuesGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        project_id=project_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    project_id: str,
) -> HTTPValidationError | list[GetProjectIssuesApiV1ScanSnykIssuesGetResponse200Item] | None:
    """Get issues for a Snyk project

     Get all open issues for a specific Snyk project.

    Returns mock issue data when SNYK_API_TOKEN is not configured.

    Args:
        project_id (str): Snyk project UUID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[GetProjectIssuesApiV1ScanSnykIssuesGetResponse200Item]
    """

    return (
        await asyncio_detailed(
            client=client,
            project_id=project_id,
        )
    ).parsed
