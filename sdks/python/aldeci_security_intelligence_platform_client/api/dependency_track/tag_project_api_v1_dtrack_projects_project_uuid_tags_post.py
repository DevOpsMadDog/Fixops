from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.tag_project_api_v1_dtrack_projects_project_uuid_tags_post_response_tag_project_api_v1_dtrack_projects_project_uuid_tags_post import (
    TagProjectApiV1DtrackProjectsProjectUuidTagsPostResponseTagProjectApiV1DtrackProjectsProjectUuidTagsPost,
)
from ...models.tag_request import TagRequest
from ...types import Response


def _get_kwargs(
    project_uuid: str,
    *,
    body: TagRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/dtrack/projects/{project_uuid}/tags".format(
            project_uuid=quote(str(project_uuid), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | TagProjectApiV1DtrackProjectsProjectUuidTagsPostResponseTagProjectApiV1DtrackProjectsProjectUuidTagsPost
    | None
):
    if response.status_code == 200:
        response_200 = TagProjectApiV1DtrackProjectsProjectUuidTagsPostResponseTagProjectApiV1DtrackProjectsProjectUuidTagsPost.from_dict(
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
    | TagProjectApiV1DtrackProjectsProjectUuidTagsPostResponseTagProjectApiV1DtrackProjectsProjectUuidTagsPost
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    project_uuid: str,
    *,
    client: AuthenticatedClient,
    body: TagRequest,
) -> Response[
    HTTPValidationError
    | TagProjectApiV1DtrackProjectsProjectUuidTagsPostResponseTagProjectApiV1DtrackProjectsProjectUuidTagsPost
]:
    """Tag Project

     Add tags to a project for FixOps categorization and filtering.

    Args:
        project_uuid (str):
        body (TagRequest): Add tags to a project for FixOps categorization.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TagProjectApiV1DtrackProjectsProjectUuidTagsPostResponseTagProjectApiV1DtrackProjectsProjectUuidTagsPost]
    """

    kwargs = _get_kwargs(
        project_uuid=project_uuid,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    project_uuid: str,
    *,
    client: AuthenticatedClient,
    body: TagRequest,
) -> (
    HTTPValidationError
    | TagProjectApiV1DtrackProjectsProjectUuidTagsPostResponseTagProjectApiV1DtrackProjectsProjectUuidTagsPost
    | None
):
    """Tag Project

     Add tags to a project for FixOps categorization and filtering.

    Args:
        project_uuid (str):
        body (TagRequest): Add tags to a project for FixOps categorization.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TagProjectApiV1DtrackProjectsProjectUuidTagsPostResponseTagProjectApiV1DtrackProjectsProjectUuidTagsPost
    """

    return sync_detailed(
        project_uuid=project_uuid,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    project_uuid: str,
    *,
    client: AuthenticatedClient,
    body: TagRequest,
) -> Response[
    HTTPValidationError
    | TagProjectApiV1DtrackProjectsProjectUuidTagsPostResponseTagProjectApiV1DtrackProjectsProjectUuidTagsPost
]:
    """Tag Project

     Add tags to a project for FixOps categorization and filtering.

    Args:
        project_uuid (str):
        body (TagRequest): Add tags to a project for FixOps categorization.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TagProjectApiV1DtrackProjectsProjectUuidTagsPostResponseTagProjectApiV1DtrackProjectsProjectUuidTagsPost]
    """

    kwargs = _get_kwargs(
        project_uuid=project_uuid,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    project_uuid: str,
    *,
    client: AuthenticatedClient,
    body: TagRequest,
) -> (
    HTTPValidationError
    | TagProjectApiV1DtrackProjectsProjectUuidTagsPostResponseTagProjectApiV1DtrackProjectsProjectUuidTagsPost
    | None
):
    """Tag Project

     Add tags to a project for FixOps categorization and filtering.

    Args:
        project_uuid (str):
        body (TagRequest): Add tags to a project for FixOps categorization.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TagProjectApiV1DtrackProjectsProjectUuidTagsPostResponseTagProjectApiV1DtrackProjectsProjectUuidTagsPost
    """

    return (
        await asyncio_detailed(
            project_uuid=project_uuid,
            client=client,
            body=body,
        )
    ).parsed
