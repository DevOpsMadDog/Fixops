from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.project_metrics_api_v1_dtrack_metrics_project_project_uuid_get_response_project_metrics_api_v1_dtrack_metrics_project_project_uuid_get import (
    ProjectMetricsApiV1DtrackMetricsProjectProjectUuidGetResponseProjectMetricsApiV1DtrackMetricsProjectProjectUuidGet,
)
from ...types import Response


def _get_kwargs(
    project_uuid: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/dtrack/metrics/project/{project_uuid}".format(
            project_uuid=quote(str(project_uuid), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | ProjectMetricsApiV1DtrackMetricsProjectProjectUuidGetResponseProjectMetricsApiV1DtrackMetricsProjectProjectUuidGet
    | None
):
    if response.status_code == 200:
        response_200 = ProjectMetricsApiV1DtrackMetricsProjectProjectUuidGetResponseProjectMetricsApiV1DtrackMetricsProjectProjectUuidGet.from_dict(
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
    | ProjectMetricsApiV1DtrackMetricsProjectProjectUuidGetResponseProjectMetricsApiV1DtrackMetricsProjectProjectUuidGet
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
) -> Response[
    HTTPValidationError
    | ProjectMetricsApiV1DtrackMetricsProjectProjectUuidGetResponseProjectMetricsApiV1DtrackMetricsProjectProjectUuidGet
]:
    """Project Metrics

     Fetch project-level vulnerability metrics from Dependency-Track.

    Args:
        project_uuid (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ProjectMetricsApiV1DtrackMetricsProjectProjectUuidGetResponseProjectMetricsApiV1DtrackMetricsProjectProjectUuidGet]
    """

    kwargs = _get_kwargs(
        project_uuid=project_uuid,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    project_uuid: str,
    *,
    client: AuthenticatedClient,
) -> (
    HTTPValidationError
    | ProjectMetricsApiV1DtrackMetricsProjectProjectUuidGetResponseProjectMetricsApiV1DtrackMetricsProjectProjectUuidGet
    | None
):
    """Project Metrics

     Fetch project-level vulnerability metrics from Dependency-Track.

    Args:
        project_uuid (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ProjectMetricsApiV1DtrackMetricsProjectProjectUuidGetResponseProjectMetricsApiV1DtrackMetricsProjectProjectUuidGet
    """

    return sync_detailed(
        project_uuid=project_uuid,
        client=client,
    ).parsed


async def asyncio_detailed(
    project_uuid: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    HTTPValidationError
    | ProjectMetricsApiV1DtrackMetricsProjectProjectUuidGetResponseProjectMetricsApiV1DtrackMetricsProjectProjectUuidGet
]:
    """Project Metrics

     Fetch project-level vulnerability metrics from Dependency-Track.

    Args:
        project_uuid (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ProjectMetricsApiV1DtrackMetricsProjectProjectUuidGetResponseProjectMetricsApiV1DtrackMetricsProjectProjectUuidGet]
    """

    kwargs = _get_kwargs(
        project_uuid=project_uuid,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    project_uuid: str,
    *,
    client: AuthenticatedClient,
) -> (
    HTTPValidationError
    | ProjectMetricsApiV1DtrackMetricsProjectProjectUuidGetResponseProjectMetricsApiV1DtrackMetricsProjectProjectUuidGet
    | None
):
    """Project Metrics

     Fetch project-level vulnerability metrics from Dependency-Track.

    Args:
        project_uuid (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ProjectMetricsApiV1DtrackMetricsProjectProjectUuidGetResponseProjectMetricsApiV1DtrackMetricsProjectProjectUuidGet
    """

    return (
        await asyncio_detailed(
            project_uuid=project_uuid,
            client=client,
        )
    ).parsed
