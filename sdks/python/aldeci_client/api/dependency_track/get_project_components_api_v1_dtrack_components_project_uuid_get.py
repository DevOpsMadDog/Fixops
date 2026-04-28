from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_project_components_api_v1_dtrack_components_project_uuid_get_response_get_project_components_api_v1_dtrack_components_project_uuid_get import (
    GetProjectComponentsApiV1DtrackComponentsProjectUuidGetResponseGetProjectComponentsApiV1DtrackComponentsProjectUuidGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    project_uuid: str,
    *,
    page: int | Unset = 1,
    page_size: int | Unset = 100,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["page"] = page

    params["page_size"] = page_size

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/dtrack/components/{project_uuid}".format(
            project_uuid=quote(str(project_uuid), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetProjectComponentsApiV1DtrackComponentsProjectUuidGetResponseGetProjectComponentsApiV1DtrackComponentsProjectUuidGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetProjectComponentsApiV1DtrackComponentsProjectUuidGetResponseGetProjectComponentsApiV1DtrackComponentsProjectUuidGet.from_dict(
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
    GetProjectComponentsApiV1DtrackComponentsProjectUuidGetResponseGetProjectComponentsApiV1DtrackComponentsProjectUuidGet
    | HTTPValidationError
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
    page: int | Unset = 1,
    page_size: int | Unset = 100,
) -> Response[
    GetProjectComponentsApiV1DtrackComponentsProjectUuidGetResponseGetProjectComponentsApiV1DtrackComponentsProjectUuidGet
    | HTTPValidationError
]:
    """Get Project Components

     Fetch all components (dependencies) for a project.

    Args:
        project_uuid (str):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetProjectComponentsApiV1DtrackComponentsProjectUuidGetResponseGetProjectComponentsApiV1DtrackComponentsProjectUuidGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        project_uuid=project_uuid,
        page=page,
        page_size=page_size,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    project_uuid: str,
    *,
    client: AuthenticatedClient,
    page: int | Unset = 1,
    page_size: int | Unset = 100,
) -> (
    GetProjectComponentsApiV1DtrackComponentsProjectUuidGetResponseGetProjectComponentsApiV1DtrackComponentsProjectUuidGet
    | HTTPValidationError
    | None
):
    """Get Project Components

     Fetch all components (dependencies) for a project.

    Args:
        project_uuid (str):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetProjectComponentsApiV1DtrackComponentsProjectUuidGetResponseGetProjectComponentsApiV1DtrackComponentsProjectUuidGet | HTTPValidationError
    """

    return sync_detailed(
        project_uuid=project_uuid,
        client=client,
        page=page,
        page_size=page_size,
    ).parsed


async def asyncio_detailed(
    project_uuid: str,
    *,
    client: AuthenticatedClient,
    page: int | Unset = 1,
    page_size: int | Unset = 100,
) -> Response[
    GetProjectComponentsApiV1DtrackComponentsProjectUuidGetResponseGetProjectComponentsApiV1DtrackComponentsProjectUuidGet
    | HTTPValidationError
]:
    """Get Project Components

     Fetch all components (dependencies) for a project.

    Args:
        project_uuid (str):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetProjectComponentsApiV1DtrackComponentsProjectUuidGetResponseGetProjectComponentsApiV1DtrackComponentsProjectUuidGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        project_uuid=project_uuid,
        page=page,
        page_size=page_size,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    project_uuid: str,
    *,
    client: AuthenticatedClient,
    page: int | Unset = 1,
    page_size: int | Unset = 100,
) -> (
    GetProjectComponentsApiV1DtrackComponentsProjectUuidGetResponseGetProjectComponentsApiV1DtrackComponentsProjectUuidGet
    | HTTPValidationError
    | None
):
    """Get Project Components

     Fetch all components (dependencies) for a project.

    Args:
        project_uuid (str):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetProjectComponentsApiV1DtrackComponentsProjectUuidGetResponseGetProjectComponentsApiV1DtrackComponentsProjectUuidGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            project_uuid=project_uuid,
            client=client,
            page=page,
            page_size=page_size,
        )
    ).parsed
