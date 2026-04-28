from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_findings_api_v1_dtrack_findings_project_uuid_get_response_get_findings_api_v1_dtrack_findings_project_uuid_get import (
    GetFindingsApiV1DtrackFindingsProjectUuidGetResponseGetFindingsApiV1DtrackFindingsProjectUuidGet,
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
        "url": "/api/v1/dtrack/findings/{project_uuid}".format(
            project_uuid=quote(str(project_uuid), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetFindingsApiV1DtrackFindingsProjectUuidGetResponseGetFindingsApiV1DtrackFindingsProjectUuidGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            GetFindingsApiV1DtrackFindingsProjectUuidGetResponseGetFindingsApiV1DtrackFindingsProjectUuidGet.from_dict(
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
    GetFindingsApiV1DtrackFindingsProjectUuidGetResponseGetFindingsApiV1DtrackFindingsProjectUuidGet
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
    GetFindingsApiV1DtrackFindingsProjectUuidGetResponseGetFindingsApiV1DtrackFindingsProjectUuidGet
    | HTTPValidationError
]:
    """Get Findings

     Fetch vulnerability findings for a project from Dependency-Track.

    Args:
        project_uuid (str):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetFindingsApiV1DtrackFindingsProjectUuidGetResponseGetFindingsApiV1DtrackFindingsProjectUuidGet | HTTPValidationError]
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
    GetFindingsApiV1DtrackFindingsProjectUuidGetResponseGetFindingsApiV1DtrackFindingsProjectUuidGet
    | HTTPValidationError
    | None
):
    """Get Findings

     Fetch vulnerability findings for a project from Dependency-Track.

    Args:
        project_uuid (str):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetFindingsApiV1DtrackFindingsProjectUuidGetResponseGetFindingsApiV1DtrackFindingsProjectUuidGet | HTTPValidationError
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
    GetFindingsApiV1DtrackFindingsProjectUuidGetResponseGetFindingsApiV1DtrackFindingsProjectUuidGet
    | HTTPValidationError
]:
    """Get Findings

     Fetch vulnerability findings for a project from Dependency-Track.

    Args:
        project_uuid (str):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetFindingsApiV1DtrackFindingsProjectUuidGetResponseGetFindingsApiV1DtrackFindingsProjectUuidGet | HTTPValidationError]
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
    GetFindingsApiV1DtrackFindingsProjectUuidGetResponseGetFindingsApiV1DtrackFindingsProjectUuidGet
    | HTTPValidationError
    | None
):
    """Get Findings

     Fetch vulnerability findings for a project from Dependency-Track.

    Args:
        project_uuid (str):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetFindingsApiV1DtrackFindingsProjectUuidGetResponseGetFindingsApiV1DtrackFindingsProjectUuidGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            project_uuid=project_uuid,
            client=client,
            page=page,
            page_size=page_size,
        )
    ).parsed
