from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.export_sbom_api_v1_dtrack_sbom_export_project_uuid_get_response_export_sbom_api_v1_dtrack_sbom_export_project_uuid_get import (
    ExportSbomApiV1DtrackSbomExportProjectUuidGetResponseExportSbomApiV1DtrackSbomExportProjectUuidGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    project_uuid: str,
    *,
    fmt: str | Unset = "json",
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["fmt"] = fmt

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/dtrack/sbom/export/{project_uuid}".format(
            project_uuid=quote(str(project_uuid), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    ExportSbomApiV1DtrackSbomExportProjectUuidGetResponseExportSbomApiV1DtrackSbomExportProjectUuidGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = ExportSbomApiV1DtrackSbomExportProjectUuidGetResponseExportSbomApiV1DtrackSbomExportProjectUuidGet.from_dict(
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
    ExportSbomApiV1DtrackSbomExportProjectUuidGetResponseExportSbomApiV1DtrackSbomExportProjectUuidGet
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
    fmt: str | Unset = "json",
) -> Response[
    ExportSbomApiV1DtrackSbomExportProjectUuidGetResponseExportSbomApiV1DtrackSbomExportProjectUuidGet
    | HTTPValidationError
]:
    """Export Sbom

     Export the current SBOM for a project in CycloneDX format.

    Args:
        project_uuid (str):
        fmt (str | Unset):  Default: 'json'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ExportSbomApiV1DtrackSbomExportProjectUuidGetResponseExportSbomApiV1DtrackSbomExportProjectUuidGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        project_uuid=project_uuid,
        fmt=fmt,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    project_uuid: str,
    *,
    client: AuthenticatedClient,
    fmt: str | Unset = "json",
) -> (
    ExportSbomApiV1DtrackSbomExportProjectUuidGetResponseExportSbomApiV1DtrackSbomExportProjectUuidGet
    | HTTPValidationError
    | None
):
    """Export Sbom

     Export the current SBOM for a project in CycloneDX format.

    Args:
        project_uuid (str):
        fmt (str | Unset):  Default: 'json'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ExportSbomApiV1DtrackSbomExportProjectUuidGetResponseExportSbomApiV1DtrackSbomExportProjectUuidGet | HTTPValidationError
    """

    return sync_detailed(
        project_uuid=project_uuid,
        client=client,
        fmt=fmt,
    ).parsed


async def asyncio_detailed(
    project_uuid: str,
    *,
    client: AuthenticatedClient,
    fmt: str | Unset = "json",
) -> Response[
    ExportSbomApiV1DtrackSbomExportProjectUuidGetResponseExportSbomApiV1DtrackSbomExportProjectUuidGet
    | HTTPValidationError
]:
    """Export Sbom

     Export the current SBOM for a project in CycloneDX format.

    Args:
        project_uuid (str):
        fmt (str | Unset):  Default: 'json'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ExportSbomApiV1DtrackSbomExportProjectUuidGetResponseExportSbomApiV1DtrackSbomExportProjectUuidGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        project_uuid=project_uuid,
        fmt=fmt,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    project_uuid: str,
    *,
    client: AuthenticatedClient,
    fmt: str | Unset = "json",
) -> (
    ExportSbomApiV1DtrackSbomExportProjectUuidGetResponseExportSbomApiV1DtrackSbomExportProjectUuidGet
    | HTTPValidationError
    | None
):
    """Export Sbom

     Export the current SBOM for a project in CycloneDX format.

    Args:
        project_uuid (str):
        fmt (str | Unset):  Default: 'json'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ExportSbomApiV1DtrackSbomExportProjectUuidGetResponseExportSbomApiV1DtrackSbomExportProjectUuidGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            project_uuid=project_uuid,
            client=client,
            fmt=fmt,
        )
    ).parsed
