from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.sbom_upload_request import SBOMUploadRequest
from ...models.upload_sbom_json_api_v1_dtrack_sbom_upload_post_response_upload_sbom_json_api_v1_dtrack_sbom_upload_post import (
    UploadSbomJsonApiV1DtrackSbomUploadPostResponseUploadSbomJsonApiV1DtrackSbomUploadPost,
)
from ...types import Response


def _get_kwargs(
    *,
    body: SBOMUploadRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/dtrack/sbom/upload",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError | UploadSbomJsonApiV1DtrackSbomUploadPostResponseUploadSbomJsonApiV1DtrackSbomUploadPost | None
):
    if response.status_code == 200:
        response_200 = UploadSbomJsonApiV1DtrackSbomUploadPostResponseUploadSbomJsonApiV1DtrackSbomUploadPost.from_dict(
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
    HTTPValidationError | UploadSbomJsonApiV1DtrackSbomUploadPostResponseUploadSbomJsonApiV1DtrackSbomUploadPost
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
    body: SBOMUploadRequest,
) -> Response[
    HTTPValidationError | UploadSbomJsonApiV1DtrackSbomUploadPostResponseUploadSbomJsonApiV1DtrackSbomUploadPost
]:
    """Upload Sbom Json

     Upload a CycloneDX or SPDX SBOM (JSON body). DTrack auto-detects format.

    Args:
        body (SBOMUploadRequest): Upload SBOM via JSON body (alternative to file upload).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UploadSbomJsonApiV1DtrackSbomUploadPostResponseUploadSbomJsonApiV1DtrackSbomUploadPost]
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
    body: SBOMUploadRequest,
) -> (
    HTTPValidationError | UploadSbomJsonApiV1DtrackSbomUploadPostResponseUploadSbomJsonApiV1DtrackSbomUploadPost | None
):
    """Upload Sbom Json

     Upload a CycloneDX or SPDX SBOM (JSON body). DTrack auto-detects format.

    Args:
        body (SBOMUploadRequest): Upload SBOM via JSON body (alternative to file upload).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UploadSbomJsonApiV1DtrackSbomUploadPostResponseUploadSbomJsonApiV1DtrackSbomUploadPost
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: SBOMUploadRequest,
) -> Response[
    HTTPValidationError | UploadSbomJsonApiV1DtrackSbomUploadPostResponseUploadSbomJsonApiV1DtrackSbomUploadPost
]:
    """Upload Sbom Json

     Upload a CycloneDX or SPDX SBOM (JSON body). DTrack auto-detects format.

    Args:
        body (SBOMUploadRequest): Upload SBOM via JSON body (alternative to file upload).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UploadSbomJsonApiV1DtrackSbomUploadPostResponseUploadSbomJsonApiV1DtrackSbomUploadPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: SBOMUploadRequest,
) -> (
    HTTPValidationError | UploadSbomJsonApiV1DtrackSbomUploadPostResponseUploadSbomJsonApiV1DtrackSbomUploadPost | None
):
    """Upload Sbom Json

     Upload a CycloneDX or SPDX SBOM (JSON body). DTrack auto-detects format.

    Args:
        body (SBOMUploadRequest): Upload SBOM via JSON body (alternative to file upload).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UploadSbomJsonApiV1DtrackSbomUploadPostResponseUploadSbomJsonApiV1DtrackSbomUploadPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
