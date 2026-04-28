from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.upload_vex_api_v1_dtrack_vex_upload_post_response_upload_vex_api_v1_dtrack_vex_upload_post import (
    UploadVexApiV1DtrackVexUploadPostResponseUploadVexApiV1DtrackVexUploadPost,
)
from ...models.vex_upload_request import VEXUploadRequest
from ...types import Response


def _get_kwargs(
    *,
    body: VEXUploadRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/dtrack/vex/upload",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | UploadVexApiV1DtrackVexUploadPostResponseUploadVexApiV1DtrackVexUploadPost | None:
    if response.status_code == 200:
        response_200 = UploadVexApiV1DtrackVexUploadPostResponseUploadVexApiV1DtrackVexUploadPost.from_dict(
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
) -> Response[HTTPValidationError | UploadVexApiV1DtrackVexUploadPostResponseUploadVexApiV1DtrackVexUploadPost]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: VEXUploadRequest,
) -> Response[HTTPValidationError | UploadVexApiV1DtrackVexUploadPostResponseUploadVexApiV1DtrackVexUploadPost]:
    """Upload Vex

     Upload a CycloneDX VEX document to apply analysis decisions
    (e.g., mark findings as not_affected, false_positive, in_triage).

    Args:
        body (VEXUploadRequest): Upload VEX document to apply analysis decisions in bulk.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UploadVexApiV1DtrackVexUploadPostResponseUploadVexApiV1DtrackVexUploadPost]
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
    body: VEXUploadRequest,
) -> HTTPValidationError | UploadVexApiV1DtrackVexUploadPostResponseUploadVexApiV1DtrackVexUploadPost | None:
    """Upload Vex

     Upload a CycloneDX VEX document to apply analysis decisions
    (e.g., mark findings as not_affected, false_positive, in_triage).

    Args:
        body (VEXUploadRequest): Upload VEX document to apply analysis decisions in bulk.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UploadVexApiV1DtrackVexUploadPostResponseUploadVexApiV1DtrackVexUploadPost
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: VEXUploadRequest,
) -> Response[HTTPValidationError | UploadVexApiV1DtrackVexUploadPostResponseUploadVexApiV1DtrackVexUploadPost]:
    """Upload Vex

     Upload a CycloneDX VEX document to apply analysis decisions
    (e.g., mark findings as not_affected, false_positive, in_triage).

    Args:
        body (VEXUploadRequest): Upload VEX document to apply analysis decisions in bulk.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UploadVexApiV1DtrackVexUploadPostResponseUploadVexApiV1DtrackVexUploadPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: VEXUploadRequest,
) -> HTTPValidationError | UploadVexApiV1DtrackVexUploadPostResponseUploadVexApiV1DtrackVexUploadPost | None:
    """Upload Vex

     Upload a CycloneDX VEX document to apply analysis decisions
    (e.g., mark findings as not_affected, false_positive, in_triage).

    Args:
        body (VEXUploadRequest): Upload VEX document to apply analysis decisions in bulk.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UploadVexApiV1DtrackVexUploadPostResponseUploadVexApiV1DtrackVexUploadPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
