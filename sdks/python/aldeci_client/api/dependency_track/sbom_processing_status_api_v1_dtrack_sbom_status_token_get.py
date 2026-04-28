from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.sbom_processing_status_api_v1_dtrack_sbom_status_token_get_response_sbom_processing_status_api_v1_dtrack_sbom_status_token_get import (
    SbomProcessingStatusApiV1DtrackSbomStatusTokenGetResponseSbomProcessingStatusApiV1DtrackSbomStatusTokenGet,
)
from ...types import Response


def _get_kwargs(
    token: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/dtrack/sbom/status/{token}".format(
            token=quote(str(token), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | SbomProcessingStatusApiV1DtrackSbomStatusTokenGetResponseSbomProcessingStatusApiV1DtrackSbomStatusTokenGet
    | None
):
    if response.status_code == 200:
        response_200 = SbomProcessingStatusApiV1DtrackSbomStatusTokenGetResponseSbomProcessingStatusApiV1DtrackSbomStatusTokenGet.from_dict(
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
    | SbomProcessingStatusApiV1DtrackSbomStatusTokenGetResponseSbomProcessingStatusApiV1DtrackSbomStatusTokenGet
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    token: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    HTTPValidationError
    | SbomProcessingStatusApiV1DtrackSbomStatusTokenGetResponseSbomProcessingStatusApiV1DtrackSbomStatusTokenGet
]:
    """Sbom Processing Status

     Check whether a previously uploaded SBOM has been fully processed.

    Args:
        token (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SbomProcessingStatusApiV1DtrackSbomStatusTokenGetResponseSbomProcessingStatusApiV1DtrackSbomStatusTokenGet]
    """

    kwargs = _get_kwargs(
        token=token,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    token: str,
    *,
    client: AuthenticatedClient,
) -> (
    HTTPValidationError
    | SbomProcessingStatusApiV1DtrackSbomStatusTokenGetResponseSbomProcessingStatusApiV1DtrackSbomStatusTokenGet
    | None
):
    """Sbom Processing Status

     Check whether a previously uploaded SBOM has been fully processed.

    Args:
        token (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SbomProcessingStatusApiV1DtrackSbomStatusTokenGetResponseSbomProcessingStatusApiV1DtrackSbomStatusTokenGet
    """

    return sync_detailed(
        token=token,
        client=client,
    ).parsed


async def asyncio_detailed(
    token: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    HTTPValidationError
    | SbomProcessingStatusApiV1DtrackSbomStatusTokenGetResponseSbomProcessingStatusApiV1DtrackSbomStatusTokenGet
]:
    """Sbom Processing Status

     Check whether a previously uploaded SBOM has been fully processed.

    Args:
        token (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SbomProcessingStatusApiV1DtrackSbomStatusTokenGetResponseSbomProcessingStatusApiV1DtrackSbomStatusTokenGet]
    """

    kwargs = _get_kwargs(
        token=token,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    token: str,
    *,
    client: AuthenticatedClient,
) -> (
    HTTPValidationError
    | SbomProcessingStatusApiV1DtrackSbomStatusTokenGetResponseSbomProcessingStatusApiV1DtrackSbomStatusTokenGet
    | None
):
    """Sbom Processing Status

     Check whether a previously uploaded SBOM has been fully processed.

    Args:
        token (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SbomProcessingStatusApiV1DtrackSbomStatusTokenGetResponseSbomProcessingStatusApiV1DtrackSbomStatusTokenGet
    """

    return (
        await asyncio_detailed(
            token=token,
            client=client,
        )
    ).parsed
