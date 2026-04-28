from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_supported_formats_api_v1_validate_supported_formats_get_response_get_supported_formats_api_v1_validate_supported_formats_get import (
    GetSupportedFormatsApiV1ValidateSupportedFormatsGetResponseGetSupportedFormatsApiV1ValidateSupportedFormatsGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/validate/supported-formats",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetSupportedFormatsApiV1ValidateSupportedFormatsGetResponseGetSupportedFormatsApiV1ValidateSupportedFormatsGet
    | None
):
    if response.status_code == 200:
        response_200 = GetSupportedFormatsApiV1ValidateSupportedFormatsGetResponseGetSupportedFormatsApiV1ValidateSupportedFormatsGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetSupportedFormatsApiV1ValidateSupportedFormatsGetResponseGetSupportedFormatsApiV1ValidateSupportedFormatsGet
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
) -> Response[
    GetSupportedFormatsApiV1ValidateSupportedFormatsGetResponseGetSupportedFormatsApiV1ValidateSupportedFormatsGet
]:
    """Get Supported Formats

     List all supported input formats and their versions.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetSupportedFormatsApiV1ValidateSupportedFormatsGetResponseGetSupportedFormatsApiV1ValidateSupportedFormatsGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> (
    GetSupportedFormatsApiV1ValidateSupportedFormatsGetResponseGetSupportedFormatsApiV1ValidateSupportedFormatsGet
    | None
):
    """Get Supported Formats

     List all supported input formats and their versions.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetSupportedFormatsApiV1ValidateSupportedFormatsGetResponseGetSupportedFormatsApiV1ValidateSupportedFormatsGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    GetSupportedFormatsApiV1ValidateSupportedFormatsGetResponseGetSupportedFormatsApiV1ValidateSupportedFormatsGet
]:
    """Get Supported Formats

     List all supported input formats and their versions.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetSupportedFormatsApiV1ValidateSupportedFormatsGetResponseGetSupportedFormatsApiV1ValidateSupportedFormatsGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> (
    GetSupportedFormatsApiV1ValidateSupportedFormatsGetResponseGetSupportedFormatsApiV1ValidateSupportedFormatsGet
    | None
):
    """Get Supported Formats

     List all supported input formats and their versions.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetSupportedFormatsApiV1ValidateSupportedFormatsGetResponseGetSupportedFormatsApiV1ValidateSupportedFormatsGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
