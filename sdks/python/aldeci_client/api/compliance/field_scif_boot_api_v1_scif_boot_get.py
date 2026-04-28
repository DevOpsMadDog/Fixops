from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.scif_boot_api_v1_scif_boot_get_response_scif_boot_api_v1_scif_boot_get import (
    ScifBootApiV1ScifBootGetResponseScifBootApiV1ScifBootGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/scif/boot",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ScifBootApiV1ScifBootGetResponseScifBootApiV1ScifBootGet | None:
    if response.status_code == 200:
        response_200 = ScifBootApiV1ScifBootGetResponseScifBootApiV1ScifBootGet.from_dict(response.json())

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ScifBootApiV1ScifBootGetResponseScifBootApiV1ScifBootGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[ScifBootApiV1ScifBootGetResponseScifBootApiV1ScifBootGet]:
    """Scif Boot

     Return SCIF boot posture (FIPS_MODE, HSM, audit chain init).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ScifBootApiV1ScifBootGetResponseScifBootApiV1ScifBootGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
) -> ScifBootApiV1ScifBootGetResponseScifBootApiV1ScifBootGet | None:
    """Scif Boot

     Return SCIF boot posture (FIPS_MODE, HSM, audit chain init).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ScifBootApiV1ScifBootGetResponseScifBootApiV1ScifBootGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[ScifBootApiV1ScifBootGetResponseScifBootApiV1ScifBootGet]:
    """Scif Boot

     Return SCIF boot posture (FIPS_MODE, HSM, audit chain init).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ScifBootApiV1ScifBootGetResponseScifBootApiV1ScifBootGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
) -> ScifBootApiV1ScifBootGetResponseScifBootApiV1ScifBootGet | None:
    """Scif Boot

     Return SCIF boot posture (FIPS_MODE, HSM, audit chain init).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ScifBootApiV1ScifBootGetResponseScifBootApiV1ScifBootGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
