from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.status_api_v1_connectors_iam_sso_status_get_response_status_api_v1_connectors_iam_sso_status_get import (
    StatusApiV1ConnectorsIamSsoStatusGetResponseStatusApiV1ConnectorsIamSsoStatusGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/connectors/iam-sso/status",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> StatusApiV1ConnectorsIamSsoStatusGetResponseStatusApiV1ConnectorsIamSsoStatusGet | None:
    if response.status_code == 200:
        response_200 = StatusApiV1ConnectorsIamSsoStatusGetResponseStatusApiV1ConnectorsIamSsoStatusGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[StatusApiV1ConnectorsIamSsoStatusGetResponseStatusApiV1ConnectorsIamSsoStatusGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[StatusApiV1ConnectorsIamSsoStatusGetResponseStatusApiV1ConnectorsIamSsoStatusGet]:
    """Status

     Return cached last-sync result (or empty if never run).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[StatusApiV1ConnectorsIamSsoStatusGetResponseStatusApiV1ConnectorsIamSsoStatusGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> StatusApiV1ConnectorsIamSsoStatusGetResponseStatusApiV1ConnectorsIamSsoStatusGet | None:
    """Status

     Return cached last-sync result (or empty if never run).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        StatusApiV1ConnectorsIamSsoStatusGetResponseStatusApiV1ConnectorsIamSsoStatusGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[StatusApiV1ConnectorsIamSsoStatusGetResponseStatusApiV1ConnectorsIamSsoStatusGet]:
    """Status

     Return cached last-sync result (or empty if never run).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[StatusApiV1ConnectorsIamSsoStatusGetResponseStatusApiV1ConnectorsIamSsoStatusGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> StatusApiV1ConnectorsIamSsoStatusGetResponseStatusApiV1ConnectorsIamSsoStatusGet | None:
    """Status

     Return cached last-sync result (or empty if never run).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        StatusApiV1ConnectorsIamSsoStatusGetResponseStatusApiV1ConnectorsIamSsoStatusGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
