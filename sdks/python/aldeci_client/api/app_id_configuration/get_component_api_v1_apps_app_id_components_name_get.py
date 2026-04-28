from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_component_api_v1_apps_app_id_components_name_get_response_get_component_api_v1_apps_app_id_components_name_get import (
    GetComponentApiV1AppsAppIdComponentsNameGetResponseGetComponentApiV1AppsAppIdComponentsNameGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    app_id: str,
    name: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/apps/{app_id}/components/{name}".format(
            app_id=quote(str(app_id), safe=""),
            name=quote(str(name), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetComponentApiV1AppsAppIdComponentsNameGetResponseGetComponentApiV1AppsAppIdComponentsNameGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            GetComponentApiV1AppsAppIdComponentsNameGetResponseGetComponentApiV1AppsAppIdComponentsNameGet.from_dict(
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
    GetComponentApiV1AppsAppIdComponentsNameGetResponseGetComponentApiV1AppsAppIdComponentsNameGet | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    app_id: str,
    name: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetComponentApiV1AppsAppIdComponentsNameGetResponseGetComponentApiV1AppsAppIdComponentsNameGet | HTTPValidationError
]:
    """Get a specific component

     Retrieve configuration for a single named component.

    Args:
        app_id (str):
        name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetComponentApiV1AppsAppIdComponentsNameGetResponseGetComponentApiV1AppsAppIdComponentsNameGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        app_id=app_id,
        name=name,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    app_id: str,
    name: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetComponentApiV1AppsAppIdComponentsNameGetResponseGetComponentApiV1AppsAppIdComponentsNameGet
    | HTTPValidationError
    | None
):
    """Get a specific component

     Retrieve configuration for a single named component.

    Args:
        app_id (str):
        name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetComponentApiV1AppsAppIdComponentsNameGetResponseGetComponentApiV1AppsAppIdComponentsNameGet | HTTPValidationError
    """

    return sync_detailed(
        app_id=app_id,
        name=name,
        client=client,
    ).parsed


async def asyncio_detailed(
    app_id: str,
    name: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetComponentApiV1AppsAppIdComponentsNameGetResponseGetComponentApiV1AppsAppIdComponentsNameGet | HTTPValidationError
]:
    """Get a specific component

     Retrieve configuration for a single named component.

    Args:
        app_id (str):
        name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetComponentApiV1AppsAppIdComponentsNameGetResponseGetComponentApiV1AppsAppIdComponentsNameGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        app_id=app_id,
        name=name,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    app_id: str,
    name: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetComponentApiV1AppsAppIdComponentsNameGetResponseGetComponentApiV1AppsAppIdComponentsNameGet
    | HTTPValidationError
    | None
):
    """Get a specific component

     Retrieve configuration for a single named component.

    Args:
        app_id (str):
        name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetComponentApiV1AppsAppIdComponentsNameGetResponseGetComponentApiV1AppsAppIdComponentsNameGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            app_id=app_id,
            name=name,
            client=client,
        )
    ).parsed
