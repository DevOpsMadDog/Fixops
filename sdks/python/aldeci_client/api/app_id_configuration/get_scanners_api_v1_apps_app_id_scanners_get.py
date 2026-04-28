from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_scanners_api_v1_apps_app_id_scanners_get_response_get_scanners_api_v1_apps_app_id_scanners_get import (
    GetScannersApiV1AppsAppIdScannersGetResponseGetScannersApiV1AppsAppIdScannersGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    app_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/apps/{app_id}/scanners".format(
            app_id=quote(str(app_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetScannersApiV1AppsAppIdScannersGetResponseGetScannersApiV1AppsAppIdScannersGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GetScannersApiV1AppsAppIdScannersGetResponseGetScannersApiV1AppsAppIdScannersGet.from_dict(
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
) -> Response[GetScannersApiV1AppsAppIdScannersGetResponseGetScannersApiV1AppsAppIdScannersGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    app_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[GetScannersApiV1AppsAppIdScannersGetResponseGetScannersApiV1AppsAppIdScannersGet | HTTPValidationError]:
    """Get scanner assignments

     Return all scanner category assignments for the given app.

    Args:
        app_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetScannersApiV1AppsAppIdScannersGetResponseGetScannersApiV1AppsAppIdScannersGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        app_id=app_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    app_id: str,
    *,
    client: AuthenticatedClient,
) -> GetScannersApiV1AppsAppIdScannersGetResponseGetScannersApiV1AppsAppIdScannersGet | HTTPValidationError | None:
    """Get scanner assignments

     Return all scanner category assignments for the given app.

    Args:
        app_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetScannersApiV1AppsAppIdScannersGetResponseGetScannersApiV1AppsAppIdScannersGet | HTTPValidationError
    """

    return sync_detailed(
        app_id=app_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    app_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[GetScannersApiV1AppsAppIdScannersGetResponseGetScannersApiV1AppsAppIdScannersGet | HTTPValidationError]:
    """Get scanner assignments

     Return all scanner category assignments for the given app.

    Args:
        app_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetScannersApiV1AppsAppIdScannersGetResponseGetScannersApiV1AppsAppIdScannersGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        app_id=app_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    app_id: str,
    *,
    client: AuthenticatedClient,
) -> GetScannersApiV1AppsAppIdScannersGetResponseGetScannersApiV1AppsAppIdScannersGet | HTTPValidationError | None:
    """Get scanner assignments

     Return all scanner category assignments for the given app.

    Args:
        app_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetScannersApiV1AppsAppIdScannersGetResponseGetScannersApiV1AppsAppIdScannersGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            app_id=app_id,
            client=client,
        )
    ).parsed
