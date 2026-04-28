from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.update_app_api_v1_apps_app_id_put_response_update_app_api_v1_apps_app_id_put import (
    UpdateAppApiV1AppsAppIdPutResponseUpdateAppApiV1AppsAppIdPut,
)
from ...models.update_app_request import UpdateAppRequest
from ...types import Response


def _get_kwargs(
    app_id: str,
    *,
    body: UpdateAppRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/apps/{app_id}".format(
            app_id=quote(str(app_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | UpdateAppApiV1AppsAppIdPutResponseUpdateAppApiV1AppsAppIdPut | None:
    if response.status_code == 200:
        response_200 = UpdateAppApiV1AppsAppIdPutResponseUpdateAppApiV1AppsAppIdPut.from_dict(response.json())

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
) -> Response[HTTPValidationError | UpdateAppApiV1AppsAppIdPutResponseUpdateAppApiV1AppsAppIdPut]:
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
    body: UpdateAppRequest,
) -> Response[HTTPValidationError | UpdateAppApiV1AppsAppIdPutResponseUpdateAppApiV1AppsAppIdPut]:
    """Update app config

     Apply a partial update to an existing app config.

    Top-level keys in ``updates`` are merged into the current config.
    Nested dicts (e.g. ``policies``) are shallow-merged.

    Args:
        app_id (str):
        body (UpdateAppRequest): Partial update payload — any top-level keys will be merged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdateAppApiV1AppsAppIdPutResponseUpdateAppApiV1AppsAppIdPut]
    """

    kwargs = _get_kwargs(
        app_id=app_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    app_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAppRequest,
) -> HTTPValidationError | UpdateAppApiV1AppsAppIdPutResponseUpdateAppApiV1AppsAppIdPut | None:
    """Update app config

     Apply a partial update to an existing app config.

    Top-level keys in ``updates`` are merged into the current config.
    Nested dicts (e.g. ``policies``) are shallow-merged.

    Args:
        app_id (str):
        body (UpdateAppRequest): Partial update payload — any top-level keys will be merged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdateAppApiV1AppsAppIdPutResponseUpdateAppApiV1AppsAppIdPut
    """

    return sync_detailed(
        app_id=app_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    app_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAppRequest,
) -> Response[HTTPValidationError | UpdateAppApiV1AppsAppIdPutResponseUpdateAppApiV1AppsAppIdPut]:
    """Update app config

     Apply a partial update to an existing app config.

    Top-level keys in ``updates`` are merged into the current config.
    Nested dicts (e.g. ``policies``) are shallow-merged.

    Args:
        app_id (str):
        body (UpdateAppRequest): Partial update payload — any top-level keys will be merged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdateAppApiV1AppsAppIdPutResponseUpdateAppApiV1AppsAppIdPut]
    """

    kwargs = _get_kwargs(
        app_id=app_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    app_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAppRequest,
) -> HTTPValidationError | UpdateAppApiV1AppsAppIdPutResponseUpdateAppApiV1AppsAppIdPut | None:
    """Update app config

     Apply a partial update to an existing app config.

    Top-level keys in ``updates`` are merged into the current config.
    Nested dicts (e.g. ``policies``) are shallow-merged.

    Args:
        app_id (str):
        body (UpdateAppRequest): Partial update payload — any top-level keys will be merged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdateAppApiV1AppsAppIdPutResponseUpdateAppApiV1AppsAppIdPut
    """

    return (
        await asyncio_detailed(
            app_id=app_id,
            client=client,
            body=body,
        )
    ).parsed
