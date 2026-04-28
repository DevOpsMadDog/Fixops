from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.crown_jewel_tag_request import CrownJewelTagRequest
from ...models.http_validation_error import HTTPValidationError
from ...models.tag_crown_jewel_api_v1_assets_id_crown_jewel_tag_post_response_tag_crown_jewel_api_v1_assets_id_crown_jewel_tag_post import (
    TagCrownJewelApiV1AssetsIdCrownJewelTagPostResponseTagCrownJewelApiV1AssetsIdCrownJewelTagPost,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    id: str,
    *,
    body: CrownJewelTagRequest,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/assets/{id}/crown-jewel-tag".format(
            id=quote(str(id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | TagCrownJewelApiV1AssetsIdCrownJewelTagPostResponseTagCrownJewelApiV1AssetsIdCrownJewelTagPost
    | None
):
    if response.status_code == 200:
        response_200 = (
            TagCrownJewelApiV1AssetsIdCrownJewelTagPostResponseTagCrownJewelApiV1AssetsIdCrownJewelTagPost.from_dict(
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
    HTTPValidationError | TagCrownJewelApiV1AssetsIdCrownJewelTagPostResponseTagCrownJewelApiV1AssetsIdCrownJewelTagPost
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    id: str,
    *,
    client: AuthenticatedClient,
    body: CrownJewelTagRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError | TagCrownJewelApiV1AssetsIdCrownJewelTagPostResponseTagCrownJewelApiV1AssetsIdCrownJewelTagPost
]:
    """Tag Crown Jewel

     Tag an asset as a crown-jewel (or untag). (Multica 68162b9b)

    Args:
        id (str):
        x_org_id (None | str | Unset):
        body (CrownJewelTagRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TagCrownJewelApiV1AssetsIdCrownJewelTagPostResponseTagCrownJewelApiV1AssetsIdCrownJewelTagPost]
    """

    kwargs = _get_kwargs(
        id=id,
        body=body,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    id: str,
    *,
    client: AuthenticatedClient,
    body: CrownJewelTagRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | TagCrownJewelApiV1AssetsIdCrownJewelTagPostResponseTagCrownJewelApiV1AssetsIdCrownJewelTagPost
    | None
):
    """Tag Crown Jewel

     Tag an asset as a crown-jewel (or untag). (Multica 68162b9b)

    Args:
        id (str):
        x_org_id (None | str | Unset):
        body (CrownJewelTagRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TagCrownJewelApiV1AssetsIdCrownJewelTagPostResponseTagCrownJewelApiV1AssetsIdCrownJewelTagPost
    """

    return sync_detailed(
        id=id,
        client=client,
        body=body,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    id: str,
    *,
    client: AuthenticatedClient,
    body: CrownJewelTagRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError | TagCrownJewelApiV1AssetsIdCrownJewelTagPostResponseTagCrownJewelApiV1AssetsIdCrownJewelTagPost
]:
    """Tag Crown Jewel

     Tag an asset as a crown-jewel (or untag). (Multica 68162b9b)

    Args:
        id (str):
        x_org_id (None | str | Unset):
        body (CrownJewelTagRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TagCrownJewelApiV1AssetsIdCrownJewelTagPostResponseTagCrownJewelApiV1AssetsIdCrownJewelTagPost]
    """

    kwargs = _get_kwargs(
        id=id,
        body=body,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    id: str,
    *,
    client: AuthenticatedClient,
    body: CrownJewelTagRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | TagCrownJewelApiV1AssetsIdCrownJewelTagPostResponseTagCrownJewelApiV1AssetsIdCrownJewelTagPost
    | None
):
    """Tag Crown Jewel

     Tag an asset as a crown-jewel (or untag). (Multica 68162b9b)

    Args:
        id (str):
        x_org_id (None | str | Unset):
        body (CrownJewelTagRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TagCrownJewelApiV1AssetsIdCrownJewelTagPostResponseTagCrownJewelApiV1AssetsIdCrownJewelTagPost
    """

    return (
        await asyncio_detailed(
            id=id,
            client=client,
            body=body,
            x_org_id=x_org_id,
        )
    ).parsed
