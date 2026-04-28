from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.expire_stale_changes_api_v1_changes_admin_expire_stale_post_response_expire_stale_changes_api_v1_changes_admin_expire_stale_post import (
    ExpireStaleChangesApiV1ChangesAdminExpireStalePostResponseExpireStaleChangesApiV1ChangesAdminExpireStalePost,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/changes/admin/expire-stale",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    ExpireStaleChangesApiV1ChangesAdminExpireStalePostResponseExpireStaleChangesApiV1ChangesAdminExpireStalePost | None
):
    if response.status_code == 200:
        response_200 = ExpireStaleChangesApiV1ChangesAdminExpireStalePostResponseExpireStaleChangesApiV1ChangesAdminExpireStalePost.from_dict(
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
    ExpireStaleChangesApiV1ChangesAdminExpireStalePostResponseExpireStaleChangesApiV1ChangesAdminExpireStalePost
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
    ExpireStaleChangesApiV1ChangesAdminExpireStalePostResponseExpireStaleChangesApiV1ChangesAdminExpireStalePost
]:
    """Expire Stale Changes

     Expire change requests that have breached their SLA review deadline.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ExpireStaleChangesApiV1ChangesAdminExpireStalePostResponseExpireStaleChangesApiV1ChangesAdminExpireStalePost]
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
    ExpireStaleChangesApiV1ChangesAdminExpireStalePostResponseExpireStaleChangesApiV1ChangesAdminExpireStalePost | None
):
    """Expire Stale Changes

     Expire change requests that have breached their SLA review deadline.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ExpireStaleChangesApiV1ChangesAdminExpireStalePostResponseExpireStaleChangesApiV1ChangesAdminExpireStalePost
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    ExpireStaleChangesApiV1ChangesAdminExpireStalePostResponseExpireStaleChangesApiV1ChangesAdminExpireStalePost
]:
    """Expire Stale Changes

     Expire change requests that have breached their SLA review deadline.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ExpireStaleChangesApiV1ChangesAdminExpireStalePostResponseExpireStaleChangesApiV1ChangesAdminExpireStalePost]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> (
    ExpireStaleChangesApiV1ChangesAdminExpireStalePostResponseExpireStaleChangesApiV1ChangesAdminExpireStalePost | None
):
    """Expire Stale Changes

     Expire change requests that have breached their SLA review deadline.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ExpireStaleChangesApiV1ChangesAdminExpireStalePostResponseExpireStaleChangesApiV1ChangesAdminExpireStalePost
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
