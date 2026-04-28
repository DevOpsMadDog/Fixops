from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.hook_uninstall_request import HookUninstallRequest
from ...models.http_validation_error import HTTPValidationError
from ...models.uninstall_hook_api_v1_hooks_uninstall_post_response_uninstall_hook_api_v1_hooks_uninstall_post import (
    UninstallHookApiV1HooksUninstallPostResponseUninstallHookApiV1HooksUninstallPost,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: HookUninstallRequest,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/hooks/uninstall",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | UninstallHookApiV1HooksUninstallPostResponseUninstallHookApiV1HooksUninstallPost | None:
    if response.status_code == 200:
        response_200 = UninstallHookApiV1HooksUninstallPostResponseUninstallHookApiV1HooksUninstallPost.from_dict(
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
) -> Response[HTTPValidationError | UninstallHookApiV1HooksUninstallPostResponseUninstallHookApiV1HooksUninstallPost]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: HookUninstallRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | UninstallHookApiV1HooksUninstallPostResponseUninstallHookApiV1HooksUninstallPost]:
    """Uninstall an active hook policy (delete by id, hash, or org)

     Delete an active hook policy and emit an audit tombstone.

    Resolution order:
      1. ``hook_id`` — exact policy record id
      2. ``policy_hash`` + org — content-addressed delete
      3. ``org_id`` alone — uninstall the *active* (most recent) policy for that org

    Returns: deleted_count, deleted record metadata, tombstone id.
    Raises 404 if nothing matches, 422 if no resolver fields supplied.

    Args:
        x_org_id (None | str | Unset):
        body (HookUninstallRequest): Body for POST /api/v1/hooks/uninstall.

            At least one of ``hook_id``, ``policy_hash``, or ``org_id`` must be
            supplied. ``org_id`` may also be supplied via the ``X-Org-ID`` header.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UninstallHookApiV1HooksUninstallPostResponseUninstallHookApiV1HooksUninstallPost]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: HookUninstallRequest,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | UninstallHookApiV1HooksUninstallPostResponseUninstallHookApiV1HooksUninstallPost | None:
    """Uninstall an active hook policy (delete by id, hash, or org)

     Delete an active hook policy and emit an audit tombstone.

    Resolution order:
      1. ``hook_id`` — exact policy record id
      2. ``policy_hash`` + org — content-addressed delete
      3. ``org_id`` alone — uninstall the *active* (most recent) policy for that org

    Returns: deleted_count, deleted record metadata, tombstone id.
    Raises 404 if nothing matches, 422 if no resolver fields supplied.

    Args:
        x_org_id (None | str | Unset):
        body (HookUninstallRequest): Body for POST /api/v1/hooks/uninstall.

            At least one of ``hook_id``, ``policy_hash``, or ``org_id`` must be
            supplied. ``org_id`` may also be supplied via the ``X-Org-ID`` header.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UninstallHookApiV1HooksUninstallPostResponseUninstallHookApiV1HooksUninstallPost
    """

    return sync_detailed(
        client=client,
        body=body,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: HookUninstallRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | UninstallHookApiV1HooksUninstallPostResponseUninstallHookApiV1HooksUninstallPost]:
    """Uninstall an active hook policy (delete by id, hash, or org)

     Delete an active hook policy and emit an audit tombstone.

    Resolution order:
      1. ``hook_id`` — exact policy record id
      2. ``policy_hash`` + org — content-addressed delete
      3. ``org_id`` alone — uninstall the *active* (most recent) policy for that org

    Returns: deleted_count, deleted record metadata, tombstone id.
    Raises 404 if nothing matches, 422 if no resolver fields supplied.

    Args:
        x_org_id (None | str | Unset):
        body (HookUninstallRequest): Body for POST /api/v1/hooks/uninstall.

            At least one of ``hook_id``, ``policy_hash``, or ``org_id`` must be
            supplied. ``org_id`` may also be supplied via the ``X-Org-ID`` header.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UninstallHookApiV1HooksUninstallPostResponseUninstallHookApiV1HooksUninstallPost]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: HookUninstallRequest,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | UninstallHookApiV1HooksUninstallPostResponseUninstallHookApiV1HooksUninstallPost | None:
    """Uninstall an active hook policy (delete by id, hash, or org)

     Delete an active hook policy and emit an audit tombstone.

    Resolution order:
      1. ``hook_id`` — exact policy record id
      2. ``policy_hash`` + org — content-addressed delete
      3. ``org_id`` alone — uninstall the *active* (most recent) policy for that org

    Returns: deleted_count, deleted record metadata, tombstone id.
    Raises 404 if nothing matches, 422 if no resolver fields supplied.

    Args:
        x_org_id (None | str | Unset):
        body (HookUninstallRequest): Body for POST /api/v1/hooks/uninstall.

            At least one of ``hook_id``, ``policy_hash``, or ``org_id`` must be
            supplied. ``org_id`` may also be supplied via the ``X-Org-ID`` header.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UninstallHookApiV1HooksUninstallPostResponseUninstallHookApiV1HooksUninstallPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            x_org_id=x_org_id,
        )
    ).parsed
