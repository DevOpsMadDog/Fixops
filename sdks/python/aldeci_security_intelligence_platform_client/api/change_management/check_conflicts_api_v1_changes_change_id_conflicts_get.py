from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.check_conflicts_api_v1_changes_change_id_conflicts_get_response_check_conflicts_api_v1_changes_change_id_conflicts_get import (
    CheckConflictsApiV1ChangesChangeIdConflictsGetResponseCheckConflictsApiV1ChangesChangeIdConflictsGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    change_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/changes/{change_id}/conflicts".format(
            change_id=quote(str(change_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    CheckConflictsApiV1ChangesChangeIdConflictsGetResponseCheckConflictsApiV1ChangesChangeIdConflictsGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = CheckConflictsApiV1ChangesChangeIdConflictsGetResponseCheckConflictsApiV1ChangesChangeIdConflictsGet.from_dict(
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
    CheckConflictsApiV1ChangesChangeIdConflictsGetResponseCheckConflictsApiV1ChangesChangeIdConflictsGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    change_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    CheckConflictsApiV1ChangesChangeIdConflictsGetResponseCheckConflictsApiV1ChangesChangeIdConflictsGet
    | HTTPValidationError
]:
    """Check Conflicts

     Check a scheduled change for calendar conflicts and freeze periods.

    Args:
        change_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CheckConflictsApiV1ChangesChangeIdConflictsGetResponseCheckConflictsApiV1ChangesChangeIdConflictsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        change_id=change_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    change_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    CheckConflictsApiV1ChangesChangeIdConflictsGetResponseCheckConflictsApiV1ChangesChangeIdConflictsGet
    | HTTPValidationError
    | None
):
    """Check Conflicts

     Check a scheduled change for calendar conflicts and freeze periods.

    Args:
        change_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CheckConflictsApiV1ChangesChangeIdConflictsGetResponseCheckConflictsApiV1ChangesChangeIdConflictsGet | HTTPValidationError
    """

    return sync_detailed(
        change_id=change_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    change_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    CheckConflictsApiV1ChangesChangeIdConflictsGetResponseCheckConflictsApiV1ChangesChangeIdConflictsGet
    | HTTPValidationError
]:
    """Check Conflicts

     Check a scheduled change for calendar conflicts and freeze periods.

    Args:
        change_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CheckConflictsApiV1ChangesChangeIdConflictsGetResponseCheckConflictsApiV1ChangesChangeIdConflictsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        change_id=change_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    change_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    CheckConflictsApiV1ChangesChangeIdConflictsGetResponseCheckConflictsApiV1ChangesChangeIdConflictsGet
    | HTTPValidationError
    | None
):
    """Check Conflicts

     Check a scheduled change for calendar conflicts and freeze periods.

    Args:
        change_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CheckConflictsApiV1ChangesChangeIdConflictsGetResponseCheckConflictsApiV1ChangesChangeIdConflictsGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            change_id=change_id,
            client=client,
        )
    ).parsed
