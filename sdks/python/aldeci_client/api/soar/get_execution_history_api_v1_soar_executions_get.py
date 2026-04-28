from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.soar_execution import SOARExecution
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str | Unset = "default",
    playbook_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    json_playbook_id: None | str | Unset
    if isinstance(playbook_id, Unset):
        json_playbook_id = UNSET
    else:
        json_playbook_id = playbook_id
    params["playbook_id"] = json_playbook_id

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/soar/executions",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[SOARExecution] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = SOARExecution.from_dict(response_200_item_data)

            response_200.append(response_200_item)

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
) -> Response[HTTPValidationError | list[SOARExecution]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    playbook_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> Response[HTTPValidationError | list[SOARExecution]]:
    """Get SOAR execution history

     Return past SOAR execution records for the org.

    Optionally filter by a specific playbook ID. Results are ordered by
    most recent first.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        playbook_id (None | str | Unset): Filter by playbook ID
        limit (int | Unset): Max results Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[SOARExecution]]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        playbook_id=playbook_id,
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    playbook_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> HTTPValidationError | list[SOARExecution] | None:
    """Get SOAR execution history

     Return past SOAR execution records for the org.

    Optionally filter by a specific playbook ID. Results are ordered by
    most recent first.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        playbook_id (None | str | Unset): Filter by playbook ID
        limit (int | Unset): Max results Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[SOARExecution]
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        playbook_id=playbook_id,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    playbook_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> Response[HTTPValidationError | list[SOARExecution]]:
    """Get SOAR execution history

     Return past SOAR execution records for the org.

    Optionally filter by a specific playbook ID. Results are ordered by
    most recent first.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        playbook_id (None | str | Unset): Filter by playbook ID
        limit (int | Unset): Max results Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[SOARExecution]]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        playbook_id=playbook_id,
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    playbook_id: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> HTTPValidationError | list[SOARExecution] | None:
    """Get SOAR execution history

     Return past SOAR execution records for the org.

    Optionally filter by a specific playbook ID. Results are ordered by
    most recent first.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        playbook_id (None | str | Unset): Filter by playbook ID
        limit (int | Unset): Max results Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[SOARExecution]
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            playbook_id=playbook_id,
            limit=limit,
        )
    ).parsed
