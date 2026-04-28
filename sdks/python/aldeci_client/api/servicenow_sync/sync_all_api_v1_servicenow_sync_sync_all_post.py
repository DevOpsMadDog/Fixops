from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.sync_all_request import SyncAllRequest
from ...types import Response


def _get_kwargs(
    *,
    body: SyncAllRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/servicenow-sync/sync-all",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> HTTPValidationError | None:
    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: SyncAllRequest,
) -> Response[HTTPValidationError]:
    """Sync a batch of findings to ServiceNow

     Push a list of findings to ServiceNow, creating or updating incidents as needed.

    Each finding dict must contain a ``finding_id`` or ``id`` field.
    Returns per-finding results and aggregate counters.

    Args:
        body (SyncAllRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: SyncAllRequest,
) -> HTTPValidationError | None:
    """Sync a batch of findings to ServiceNow

     Push a list of findings to ServiceNow, creating or updating incidents as needed.

    Each finding dict must contain a ``finding_id`` or ``id`` field.
    Returns per-finding results and aggregate counters.

    Args:
        body (SyncAllRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: SyncAllRequest,
) -> Response[HTTPValidationError]:
    """Sync a batch of findings to ServiceNow

     Push a list of findings to ServiceNow, creating or updating incidents as needed.

    Each finding dict must contain a ``finding_id`` or ``id`` field.
    Returns per-finding results and aggregate counters.

    Args:
        body (SyncAllRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: SyncAllRequest,
) -> HTTPValidationError | None:
    """Sync a batch of findings to ServiceNow

     Push a list of findings to ServiceNow, creating or updating incidents as needed.

    Each finding dict must contain a ``finding_id`` or ``id`` field.
    Returns per-finding results and aggregate counters.

    Args:
        body (SyncAllRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
