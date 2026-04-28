from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.sync_status_request import SyncStatusRequest
from ...types import Response


def _get_kwargs(
    *,
    body: SyncStatusRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/servicenow-sync/sync-status",
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
    body: SyncStatusRequest,
) -> Response[HTTPValidationError]:
    """Propagate finding status change to ServiceNow

     Update the linked ServiceNow incident state to reflect the finding's new status.

    Requires a pre-existing link between ``finding_id`` and a ServiceNow incident
    (established via ``sync-finding``). Uses the configured
    ``finding_to_sn_state`` mapping to determine the ServiceNow state code.

    Args:
        body (SyncStatusRequest):

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
    body: SyncStatusRequest,
) -> HTTPValidationError | None:
    """Propagate finding status change to ServiceNow

     Update the linked ServiceNow incident state to reflect the finding's new status.

    Requires a pre-existing link between ``finding_id`` and a ServiceNow incident
    (established via ``sync-finding``). Uses the configured
    ``finding_to_sn_state`` mapping to determine the ServiceNow state code.

    Args:
        body (SyncStatusRequest):

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
    body: SyncStatusRequest,
) -> Response[HTTPValidationError]:
    """Propagate finding status change to ServiceNow

     Update the linked ServiceNow incident state to reflect the finding's new status.

    Requires a pre-existing link between ``finding_id`` and a ServiceNow incident
    (established via ``sync-finding``). Uses the configured
    ``finding_to_sn_state`` mapping to determine the ServiceNow state code.

    Args:
        body (SyncStatusRequest):

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
    body: SyncStatusRequest,
) -> HTTPValidationError | None:
    """Propagate finding status change to ServiceNow

     Update the linked ServiceNow incident state to reflect the finding's new status.

    Requires a pre-existing link between ``finding_id`` and a ServiceNow incident
    (established via ``sync-finding``). Uses the configured
    ``finding_to_sn_state`` mapping to determine the ServiceNow state code.

    Args:
        body (SyncStatusRequest):

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
