from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.cancel_drill_api_v1_fail_drills_drill_id_delete_response_cancel_drill_api_v1_fail_drills_drill_id_delete import (
    CancelDrillApiV1FailDrillsDrillIdDeleteResponseCancelDrillApiV1FailDrillsDrillIdDelete,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    drill_id: str,
    *,
    cancelled_by: None | str | Unset = UNSET,
    reason: str | Unset = "",
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_cancelled_by: None | str | Unset
    if isinstance(cancelled_by, Unset):
        json_cancelled_by = UNSET
    else:
        json_cancelled_by = cancelled_by
    params["cancelled_by"] = json_cancelled_by

    params["reason"] = reason

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/fail/drills/{drill_id}".format(
            drill_id=quote(str(drill_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    CancelDrillApiV1FailDrillsDrillIdDeleteResponseCancelDrillApiV1FailDrillsDrillIdDelete | HTTPValidationError | None
):
    if response.status_code == 200:
        response_200 = CancelDrillApiV1FailDrillsDrillIdDeleteResponseCancelDrillApiV1FailDrillsDrillIdDelete.from_dict(
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
    CancelDrillApiV1FailDrillsDrillIdDeleteResponseCancelDrillApiV1FailDrillsDrillIdDelete | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    drill_id: str,
    *,
    client: AuthenticatedClient,
    cancelled_by: None | str | Unset = UNSET,
    reason: str | Unset = "",
) -> Response[
    CancelDrillApiV1FailDrillsDrillIdDeleteResponseCancelDrillApiV1FailDrillsDrillIdDelete | HTTPValidationError
]:
    """Cancel an active drill

     Cancel an active drill without grading it.

    The drill will be marked as cancelled and removed from the active list.
    Cancelled drills are excluded from readiness scoring.

    Args:
        drill_id (str):
        cancelled_by (None | str | Unset): Who is cancelling the drill
        reason (str | Unset): Reason for cancellation Default: ''.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CancelDrillApiV1FailDrillsDrillIdDeleteResponseCancelDrillApiV1FailDrillsDrillIdDelete | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        drill_id=drill_id,
        cancelled_by=cancelled_by,
        reason=reason,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    drill_id: str,
    *,
    client: AuthenticatedClient,
    cancelled_by: None | str | Unset = UNSET,
    reason: str | Unset = "",
) -> (
    CancelDrillApiV1FailDrillsDrillIdDeleteResponseCancelDrillApiV1FailDrillsDrillIdDelete | HTTPValidationError | None
):
    """Cancel an active drill

     Cancel an active drill without grading it.

    The drill will be marked as cancelled and removed from the active list.
    Cancelled drills are excluded from readiness scoring.

    Args:
        drill_id (str):
        cancelled_by (None | str | Unset): Who is cancelling the drill
        reason (str | Unset): Reason for cancellation Default: ''.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CancelDrillApiV1FailDrillsDrillIdDeleteResponseCancelDrillApiV1FailDrillsDrillIdDelete | HTTPValidationError
    """

    return sync_detailed(
        drill_id=drill_id,
        client=client,
        cancelled_by=cancelled_by,
        reason=reason,
    ).parsed


async def asyncio_detailed(
    drill_id: str,
    *,
    client: AuthenticatedClient,
    cancelled_by: None | str | Unset = UNSET,
    reason: str | Unset = "",
) -> Response[
    CancelDrillApiV1FailDrillsDrillIdDeleteResponseCancelDrillApiV1FailDrillsDrillIdDelete | HTTPValidationError
]:
    """Cancel an active drill

     Cancel an active drill without grading it.

    The drill will be marked as cancelled and removed from the active list.
    Cancelled drills are excluded from readiness scoring.

    Args:
        drill_id (str):
        cancelled_by (None | str | Unset): Who is cancelling the drill
        reason (str | Unset): Reason for cancellation Default: ''.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CancelDrillApiV1FailDrillsDrillIdDeleteResponseCancelDrillApiV1FailDrillsDrillIdDelete | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        drill_id=drill_id,
        cancelled_by=cancelled_by,
        reason=reason,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    drill_id: str,
    *,
    client: AuthenticatedClient,
    cancelled_by: None | str | Unset = UNSET,
    reason: str | Unset = "",
) -> (
    CancelDrillApiV1FailDrillsDrillIdDeleteResponseCancelDrillApiV1FailDrillsDrillIdDelete | HTTPValidationError | None
):
    """Cancel an active drill

     Cancel an active drill without grading it.

    The drill will be marked as cancelled and removed from the active list.
    Cancelled drills are excluded from readiness scoring.

    Args:
        drill_id (str):
        cancelled_by (None | str | Unset): Who is cancelling the drill
        reason (str | Unset): Reason for cancellation Default: ''.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CancelDrillApiV1FailDrillsDrillIdDeleteResponseCancelDrillApiV1FailDrillsDrillIdDelete | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            drill_id=drill_id,
            client=client,
            cancelled_by=cancelled_by,
            reason=reason,
        )
    ).parsed
