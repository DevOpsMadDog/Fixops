from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.unmap_control_api_v1_risks_risk_id_controls_ctrl_id_delete_response_unmap_control_api_v1_risks_risk_id_controls_ctrl_id_delete import (
    UnmapControlApiV1RisksRiskIdControlsCtrlIdDeleteResponseUnmapControlApiV1RisksRiskIdControlsCtrlIdDelete,
)
from ...types import Response


def _get_kwargs(
    risk_id: str,
    ctrl_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/risks/{risk_id}/controls/{ctrl_id}".format(
            risk_id=quote(str(risk_id), safe=""),
            ctrl_id=quote(str(ctrl_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | UnmapControlApiV1RisksRiskIdControlsCtrlIdDeleteResponseUnmapControlApiV1RisksRiskIdControlsCtrlIdDelete
    | None
):
    if response.status_code == 200:
        response_200 = UnmapControlApiV1RisksRiskIdControlsCtrlIdDeleteResponseUnmapControlApiV1RisksRiskIdControlsCtrlIdDelete.from_dict(
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
    HTTPValidationError
    | UnmapControlApiV1RisksRiskIdControlsCtrlIdDeleteResponseUnmapControlApiV1RisksRiskIdControlsCtrlIdDelete
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    risk_id: str,
    ctrl_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    HTTPValidationError
    | UnmapControlApiV1RisksRiskIdControlsCtrlIdDeleteResponseUnmapControlApiV1RisksRiskIdControlsCtrlIdDelete
]:
    """Unmap a control from a risk

    Args:
        risk_id (str):
        ctrl_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UnmapControlApiV1RisksRiskIdControlsCtrlIdDeleteResponseUnmapControlApiV1RisksRiskIdControlsCtrlIdDelete]
    """

    kwargs = _get_kwargs(
        risk_id=risk_id,
        ctrl_id=ctrl_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    risk_id: str,
    ctrl_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    HTTPValidationError
    | UnmapControlApiV1RisksRiskIdControlsCtrlIdDeleteResponseUnmapControlApiV1RisksRiskIdControlsCtrlIdDelete
    | None
):
    """Unmap a control from a risk

    Args:
        risk_id (str):
        ctrl_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UnmapControlApiV1RisksRiskIdControlsCtrlIdDeleteResponseUnmapControlApiV1RisksRiskIdControlsCtrlIdDelete
    """

    return sync_detailed(
        risk_id=risk_id,
        ctrl_id=ctrl_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    risk_id: str,
    ctrl_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    HTTPValidationError
    | UnmapControlApiV1RisksRiskIdControlsCtrlIdDeleteResponseUnmapControlApiV1RisksRiskIdControlsCtrlIdDelete
]:
    """Unmap a control from a risk

    Args:
        risk_id (str):
        ctrl_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UnmapControlApiV1RisksRiskIdControlsCtrlIdDeleteResponseUnmapControlApiV1RisksRiskIdControlsCtrlIdDelete]
    """

    kwargs = _get_kwargs(
        risk_id=risk_id,
        ctrl_id=ctrl_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    risk_id: str,
    ctrl_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    HTTPValidationError
    | UnmapControlApiV1RisksRiskIdControlsCtrlIdDeleteResponseUnmapControlApiV1RisksRiskIdControlsCtrlIdDelete
    | None
):
    """Unmap a control from a risk

    Args:
        risk_id (str):
        ctrl_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UnmapControlApiV1RisksRiskIdControlsCtrlIdDeleteResponseUnmapControlApiV1RisksRiskIdControlsCtrlIdDelete
    """

    return (
        await asyncio_detailed(
            risk_id=risk_id,
            ctrl_id=ctrl_id,
            client=client,
        )
    ).parsed
