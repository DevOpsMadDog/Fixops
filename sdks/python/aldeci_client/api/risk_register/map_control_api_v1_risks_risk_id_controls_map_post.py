from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.map_control_api_v1_risks_risk_id_controls_map_post_response_map_control_api_v1_risks_risk_id_controls_map_post import (
    MapControlApiV1RisksRiskIdControlsMapPostResponseMapControlApiV1RisksRiskIdControlsMapPost,
)
from ...models.map_control_request import MapControlRequest
from ...types import Response


def _get_kwargs(
    risk_id: str,
    *,
    body: MapControlRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/risks/{risk_id}/controls/map".format(
            risk_id=quote(str(risk_id), safe=""),
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
    | MapControlApiV1RisksRiskIdControlsMapPostResponseMapControlApiV1RisksRiskIdControlsMapPost
    | None
):
    if response.status_code == 200:
        response_200 = (
            MapControlApiV1RisksRiskIdControlsMapPostResponseMapControlApiV1RisksRiskIdControlsMapPost.from_dict(
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
    HTTPValidationError | MapControlApiV1RisksRiskIdControlsMapPostResponseMapControlApiV1RisksRiskIdControlsMapPost
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    risk_id: str,
    *,
    client: AuthenticatedClient,
    body: MapControlRequest,
) -> Response[
    HTTPValidationError | MapControlApiV1RisksRiskIdControlsMapPostResponseMapControlApiV1RisksRiskIdControlsMapPost
]:
    """Map a control to a risk

    Args:
        risk_id (str):
        body (MapControlRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | MapControlApiV1RisksRiskIdControlsMapPostResponseMapControlApiV1RisksRiskIdControlsMapPost]
    """

    kwargs = _get_kwargs(
        risk_id=risk_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    risk_id: str,
    *,
    client: AuthenticatedClient,
    body: MapControlRequest,
) -> (
    HTTPValidationError
    | MapControlApiV1RisksRiskIdControlsMapPostResponseMapControlApiV1RisksRiskIdControlsMapPost
    | None
):
    """Map a control to a risk

    Args:
        risk_id (str):
        body (MapControlRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | MapControlApiV1RisksRiskIdControlsMapPostResponseMapControlApiV1RisksRiskIdControlsMapPost
    """

    return sync_detailed(
        risk_id=risk_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    risk_id: str,
    *,
    client: AuthenticatedClient,
    body: MapControlRequest,
) -> Response[
    HTTPValidationError | MapControlApiV1RisksRiskIdControlsMapPostResponseMapControlApiV1RisksRiskIdControlsMapPost
]:
    """Map a control to a risk

    Args:
        risk_id (str):
        body (MapControlRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | MapControlApiV1RisksRiskIdControlsMapPostResponseMapControlApiV1RisksRiskIdControlsMapPost]
    """

    kwargs = _get_kwargs(
        risk_id=risk_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    risk_id: str,
    *,
    client: AuthenticatedClient,
    body: MapControlRequest,
) -> (
    HTTPValidationError
    | MapControlApiV1RisksRiskIdControlsMapPostResponseMapControlApiV1RisksRiskIdControlsMapPost
    | None
):
    """Map a control to a risk

    Args:
        risk_id (str):
        body (MapControlRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | MapControlApiV1RisksRiskIdControlsMapPostResponseMapControlApiV1RisksRiskIdControlsMapPost
    """

    return (
        await asyncio_detailed(
            risk_id=risk_id,
            client=client,
            body=body,
        )
    ).parsed
