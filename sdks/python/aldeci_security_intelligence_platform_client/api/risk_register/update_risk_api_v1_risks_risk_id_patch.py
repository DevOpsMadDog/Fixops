from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.update_risk_api_v1_risks_risk_id_patch_response_update_risk_api_v1_risks_risk_id_patch import (
    UpdateRiskApiV1RisksRiskIdPatchResponseUpdateRiskApiV1RisksRiskIdPatch,
)
from ...models.update_risk_request import UpdateRiskRequest
from ...types import Response


def _get_kwargs(
    risk_id: str,
    *,
    body: UpdateRiskRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "patch",
        "url": "/api/v1/risks/{risk_id}".format(
            risk_id=quote(str(risk_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | UpdateRiskApiV1RisksRiskIdPatchResponseUpdateRiskApiV1RisksRiskIdPatch | None:
    if response.status_code == 200:
        response_200 = UpdateRiskApiV1RisksRiskIdPatchResponseUpdateRiskApiV1RisksRiskIdPatch.from_dict(response.json())

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
) -> Response[HTTPValidationError | UpdateRiskApiV1RisksRiskIdPatchResponseUpdateRiskApiV1RisksRiskIdPatch]:
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
    body: UpdateRiskRequest,
) -> Response[HTTPValidationError | UpdateRiskApiV1RisksRiskIdPatchResponseUpdateRiskApiV1RisksRiskIdPatch]:
    """Update a risk

    Args:
        risk_id (str):
        body (UpdateRiskRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdateRiskApiV1RisksRiskIdPatchResponseUpdateRiskApiV1RisksRiskIdPatch]
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
    body: UpdateRiskRequest,
) -> HTTPValidationError | UpdateRiskApiV1RisksRiskIdPatchResponseUpdateRiskApiV1RisksRiskIdPatch | None:
    """Update a risk

    Args:
        risk_id (str):
        body (UpdateRiskRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdateRiskApiV1RisksRiskIdPatchResponseUpdateRiskApiV1RisksRiskIdPatch
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
    body: UpdateRiskRequest,
) -> Response[HTTPValidationError | UpdateRiskApiV1RisksRiskIdPatchResponseUpdateRiskApiV1RisksRiskIdPatch]:
    """Update a risk

    Args:
        risk_id (str):
        body (UpdateRiskRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdateRiskApiV1RisksRiskIdPatchResponseUpdateRiskApiV1RisksRiskIdPatch]
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
    body: UpdateRiskRequest,
) -> HTTPValidationError | UpdateRiskApiV1RisksRiskIdPatchResponseUpdateRiskApiV1RisksRiskIdPatch | None:
    """Update a risk

    Args:
        risk_id (str):
        body (UpdateRiskRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdateRiskApiV1RisksRiskIdPatchResponseUpdateRiskApiV1RisksRiskIdPatch
    """

    return (
        await asyncio_detailed(
            risk_id=risk_id,
            client=client,
            body=body,
        )
    ).parsed
