from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_treatments_api_v1_risks_risk_id_treatments_get_response_200_item import (
    ListTreatmentsApiV1RisksRiskIdTreatmentsGetResponse200Item,
)
from ...types import Response


def _get_kwargs(
    risk_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/risks/{risk_id}/treatments".format(
            risk_id=quote(str(risk_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[ListTreatmentsApiV1RisksRiskIdTreatmentsGetResponse200Item] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = ListTreatmentsApiV1RisksRiskIdTreatmentsGetResponse200Item.from_dict(
                response_200_item_data
            )

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
) -> Response[HTTPValidationError | list[ListTreatmentsApiV1RisksRiskIdTreatmentsGetResponse200Item]]:
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
) -> Response[HTTPValidationError | list[ListTreatmentsApiV1RisksRiskIdTreatmentsGetResponse200Item]]:
    """List treatment plans for a risk

    Args:
        risk_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ListTreatmentsApiV1RisksRiskIdTreatmentsGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        risk_id=risk_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    risk_id: str,
    *,
    client: AuthenticatedClient,
) -> HTTPValidationError | list[ListTreatmentsApiV1RisksRiskIdTreatmentsGetResponse200Item] | None:
    """List treatment plans for a risk

    Args:
        risk_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ListTreatmentsApiV1RisksRiskIdTreatmentsGetResponse200Item]
    """

    return sync_detailed(
        risk_id=risk_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    risk_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[HTTPValidationError | list[ListTreatmentsApiV1RisksRiskIdTreatmentsGetResponse200Item]]:
    """List treatment plans for a risk

    Args:
        risk_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ListTreatmentsApiV1RisksRiskIdTreatmentsGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        risk_id=risk_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    risk_id: str,
    *,
    client: AuthenticatedClient,
) -> HTTPValidationError | list[ListTreatmentsApiV1RisksRiskIdTreatmentsGetResponse200Item] | None:
    """List treatment plans for a risk

    Args:
        risk_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ListTreatmentsApiV1RisksRiskIdTreatmentsGetResponse200Item]
    """

    return (
        await asyncio_detailed(
            risk_id=risk_id,
            client=client,
        )
    ).parsed
