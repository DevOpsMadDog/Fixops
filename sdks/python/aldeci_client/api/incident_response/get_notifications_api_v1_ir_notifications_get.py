from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.notification_response import NotificationResponse
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str | Unset = "default",
    incident_id: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    json_incident_id: None | str | Unset
    if isinstance(incident_id, Unset):
        json_incident_id = UNSET
    else:
        json_incident_id = incident_id
    params["incident_id"] = json_incident_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/ir/notifications",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[NotificationResponse] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = NotificationResponse.from_dict(response_200_item_data)

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
) -> Response[HTTPValidationError | list[NotificationResponse]]:
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
    incident_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[NotificationResponse]]:
    """Regulatory Notification Deadlines

     Return all regulatory notification deadlines and status: GDPR (72h), HIPAA (60d), PCI-DSS
    (immediate), CCPA (30d), SOC2, NIST. Includes hours remaining and generated notification templates.

    Args:
        org_id (str | Unset): Organization ID Default: 'default'.
        incident_id (None | str | Unset): Filter by incident ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[NotificationResponse]]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        incident_id=incident_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    incident_id: None | str | Unset = UNSET,
) -> HTTPValidationError | list[NotificationResponse] | None:
    """Regulatory Notification Deadlines

     Return all regulatory notification deadlines and status: GDPR (72h), HIPAA (60d), PCI-DSS
    (immediate), CCPA (30d), SOC2, NIST. Includes hours remaining and generated notification templates.

    Args:
        org_id (str | Unset): Organization ID Default: 'default'.
        incident_id (None | str | Unset): Filter by incident ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[NotificationResponse]
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        incident_id=incident_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    incident_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[NotificationResponse]]:
    """Regulatory Notification Deadlines

     Return all regulatory notification deadlines and status: GDPR (72h), HIPAA (60d), PCI-DSS
    (immediate), CCPA (30d), SOC2, NIST. Includes hours remaining and generated notification templates.

    Args:
        org_id (str | Unset): Organization ID Default: 'default'.
        incident_id (None | str | Unset): Filter by incident ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[NotificationResponse]]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        incident_id=incident_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    incident_id: None | str | Unset = UNSET,
) -> HTTPValidationError | list[NotificationResponse] | None:
    """Regulatory Notification Deadlines

     Return all regulatory notification deadlines and status: GDPR (72h), HIPAA (60d), PCI-DSS
    (immediate), CCPA (30d), SOC2, NIST. Includes hours remaining and generated notification templates.

    Args:
        org_id (str | Unset): Organization ID Default: 'default'.
        incident_id (None | str | Unset): Filter by incident ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[NotificationResponse]
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            incident_id=incident_id,
        )
    ).parsed
